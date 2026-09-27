#![no_std]
//! Assay safety registry: an on-chain gate for Stellar asset trap mechanics.
//!
//! # What this contract is, and what it is not
//!
//! A Soroban contract cannot call Horizon, fetch a stellar.toml, or read an
//! issuer's authorization flags from within a transaction. So this contract
//! does not scan anything. It stores *attestations* produced by an off-chain
//! Assay scanner and lets another contract read one atomically, in the same
//! transaction as the action it is protecting.
//!
//! That distinction is deliberate and is stated here rather than hidden behind
//! a reassuring function name. A caller is trusting the attester, plus the
//! `evidence_hash` that lets anyone verify the attestation against the evidence
//! the scanner actually fetched.
//!
//! # Why severity is safe to gate on
//!
//! [`Safety::severity`] is capability-only: it is derived from the issuer's
//! authorization flags and never adjusted by reputation, attribution, age, or
//! popularity. Two assets whose issuers hold identical power over holders get
//! identical severity. A gate reading `severity <= MEDIUM` is therefore relying
//! on a statement about ledger mechanics, not on anyone's opinion of an issuer.
//!
//! The one exception moves in the safe direction only: a confirmed malicious
//! listing escalates severity to [`SEVERITY_CRITICAL`]. Reputation can raise a
//! level, never lower one.

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, Address, BytesN, Env,
};

/// No authorization flags: the issuer has no special power over holders.
pub const SEVERITY_CLEAR: u32 = 0;
/// `auth_required`: the issuer controls who may open a trustline.
pub const SEVERITY_LOW: u32 = 1;
/// `auth_revocable`: the issuer can freeze an existing holder's balance.
pub const SEVERITY_MEDIUM: u32 = 2;
/// `auth_clawback_enabled`: the issuer can confiscate and burn a balance.
pub const SEVERITY_HIGH: u32 = 3;
/// Reserved for reputation escalation; never produced by reading flags.
pub const SEVERITY_CRITICAL: u32 = 4;

/// Mechanic bits. These positions are ABI and must not be renumbered; they
/// match `internal/mechanics.Mechanic` on the Go side.
pub const MECH_AUTH_REQUIRED: u32 = 1 << 0;
pub const MECH_AUTH_REVOCABLE: u32 = 1 << 1;
pub const MECH_CLAWBACK_ENABLED: u32 = 1 << 2;
pub const MECH_FLAGS_LOCKED: u32 = 1 << 3;
pub const MECH_DOMAIN_UNVERIFIED: u32 = 1 << 4;
pub const MECH_BLOCKLISTED: u32 = 1 << 5;

/// Mechanics that let an issuer take a balance outright. Any asset matching
/// this mask has `severity >= SEVERITY_HIGH` by construction.
pub const CONFISCATION_MASK: u32 = MECH_CLAWBACK_ENABLED;

/// Capability bits only: the mechanics that are issuer powers over a holder's
/// balance (auth_required, auth_revocable, auth_clawback_enabled). Everything
/// outside this mask (auth_immutable, domain_unverified, blocklisted) is a
/// reported fact, not a power.
///
/// This is the mask a consumer should reach for when it wants "the dangerous
/// bits": #26 happened because a caller hand-rolled that mask from memory and
/// silently missed the other half of the bitset. The Go side exports the same
/// value as `mechanics.CapabilityMask`; the ABI drift test fails the build if
/// the two ever disagree. Bit positions are unchanged — existing attestations
/// commit to them.
pub const CAPABILITY_MASK: u32 = MECH_AUTH_REQUIRED | MECH_AUTH_REVOCABLE | MECH_CLAWBACK_ENABLED;

/// Named forbidden-bit masks for [`SafetyRegistry::is_safe_masked`]. They exist
/// so a caller expresses a policy ("I never accept confiscation") rather than
/// hand-rolling bits. A caller may still pass any `u32`; these are the two
/// documented shapes.
///
/// `POLICY_MASK_CONFISCATION_ONLY` refuses only confiscation capability. A
/// protocol that can tolerate a freeze but never a clawback uses this mask.
pub const POLICY_MASK_CONFISCATION_ONLY: u32 = MECH_CLAWBACK_ENABLED;

/// `POLICY_MASK_FREEZE_INCLUSIVE` refuses both freeze and confiscation. A
/// custody product that must never see a holder's balance altered by the
/// issuer uses this mask.
pub const POLICY_MASK_FREEZE_INCLUSIVE: u32 = MECH_AUTH_REVOCABLE | MECH_CLAWBACK_ENABLED;

/// Event emitted on every successful `attest` write. Rejected attestations
/// (`InvalidSeverity`, `InconsistentAttestation`, unauthorized caller) publish
/// nothing, so observers never see writes that did not happen.
///
/// Topics: `("attest", asset)`. The asset address is a topic (not a data
/// field) so indexers can subscribe by asset without decoding every event.
/// Two topics stay well within the SDK's four-topic limit.
///
/// Data is a `Map` keyed by field name for readability from RPC output. The
/// exact shape is part of the observable ABI: see `docs/contract-interface.md`.
#[contractevent(topics = ["attest"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attested {
    /// The attested asset, identified by its Stellar Asset Contract address.
    #[topic]
    pub asset: Address,
    /// Capability severity written for the asset.
    pub severity: u32,
    /// Mechanic bitset written for the asset.
    pub flags: u32,
    /// Ledger timestamp of the write.
    pub attested_at: u64,
}

/// A stored safety attestation for one asset.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Safety {
    /// Capability severity, `SEVERITY_CLEAR..=SEVERITY_CRITICAL`.
    pub severity: u32,
    /// Bitset of observed mechanics.
    pub flags: u32,
    /// SHA-256 over the canonical evidence bundle the scanner fetched. It lets
    /// a verifier prove this attestation corresponds to specific evidence,
    /// rather than trusting the severity number on its own. The exact bytes
    /// hashed are specified by `internal/attest` and reproducible with
    /// `assay attestation -preimage CODE-ISSUER`.
    pub evidence_hash: BytesN<32>,
    /// Ledger timestamp when this attestation was written.
    pub attested_at: u64,
}

#[contracttype]
enum DataKey {
    /// Contract admin, the only address permitted to attest.
    Admin,
    /// Attestation for one asset, keyed by its Stellar Asset Contract address.
    Safety(Address),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    /// `init` was called on an already-initialized contract.
    AlreadyInitialized = 1,
    /// The contract has no admin yet.
    NotInitialized = 2,
    /// Severity outside `SEVERITY_CLEAR..=SEVERITY_CRITICAL`.
    InvalidSeverity = 3,
    /// An attestation violated the confiscation invariant: the clawback bit is
    /// set but severity is below `SEVERITY_HIGH`. Rejected at write time so a
    /// gate can rely on the invariant at read time.
    InconsistentAttestation = 4,
}

#[contract]
pub struct SafetyRegistry;

#[contractimpl]
impl SafetyRegistry {
    /// Sets the admin permitted to write attestations.
    pub fn init(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        Ok(())
    }

    /// Writes an attestation for `asset`, identified by its SAC address.
    ///
    /// `severity`, `flags`, and `evidence_hash` come from the off-chain
    /// scanner: `assay attestation CODE-ISSUER` derives all three from a live
    /// scan, and `make attest` submits them. Validation here is not a
    /// formality: it enforces at write time the invariants that
    /// [`Self::is_safe`] relies on at read time.
    pub fn attest(
        env: Env,
        asset: Address,
        severity: u32,
        flags: u32,
        evidence_hash: BytesN<32>,
    ) -> Result<(), Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();

        if severity > SEVERITY_CRITICAL {
            return Err(Error::InvalidSeverity);
        }
        if flags & CONFISCATION_MASK != 0 && severity < SEVERITY_HIGH {
            return Err(Error::InconsistentAttestation);
        }

        let attested_at = env.ledger().timestamp();
        let safety = Safety {
            severity,
            flags,
            evidence_hash,
            attested_at,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Safety(asset.clone()), &safety);

        // Publish after the write. Emitting before would let a storage failure
        // produce a visible "attest" for an attestation that does not exist;
        // emitting after means indexers observe writes that actually happened.
        // Rejected calls return early above, so no event is published for them.
        Attested {
            asset,
            severity,
            flags,
            attested_at,
        }
        .publish(&env);
        Ok(())
    }

    /// Reads the attestation for `asset`.
    ///
    /// Returns `None` when the asset has never been attested. That case is
    /// deliberately distinguishable from an attestation of `SEVERITY_CLEAR`:
    /// collapsing the two would make every unknown asset read as safe, which is
    /// the single worst failure this contract could have.
    pub fn get_safety(env: Env, asset: Address) -> Option<Safety> {
        env.storage().persistent().get(&DataKey::Safety(asset))
    }

    /// The fail-closed gate helper.
    ///
    /// Returns `true` only when an attestation exists, is fresh enough, and is
    /// at or below `max_severity`. Every other path returns `false`: never
    /// attested, stale, too severe, or inconsistent. The safe answer is the
    /// default, so a caller that gets the arguments wrong blocks rather than
    /// admits.
    ///
    /// `max_age_secs` of 0 disables the freshness requirement.
    pub fn is_safe(env: Env, asset: Address, max_severity: u32, max_age_secs: u64) -> bool {
        let Some(safety) = Self::get_safety(env.clone(), asset) else {
            return false; // never attested: fail closed
        };

        if safety.severity > max_severity {
            return false;
        }

        // Defence in depth: attest() rejects this, but a gate must not depend
        // on the writer having been correct.
        if safety.flags & CONFISCATION_MASK != 0 && max_severity < SEVERITY_HIGH {
            return false;
        }

        if max_age_secs > 0 {
            let now = env.ledger().timestamp();
            // saturating_sub avoids underflow if an attestation carries a
            // timestamp ahead of the current ledger.
            if now.saturating_sub(safety.attested_at) > max_age_secs {
                return false;
            }
        }

        true
    }

    /// The mask-based fail-closed gate.
    ///
    /// Returns `true` only when an attestation exists, is fresh enough, and
    /// carries none of the bits set in `forbidden_mask`. Every other path
    /// returns `false`: never attested, stale, or forbidden bit set. An empty
    /// `forbidden_mask` still requires an attestation — an unattested asset
    /// must never read as safe, even with a policy that forbids nothing.
    ///
    /// Severity is a total order; policies are not. Severity-based gating with
    /// `is_safe` collapses two independent questions ("can they freeze it?"
    /// "can they take it?") onto one axis. A caller that can tolerate a freeze
    /// but never a confiscation should gate on `POLICY_MASK_CONFISCATION_ONLY`;
    /// a custody product refusing both should gate on
    /// `POLICY_MASK_FREEZE_INCLUSIVE`. See `docs/contract-interface.md`.
    ///
    /// `max_age_secs` of 0 disables the freshness requirement.
    pub fn is_safe_masked(
        env: Env,
        asset: Address,
        forbidden_mask: u32,
        max_age_secs: u64,
    ) -> bool {
        let Some(safety) = Self::get_safety(env.clone(), asset) else {
            return false; // never attested: fail closed
        };

        if safety.flags & forbidden_mask != 0 {
            return false;
        }

        if max_age_secs > 0 {
            let now = env.ledger().timestamp();
            if now.saturating_sub(safety.attested_at) > max_age_secs {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod test;
