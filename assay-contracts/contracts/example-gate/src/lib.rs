#![no_std]
//! A worked example of gating a Soroban contract on Assay.
//!
//! This is the smallest contract that refuses to accept a deposit in an asset
//! whose issuer can take it back. It exists to be copied: everything an
//! integrator needs is in this file, and it depends on nothing from Assay at
//! build time — only on the deployed registry's interface, declared below.
//!
//! It is deliberately not a vault. It stores a balance and nothing else, so
//! the only thing worth reading here is the gate.
//!
//! See `docs/integrating.md` for the deployed testnet registry address and the
//! deploy command that wires it in.

use soroban_sdk::{
    contract, contractclient, contracterror, contractimpl, contracttype, Address, BytesN, Env,
};

// ---------------------------------------------------------------------------
// The registry interface, as an integrator declares it.
// ---------------------------------------------------------------------------

/// Mirror of the registry's stored attestation.
///
/// Field names and types are ABI: they must match the registry exactly, because
/// a `#[contracttype]` struct crosses the contract boundary as a map keyed by
/// these names.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Safety {
    pub severity: u32,
    pub flags: u32,
    pub evidence_hash: BytesN<32>,
    pub attested_at: u64,
}

/// The part of the registry this gate calls.
#[contractclient(name = "SafetyRegistryClient")]
pub trait SafetyRegistry {
    fn get_safety(env: Env, asset: Address) -> Option<Safety>;
    fn is_safe(env: Env, asset: Address, max_severity: u32, max_age_secs: u64) -> bool;
}

/// The issuer can confiscate a holder's balance outright (`1 << 2`).
pub const MECH_CLAWBACK_ENABLED: u32 = 1 << 2;
/// The issuer can freeze a holder's balance (`1 << 1`).
pub const MECH_AUTH_REVOCABLE: u32 = 1 << 1;

/// Mechanics this gate refuses outright, whatever the severity number says.
///
/// Severity is a single ordered number and answers "how bad"; the bitset
/// answers "which power", and a contract usually has an opinion about a
/// specific power. A custodial balance cannot survive confiscation or a freeze,
/// so both bits are refused here regardless of how the levels are ordered.
pub const REFUSED_MECHANICS: u32 = MECH_CLAWBACK_ENABLED | MECH_AUTH_REVOCABLE;

/// The severity ceiling, checked *in addition to* [`REFUSED_MECHANICS`].
///
/// Both are necessary and neither is redundant, which is the whole lesson of
/// this example. They catch disjoint things:
///
/// - `USDC` is severity 2 with `auth_revocable` set. The ceiling admits it;
///   the mask refuses it. Without the mask, a freeze-capable issuer gets in.
/// - `DOGE` is severity 4 with flags `48` — `domain_unverified | blocklisted`
///   and **no capability bits at all**, because its issuer genuinely cannot
///   freeze or confiscate. The mask computes `48 & 6 == 0` and admits it; the
///   ceiling refuses it. Without the ceiling, a known scam gets in.
///
/// That second case is not a hypothetical. This contract shipped without the
/// ceiling and admitted `DOGE` on testnet.
///
/// The asymmetry is structural rather than accidental. Reputation escalation
/// raises severity and sets `blocklisted`; it must never set a capability bit,
/// because capability bits describe what an issuer *can do* and a scam listing
/// is not a capability. So a mask over capability bits cannot see escalation,
/// by construction — and any gate that reads only the mask is blind to half
/// the severity model.
pub const MAX_SEVERITY: u32 = 2;

/// How stale an attestation may be before this gate stops trusting it.
///
/// Twenty-four hours is this contract's policy, not Assay's. The registry
/// exposes `attested_at` and takes the tolerance as a parameter precisely
/// because a deposit gate and a large settlement should not be forced to agree.
///
/// The derivation lives in `docs/freshness.md`: measured issuer-flag change
/// rates (zero among attested legitimate issuers over six months, month-scale
/// churn demonstrated on a scam issuer), the use classes that need different
/// windows, and the caveat that all ten live attestations are already past
/// this constant — a window without a re-attestation path behind it is a
/// countdown, and this example has no refresher.
pub const MAX_ATTESTATION_AGE: u64 = 24 * 60 * 60;

// ---------------------------------------------------------------------------
// The gate.
// ---------------------------------------------------------------------------

#[contracttype]
enum DataKey {
    /// The Assay registry this gate reads.
    Registry,
    /// Deposited balance per (asset, depositor).
    Balance(Address, Address),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    /// No attestation exists for this asset. The gate does not know the asset,
    /// which is not the same as the asset being safe.
    NotAttested = 1,
    /// The newest attestation is older than [`MAX_ATTESTATION_AGE`].
    AttestationStale = 2,
    /// The issuer holds a power in [`REFUSED_MECHANICS`].
    IssuerCanTakeIt = 3,
    /// Severity exceeds [`MAX_SEVERITY`]. Kept distinct from
    /// [`Self::IssuerCanTakeIt`] because the two mean different things to a
    /// caller: one says the issuer can take your balance, the other says
    /// someone has affirmatively identified this asset as malicious. A client
    /// that cannot tell them apart cannot explain either.
    SeverityTooHigh = 4,
}

#[contract]
pub struct ExampleGate;

#[contractimpl]
impl ExampleGate {
    /// Binds this gate to a deployed Assay registry.
    pub fn __constructor(env: Env, registry: Address) {
        env.storage().instance().set(&DataKey::Registry, &registry);
    }

    /// Accepts a deposit, but only in an asset the issuer cannot claw back.
    ///
    /// The read is a cross-contract call in the same transaction as the
    /// deposit, so the attestation cannot change between the check and the
    /// credit. That atomicity is the reason the registry is on-chain at all —
    /// an HTTP call to a scanner before submitting could be answered against a
    /// different ledger state than the one the deposit lands in.
    pub fn deposit(env: Env, asset: Address, from: Address, amount: i128) -> Result<(), Error> {
        from.require_auth();

        Self::assert_safe(&env, &asset)?;

        let key = DataKey::Balance(asset, from);
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
        Ok(())
    }

    /// Reports whether [`Self::deposit`] would admit this asset right now.
    ///
    /// Exposed so a client can show the reason before spending a fee on a
    /// transaction that would revert.
    pub fn would_admit(env: Env, asset: Address) -> bool {
        Self::assert_safe(&env, &asset).is_ok()
    }

    pub fn balance(env: Env, asset: Address, holder: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(asset, holder))
            .unwrap_or(0)
    }

    /// The gate itself.
    ///
    /// Every path that is not an affirmative, fresh, clean attestation is an
    /// error. `None` is handled first and explicitly: an asset nobody has
    /// attested is unknown, and treating unknown as safe would let any asset
    /// through by the simple expedient of never being scanned.
    fn assert_safe(env: &Env, asset: &Address) -> Result<(), Error> {
        let registry: Address = env
            .storage()
            .instance()
            .get(&DataKey::Registry)
            .expect("gate was constructed with a registry");
        let registry = SafetyRegistryClient::new(env, &registry);

        let Some(safety) = registry.get_safety(asset) else {
            return Err(Error::NotAttested);
        };

        if env.ledger().timestamp().saturating_sub(safety.attested_at) > MAX_ATTESTATION_AGE {
            return Err(Error::AttestationStale);
        }

        // Severity ceiling. Without this, an asset that is critical purely by
        // reputation — no capability bits set — passes the mask below and is
        // admitted. See DOGE in the module docs and docs/integrating.md.
        if safety.severity > MAX_SEVERITY {
            return Err(Error::SeverityTooHigh);
        }

        if safety.flags & REFUSED_MECHANICS != 0 {
            return Err(Error::IssuerCanTakeIt);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test;
