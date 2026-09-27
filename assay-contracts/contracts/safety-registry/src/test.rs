#![cfg(test)]

use super::*;
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Events as _, Ledger as _},
    vec, BytesN, Env, IntoVal, Map, Symbol,
};

fn setup() -> (Env, SafetyRegistryClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(SafetyRegistry, ());
    let client = SafetyRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    (env, client, admin)
}

fn hash(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[7u8; 32])
}

#[test]
fn unattested_asset_returns_none() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    assert_eq!(client.get_safety(&asset), None);
}

/// The most important test in this contract. An asset nobody has ever scanned
/// must never be treated as safe.
#[test]
fn gate_fails_closed_on_unattested_asset() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    assert!(!client.is_safe(&asset, &SEVERITY_CRITICAL, &0));
    assert!(!client.is_safe(&asset, &SEVERITY_CLEAR, &0));
}

#[test]
fn attest_then_read_roundtrips() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);
    env.ledger().set_timestamp(1_000);

    client.attest(&asset, &SEVERITY_MEDIUM, &MECH_AUTH_REVOCABLE, &hash(&env));

    let got = client.get_safety(&asset).expect("attestation should exist");
    assert_eq!(got.severity, SEVERITY_MEDIUM);
    assert_eq!(got.flags, MECH_AUTH_REVOCABLE);
    assert_eq!(got.attested_at, 1_000);
    assert_eq!(got.evidence_hash, hash(&env));
}

#[test]
fn gate_admits_within_threshold_and_blocks_above() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    client.attest(&asset, &SEVERITY_MEDIUM, &MECH_AUTH_REVOCABLE, &hash(&env));

    assert!(client.is_safe(&asset, &SEVERITY_MEDIUM, &0));
    assert!(client.is_safe(&asset, &SEVERITY_HIGH, &0));
    assert!(!client.is_safe(&asset, &SEVERITY_LOW, &0));
    assert!(!client.is_safe(&asset, &SEVERITY_CLEAR, &0));
}

#[test]
fn stale_attestation_fails_closed() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    env.ledger().set_timestamp(1_000);
    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    assert!(client.is_safe(&asset, &SEVERITY_MEDIUM, &600));

    env.ledger().set_timestamp(1_000 + 601);
    assert!(!client.is_safe(&asset, &SEVERITY_MEDIUM, &600));

    // max_age_secs = 0 disables the freshness requirement.
    assert!(client.is_safe(&asset, &SEVERITY_MEDIUM, &0));
}

#[test]
fn attestation_from_the_future_does_not_underflow() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    env.ledger().set_timestamp(5_000);
    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    env.ledger().set_timestamp(1_000);

    assert!(client.is_safe(&asset, &SEVERITY_MEDIUM, &600));
}

/// Confiscation capability must not be expressible below High. The writer
/// rejects it so a reader can rely on the invariant.
#[test]
fn attest_rejects_clawback_below_high() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    let err = client
        .try_attest(
            &asset,
            &SEVERITY_MEDIUM,
            &MECH_CLAWBACK_ENABLED,
            &hash(&env),
        )
        .expect_err("clawback below high must be rejected");

    assert_eq!(err, Ok(Error::InconsistentAttestation));
}

#[test]
fn attest_rejects_out_of_range_severity() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    let err = client
        .try_attest(&asset, &(SEVERITY_CRITICAL + 1), &0, &hash(&env))
        .expect_err("severity above critical must be rejected");

    assert_eq!(err, Ok(Error::InvalidSeverity));
}

/// Even if a bad attestation somehow existed, a gate below High must not admit
/// a confiscation-capable asset.
#[test]
fn gate_blocks_confiscation_below_high_threshold() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    client.attest(
        &asset,
        &SEVERITY_HIGH,
        &(MECH_CLAWBACK_ENABLED | MECH_AUTH_REVOCABLE),
        &hash(&env),
    );

    assert!(!client.is_safe(&asset, &SEVERITY_MEDIUM, &0));
    assert!(client.is_safe(&asset, &SEVERITY_HIGH, &0));
}

#[test]
fn init_is_single_shot() {
    let (env, client, _) = setup();
    let other = Address::generate(&env);

    let err = client.try_init(&other).expect_err("second init must fail");
    assert_eq!(err, Ok(Error::AlreadyInitialized));
}

/// An empty forbidden_mask must NOT become a blanket allow for unattested
/// assets. The gate still requires that an attestation exists.
#[test]
fn masked_gate_fails_closed_on_unattested_asset() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    assert!(!client.is_safe_masked(&asset, &0, &0));
    assert!(!client.is_safe_masked(&asset, &u32::MAX, &0));
}

#[test]
fn masked_gate_admits_when_no_forbidden_bit_is_set() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    // Freeze-capable but not confiscation-capable.
    client.attest(&asset, &SEVERITY_MEDIUM, &MECH_AUTH_REVOCABLE, &hash(&env));

    // A policy that only refuses confiscation admits this asset.
    assert!(client.is_safe_masked(&asset, &POLICY_MASK_CONFISCATION_ONLY, &0));
    // A freeze-inclusive policy refuses it.
    assert!(!client.is_safe_masked(&asset, &POLICY_MASK_FREEZE_INCLUSIVE, &0));
}

#[test]
fn masked_gate_blocks_confiscation_capable_asset() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    client.attest(
        &asset,
        &SEVERITY_HIGH,
        &(MECH_AUTH_REVOCABLE | MECH_CLAWBACK_ENABLED),
        &hash(&env),
    );

    assert!(!client.is_safe_masked(&asset, &POLICY_MASK_CONFISCATION_ONLY, &0));
    assert!(!client.is_safe_masked(&asset, &POLICY_MASK_FREEZE_INCLUSIVE, &0));
}

#[test]
fn masked_gate_all_bits_blocks_any_attested_flag() {
    let (env, client, _) = setup();
    let clean = Address::generate(&env);
    let dirty = Address::generate(&env);

    // Zero flags: an all-bits mask admits it (no forbidden bit is set).
    client.attest(&clean, &SEVERITY_CLEAR, &0, &hash(&env));
    assert!(client.is_safe_masked(&clean, &u32::MAX, &0));

    // Any flag set: an all-bits mask refuses it.
    client.attest(&dirty, &SEVERITY_LOW, &MECH_AUTH_REQUIRED, &hash(&env));
    assert!(!client.is_safe_masked(&dirty, &u32::MAX, &0));
}

#[test]
fn masked_gate_stale_attestation_fails_closed() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    env.ledger().set_timestamp(1_000);
    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    assert!(client.is_safe_masked(&asset, &POLICY_MASK_CONFISCATION_ONLY, &600));

    env.ledger().set_timestamp(1_000 + 601);
    assert!(!client.is_safe_masked(&asset, &POLICY_MASK_CONFISCATION_ONLY, &600));

    // max_age_secs = 0 disables the freshness requirement.
    assert!(client.is_safe_masked(&asset, &POLICY_MASK_CONFISCATION_ONLY, &0));
}

/// A successful attest emits one event with topics ("attest", asset) and data
/// (severity, flags, attested_at). Events published by this contract are
/// isolated with filter_by_contract so any auth-machinery events elsewhere in
/// the environment do not confuse the assertion.
#[test]
fn attest_emits_event_on_success() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);
    env.ledger().set_timestamp(1_234);

    client.attest(&asset, &SEVERITY_MEDIUM, &MECH_AUTH_REVOCABLE, &hash(&env));

    // Data is the Map produced by #[contractevent]: field-name Symbols to
    // their values. Building it this way makes what a consumer decoding the
    // event will see explicit.
    let mut data = Map::<Symbol, soroban_sdk::Val>::new(&env);
    data.set(Symbol::new(&env, "attested_at"), 1_234u64.into_val(&env));
    data.set(
        Symbol::new(&env, "flags"),
        MECH_AUTH_REVOCABLE.into_val(&env),
    );
    data.set(
        Symbol::new(&env, "severity"),
        SEVERITY_MEDIUM.into_val(&env),
    );

    assert_eq!(
        env.events().all().filter_by_contract(&client.address),
        vec![
            &env,
            (
                client.address.clone(),
                (symbol_short!("attest"), asset).into_val(&env),
                data.into_val(&env),
            ),
        ],
    );
}

/// A rejected attestation must not publish an event; otherwise observers see
/// writes that never happened.
#[test]
fn attest_publishes_no_event_on_rejection() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    // InvalidSeverity.
    let _ = client.try_attest(&asset, &(SEVERITY_CRITICAL + 1), &0, &hash(&env));
    // InconsistentAttestation.
    let _ = client.try_attest(
        &asset,
        &SEVERITY_MEDIUM,
        &MECH_CLAWBACK_ENABLED,
        &hash(&env),
    );

    assert_eq!(
        env.events().all().filter_by_contract(&client.address),
        vec![&env, /* empty: rejected attest calls must not emit events */],
    );
}

/// attest() requires auth from the admin set at init time. A non-admin
/// caller must be rejected. This test does not use mock_all_auths(), so
/// require_auth() on the admin address actually enforces.
#[test]
fn attest_rejects_unauthorized_caller() {
    let env = Env::default();
    let contract_id = env.register(SafetyRegistry, ());
    let client = SafetyRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let _caller = Address::generate(&env);
    let asset = Address::generate(&env);

    let err = client
        .try_attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env))
        .expect_err("non-admin must be rejected");

    // The error type is SDK-internal (soroban_sdk::Error), not our contract
    // Error enum. The important property is that it is an error at all: a
    // non-admin caller must not be able to write attestations.
    assert!(err.is_err());
}

#[test]
fn successful_admin_transfer() {
    let (env, client, _admin) = setup();
    let new_admin = Address::generate(&env);
    let asset = Address::generate(&env);

    client.transfer_admin(&new_admin);
    client.accept_admin();

    // New admin can attest successfully
    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    assert_eq!(client.get_safety(&asset).unwrap().severity, SEVERITY_CLEAR);
}

#[test]
fn transfer_before_init_fails() {
    let env = Env::default();
    let contract_id = env.register(SafetyRegistry, ());
    let client = SafetyRegistryClient::new(&env, &contract_id);
    let new_admin = Address::generate(&env);

    let err = client
        .try_transfer_admin(&new_admin)
        .expect_err("transfer before init must fail");
    assert_eq!(err, Ok(Error::NotInitialized));
}

#[test]
fn accept_without_pending_admin_fails() {
    let (env, client, _) = setup();
    let err = client
        .try_accept_admin()
        .expect_err("accept without pending transfer must fail");
    assert_eq!(err, Ok(Error::NoPendingAdmin));
}
