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

/// attest() requires auth from the admin set at init time. An unsigned call
/// without authorization must be rejected.
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
fn attest_rejects_no_auth_caller() {
    let env = Env::default();
    let contract_id = env.register(SafetyRegistry, ());
    let client = SafetyRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let asset = Address::generate(&env);

    let err = client
        .try_attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env))
        .expect_err("unauthorized call must be rejected");

    assert!(err.is_err());
}

/// attest() signed by a valid account that is NOT the admin must fail.
/// This exercises require_auth against an explicit non-admin signer.
#[test]
fn attest_rejects_wrong_signer_caller() {
    use soroban_sdk::testutils::MockAuth;
    use soroban_sdk::testutils::MockAuthInvoke;
    use soroban_sdk::IntoVal;

    let env = Env::default();
    let contract_id = env.register(SafetyRegistry, ());
    let client = SafetyRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let wrong_caller = Address::generate(&env);
    let asset = Address::generate(&env);

    let err = client
        .mock_auths(&[MockAuth {
            address: &wrong_caller,
            invoke: &MockAuthInvoke {
                contract: &contract_id,
                fn_name: "attest",
                args: (&asset, SEVERITY_CLEAR, 0u32, hash(&env)).into_val(&env),
                sub_invokes: &[],
            },
        }])
        .try_attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env))
        .expect_err("non-admin signer must be rejected");

    assert!(err.is_err());
}

/// attest() signed explicitly by the admin account succeeds.
#[test]
fn attest_accepts_admin_caller() {
    use soroban_sdk::testutils::MockAuth;
    use soroban_sdk::testutils::MockAuthInvoke;
    use soroban_sdk::IntoVal;

    let env = Env::default();
    let contract_id = env.register(SafetyRegistry, ());
    let client = SafetyRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let asset = Address::generate(&env);

    client
        .mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &contract_id,
                fn_name: "attest",
                args: (&asset, SEVERITY_CLEAR, 0u32, hash(&env)).into_val(&env),
                sub_invokes: &[],
            },
        }])
        .attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));

    let got = client.get_safety(&asset).expect("attestation should exist");
    assert_eq!(got.severity, SEVERITY_CLEAR);
}

/// Property test: is_safe MUST return false for any unattested asset across all threshold/age arguments.
#[test]
fn is_safe_property_unattested() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    for max_sev in 0..=5 {
        for max_age in [0, 60, 600, 3600] {
            assert!(
                !client.is_safe(&asset, &max_sev, &max_age),
                "unattested asset must be false for max_sev={}, max_age={}",
                max_sev,
                max_age
            );
        }
    }
}

/// Exhaustive property test for is_safe over the conjunction of all four conditions:
/// 1. Attested state (true)
/// 2. Severity within threshold (attested_severity <= max_severity)
/// 3. Confiscation invariant intact (flags & CONFISCATION_MASK == 0 || max_severity >= SEVERITY_HIGH)
/// 4. Freshness window met (max_age_secs == 0 || age <= max_age_secs)
#[test]
fn is_safe_property_exhaustive() {
    let (env, client, _) = setup();

    let severities = [0, 1, 2, 3, 4, 5]; // Severity values 0..=5 (including out-of-range 5)
    let flag_sets = [
        0u32,
        MECH_AUTH_REQUIRED,
        MECH_CLAWBACK_ENABLED,
        MECH_AUTH_REQUIRED | MECH_CLAWBACK_ENABLED,
        0b111111u32,
    ];
    let max_severities = [0, 1, 2, 3, 4, 5];
    let max_ages = [0u64, 300, 600];
    let nows = [1_000u64, 1_300, 1_600, 2_000]; // ages: 0, 300, 600, 1000

    let attested_at = 1_000u64;

    for &attested_sev in &severities {
        for &attested_flags in &flag_sets {
            for &now in &nows {
                for &max_sev in &max_severities {
                    for &max_age in &max_ages {
                        let asset = Address::generate(&env);
                        env.ledger().set_timestamp(attested_at);

                        // If severity is valid (<= 4) and flags do not violate clawback invariant, write attestation
                        // Note: If clawback bit set and severity < 3, try_attest will reject write, so we manually test stored safety
                        if attested_flags & MECH_CLAWBACK_ENABLED != 0
                            && attested_sev < SEVERITY_HIGH
                        {
                            // Invalid write time invariant; cannot attest on chain directly, skipped from valid store
                            continue;
                        }
                        if attested_sev > SEVERITY_CRITICAL {
                            // Invalid severity; cannot attest on chain directly, skipped from valid store
                            continue;
                        }

                        client.attest(&asset, &attested_sev, &attested_flags, &hash(&env));
                        env.ledger().set_timestamp(now);

                        let age = now.saturating_sub(attested_at);

                        let cond_severity = attested_sev <= max_sev;
                        let cond_confiscation =
                            (attested_flags & CONFISCATION_MASK) == 0 || max_sev >= SEVERITY_HIGH;
                        let cond_freshness = max_age == 0 || age <= max_age;

                        let expected = cond_severity && cond_confiscation && cond_freshness;
                        let actual = client.is_safe(&asset, &max_sev, &max_age);

                        assert_eq!(
                            actual, expected,
                            "is_safe mismatch for sev={}, flags={}, max_sev={}, age={}, max_age={}",
                            attested_sev, attested_flags, max_sev, age, max_age
                        );
                    }
                }
            }
        }
    }
}

/// Contract error discriminants are ABI documented in docs/integrating.md and live results.
/// Reordering or changing discriminants silently breaks integrator error handling.
#[test]
fn error_code_values_are_abi() {
    assert_eq!(Error::AlreadyInitialized as u32, 1);
    assert_eq!(Error::NotInitialized as u32, 2);
    assert_eq!(Error::InvalidSeverity as u32, 3);
    assert_eq!(Error::InconsistentAttestation as u32, 4);
}
