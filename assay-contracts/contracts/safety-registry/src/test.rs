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

// ---------------------------------------------------------------------------
// Revocation (#86)
// ---------------------------------------------------------------------------

/// Revoking restores the never-attested state exactly: get_safety returns
/// None and both gates fail closed, even with their most permissive arguments.
#[test]
fn admin_revokes_attestation() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    assert!(client.is_safe(&asset, &SEVERITY_CRITICAL, &0));

    client.revoke(&asset);

    assert_eq!(client.get_safety(&asset), None);
    assert!(!client.is_safe(&asset, &SEVERITY_CRITICAL, &0));
    assert!(!client.is_safe_masked(&asset, &0, &0));
}

/// Revocation only touches the named asset.
#[test]
fn revoke_leaves_other_assets_attested() {
    let (env, client, _) = setup();
    let revoked = Address::generate(&env);
    let kept = Address::generate(&env);

    client.attest(&revoked, &SEVERITY_CLEAR, &0, &hash(&env));
    client.attest(&kept, &SEVERITY_LOW, &MECH_AUTH_REQUIRED, &hash(&env));
    client.revoke(&revoked);

    assert_eq!(client.get_safety(&revoked), None);
    assert!(client.get_safety(&kept).is_some());
}

/// A revoked asset can be attested again, and the new attestation is read
/// normally with its own timestamp.
#[test]
fn revoke_then_reattest() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    env.ledger().set_timestamp(1_000);
    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    client.revoke(&asset);

    env.ledger().set_timestamp(2_000);
    client.attest(&asset, &SEVERITY_MEDIUM, &MECH_AUTH_REVOCABLE, &hash(&env));

    let got = client
        .get_safety(&asset)
        .expect("re-attestation should exist");
    assert_eq!(got.severity, SEVERITY_MEDIUM);
    assert_eq!(got.flags, MECH_AUTH_REVOCABLE);
    assert_eq!(got.attested_at, 2_000);
}

/// Revoking an asset with no attestation is an error, not a silent success:
/// a revocation aimed at the wrong address must not report that it worked.
/// The same holds for a second revoke of the same asset.
#[test]
fn revoke_nonexistent_returns_not_attested() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    let err = client
        .try_revoke(&asset)
        .expect_err("revoking a never-attested asset must fail");
    assert_eq!(err, Ok(Error::NotAttested));

    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    client.revoke(&asset);
    let err = client
        .try_revoke(&asset)
        .expect_err("a second revoke must fail");
    assert_eq!(err, Ok(Error::NotAttested));
}

#[test]
fn revoke_before_init_returns_not_initialized() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(SafetyRegistry, ());
    let client = SafetyRegistryClient::new(&env, &contract_id);

    let err = client
        .try_revoke(&Address::generate(&env))
        .expect_err("revoke before init must fail");
    assert_eq!(err, Ok(Error::NotInitialized));
}

/// revoke() requires the admin's authorization, exactly as attest() does. The
/// attestation is written with the admin's auth mocked for that one call; the
/// revoke is then signed by a different address, which must be rejected and
/// must leave the attestation in place.
#[test]
fn revoke_rejects_unauthorized_caller() {
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

    let caller = Address::generate(&env);
    let err = client
        .mock_auths(&[MockAuth {
            address: &caller,
            invoke: &MockAuthInvoke {
                contract: &contract_id,
                fn_name: "revoke",
                args: (&asset,).into_val(&env),
                sub_invokes: &[],
            },
        }])
        .try_revoke(&asset)
        .expect_err("non-admin must be rejected");

    // As in attest_rejects_unauthorized_caller, the error is the host's auth
    // error rather than a contract Error; what matters is that it is one.
    assert!(err.is_err());
    assert!(client.get_safety(&asset).is_some());
}

/// A successful revoke emits one event with topics ("revoke", asset).
#[test]
fn revoke_emits_event_on_success() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    env.ledger().set_timestamp(4_321);
    client.revoke(&asset);

    let mut data = Map::<Symbol, soroban_sdk::Val>::new(&env);
    data.set(Symbol::new(&env, "revoked_at"), 4_321u64.into_val(&env));

    assert_eq!(
        env.events().all().filter_by_contract(&client.address),
        vec![
            &env,
            (
                client.address.clone(),
                (symbol_short!("revoke"), asset).into_val(&env),
                data.into_val(&env),
            ),
        ],
    );
}

/// A failed revoke publishes nothing.
#[test]
fn revoke_publishes_no_event_on_rejection() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    let _ = client.try_revoke(&asset);

    assert_eq!(
        env.events().all().filter_by_contract(&client.address),
        vec![&env, /* empty: a failed revoke must not emit an event */],
    );
}

// ---------------------------------------------------------------------------
// TTL and archival (#87)
// ---------------------------------------------------------------------------

use soroban_sdk::testutils::storage::{Instance as _, Persistent as _};

fn safety_ttl(env: &Env, client: &SafetyRegistryClient, asset: &Address) -> u32 {
    env.as_contract(&client.address, || {
        env.storage()
            .persistent()
            .get_ttl(&DataKey::Safety(asset.clone()))
    })
}

fn instance_ttl(env: &Env, client: &SafetyRegistryClient) -> u32 {
    env.as_contract(&client.address, || env.storage().instance().get_ttl())
}

fn max_ttl(env: &Env, client: &SafetyRegistryClient) -> u32 {
    env.as_contract(&client.address, || env.storage().max_ttl())
}

/// attest extends the attestation entry and the contract instance to the
/// network's maximum TTL, read from the host rather than hard-coded.
#[test]
fn attest_extends_ttl_to_network_max() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));

    let max = max_ttl(&env, &client);
    assert!(
        max > env.ledger().get().min_persistent_entry_ttl,
        "test is meaningless if the max equals the default"
    );
    assert_eq!(safety_ttl(&env, &client, &asset), max);
    assert_eq!(instance_ttl(&env, &client), max);
}

/// Re-attesting renews the TTL: an entry that has aged is pushed back out to
/// the maximum by the next write.
#[test]
fn reattest_renews_ttl() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    let max = max_ttl(&env, &client);

    let seq = env.ledger().sequence();
    env.ledger().set_sequence_number(seq + 10_000);
    assert_eq!(safety_ttl(&env, &client, &asset), max - 10_000);

    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    assert_eq!(safety_ttl(&env, &client, &asset), max);
}

/// Reads do not extend TTL. Retention follows writes, so an attestation nobody
/// refreshes ages out rather than being kept alive by the gates reading it.
#[test]
fn reads_do_not_extend_ttl() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    let max = max_ttl(&env, &client);

    let seq = env.ledger().sequence();
    env.ledger().set_sequence_number(seq + 10_000);
    let _ = client.get_safety(&asset);
    let _ = client.is_safe(&asset, &SEVERITY_CRITICAL, &0);
    let _ = client.is_safe_masked(&asset, &0, &0);

    assert_eq!(safety_ttl(&env, &client, &asset), max - 10_000);
}

/// Documents what the host does when an attestation's TTL has run out, which
/// is not what the obvious guess says. The read does not return `None` and does
/// not trap: since protocol 23 an archived persistent entry is restored on
/// access, so the read returns the original attestation with its original
/// `attested_at`. The test host models this, and the same behaviour was
/// observed on testnet on 2026-09-27, where simulating `get_safety` against an
/// archived entry returned it and marked it for restoration in the footprint
/// (see "Entry lifetime" in docs/deployment.md).
///
/// So archival is not an expiry control. What stops a gate trusting a
/// months-old attestation is `max_age_secs`, which still sees the original
/// timestamp; a caller passing `max_age_secs = 0` gets no such protection.
#[test]
fn read_after_archival_returns_original_attestation() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    env.ledger().set_timestamp(1_000);
    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    let entry_ttl = safety_ttl(&env, &client, &asset);

    // Keep the instance and code live so only the attestation has expired,
    // then move past its live-until ledger, advancing the clock with it.
    env.as_contract(&client.address, || {
        let max = env.storage().max_ttl();
        env.storage().instance().extend_ttl(max, max);
    });
    let seq = env.ledger().sequence();
    env.ledger().set_sequence_number(seq + entry_ttl + 1);
    let aged = 1_000 + u64::from(entry_ttl + 1) * 5;
    env.ledger().set_timestamp(aged);

    let got = client
        .get_safety(&asset)
        .expect("an archived attestation is restored, not read as None");
    assert_eq!(got.attested_at, 1_000, "the original timestamp survives");

    // A freshness window shorter than the entry's age refuses it...
    assert!(!client.is_safe(&asset, &SEVERITY_CRITICAL, &86_400));
    assert!(!client.is_safe_masked(&asset, &0, &86_400));
    // ...and a caller that disabled freshness is served it as-is.
    assert!(client.is_safe(&asset, &SEVERITY_CRITICAL, &0));
}

// ---------------------------------------------------------------------------
// Re-attestation (#91)
// ---------------------------------------------------------------------------

/// Re-attestation with identical evidence must move only the timestamp.
///
/// This is the property that makes routine re-attestation safe: re-scanning an
/// asset whose severity, flags and evidence hash have not changed must overwrite
/// the stored attestation with the same values and a fresh `attested_at`, and
/// nothing a gate reads may move. It was observed by hand on AQUA and DOGE on
/// 2026-09-16 (both reproduced their original hashes exactly; only the timestamp
/// advanced) and is pinned here so a regression names the field that changed.
#[test]
fn re_attestation_identical_evidence_moves_only_timestamp() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    env.ledger().set_timestamp(1_000);
    client.attest(&asset, &SEVERITY_MEDIUM, &MECH_AUTH_REVOCABLE, &hash(&env));

    let first = client
        .get_safety(&asset)
        .expect("first attestation should exist");
    assert_eq!(
        first.attested_at, 1_000,
        "first write carries its ledger time"
    );

    // Advance the ledger, then re-attest with byte-identical inputs.
    let later = 1_000 + 86_400;
    env.ledger().set_timestamp(later);
    client.attest(&asset, &SEVERITY_MEDIUM, &MECH_AUTH_REVOCABLE, &hash(&env));

    let second = client
        .get_safety(&asset)
        .expect("second attestation should exist");

    // Each field is compared on its own so a failure names the one that moved,
    // rather than reporting that two whole structs differ.
    assert_eq!(second.severity, first.severity, "severity must not move");
    assert_eq!(second.flags, first.flags, "flags must not move");
    assert_eq!(
        second.evidence_hash, first.evidence_hash,
        "evidence_hash must not move"
    );
    assert_eq!(
        second.attested_at, later,
        "attested_at must advance to the re-attestation time"
    );
}