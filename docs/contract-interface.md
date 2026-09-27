# `get_safety(asset)`

The on-chain half of Assay: a Soroban contract another contract can call
atomically, in the same transaction as the action it protects.

Source: [`assay-contracts/contracts/safety-registry`](../assay-contracts/contracts/safety-registry).
Deployed to testnet at `CBK4FBIHMDTXCUPE4E3ZDVSFJSCY5FJETTKNIQPN4LFJIKKIBLKIXQ73`
— see [deployment.md](deployment.md) for addresses and transaction hashes, and
[integrating.md](integrating.md) for how to call it.

## What it is, honestly

**It is an attestation store, not a scanner.**

A Soroban contract cannot call Horizon, fetch a stellar.toml, or read an
issuer's authorization flags mid-transaction. So the contract does not scan. It
stores attestations produced by the off-chain scanner and serves them for atomic
reads.

This is stated plainly rather than hidden behind a reassuring function name,
because a caller is trusting the attester and needs to know that. `evidence_hash`
is what makes that trust checkable: a SHA-256 over the canonical evidence bundle
the scanner fetched, so anyone can verify an attestation corresponds to specific
evidence rather than to a number someone typed.

Attestations are written by `assay attestation`, which derives severity, the
mechanic bitset, and the evidence hash from a live scan, and `make attest`,
which submits them. No path through either lets a hand-written severity reach
the contract. The pipeline that would keep the registry continuously current
is designed (not yet built) in [attestation-writer.md](attestation-writer.md).

## ABI

```rust
// What storage holds, returned by get_safety.
pub struct Safety {
    pub severity: u32,             // 0..=4, capability-only
    pub flags: u32,                // mechanic bitset
    pub evidence_hash: BytesN<32>, // sha256 of the evidence bundle
    pub attested_at: u64,          // ledger timestamp
}

// One element of an attest_many batch: the arguments of attest(), grouped.
pub struct Attestation {
    pub asset: Address,
    pub severity: u32,
    pub flags: u32,
    pub evidence_hash: BytesN<32>,
}

/// The largest batch attest_many accepts. The cap is derived from the
/// live transaction resource limits; see "attest_many" below.
pub const MAX_BATCH_SIZE: u32 = 50;

pub fn get_safety(env: Env, asset: Address) -> Option<Safety>;
pub fn is_safe(env: Env, asset: Address, max_severity: u32, max_age_secs: u64) -> bool;
pub fn is_safe_masked(env: Env, asset: Address, forbidden_mask: u32, max_age_secs: u64) -> bool;
pub fn attest(env: Env, asset: Address, severity: u32, flags: u32, evidence_hash: BytesN<32>) -> Result<(), Error>;
pub fn attest_many(env: Env, attestations: Vec<Attestation>) -> Result<(), Error>;
pub fn revoke(env: Env, asset: Address) -> Result<(), Error>;
pub fn init(env: Env, admin: Address) -> Result<(), Error>;
```

The `Vec<Attestation>` argument is confirmed against the built artifact rather
than assumed: `stellar contract info interface` on the compiled wasm publishes
`fn attest_many(env: soroban_sdk::Env, attestations: soroban_sdk::Vec<Attestation>)`
with `Attestation` as a contracttype UDT, so a `Vec` of a `#[contracttype]`
struct is a supported argument type in soroban-sdk 27.

| Error | Code | Returned by |
| --- | --- | --- |
| `AlreadyInitialized` | 1 | `init` on an initialized contract |
| `NotInitialized` | 2 | `attest`, `attest_many`, `revoke` before `init` |
| `InvalidSeverity` | 3 | `attest`, `attest_many` with severity above 4 |
| `InconsistentAttestation` | 4 | `attest`, `attest_many` with the clawback bit below `SEVERITY_HIGH` |
| `NotAttested` | 5 | `revoke` for an asset with no attestation |
| `BatchTooLarge` | 6 | `attest_many` with more than `MAX_BATCH_SIZE` elements |

### `attest_many`: many attestations in one transaction

`attest_many(attestations)` is `attest`, repeated. One transaction writes up to
`MAX_BATCH_SIZE` attestations, which is what lets a re-attestation run cover a
useful set of assets instead of one asset per ledger and per fee.

Every element is written exactly as `attest` writes it — the same
`DataKey::Safety(asset)` key, the same stored `Safety`, the same `Attested`
event — and both entrypoints call the same validation function. A batch is
**not** a lower bar:

- `InvalidSeverity` and `InconsistentAttestation` are the same checks, on every
  element. There is no batch path around the confiscation invariant.
- `require_auth` on the admin is required, as for `attest`. An empty batch is
  authorized too: who may call an entrypoint is a property of the entrypoint,
  not of what it was handed.
- Per-asset reads after a batch are identical to per-asset reads after the
  equivalent single writes. The contract test
  `batch_reads_match_single_write_path` asserts the stored value is equal, not
  merely equivalent.

#### All-or-nothing, not partial

**A batch is applied whole or not at all.** Every element is validated before
the first write, so a batch containing one bad element stores nothing, publishes
nothing, and returns the same typed error the single-write path returns for that
element. There is no state in which some assets of a batch were re-attested and
others silently were not, and the tail is never truncated to make a partly-bad
batch fit.

This is stronger than the host gives for free, and the extra is worth stating
precisely rather than overclaiming. Soroban already rolls the whole transaction
back on failure, so a batch could not half-commit even with a write-as-you-go
loop. What validating up front adds is (a) a failure that is *typed and
deterministic* — an error a caller can branch on, rather than a resource failure
from whichever write happened to be in flight — and (b) a failure that is cheap,
because a batch whose last element is bad does not first pay to write every
element before it.

#### The cap, and why it is 50

The bound is a network limit, not a round number. Read live on 2026-09-27 with
`stellar network settings --network testnet` (protocol 28), and measured against
the same enforcement the SDK applies in the tests:

| Limit | Live network | A full 50-element batch | Used |
| --- | --- | --- | --- |
| **contract event bytes** | **16 384** | **10 000** | **61% — the binding limit** |
| ledger entries written | 200 | 51 | 26% |
| transaction footprint entries | 400 | 105 | 26% |
| bytes written | 132 096 | 14 072 | 11% |
| instructions | 400 000 000 | 3 275 513 | 0.8% |
| memory | 41 943 040 | 514 609 | 1.2% |

Each element publishes its own `Attested` event and one such event is exactly
200 bytes, so the event budget admits **at most 81 elements** however frugal the
writes are. That is the hard ceiling: a 100-element batch was measured failing
with `contract events size bytes: 20000 > 16384`. 50 sits at 61% of that
budget — room for the event schema to grow before the cap becomes wrong — and
costs about a quarter of every other limit, including the write budget one would
naturally have guessed was binding.

Per-asset events are kept rather than collapsed into one batch-sized event for
precisely this reason. A single event would raise the ceiling, but it would
take away the property that an indexer subscribed to `("attest", asset)` sees
every write to that asset without decoding batch bodies. A higher cap is worth
less than that.

`batch_size_bound_is_measured_and_holds_headroom` in the contract tests runs a
full batch with the SDK's mainnet resource enforcement switched on (which
`Env::default` enables), asserts it fits every limit, and pins the 200-byte
per-event cost so the cap is re-derived rather than silently wrong if the event
or the write path changes.

#### Empty batches, and one timestamp per batch

An empty batch succeeds and does nothing: no storage write, no event, and no
instance TTL extension. That is the honest reading of all-or-nothing over zero
elements, and it lets a pipeline pass whatever a scan produced without
special-casing "nothing changed this round".

Every element of one batch carries the same `attested_at`: the timestamp of the
ledger the batch landed in. `attested_at` records when the write happened, not
when each scan ran, and the elements of one call were written at the same
instant. If the same asset appears twice in a batch, both are applied in order
and both events are published, with the second write winning — exactly what two
calls to `attest` would have done.

### `revoke`: withdrawing an attestation

`revoke(asset)` removes the stored attestation, which restores the
never-attested state exactly: `get_safety` returns `None`, and `is_safe` and
`is_safe_masked` return `false` whatever arguments they get. It requires the
admin's authorization, as `attest` does.

It exists because overwriting is not a retraction. If an attestation turns out
to be wrong (a scanner bug, a compromised key, evidence that does not support
it), writing a higher severity over it makes a *new* claim the scanner never
reached. Revoking says only that the old claim no longer stands, and it leaves
every gate failing closed until a correct attestation is written.

- **Admin, existing attestation:** removed; a `revoke` event is published.
- **Non-admin caller:** rejected by `require_auth`, as `attest` is. Nothing
  changes.
- **No attestation for the asset:** returns `NotAttested`, changes nothing, and
  publishes nothing. This is an error rather than a no-op on purpose: a revoke
  sent to the wrong SAC address (easy to do, since addresses are
  network-derived) must fail loudly rather than report success while the
  attestation it was meant to withdraw is still there. A retried revoke also
  gets `NotAttested`, which an operator can read as "already gone".
- **Re-attesting afterwards** works normally. The new attestation carries its
  own `attested_at`.

#### Revoked and never-attested look the same on-chain, deliberately

**A consumer calling `get_safety` cannot tell a revoked asset from one that was
never attested.** Both return `None`. The contract keeps no tombstone.

That is a choice, not something left out:

- Both states mean the same thing to a gate: no claim stands, so fail closed.
  Every correctly written gate already handles `None`, so revocation needs no
  consumer changes.
- A tombstone would be a new stored type and a new read path that every
  integrator would have to understand. It would also be one more persistent
  entry with its own TTL (see [deployment.md](deployment.md#entry-lifetime)),
  and it would archive like any other entry.
- The one party that needs the difference is an off-chain observer, for
  example an indexer that saw the `attest` event and would otherwise go on
  believing it. That party gets the `revoke` event below.

If a future consumer needs to prove on-chain that an asset *was* revoked,
that is a new feature with its own ABI. It is not implied by this one.

#### Migration

The deployed registry (`CBK4FBIH…`) has no upgrade entrypoint, so `revoke` and
the TTL handling cannot be added to it in place. Using them needs a **new
deployment**: a new contract ID, `init`, re-attesting the assets from live
scans, and redeploying the example gate against the new address. The steps are
in [deployment.md](deployment.md#migrating-to-a-registry-with-revoke).
Until that is done, the live testnet registry still has no revoke path.

### Named policy masks for `is_safe_masked`

`is_safe_masked` gates on **which mechanics** are unacceptable rather than on a
severity ceiling. Severity is a total order; real policies are not — a
protocol that can tolerate a freeze but never a confiscation would otherwise
have to gate on `severity <= MEDIUM`, which also excludes `auth_required`
assets it may be perfectly happy with.

Two named masks are published as the two common policies; a caller may pass
any `u32`.

| Mask | Bits | When to use |
| --- | --- | --- |
| `POLICY_MASK_CONFISCATION_ONLY` | `MECH_CLAWBACK_ENABLED` | You accept freeze-capable assets but never confiscation-capable ones. |
| `POLICY_MASK_FREEZE_INCLUSIVE` | `MECH_AUTH_REVOCABLE \| MECH_CLAWBACK_ENABLED` | A custody product refusing anything the issuer can act on. |

`is_safe_masked` fails closed on every non-happy path, exactly like `is_safe`:
never-attested, stale, and any forbidden bit set all return `false`. An empty
`forbidden_mask` (`0`) still requires an attestation — an unattested asset
must never read as safe, even for a policy that forbids nothing.

### Attestation events

Every successful `attest` publishes one Soroban event so indexers do not have
to poll storage. Rejected calls (`InvalidSeverity`, `InconsistentAttestation`,
unauthorized) publish nothing: observers must never see a write that did not
happen.

| Topic 0 | Topic 1 | Data |
| --- | --- | --- |
| `symbol_short!("attest")` | asset `Address` | `Map<Symbol, Val>` with keys `severity: u32`, `flags: u32`, `attested_at: u64` |
| `symbol_short!("revoke")` | asset `Address` | `Map<Symbol, Val>` with key `revoked_at: u64` |

`attest_many` publishes one such `attest` event per element, in batch order,
with no batch-specific event or decoding path. A rejected batch publishes
nothing at all.

A successful `revoke` publishes the second row. A failed revoke (`NotAttested`,
unauthorized) publishes nothing. The `revoke` event uses the same topic layout
as `attest`, so an indexer subscribed by asset sees both the write and its
withdrawal.

The events are defined with the `#[contractevent]` macro on the `Attested` and
`Revoked` structs
in the contract (see `assay-contracts/contracts/safety-registry/src/lib.rs`),
so the schema is discoverable from the contract spec rather than only from
this document.

The asset address is a topic rather than a data-map field so an indexer can
subscribe by asset without decoding every event body. The topic count is two,
well within the SDK's four-topic limit, and `Symbol` is the required
topic-0 shape for a filterable label.

Severity values and mechanic bit positions are **ABI** and mirror
`internal/mechanics` exactly. Do not renumber them.

| Severity | | Mechanic bit | |
| --- | --- | --- | --- |
| 0 | `SEVERITY_CLEAR` | `1 << 0` | `MECH_AUTH_REQUIRED` |
| 1 | `SEVERITY_LOW` | `1 << 1` | `MECH_AUTH_REVOCABLE` |
| 2 | `SEVERITY_MEDIUM` | `1 << 2` | `MECH_CLAWBACK_ENABLED` |
| 3 | `SEVERITY_HIGH` | `1 << 3` | `MECH_FLAGS_LOCKED` |
| 4 | `SEVERITY_CRITICAL` | `1 << 4` | `MECH_DOMAIN_UNVERIFIED` |
| | | `1 << 5` | `MECH_BLOCKLISTED` |

`CONFISCATION_MASK = MECH_CLAWBACK_ENABLED`. Anything matching it has
`severity >= SEVERITY_HIGH`, enforced at write time and re-checked at read time.

One more value exists on the Go side and **never reaches the chain**:
`mechanics.Unevaluated` (5) marks a report whose issuer flags were never read,
so no capability statement exists at all. `attest.FromReport` refuses it with
`ErrUnevaluated`, and the contract would reject it as `InvalidSeverity` anyway.
The 0..4 table above is the complete on-chain ABI and is unchanged by this
value's existence; it is there so that an unread flag can never be serialized
as `SEVERITY_CLEAR`, the safest value in the table.

## Design decisions

### Assets are SAC addresses

An asset is identified by its Stellar Asset Contract address, not by a
code+issuer string pair. Verified live on Horizon (first recorded 2026-08-11,
re-checked 2026-09-17): Circle's USDC has a canonical
`contract_id` of `CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75`.
`Address` comparison is cheap on-chain; string handling is not.

### `Option`, so unknown is not safe

`get_safety` returns `Option<Safety>`. A never-attested asset returns `None`,
which stays distinguishable from an attestation of `SEVERITY_CLEAR`. A revoked
asset also returns `None` (see [`revoke`](#revoke-withdrawing-an-attestation)).
An **archived** attestation does not: it is restored on access and read with
its original `attested_at` (see [deployment.md](deployment.md#entry-lifetime)).

Collapsing those two would make every asset nobody has scanned read as safe —
the single worst failure this contract could have, and the default a
`Severity::Unknown = 0` variant would have quietly produced.

### `is_safe` fails closed

The gate helper returns `true` only when an attestation exists, is fresh enough,
and is at or below `max_severity`. Every other path returns `false`: never
attested, stale, too severe, or internally inconsistent.

The safe answer is the default, so a caller who gets the arguments wrong blocks
rather than admits.

### Staleness is the caller's policy

`attested_at` is exposed and `max_age_secs` is a parameter rather than a
contract constant. Assay does not silently serve stale safety, and it does not
guess how fresh is fresh enough — a DEX listing gate and a large settlement
have very different tolerances. `max_age_secs = 0` opts out explicitly.
Recommended bands with reasoning, the re-attestation cadence, and consumer
guidance are in [freshness.md](freshness.md).

[freshness.md](freshness.md) is the guidance for picking a value: what changes
under an attestation, how fast (measured, not guessed), and defensible windows
per use class.

### The invariant is enforced twice

`attest` rejects an attestation whose clawback bit is set below `SEVERITY_HIGH`.
`is_safe` re-checks it anyway. A gate should not have to assume the writer was
correct.

## Using it

```rust
// Refuse to list an asset whose issuer can freeze or confiscate,
// using an attestation no more than an hour old.
let registry = SafetyRegistryClient::new(&env, &registry_address);
if !registry.is_safe(&asset, &SEVERITY_LOW, &3600) {
    panic_with_error!(&env, MyError::AssetNotSafe);
}
```

Gating on `severity` is sound precisely because severity is capability-only:
the contract is relying on a statement about ledger mechanics, not on a third
party's opinion of an issuer. See [the severity model](severity-model.md).

Gating on the `flags` bitset instead is usually sharper, because a contract
tends to care about a specific power rather than about an ordering.
[integrating.md](integrating.md) works through both, against the live
deployment.

### `evidence_hash` commits to the claims, not to the clock

`evidence_hash` is `SHA-256` over a canonical rendering of the report, produced
by [`internal/attest`](../internal/attest) and printable with
`assay attestation -preimage CODE-ISSUER`. The encoding is line-oriented,
tab-separated, LF-terminated UTF-8:

```
assay-evidence-v1
asset	CODE-ISSUER
severity	N
base_severity	N
escalated	true|false
mechanics	N
accountability	unknown|unverified|verified
evidence	SOURCE	URL	CLAIM
```

A report that binds its check set is written as `assay-evidence-v2`, which adds
one line after `accountability`:

```
checks	ID,ID,...        (the checks the engine ran, sorted)
```

Reports produced before check-set binding carry no `checks` line and are still
written as `v1`, so an attestation already on-chain keeps reproducing its hash.
A verifier reads a report with no bound check set as *unknown*, never as
complete.

with one `evidence` line per attributed claim, sorted bytewise. Inside any
field, `\` becomes `\\`, tab becomes `\t`, newline `\n`, carriage return `\r`.
That escaping is load-bearing rather than tidy: a claim embeds third-party text
such as a directory name, so without it an issuer could publish a name
containing a tab and forge the preimage of a report that was never produced.

**Retrieval timestamps are deliberately excluded.** Hashing them would give the
same unchanged evidence a different hash on every scan, which would make the
field unverifiable by anyone who was not present for the original fetch.
Excluding them means a verifier can re-scan and reproduce the hash exactly. The
cost is that the hash cannot distinguish a fresh confirmation from a stale one
— which is precisely why `attested_at` is stored separately and `is_safe` takes
`max_age_secs` against it.

The version line is inside the hash, so a future encoding change cannot produce
bytes a verifier would silently compare against v1.

#### The preimage binds the check set

`Engine.Run` iterates whatever checks the engine holds, and a report used to
commit only to the aggregate result and the evidence lines. That made a scan run
with a check removed indistinguishable from one where the check ran and found
nothing: DOGE is critical solely through the reputation check, so removing that
check turns it clear, and a two-check engine could produce a report that hashed
like a three-check one whose removed check changed no other field.

The v2 encoding closes that: the sorted check IDs the engine ran are part of the
preimage, so a report from a smaller engine hashes differently. `Report.CheckSet`
carries them, and `attest.VerifyCheckSet` compares a report's bound set against
the set a verifier expects, returning `CheckSetIncomplete` with the absent checks
named — not a generic mismatch. A report with no bound set is
`CheckSetUnknown`, reported as such rather than failed, because there is nothing
to compare.

The check-set binding is a v2 rather than an amendment to v1 deliberately: an
attestation written under v1 omitted the check set entirely, and re-hashing it
under a changed v1 format would break every existing attestation.

## Not done yet

- **Single admin.** One key can write or revoke any attestation. A production
  deployment wants multisig or a threshold of independent attesters. The
  options are compared, with a recommendation, in
  [multi-attestor.md](multi-attestor.md).
- **No re-attestation schedule.** Nothing refreshes an attestation when an
  issuer's flags change. Freshness is entirely the caller's problem, via
  `attested_at` and `max_age_secs`.
- **TTL is extended on write only.** `init`, `attest`, `attest_many` and
  `revoke` extend the contract instance and code to the network maximum, and the
  two write paths extend the attestation entries they write. Reads extend nothing. An attestation nobody re-attests
  is archived after roughly 180 days on current testnet parameters. It is then
  restored on the next access at the reader's expense, not lost. See
  [deployment.md](deployment.md#entry-lifetime). The live testnet deployment
  predates this change, and all its entries are archived today.
- **Testnet only.** No pubnet deployment exists, and the points above are why
  one would be premature.
