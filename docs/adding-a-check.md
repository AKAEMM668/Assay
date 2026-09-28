# Adding a check

A practical guide to writing a new mechanic check. Read
[the severity model](severity-model.md) first — most review feedback on new
checks is about judgment, not code.

## The one rule: checks do no I/O

Everything a check needs is fetched **once, up front**, by
[`internal/scan`](../internal/scan/scan.go) into a `Subject`. A check is then a
pure function from `Subject` to `Finding`.

```
scan.Scanner.Subject()   ← the only place a scan touches the network
        ↓  *mechanics.Subject
mechanics.Engine.Run()   → runs every Check, aggregates into a Report
```

This buys three things, and all three are load-bearing:

- Checks are deterministic and testable from fixtures with **no network**, so CI
  cannot go red because a third-party API had a bad day, nor green because one
  silently changed.
- Each fetcher stays in its own package with a clean signature, so it can be
  extracted later without untangling judgment logic from transport.
- A check *cannot* quietly add a network dependency, because it has nowhere to
  put one.

If your check needs data that isn't in `Subject` yet, add the fetch to
`internal/scan` and the field to `Subject`. Do not fetch from inside `Run`.

## The interface

From [`internal/mechanics/mechanics.go`](../internal/mechanics/mechanics.go):

```go
type Check interface {
	// ID is the stable identifier used in reports and issue tracking.
	ID() string
	// Describe states what the check concludes, and what it does not.
	Describe() string
	// Run classifies the subject.
	Run(ctx context.Context, s *Subject) (Finding, error)
}
```

`Describe()` must state the limits, not just the capability. "Says nothing about
who the issuer is" is the kind of sentence that belongs there — it is what stops
a caller over-reading the result.

### What `Subject` gives you

```go
type Subject struct {
	Asset           Asset
	Stat            *horizon.AssetStat // asset record, incl. Flags
	StatFetchedAt   time.Time          // when Horizon answered /assets
	Issuer          *horizon.Account   // issuer account, incl. Flags + HomeDomain
	IssuerFetchedAt time.Time          // when Horizon answered /accounts

	Toml            *sep1.Doc  // nil if it did not resolve; carries its own FetchedAt
	TomlURL         string
	TomlErr         string     // why it did not, verbatim
	TomlAttemptedAt time.Time  // when the fetch was attempted

	Directory            *stellarexpert.DirectoryEntry
	DirectoryURL         string
	DirectoryErr         string
	DirectoryFetchedAt   time.Time // when the source answered
	DirectoryAttemptedAt time.Time // when it was asked
	Blocked              *stellarexpert.BlockedDomain
	BlockedURL           string
	BlockedErr           string
	BlockedFetchedAt     time.Time
	BlockedAttemptedAt   time.Time

	ScannedAt time.Time // when the scan started
}
```

Every fetch records **its own** completion time, and every failed fetch records
its attempt time. Stamp evidence from the field matching the source the claim is
attributed to — never from a shared scan-start timestamp: a StellarExpert answer
that arrived twenty seconds after the Horizon one must not report Horizon's
instant. Failure evidence (`"not retrievable: …"`) carries the attempt time and
sets `Evidence.Attempted = true`, so a program can tell an attempt from an
answer without parsing the claim.

Any pointer field can be `nil`. Handle it explicitly — a missing source is not a
clean result. **"We could not check" and "this is fine" must never render the
same.**

## Where files go

| Thing | Location |
| --- | --- |
| Your check | `internal/mechanics/check_<name>.go` |
| Registration | `NewEngine()` in `internal/mechanics/mechanics.go` |
| Severity / mechanic bits | `internal/mechanics/severity.go` |
| Fixtures | `internal/mechanics/testdata/<case-name>/` |
| Eval cases | `internal/mechanics/eval_test.go` |

Use [`check_capability.go`](../internal/mechanics/check_capability.go) as the
template for a check that sets severity, and
[`check_domain.go`](../internal/mechanics/check_domain.go) for one that sets
accountability without touching severity.

## The severity rules your check must respect

Full reasoning in [docs/severity-model.md](severity-model.md). The short form:

**Severity is capability-only.** It answers "what can the issuer do to my
balance?" and is derived from authorization flags and nothing else. Two assets
whose issuers hold identical power must classify identically, however well
attributed one of them is. A test enforces this directly.

**Reputation escalates, never discounts.** Set `Finding.Escalation = true` and
the engine will only let that finding *raise* the level. Nothing may lower a
severity — a discount is treated as a security bug, because it would let someone
buy their way past the on-chain gate.

**Accountability is a separate field.** If your check establishes who is behind
an asset, set `Finding.Accountability` and leave `Severity` at `Clear`.

**Don't double-count protocol preconditions.** CAP-0035 makes `auth_revocable` a
precondition for `auth_clawback_enabled`, so scoring both would inflate every
clawback asset for a reason the protocol requires. Severity is the highest
single capability, not a sum.

**Reasoning always states the raw capability**, whatever the level works out to.
A reader is never given a number without being told what the issuer can actually
do.

### Evidence must be attributed

Consumed signals enter only as `Evidence{Source, URL, Claim, RetrievedAt}`.
Attribution is structural: because the only way to surface an outside claim is
to construct an `Evidence` carrying its source URL, there is no code path that
renders someone else's data as an Assay conclusion.

**Never re-derive a consumed signal.** StellarExpert's directory, ratings, and
blocklist are inputs. If you find yourself writing a scam heuristic over domain
names, stop — that layer exists and is better maintained than anything we would
write.

## Fixtures

Capture from live sources into `internal/mechanics/testdata/<case-name>/`:

| File | Contents |
| --- | --- |
| `asset.json` | one Horizon `/assets` record |
| `account.json` | the issuer's `/accounts` record |
| `stellar.toml` | the toml, when it resolves |
| `stellar.toml.status` | the HTTP status, when it does not |
| `directory.json` | StellarExpert directory entry, if listed |
| `blocked.json` | blocked-domain lookup result |

Record every source URL in
[`testdata/PROVENANCE.md`](../internal/mechanics/testdata/PROVENANCE.md) with
the capture date. `loadSubject` in `eval_test.go` rebuilds a `Subject` using the
same decoders the live fetchers use, so a fixture that parses in the test is one
the real client would have accepted.

## The eval is not optional

**A check whose judgment isn't evaluated against the labelled set doesn't ship.**

Detecting a flag is deterministic and uninteresting. What the eval measures is
whether the model separates a trap from a legitimate compliance feature. So
every new check adds **at least two** subjects to `TestEval`:

1. One asset that should trip it.
2. One asset with the **same mechanics used legitimately** that must not be
   over-flagged.

Point 2 is the whole discipline. Any check can find `auth_revocable: true`; the
reason to have a check is that it knows when that is fine.

Each case carries a `why` string stating what it proves. It is printed on
failure, so a future maintainer learns what they broke rather than just seeing a
number change.

```go
{
	dir:          "your-case-name",
	why:          "what this subject proves and why it is labelled this way",
	wantBase:     mechanics.Medium,   // capability only, pre-escalation
	wantSeverity: mechanics.Medium,   // after escalation
	wantEscalated: false,
	wantAccount:  mechanics.AccountabilityVerified,
},
```

Then record the result and the reasoning in [docs/eval.md](eval.md).

## Verify before you encode

**Never encode a flag name, field name, or endpoint you did not verify against a
live source.** Not from memory, not from an LLM, not from a blog post.

```sh
curl "https://horizon.stellar.org/assets?asset_code=USDC&asset_issuer=GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
curl "https://api.stellar.expert/explorer/directory/<ADDRESS>"
```

Protocol semantics come from the specs themselves —
[CAP-0035](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0035.md)
for clawback, [SEP-0001](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md)
for stellar.toml. Both have caught real errors in this codebase: that
`auth_revocable` is a *precondition* for clawback, and that a `CURRENCIES` entry
may be a bare link to another toml.

Cite what you verified in the PR.

## Checklist

```sh
make test    # go test -race ./...
make lint    # golangci-lint
make fmt     # gofmt -w .
```

- [ ] Check implements `ID`, `Describe`, `Run`; `Describe` states its limits
- [ ] No I/O in `Run`; new data added to `Subject` via `internal/scan`
- [ ] `nil` source fields handled; failures reported, not smoothed
- [ ] Registered in `NewEngine()`
- [ ] Severity capability-only; escalation-only findings set `Escalation: true`
- [ ] Consumed signals attributed as `Evidence` with source URL
- [ ] Reasoning states the raw capability
- [ ] Fixtures captured, provenance recorded
- [ ] Eval subjects for a true positive **and** a legitimate use
- [ ] `docs/eval.md` updated
- [ ] Live-source verification cited in the PR
