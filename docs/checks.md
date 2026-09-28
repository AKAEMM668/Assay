# Checks

A check is a pure function from a pre-fetched `Subject` to a `Finding`. Checks
perform **no I/O**: the [`scan`](../internal/scan) package fetches everything
once, up front, and hands the result to classifiers that only compute.

That split buys three things. Checks are deterministic and testable from
fixtures with no network. Each fetcher stays in its own package with a clean
signature, so it can be extracted later without untangling judgment logic from
transport. And a check cannot quietly add a network dependency, because it has
nowhere to put one.

```go
type Check interface {
    ID() string
    Describe() string
    Run(ctx context.Context, s *Subject) (Finding, error)
}
```

## `capability`

**Concludes:** what the issuer is able to do to a holder's balance.
**Sets:** base severity.

Maps issuer authorization flags to a level, per
[the severity model](severity-model.md). Severity is the highest single
capability present, not a sum — `auth_revocable` is a protocol precondition for
`auth_clawback_enabled`, so counting both would double-count a rule CAP-0035
enforces.

The reasoning always states the raw capability in plain language, whatever the
level works out to. A reader is never told a number without being told what the
issuer can actually do.

`auth_immutable` is reported but never scored, because its meaning is
conditional: locked-with-no-dangerous-flags is a safety property, and
locked-with-clawback is permanence of a hazard. Both are stated in prose.

**Cannot conclude:** whether the issuer will ever use the power; whether an
existing holder is exposed (clawback is inherited at trustline creation, so this
answers the prospective question only); or anything about who the issuer is.

## `sep1-domain`

**Concludes:** whether an identifiable party has publicly claimed this asset.
**Sets:** accountability. **Never touches severity.**

Reciprocal verification, requiring both directions to agree:

1. The issuer account advertises `home_domain`.
2. That domain serves `/.well-known/stellar.toml`.
3. The toml's `CURRENCIES` lists **this code and this issuer**.

Either half alone is worthless. `home_domain` is free text any account can set
to any string; a stellar.toml can list any code it likes. Matching on code alone
would let any domain claim any asset — the exact impersonation this check
exists to catch — so both must match.

Two states are decided before any toml is fetched. **No `home_domain` at all**
means nobody has claimed the asset: accountability is `unknown`, and the
reasoning says so plainly — an absent claim is not a failed one. **A
`home_domain` that disagrees with the curated directory's `domain`** is
reported as `unverified` with both claims attributed to their source and URL,
because a holder cannot tell a benign brand migration from an impersonation
setup while the two sources simply contradict each other.

Verification failures are reported verbatim, including the HTTP status. "We
could not check" and "this is fine" are different answers and must never render
the same.

That rule is repo-wide, not local to this check. It was stated here first
because `stellar.toml` was the only source that honoured it; the two
StellarExpert endpoints did not, and a scan during an outage claimed reputation
had been read when it had not. Fixed, with the history in
[the attestation run](attestation-run.md#finding-1).

The same rule applies to negatives. SEP-0001 permits a currency entry whose only
field is `toml="https://DOMAIN/.well-known/CURRENCY.toml"`, delegating the
declaration to a separate file. Such an entry carries no code or issuer, so it
can never match. Assay does not follow those links yet, so when a toml contains
them it reports the asset as **unconfirmed** rather than claiming the domain
failed to name it — overstating a negative is the same class of error as
overstating a positive. Following those links is not implemented yet.

**Cannot conclude:** that a verified issuer is honest. It establishes that a
named party has published a claim, nothing more. A scammer can register a domain
and publish a valid toml in ten minutes; that is precisely why this sets
accountability rather than severity.

## `reputation`

**Concludes:** nothing of its own. It relays curated third-party determinations.
**Sets:** escalation only, upward only.

Consumes StellarExpert's address directory (the data set standardized by
SEP-0037) and malicious-domain blocklist. A `malicious`/`unsafe` directory tag
or a blocklist hit escalates to `critical`.

Everything it produces is `Evidence{Source, URL, Claim, RetrievedAt}` naming
StellarExpert and the URL the claim came from. Attribution is structural: a
check can only surface an outside claim by constructing an `Evidence`, so there
is no code path that renders someone else's data as an Assay conclusion.

Assay does not maintain a scam list, a rating, or a domain blocklist. That layer
exists, is actively curated, and is better than anything this project would
produce. **Do not re-derive it.**

**Cannot conclude:** that an unlisted asset is safe. Absence from a curated list
is not an observation — most legitimate assets are absent, and so is every scam
nobody has reported yet. The check says so explicitly in its reasoning rather
than staying silent and letting absence read as approval.

**Cannot conclude anything at all when a source did not answer.** A 404 means
the source was read and had no entry; a 429, a 5xx, or a timeout means it was
never read. Those produce different reports: an unreachable source is recorded
as attributed evidence carrying the failure verbatim, the finding is marked
`undetermined`, and the report names the check on `undetermined_checks`.

Severity is **not** raised to compensate. Capability stays exactly what the
ledger says, because inventing a level Assay did not measure would be the same
error pointed the other way. What changes is that the report states the level is
a floor, and that `attest.FromReport` refuses to write it on-chain at all —
`get_safety` returns a severity and a timestamp with nowhere to carry the
caveat, so a partial scan must not become an attestation. The contract already
handles the resulting absence correctly: `None`, and every gate fails closed.

A listing that *did* arrive still escalates even if the other source is down.
Evidence of abuse does not become less true because a second endpoint timed out,
and `critical` is the ceiling, so nothing still missing could raise the level
further.

Note that the two sources are not interchangeable and neither is complete. When
`BERKSHIRE-GA22QHSH…` was scanned, the directory tagged the issuer `malicious`
while blocked-domains returned `blocked=false` for the same domain. Consulting
only one of them would have missed a confirmed scam.

## Capability transitions

The checks above answer a prospective question: what can this issuer do to a
trustline opened now. Comparing two of those answers over time is a separate,
pure computation in [`internal/temporal`](../internal/temporal): what capability
bits were added or removed between two observations, and which axis — capability
or reputation — moved severity. It performs no I/O and stores nothing. The
representation and the on-demand-versus-stored decision are in
[transitions.md](transitions.md).

## Adding a check

See [CONTRIBUTING.md](../CONTRIBUTING.md). The short version: implement the
interface, verify every flag name and endpoint against a live source, and add
eval subjects for both a true positive **and** a legitimate use of the same
mechanics. A check whose judgment is not evaluated does not ship.
