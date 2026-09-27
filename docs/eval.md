# Eval

The mechanics detection is deterministic — a flag is either set or it is not,
and there is nothing to measure. What this eval measures is the **judgment**:
does the severity model separate a trap from a legitimate compliance feature,
and does escalation fire only on reputation?

**A check whose judgment is not evaluated against this set does not ship.**

Run it with `make test`. The eval is `TestEval` (aggregate) and
`TestEvalPerCheck` (per check) in
[`internal/mechanics/eval_test.go`](../internal/mechanics/eval_test.go); both
run from fixtures with no network access, so a result cannot drift because a
third-party API had a bad day. Their labels live in one place,
[`internal/eval`](../internal/eval), so the aggregate and per-check
expectations cannot describe different runs.

## The labelled set

Every subject is a real pubnet asset. Fixtures were captured from live sources
with provenance recorded in
[`internal/mechanics/testdata/PROVENANCE.md`](../internal/mechanics/testdata/PROVENANCE.md).

| Subject | Label | Why it is in the set |
| --- | --- | --- |
| `AQUA` | legitimate | No auth flags at all, reciprocal domain. The baseline: the model must not manufacture risk. |
| `SHX` | legitimate | No auth flags **and** `auth_immutable`. Tests that flag-locking is not mistaken for danger. |
| `XRP` (fchain.io) | legitimate | The unlocked counterpart to SHX: no auth flags, `auth_immutable` **unset**. Capability is clear, but the flag set can still change, so the `mutability` finding must report that without moving severity. |
| `USDC` (Circle) | **legitimate, uses the flags** | The critical case. A real regulated stablecoin that legitimately uses `auth_revocable`. |
| `USDZ` (Zeam Money) | **legitimate, uses clawback** | The other critical case. A regulated stablecoin (FSCA-licensed issuer, reciprocal SEP-1) that legitimately uses `auth_clawback_enabled` — the only subject in the set that measures the model's central claim that legitimate clawback is handled fairly. |
| `BERKSHIRE` (nasdaq.finance) | trap | Impersonation asset with clawback. Confiscation capability *and* confirmed-bad reputation. |
| `DOGE` (darkpool.digital) | trap | Known scam carrying **no auth flags**. The case that justifies the second axis. |
| `DOGE` (reputation outage) | **degraded** | The same real scam as the row above, captured with the StellarExpert directory unavailable. Neither legitimate nor trap: the correct answer is **undetermined**, and the subject exists so a source outage can never again be reported as a clean result (issue #23). |

## Results

Measured output from fixtures captured on 2026-08-10. `TestEval` asserts every
row on each test run, so the table cannot drift from the code without a red test:

| Subject | Asset | Base | Final | Escalated | Undetermined | Accountability | Mechanics |
| --- | --- | --- | --- | --- | --- | --- | --- |
| aqua-clear-verified | `AQUA` | clear | **clear** | false | false | verified | — |
| shx-clear-flagslocked | `SHX` | clear | **clear** | false | false | verified | `auth_immutable` |
| xrp-clear-unlocked | `XRP` | clear | **clear** | false | false | verified | — |
| usdc-revocable-regulated | `USDC` | medium | **medium** | false | false | unverified | `auth_revocable`, `domain_unverified` |
| usdz-clawback-regulated | `USDZ` | high | **high** | false | false | verified | `auth_revocable`, `auth_clawback_enabled` |
| berkshire-clawback-scam | `BERKSHIRE` | high | **critical** | true | false | unverified | `auth_revocable`, `auth_clawback_enabled`, `domain_unverified`, `blocklisted` |
| doge-noflags-scam | `DOGE` | clear | **critical** | true | false | unverified | `domain_unverified`, `blocklisted` |
| doge-reputation-outage | `DOGE` | clear | **clear** | false | **true** | unverified | `domain_unverified` |

The last row is the point of the `Undetermined` column: its severity is the
capability floor, exactly as if nothing were wrong, and the `true` is what stops
that floor from being read as a clean answer.

## What each result proves

### USDC — the false-positive test

`medium`, not escalated, not discounted.

This is the result the whole model is built to get right. USDC carries
`auth_revocable`: Circle **can** freeze a holder's balance. Assay says so
plainly, because it is true and a holder should know it.

What Assay does *not* do is either of the two easy mistakes:

- It does not call it dangerous. `auth_revocable` alone is level 2 of 4, and the
  reasoning explains that freezing is not confiscation. There is no clawback
  here — verified live, `auth_clawback_enabled: false`. The assumption that
  regulated stablecoins carry clawback is simply wrong for the biggest one on
  the network.
- It does not wave it through because Circle issues it. The severity comes from
  the flag. An anonymous issuer with the same flag gets the same `medium`.

`accountability: unverified` is a genuine finding, not a bug:
`circle.com/.well-known/stellar.toml` returns 404 (fixture captured 2026-08-10;
still 404, via a redirect to `www.circle.com`, on 2026-09-17), so reciprocal SEP-1
verification fails by the letter of the spec. It is left uncorrected because it
is the strongest available argument that accountability must never have been a
severity discount — had it been one, USDC would score worse than a scam asset
with a working toml.

### DOGE — why capability-only severity does not miss scams

`base: clear` → `final: critical`, escalated.

A known scam asset with **zero** authorization flags. Its issuer holds no
special power, so the honest capability answer is `clear` — and Assay says
`clear` for the base, without flinching.

The trap here is not a trap mechanic at all; it is impersonation. Capability
analysis cannot see that, and pretending otherwise would mean inventing a
heuristic that fires on innocent assets too. The curated malicious listing
catches it, escalation raises it to `critical`, and `base_severity: clear`
remains visible in the report so a reader can see exactly which axis did the
work.

This subject is the reason reputation is kept as a separate upward-only axis
rather than being dropped for purity.

### DOGE, reputation outage — an outage is not a clean result

`base: clear` → `final: clear`, **undetermined**, not escalated.

This is issue #23 as a fixture. It is the same real DOGE trap, but the
StellarExpert directory — the source carrying its `malicious` tag — was
unreachable when the subject was captured. The blocklist endpoint *did* answer,
and answered `blocked: false`.

An earlier scanner would have read that as a clean reputation result and
reported `clear`, because a missing directory response and a directory response
of "not listed" produced the same `Subject`. The distinction now lives in the
fixture itself: `directory.err` marks the source as asked-and-failed, so the
loader sets `DirectoryErr`, the reputation check marks itself undetermined, and
the report carries `undetermined: true` with `reputation` named in
`undetermined_checks`. Severity is **not** inflated to compensate; it stays at
the capability floor, which is why the report says the floor is a floor rather
than an answer.

Before the error markers existed this was the one regression in the project's
history that the labelled set structurally could not express. It can now, and
if a future change makes an outage render as clear again, `TestEval` and
`TestEvalPerCheck` both go red.

### BERKSHIRE — both axes firing

`base: high` → `final: critical`, escalated.

Impersonates Berkshire Hathaway, carries `auth_revocable` + `auth_clawback_enabled`.
Capability alone puts it at `high` — Assay would flag this asset as
confiscation-capable **even with no reputation data at all**, which is the case
for any brand-new trap. Reputation then escalates it.

### AQUA and SHX — no manufactured risk

Both `clear`. A scanner that only ever finds problems is as useless as one that
never does. SHX additionally carries `auth_immutable`, and the reasoning
correctly frames that as a safety property: the issuer can never add clawback
later.

### XRP — the unlocked counterpart to SHX

`clear`, not escalated, and `auth_immutable` unset.

SHX and XRP are the two halves of the `mutability` check. Both have no
authorization flags, so `capability` is `clear` for each. The difference is that
SHX's flag set is locked — clawback can never be added — while XRP's is not, so
the issuer may add freeze or confiscation later. That difference never enters
severity: `base: clear` and `severity: clear` for both, because `auth_immutable`
is not a power over holders. It is reported as its own finding instead, and this
subject is here so the unlocked branch is pinned by the eval rather than only by
a unit test.

## Per-check evaluation

An aggregate verdict can be right for the wrong reason: if the capability check
says `clear` and reputation escalates the asset to `critical`, the report is
correct while the capability error stays invisible. `TestEvalPerCheck` therefore
compares every finding against its own label, not only the total.

A check that could not conclude is compared against an **undetermined** label,
not against a severity, because an undetermined finding makes no severity claim.
A subject whose findings and labels do not line up — including one with no
per-check labels at all — is reported as **partially evaluated**, never silently
passed. `TestEvalPerCheckReportsPartialLabels` and
`TestEvalPerCheckDetectsWrongExpectation` pin those two failure modes.

Measured per-check output (same fixtures as the table above):

| Subject | capability | mutability | sep1-domain | reputation |
| --- | --- | --- | --- | --- |
| aqua-clear-verified | clear | clear | verified | clear (escalation axis) |
| shx-clear-flagslocked | clear | clear, `auth_immutable` | verified | clear (escalation axis) |
| xrp-clear-unlocked | clear | clear | verified | clear (escalation axis) |
| usdc-revocable-regulated | medium, `auth_revocable` | clear | unverified, `domain_unverified` | clear (escalation axis) |
| usdz-clawback-regulated | high, `auth_revocable`, `auth_clawback_enabled` | clear | verified | clear (escalation axis) |
| berkshire-clawback-scam | high, `auth_revocable`, `auth_clawback_enabled` | clear | unverified, `domain_unverified` | critical, `blocklisted` |
| doge-noflags-scam | clear | clear | unverified, `domain_unverified` | critical, `blocklisted` |
| doge-reputation-outage | clear | clear | unverified, `domain_unverified` | **undetermined** |

The `reputation` column carries the escalation axis: its finding is `clear` with
`escalation: true` when nothing is flagged, and `critical` with `blocklisted`
when it is. That is the one check permitted to escalate, and per-check labels
keep it from hiding a capability error. The degraded subject's reputation
finding is compared against an **undetermined** label rather than a severity,
because a check that could not conclude makes no severity claim.

## Cross-version comparison

Any change to a check can move verdicts, and pass/fail against fixed
expectations cannot show *what* moved. `make eval-record` writes the full
classifier output for the corpus — per subject, per check, with the bound check
set — to [`docs/eval-baseline.json`](eval-baseline.json), tagged with the scanner
version. `make eval-compare` records the current run and diffs it against that
baseline, reporting severity, mechanic and evidence movements separately.

Three rules keep the diff honest:

- A subject **undetermined** in either run is reported as undetermined and
excluded from the movement counts: an answer that was never reached cannot have
moved.
- A subject present in only one run is reported as **added** or **removed**, not
dropped.
- Evidence movements are reported as digests of the sorted claims, excluding
retrieval times, so a re-run of unchanged evidence does not show as a change.

Run `make eval-record` when the output is intended to change; the baseline is
what a reviewer diffs against. Run `make eval-compare STRICT=1` to make any
movement fail the command.

## Coverage gaps

Stated plainly, because an eval that hides its gaps is marketing.

- **Eight subjects, seven assets.** Enough to pin the judgment boundaries, not
  enough for a statistical claim. No precision/recall numbers are quoted,
  because eight subjects cannot support them. (`DOGE` appears twice: once as
  the live trap, once as the reputation-outage variant.)
- **~~No legitimately-clawback-enabled asset~~ Closed 2026-09-27.**
  `USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR` (Zeam Money)
  is now in the set as `usdz-clawback-regulated`: clawback-capable, reciprocal
  SEP-1 verification passes, StellarExpert directory tag is `issuer` (not
  malicious), and the issuer is FSCA-licensed. Base severity is `high` from
  the flag alone, and — critically — it is **not escalated**. That is the
  measurement the model's central claim rests on. Fixture provenance and the
  independent-verification evidence are in
  [`internal/mechanics/testdata/PROVENANCE.md`](../internal/mechanics/testdata/PROVENANCE.md).
- **Trap coverage still narrow.** The set has no subject exercising
  `auth_required` as a gating mechanism, and no subject with all four
  authorization flags set. Adding those needs live traps that actually
  exhibit those shapes; the two current traps (`BERKSHIRE`, `DOGE`) do not.
- **No frozen-trustline case.** Nothing exercises assets with unauthorized
  trustlines, where a freeze has actually been used rather than merely enabled.
- **Fixtures are a snapshot.** Issuers can change flags. Fixtures pin the
  judgment, so a live asset's real classification can drift from the fixture's;
  re-capture before citing a specific asset's current state.

## Fixture convention

Every subject is a directory under `internal/mechanics/testdata`. For each
source the checks consume, the fixture records one of three states, and
`eval.LoadSubject` maps them to exactly the three states a live scan produces:

| state | on disk | meaning | loader result |
| --- | --- | --- | --- |
| **valid** | `stellar.toml`, `directory.json`, `blocked.json` present | the source answered | payload field set (`Toml`, `Directory`, `Blocked`) |
| **missing** | no file for that source | the source was never consulted | field nil, `*Err` empty |
| **unavailable** | `stellar.toml.status`, `directory.err`, `blocked.err` present | the source was asked and failed | field nil, `*Err` set to the marker text |

`stellar.toml.status` holds an HTTP status (for example `404`), which the loader
renders as `"status 404"`. `directory.err` and `blocked.err` hold the failure
text the live client would have returned, for example
`stellarexpert: get <url>: status 429`. The marker text is recorded verbatim, so
it reaches the report's attributed evidence unchanged.

The three states are not cosmetic. **Missing** means "not consulted";
**unavailable** means "consulted and did not answer". Before `directory.err`
existed the two were the same `Subject`, which is how an outage was once
reported as a clean reputation result (#23). A fixture with `directory.err`
makes the reputation check undetermined, and `TestEval` / `TestEvalPerCheck`
assert that (`doge-reputation-outage`).

A fixture should carry at most one of a source's three states. If a payload and
its error marker are both present, the payload wins, matching the existing
`stellar.toml` precedence.

## Adding a subject

1. Capture fixtures for the asset and record provenance. If a source failed at
   capture time, write its error marker (`directory.err`, `blocked.err`) instead
   of omitting the file, so a later reader can tell an outage from a source that
   was never consulted.
2. Add a case to `TestEval` with the expected base, final, escalation, and
   accountability — and a `why` string stating what the case proves. The `why`
   is printed on failure, so a future maintainer learns what they broke.
3. Every new check must add at least one subject that trips it **and** one with
   the same mechanics legitimately that must not be over-flagged.

Point 3 is the discipline. Any check can find `auth_revocable: true`. The reason
to have a check is that it knows when that is fine.

## Dataset labeling and refresh

The machine-readable record for this set is
[`internal/mechanics/testdata/manifest.json`](../internal/mechanics/testdata/manifest.json).
The fixture metadata is CC-BY-4.0 under the dataset directory's
[`LICENSE`](../internal/mechanics/testdata/LICENSE); Assay source code remains
Apache-2.0 and upstream payloads remain subject to their providers' terms.

### Label criteria

- **Legitimate** is a control-group label for an asset with a documented issuer
  identity or a known regulated/compliance use case, supported by the captured
  source records. It does not mean risk-free: USDC is legitimate while its
  `auth_revocable` capability still produces `medium` severity.
- **Trap** requires affirmative captured reputation evidence identifying the
  issuer or domain as malicious or unsafe, or a documented impersonation case
  with corroborating source records. Capability alone is never enough for this
  label.
- **Degraded** marks a subject captured while a source it depends on was
  unavailable. It is neither legitimate nor trap: the report is a partial answer
  (`undetermined: true`), and the subject exists so that an outage is evaluated
  rather than collapsing into the same result as a clean source.
- Severity and accountability are measured independently from the label. The
  expected base severity comes from issuer capability; final severity may only
  rise through reputation escalation; accountability records reciprocal SEP-1
  verification and is never a legitimacy discount.

### Point-in-time refresh pipeline

1. Re-fetch every URL in the manifest and record one UTC capture date for the
  refresh.
2. Store only payloads whose current provider terms permit redistribution. For
  uncertain StellarExpert or issuer material, retain the URL and derived
  annotation rather than adding a new raw copy.
3. Rebuild the expected labels and metrics from the captured files, update the
  manifest atomically, and run `make test`.
4. Review the diff for source attribution, update `PROVENANCE.md`, and publish a
  new manifest version. Never overwrite an old capture without preserving its
  date and provenance.

### Disputed labels and corrections

A disputed label is not silently edited. Open a correction with the fixture
name, disputed field, evidence URL, observed date, and proposed replacement.
After review, preserve the original annotation in the change history, update
the manifest and provenance together, add or adjust the evaluation assertion,
and record the reason for the correction. A disagreement without sufficient
evidence remains `unresolved` in the correction record and is excluded from
claims about model accuracy.
