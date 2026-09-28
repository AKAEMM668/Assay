# Eval

The mechanics detection is deterministic — a flag is either set or it is not,
and there is nothing to measure. What this eval measures is the **judgment**:
does the severity model separate a trap from a legitimate compliance feature,
and does escalation fire only on reputation?

**A check whose judgment is not evaluated against this set does not ship.**

Run it with `make test`. The eval is `TestEval` in
[`internal/mechanics/eval_test.go`](../internal/mechanics/eval_test.go); it runs
from fixtures with no network access, so a result cannot drift because a
third-party API had a bad day.

## The labelled set

Every subject is a real pubnet asset. Fixtures were captured from live sources
with provenance recorded in
[`internal/mechanics/testdata/PROVENANCE.md`](../internal/mechanics/testdata/PROVENANCE.md).

| Subject | Label | Why it is in the set |
| --- | --- | --- |
| `AQUA` | legitimate | No auth flags at all, reciprocal domain. The baseline: the model must not manufacture risk. |
| `SHX` | legitimate | No auth flags **and** `auth_immutable`. Tests that flag-locking is not mistaken for danger. |
| `USDC` (Circle) | **legitimate, uses the flags** | The critical case. A real regulated stablecoin that legitimately uses `auth_revocable`. |
| `BERKSHIRE` (nasdaq.finance) | trap | Impersonation asset with clawback. Confiscation capability *and* confirmed-bad reputation. |
| `DOGE` (darkpool.digital) | trap | Known scam carrying **no auth flags**. The case that justifies the second axis. |
| `VELO` | legitimate, **unattributed** | No `home_domain` at all: nobody has claimed it. Tests that an absent claim reads `unknown` — not `unverified` — and moves no severity. |

## Results

Measured output from fixtures captured on 2026-08-10 (VELO, 2026-09-28).
`TestEval` asserts every row on each test run, so the table cannot drift from
the code without a red test:

| Subject | Asset | Base | Final | Escalated | Accountability | Mechanics |
| --- | --- | --- | --- | --- | --- | --- |
| aqua-clear-verified | `AQUA` | clear | **clear** | false | verified | — |
| shx-clear-flagslocked | `SHX` | clear | **clear** | false | verified | `auth_immutable` |
| usdc-revocable-regulated | `USDC` | medium | **medium** | false | unverified | `auth_revocable`, `domain_unverified` |
| berkshire-clawback-scam | `BERKSHIRE` | high | **critical** | true | unverified | `auth_revocable`, `auth_clawback_enabled`, `domain_unverified`, `blocklisted` |
| doge-noflags-scam | `DOGE` | clear | **critical** | true | unverified | `domain_unverified`, `blocklisted` |
| velo-no-home-domain | `VELO` | clear | **clear** | false | unknown | `domain_unverified` |

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

### VELO — no claim is not a failed claim

`clear`, accountability `unknown`.

The first subject in the set with **no `home_domain` at all**: Horizon omits
the field entirely for this account rather than returning `""` (verified live,
2026-09-28), so there is no claim to verify. Accountability is therefore
`unknown`, a different answer from `unverified` — `unverified` means somebody
advertised a domain and the claim did not hold up; `unknown` means nobody has
claimed the asset in the first place.

Its flags are identical to AQUA's and so is its severity: `base: clear`,
`final: clear`. Absence of a claim is not evidence against the asset and not
evidence for it — it only means there is nobody to name.

## Coverage gaps

Stated plainly, because an eval that hides its gaps is marketing.

- **Six subjects.** Enough to pin the judgment boundaries, not enough for a
  statistical claim. No precision/recall numbers are quoted, because six
  subjects cannot support them.
- **No legitimately-clawback-enabled asset.** The set has no confirmed-good
  regulated issuer that actually uses clawback. Sampling 2,400 live assets
  (the 2026-08-10 session, [session note](sessions/2026-08-10-mvp-core.md)) found
  541 clawback-capable ones, but they are dominated by a single tokenized-security
  issuer and none is independently confirmed legitimate. Until one is in the set,
  the claim "the model treats legitimate clawback fairly" rests on the model's
  structure rather than on measurement. This is the most important gap.

  A candidate now exists: `USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR`
  is clawback-capable, unblocklisted, and passes reciprocal SEP-1 verification —
  one of five such assets in StellarExpert's top 50 by rating. It is attested on
  testnet (see [deployment.md](deployment.md)) but is **not** in this set yet, so
  the gap is narrower than it was and not yet closed. Capturing it as a fixture
  is the next step.
- **No frozen-trustline case.** Nothing exercises assets with unauthorized
  trustlines, where a freeze has actually been used rather than merely enabled.
- **Fixtures are a snapshot.** Issuers can change flags. Fixtures pin the
  judgment, so a live asset's real classification can drift from the fixture's;
  re-capture before citing a specific asset's current state.

## Adding a subject

1. Capture fixtures for the asset and record provenance.
2. Add a case to `TestEval` with the expected base, final, escalation, and
   accountability — and a `why` string stating what the case proves. The `why`
   is printed on failure, so a future maintainer learns what they broke.
3. Every new check must add at least one subject that trips it **and** one with
   the same mechanics legitimately that must not be over-flagged.

Point 3 is the discipline. Any check can find `auth_revocable: true`. The reason
to have a check is that it knows when that is fine.
