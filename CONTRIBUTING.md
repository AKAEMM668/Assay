# Contributing to Assay

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). If you
have found a way to make Assay under-report risk, that is a security issue —
see [SECURITY.md](SECURITY.md) and report it privately rather than opening an
issue.

## Ground rules

Assay makes claims about whether someone's money can be taken. Two rules
follow from that, and they are not negotiable:

**Never display a value you did not fetch.** No placeholder balances, no
example ratings, no "typical" flag sets. If a source is unreachable, the
output says the source is unreachable.

**Never re-derive a consumed signal.** StellarExpert's directory, ratings,
and blocklist are inputs. Assay attributes them to their source and passes
them through. If you find yourself writing a scam heuristic over domain
names, stop — that layer already exists and is better maintained than
anything we would write.

## Adding a check

Full guide: [docs/adding-a-check.md](docs/adding-a-check.md).

A check is not done when it detects something. It is done when its
*judgment* has been measured.

1. Implement `mechanics.Check`.
2. Verify every flag name, field name, and endpoint against a live source
   before encoding it. Cite what you verified in the PR.
3. Add it to the labelled set in `docs/eval.md` with at least one asset that
   should trip it and one that has the same mechanics *legitimately* and
   should not be over-flagged.
4. Record the eval result. **A check whose judgment isn't evaluated against
   that set doesn't ship.**

Point 3 is the whole discipline. Any check can find `auth_revocable: true`;
the reason to have a check at all is that it knows when that is fine.

## Development

```sh
make test     # tests with -race
make lint     # golangci-lint
make cover    # per-package coverage table, lowest first
make run      # start the API on :8080
```

The Soroban side, which needs the [stellar CLI](https://developers.stellar.org/docs/build/smart-contracts/getting-started/setup):

```sh
make contract-test    # cargo test
make contract-lint    # cargo fmt --check + clippy -D warnings
make build-contract   # optimized wasm into assay-contracts/out/
make deploy-testnet   # upload + deploy, prints the new contract ID

make attest ASSET=CODE-ISSUER   # scan live and write the result on-chain
make read   ASSET=CODE-ISSUER   # read it back with get_safety
```

`make attest` derives every value from a live scan via `assay attestation`.
Never hand-write a severity, a bitset, or an evidence hash into a transaction —
see [docs/deployment.md](docs/deployment.md).

Run `make fmt` before committing; CI enforces `gofmt -l` being empty.

### Coverage

Every CI run reports Go coverage per package. Open the run, select the **Go**
job, and the table is in the job summary under **Go coverage**. It lists the
lowest coverage first, and packages with no test files are shown rather than
left out. The same table is printed in the **coverage report** step's log, and
the raw profile is attached to the run as the `coverage-profile` artifact.
From the command line:

```sh
gh run view <run-id> --log | grep coverage
gh run download <run-id> -n coverage-profile && go tool cover -html=coverage.out
```

`make cover` prints the same table locally.

Coverage is **reported, not gated**. There is no threshold, so a drop does not
fail CI. Adopting one is a separate decision
([#130](https://github.com/use-assay/Assay/issues/130)), and so is adding a
hosted coverage service. The report is computed in the workflow from `go test`
output and nothing is sent anywhere else.

### The merge gate

CI runs a merge gate on every PR. When a PR touches a **maintainer-owned
safety-critical path** or a dependency file, the gate flags it so a maintainer
reviews it before merge. The flag is **advisory: it does not fail CI**. Much of
the contributor backlog legitimately touches these paths — an issue asking you
to change the severity model cannot be completed without editing the severity
model — so a flag means "a maintainer should look at this", not "your work is
wrong". Owned paths: the [severity model](docs/severity-model.md)
and the code implementing it, the checks, the scanner's source handling, the
[evidence_hash encoding](docs/contract-interface.md), both contracts, the eval
fixtures, and the gate and CI workflow themselves. They are listed, with
reasons, in `scripts/merge-gate.sh`. PRs touching only other docs or other
tests pass.

Two limits, stated plainly. The gate checks paths, not the checklist: it
prints the checklist but cannot tell whether a box was ticked honestly. And
because the flag is advisory, the gate does not by itself prevent a merge — it
writes its finding to the job summary and relies on a maintainer reading it.
The gate does still fail CI in one case: when it cannot run at all, because
then its finding is unknown rather than clean.

Note that `make verify-gate` still exits non-zero on a flag, which is what
makes it useful as a local check. Only CI treats the flag as advisory.

Verify your PR against the gate before opening it:

```sh
make verify-gate BASE=main HEAD=HEAD
```

The checklist it prints (also in the PR template) covers the part CI cannot
check: no unjustified dependency, no threshold moved without a reason
traceable to the attestation run, nothing published that the evidence does
not support.

Tests must not require network access. Fetchers are interfaces; tests use
fixtures captured from real responses under `internal/*/testdata/`. When you
capture a new fixture, note the date and the URL it came from.

## Commits

Present tense, explain the why when it isn't obvious. Keep unrelated changes
in separate commits. Don't commit binaries, coverage output, or logs.
