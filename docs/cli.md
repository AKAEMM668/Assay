# The CLI

`assay` is one binary with five subcommands. All of them print human-readable
JSON by default; every subcommand that produces structured output also has a
`-raw` form that prints tab-separated values, for scripts and CI.

```
usage:
  assay scan CODE-ISSUER          classify one asset and print the report as JSON
  assay attestation CODE-ISSUER   print the on-chain attest() arguments for one asset
  assay verify [-hash HEX] [-raw] [PREIMAGE]
                                  check a canonical preimage against an evidence_hash
  assay history [-guarantee] [-raw] CODE-ISSUER
                                  print the asset's observation history
  assay serve [-addr]             serve the HTTP API and UI
```

## assay scan

Scans one asset and prints the full report: the findings, the reasoning behind
each, and the evidence every conclusion is attributed to.

```
./assay scan CODE-ISSUER              # the findings and reasoning
```

## assay attestation

Derives the arguments of an on-chain `attest()` call from a live scan. It
deliberately does not submit anything: signing belongs to whoever holds the
attester key, and keeping derivation separate from submission means the
numbers going on-chain can be inspected before a key ever touches them.

```
./assay attestation CODE-ISSUER       # severity, flags, evidence_hash
./assay attestation -preimage CODE-ISSUER   # + the bytes the hash commits to
./assay attestation -raw CODE-ISSUER  # just `SEVERITY<TAB>FLAGS<TAB>HASH`
```

## assay verify

Checks a canonical preimage against an `evidence_hash`. It is the third-party
half of `attestation`: the attester publishes the bytes with
`assay attestation -preimage`, the registry stores the hash, and `verify`
decides whether the two correspond. It replaces the two commands and a human
comparing hex that verification used to be.

It reaches nothing. The preimage names its own asset, and the hash either
matches these bytes or it does not. The preimage is read from a file, or from
stdin when the argument is omitted or `-`.

```
./assay verify -hash 0x688453bd… preimage.txt   # verdict for a published preimage
./assay verify -hash "$(cat digest.txt)" < preimage.txt
./assay attestation -preimage CODE-ISSUER | jq -r .preimage | ./assay verify -hash 0x688453bd…
./assay verify -raw -hash 0x688453bd… preimage.txt   # just the recomputed hash
```

Flags:

- `-hash` — the `evidence_hash` to check against, 64 hex characters, with or
  without a `0x` prefix and in either case. Omitted, the command prints the hash
  the bytes produce, which is the value to compare against what is stored.
- `-asset` — also require the preimage to be for this `CODE-ISSUER`, so a
  correct hash for the wrong asset cannot pass.
- `-raw` — print only the recomputed hash.
- `-quiet` — print nothing and report the verdict through the exit status alone.

Semantics:

- **match** — JSON with `match: true`, exit 0.
- **mismatch** — JSON carrying both `computed` and `claimed`, exit non-zero.
  Those two values are the whole answer, so they are printed before the failure.
- **malformed hash** — refused as its own error rather than reported as a
  mismatch, so a truncated or mistyped hash is not mistaken for a broken
  attestation.
- **unreadable header** — noted on stderr, and the hash is still checked. The
  bytes are what the hash covers, so a cosmetic problem must not hide a real
  mismatch.

An unrecognised version line is a note rather than a failure, but it is not
harmless: the version is inside the hash, so a version this build does not know
reports itself rather than being compared against v1. A v1 preimage binds no
check set and is reported as `unknown`, never as complete — the rule
`docs/contract-interface.md` sets out.

## assay history

Prints an asset's observation history: one line per recorded observation, in
time order, derived from the report's evidence entries. Where `scan` answers
"what is true now", `history` answers "what did we observe, and when" — the
view an auditor needs when an asset's state changed and someone wants to know
whether it was ever different.

Each entry carries the asset, the report's severity at scan time, the
**transition** — what the issuer was observed doing, reduced to a term
(`malicious`, `listed as`, `blocked`, `unverified`, `not retrievable`, …) — the
observation's reason verbatim, and the time it was retrieved.

An observation that does not reduce to a known transition prints as
`unknown`. The history view deliberately does not re-derive the verdict; it
reports what each observation said.

```
./assay history CODE-ISSUER           # the observations as JSON
./assay history -raw CODE-ISSUER      # `ASSET<TAB>SEVERITY<TAB>TRANSITION<TAB>REASON`
```

Flags:

- `-raw` — print the history tab-separated instead of as JSON, for scripting.
- `-guarantee` — exit non-zero when the asset has no observations, so a script
  can distinguish "no history" from "history ran fine" without parsing output.

Semantics:

- **valid state** — the observations print in time order.
- **missing state** — a clear message (`no observations for ASSET`), and exit
  0 unless `-guarantee` was given.
- **unknown state** — an observation whose claim matches no known transition
  prints with transition `unknown` rather than being dropped.

## assay serve

Serves the HTTP API and UI. The API exposes the same reports the CLI prints;
see `docs/integrating.md` for what a consumer reads out of it.

```
./assay serve -addr :8080
```
