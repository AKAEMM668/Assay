# Preimage vectors

Each `<name>.preimage` file is the exact canonical byte sequence that
`evidence_hash` commits to for one report, and `<name>.digest` is its SHA-256
hex digest. A third-party reimplementation of the encoding (any language) can
verify itself against these fixtures without running this repo's code.

`aqua-mainnet-onchain` is traceable to AQUA's testnet attestation for the
mainnet asset: its digest equals the `evidence_hash` recorded on chain and in
`docs/attestation-run.md` (tx
`1b6bafc1226570b2415299f5531256716f4d8dc489a9784fcd6ea347d0f63f5f`, asset
`AQUA-GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA`).

The vectors were produced by an independent implementation of the documented
rules (`docs/contract-interface.md`), not by the Go encoder — see
`vectors_test.go`, which re-derives every vector from a Report and refuses any
vector file that is not pinned there.
