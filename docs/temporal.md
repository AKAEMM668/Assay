# Temporal Trust Model

An attestation in Assay says what was true at one instant in time. It asserts the state of an asset's capabilities and accountability at the exact moment of observation.

It does **not** assert what is true now. A capability removal (like a freeze flag being lowered) does not undo past exposure. If a freeze capability existed yesterday, the asset's history carries that risk, even if the flag is cleared today.

Assay's history is a record of its own observations over time, not a complete playback of the ledger's history. Freshness of data is the caller's policy.

See the [Freshness Policy](./freshness.md) for more details.
