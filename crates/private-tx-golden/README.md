# miden-node-private-tx-golden

PoC adapter from `miden-node-private-tx` threshold traits to golden-rs vetKeys.

This crate is intentionally separate from `miden-node-private-tx` so the base private transaction
types do not pull in arkworks or golden-rs during normal builds.

## Status

This is feasibility code, not production crypto. It pins golden-rs at commit
`09f892b9d0d548dfbb9c400418f6d4c52ee4e147` and owns the adapter wire format locally so the
upstream dependency can be replaced later without changing `miden-node-private-tx` envelopes.

The adapter has a compatibility workaround for golden-rs batch eVRF verification. Upstream builds
batch proof inputs from `HashMap` iteration order, which is not stable after wire decoding. For
PoC-sized groups, `compat.rs` retries the same proof verification across recipient-order
permutations. The retry path is capped at six recipients because it is factorial work; larger
fallback cases fail closed. A production version should remove this by using an upstream ordered
verifier or a patched vendor crate.

## Layout

- `GoldenThresholdAdapter` implements DKG setup, record-key wrapping, share production,
  verification, and combination.
- DKG uses golden-rs `golden_dkg::dkg`.
- Record-key wrapping and audit recovery use golden-rs vetKeys IBE.
- Wire bytes are domain-separated, versioned, and serialized by this crate rather than exposing
  golden-rs structs directly.

## Demo

Run the in-process PoC flow:

```bash
cargo run -p miden-node-private-tx-golden --example private_validator_demo
```

The example runs the happy path and prints basic payload sizes and wall-clock timings for DKG,
client encryption, validator archive creation, and audit decryption. Timings can increase if the
PoC batch-proof compatibility fallback in `compat.rs` is exercised.
