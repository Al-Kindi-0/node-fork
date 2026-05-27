# miden-node-private-tx-golden

PoC adapter from `miden-node-private-tx` threshold traits to golden-rs vetKeys.

This crate is separate from `miden-node-private-tx`: the base private transaction envelopes stay
lightweight, while this crate owns the arkworks and golden-rs dependency graph.

## Status

This is feasibility code, not production crypto. It pins golden-rs at commit
`09f892b9d0d548dfbb9c400418f6d4c52ee4e147` and owns the adapter wire format locally so the
upstream dependency can be replaced later without changing `miden-node-private-tx` envelopes.

The PoC proves the architecture end to end with real crypto:

- The validator decrypts an encrypted submission inside its trust boundary.
- It archives the private inputs under a per-transaction record key.
- It threshold-wraps that key for a viewing group.
- It exposes the archive record by transaction ID.
- A threshold quorum recovers the original record through an in-process audit ceremony.

## What Is Real

- Client-to-validator payload encryption uses `miden_crypto` IES with
  X25519 + XChaCha20-Poly1305.
- Validator archive encryption uses `miden_crypto` XChaCha20-Poly1305 with associated data.
- Threshold DKG uses golden-rs DKG setup, dealing verification, and completion.
- Record-key wrapping and audit recovery use golden-rs vetKeys IBE.
- Validator private mode loads an unsealing key and viewing group public key from config.
- The validator stores encrypted archive records in SQLite.
- `GetPrivateTxArchiveRecord` returns a serialized `EncryptedPrivateTxRecord` by transaction ID.
- `decrypt_private_tx_archive_record` runs the in-process audit ceremony and opens the archive.
- Adapter-owned wire bytes are domain-separated and versioned; golden-rs structs do not cross the
  crate boundary.

## Production Gaps

- TEE attestation is represented by a configured `tee_attestation_id`. Production needs one concrete
  SGX, SEV-SNP, Nitro, or TDX attestation backend and verifier.
- Viewing-party governance is out of band. Production needs membership rules, approval policy, key
  custody rules, jurisdictional constraints, and an audit authorization mechanism.
- Audit parties are modeled in-process. Production needs a request/response protocol for threshold
  parties.
- Validator encryption-key discovery is manual/config-file based. Production needs an authenticated
  discovery mechanism, such as an on-chain registry or signed metadata.
- DKG setup in tests and the demo uses local helper code for a 3-party, threshold-2 group. A
  long-lived test suite should extract a shared golden fixture.
- `miden-node-private-tx-golden` is a runtime validator dependency because private mode constructs
  `GoldenThresholdAdapter` in validator config. Public-mode production builds should likely
  feature-gate this dependency.
- Decide whether to audit golden-rs, fork it, or replace the threshold primitive. The PoC treats
  golden-rs as a candidate backend, not a committed production choice.
- Key rotation, DKG refresh or resharing, and archive handling for old viewing groups are not
  implemented.
- Archived private-record size limits and retention policy are not implemented.
- CPU-heavy threshold wrapping and audit work run in-process. Production should move this work onto
  blocking worker threads.

## Code Layout

- `lib.rs`: `GoldenThresholdAdapter` implements DKG setup, record-key wrapping, share production,
  verification, and combination.
- `audit.rs` contains the reusable in-process audit helper.
- `wire.rs` owns golden-backed serialization.
- `compat.rs` contains the current golden-rs compatibility shim.
- `examples/private_validator_demo.rs` runs the happy-path PoC without starting node services.

## Running the Demo

Run the focused crate tests:

```bash
cargo test -p miden-node-private-tx-golden
```

Run the validator archive-fetch/audit integration test:

```bash
cargo test -p miden-validator get_private_tx_archive_record
```

Run the in-process demo:

```bash
cargo run -p miden-node-private-tx-golden --example private_validator_demo
```

Sample output captured on 2026-05-27:

```text
private validator golden-rs demo
participants=3 threshold=2
submission_payload_bytes=181
archive_record_bytes=973
archive_ciphertext_bytes=265
wrapped_key_bytes=444
audit_responses_count=2
audit_response_bytes_total=776
audit_response_bytes_avg=388
dkg_ms=1164
client_encrypt_ms=0
validator_archive_ms=22
audit_decrypt_ms=104
total_ms=1292
```

The timings are machine-dependent; byte counts should stay stable unless the envelope or wire format
changes.

## Metrics

- `participants` / `threshold`: viewing group shape used by the demo.
- `submission_payload_bytes`: serialized encrypted client-to-validator private payload.
- `archive_record_bytes`: serialized encrypted archive record stored by the validator.
- `archive_ciphertext_bytes`: AEAD ciphertext for the archived private transaction record.
- `wrapped_key_bytes`: threshold-wrapped per-transaction archive key.
- `audit_responses_count`: threshold responses combined by the auditor. Equals threshold on a
  successful ceremony.
- `audit_response_bytes_total` / `audit_response_bytes_avg`: serialized audit response overhead.
- `dkg_ms`: DKG ceremony wall-clock.
- `client_encrypt_ms`: client-side payload encryption time.
- `validator_archive_ms`: decrypt, archive encrypt, and threshold wrap time.
- `audit_decrypt_ms`: audit response production, verification, combine, and archive open time.
- `total_ms`: full in-process demo wall-clock time.

## Validation Coverage

- `cargo test -p miden-node-private-tx-golden` covers golden wire roundtrips, malformed wire
  rejection, DKG, threshold wrapping, audit recovery, and audit error cases.
- `cargo test -p miden-validator get_private_tx_archive_record` covers the validator archive fetch
  RPC and a composed flow: store encrypted record, fetch through gRPC, decode, audit-decrypt, and
  compare with the original private record.
- `cargo test -p miden-validator` covers private-mode config parsing, encrypted payload decode, DB
  archive storage, and archive fetch tests alongside existing validator tests.

## Workaround Notes

The adapter has a compatibility workaround for golden-rs batch eVRF verification. Upstream builds
batch proof inputs from `HashMap` iteration order, which is not stable after wire decoding. For
PoC-sized groups, `compat.rs` retries the same proof verification across recipient-order
permutations. The retry path is capped at six recipients because it is factorial work; larger
fallback cases fail closed.

As of 2026-05-27, the upstream
[`farazshaikh/golden-rs` issue tracker](https://github.com/farazshaikh/golden-rs/issues) showed
zero open issues. An
[exact search](https://github.com/farazshaikh/golden-rs/issues?q=is%3Aissue+%22batch+eVRF+verification+failed%22)
for `"batch eVRF verification failed"` returned no results.

File an upstream issue or vendor a small ordered-verification patch before treating this adapter as
more than PoC code.
