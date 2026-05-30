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
- RPC accepts encrypted private payloads in private mode (`--rpc.private-tx.enabled`) and forwards
  them opaquely; the validator owns decryption.
- Validator private mode loads an unsealing key and viewing group public key from config.
- The validator exposes a signed submission-key descriptor containing the encryption key, key ID,
  validator ID, chain ID, and block-height validity window.
- `RotateSubmissionKey` manually rotates the validator submission key and keeps the previous key
  draining until its configured destroy block.
- The validator stores encrypted archive records in SQLite.
- `GetPrivateTxArchiveRecord` returns a serialized `EncryptedPrivateTxRecord` by transaction ID.
- `decrypt_private_tx_archive_record` runs the in-process audit ceremony and opens the archive.
- `AuditCoordinator` models L1-style audit requests, response collection, party bonds, and
  non-responder slashing with an in-memory PoC backend.
- Adapter-owned wire bytes are domain-separated and versioned; golden-rs structs do not cross the
  crate boundary.

## Production Gaps

- TEE attestation is represented by a configured `tee_attestation_id`. Production needs one concrete
  SGX, SEV-SNP, Nitro, or TDX attestation backend and verifier.
- Viewing-party governance is out of band. Production needs membership rules, approval policy, key
  custody rules, jurisdictional constraints, and an audit authorization mechanism.
- Bonding and slashing are modeled with in-memory balances. Production needs token accounting and
  on-chain enforcement.
- Audit parties are modeled in-process. Production needs a request/response protocol for threshold
  parties.
- No production binary launches the RPC server today; private-mode RPC behavior is verified at the
  handler level. A full RPC-to-validator submission test still needs a real proven transaction
  fixture or a proof-verification test seam.
- Submission-key discovery is validator-direct in the PoC. Production may serve the same signed
  descriptor through RPC caches, and should anchor the validator signing key to the on-chain
  validator identity.
- Submission-key descriptors use an open-ended `genesis..max` block validity window in the PoC.
  Production should publish real validity windows per rotation epoch.
- The validator has an in-memory submission-key ring and a manual internal rotation RPC. Production
  still needs authenticated administration, a durable key-custody story, cleanup of expired draining
  keys outside the rotation path, and bounded validity windows so cached descriptors cannot outlive
  the drain window. `miden-crypto` key-exchange keys currently zeroize on drop; a production build
  should keep that as an audited dependency invariant and cover any persisted key copies.
- DKG setup in tests and the demo uses local helper code for a 3-party, threshold-2 group. A
  long-lived test suite should extract a shared golden fixture.
- `miden-node-private-tx-golden` is a runtime validator dependency because private mode constructs
  `GoldenThresholdAdapter` in validator config. Public-mode production builds should likely
  feature-gate this dependency.
- Decide whether to audit golden-rs, fork it, or replace the threshold primitive. The PoC treats
  golden-rs as a candidate backend, not a committed production choice.
- DKG refresh or resharing, and archive handling for old viewing groups are not implemented.
- Archived private-record size limits and retention policy are not implemented.
- CPU-heavy threshold wrapping and audit work run in-process. Production should move this work onto
  blocking worker threads.

## Audit Coordination Sketch

The base `miden-node-private-tx` crate exposes `AuditCoordinator` as a small L1-like coordination
surface. The PoC `InMemoryAuditCoordinator` lets an authorized auditor request an audit for one
`tx_id`, publish a fresh reply public key, collect threshold-party responses before a block
deadline, and settle the request after the deadline. The reply key is per audit, so old audit
responses are not tied to a reused auditor decryption key. The in-memory backend tracks viewing-party
bonds and deducts a configured slash amount from non-responders. Parties without a prior mock bond
deposit are still recorded as non-responders, with `0` deducted.

The MVP assumptions are deliberately narrow:

- Auditors are assumed honest and pay their own gas. Auditor bonding is deferred.
- Auditor whitelist admission is a governance question outside the trait.
- Settlement slashes non-submission only. A response with the right request context but invalid
  crypto bytes counts as submitted in the PoC; fraud-proof slashing for invalid responses is v2.
- L1 anchoring economically discourages off-chain collusion, but it does not cryptographically
  prevent a threshold quorum from colluding outside the protocol.

## Code Layout

- `lib.rs`: `GoldenThresholdAdapter` implements DKG setup, record-key wrapping, share production,
  verification, and combination.
- `audit.rs` contains the reusable in-process audit helper.
- `wire.rs` owns golden-backed serialization.
- `compat.rs` contains the current golden-rs compatibility shim.
- `examples/private_validator_demo.rs` runs the scriptable in-process demo and prints metrics.
- `examples/private_validator_tui.rs` runs the pane-based live walkthrough.

## Running the Demo

Run the focused crate tests:

```bash
cargo test -p miden-node-private-tx-golden
```

Run the validator archive-fetch/audit integration test:

```bash
cargo test -p miden-validator get_private_tx_archive_record
```

Run the pane-based TUI for a live walkthrough:

```bash
cargo run -p miden-node-private-tx-golden --example private_validator_tui
```

The TUI uses `1`/`2`/`3` to switch audit scenarios, arrows or Space to move through the
flow, `r` to reset, and `q` to quit. It can start directly in a scenario:

```bash
cargo run -p miden-node-private-tx-golden --example private_validator_tui -- --all
cargo run -p miden-node-private-tx-golden --example private_validator_tui -- --one-missing
cargo run -p miden-node-private-tx-golden --example private_validator_tui -- --below-threshold
```

Use a terminal at least 132x40. The TUI starts with signed submission-key discovery, then shows the
same private fields as cleartext for the client/validator/auditor and as sealed values for the RPC
operator. The sidebar tracks who holds secrets, what is public or opaque, measured timings, and mock
party bonds. Scenario switching re-renders one real happy-path crypto run; it does not re-run the
ceremony for each scenario.

Run the scriptable demo for compact metrics:

```bash
cargo run -p miden-node-private-tx-golden --example private_validator_demo
```

For slide data:

```bash
cargo run -p miden-node-private-tx-golden --example private_validator_demo -- --json
```

For a log-style walkthrough instead of the TUI:

```bash
cargo run -p miden-node-private-tx-golden --example private_validator_demo -- --narrated --pause
```

Narrated and JSON modes also run the audit-coordination contrast: a happy audit leaves bonds intact,
while a missed response triggers mock slashing. The prompt-based interactive mode is still available
with `--interactive`; repeatable runs can use `--scenario=all`, `--scenario=one-missing`, or
`--scenario=below-threshold`.

Sample output:

```text
private validator golden-rs demo
participants=3 threshold=2
submission_payload_bytes=203
archive_record_bytes=994
archive_ciphertext_bytes=286
wrapped_key_bytes=444
audit_responses_count=2
audit_response_bytes_total=776
audit_response_bytes_avg=388
dkg_ms=2475
client_encrypt_ms=0
validator_archive_ms=24
audit_decrypt_ms=110
total_ms=2610
```

## Metrics

- `participants` / `threshold`: viewing group shape used by the demo.
- `submission_payload_bytes`: serialized encrypted client-to-validator private payload.
- `archive_record_bytes`: serialized encrypted archive record stored by the validator.
- `archive_ciphertext_bytes`: AEAD ciphertext for the sealed `PrivateTxRecord`, including the
  private note payload and archive metadata, but not the outer archive envelope or wrapped key.
- `wrapped_key_bytes`: threshold-wrapped per-transaction archive key. This can be larger than the
  sealed record in the demo because the demo note is tiny while the threshold wrapper
  carries fixed cryptographic material. Real private inputs are expected to contain more note data,
  so this ratio is not representative of production payload sizes.
- `audit_responses_count`: threshold responses combined by the auditor. Equals threshold on a
  successful ceremony.
- `audit_response_bytes_total` / `audit_response_bytes_avg`: serialized audit response overhead.
- `dkg_ms`: DKG ceremony wall-clock.
- `client_encrypt_ms`: client-side payload encryption time.
- `validator_archive_ms`: decrypt, archive encrypt, and threshold wrap time.
- `audit_decrypt_ms`: audit response production, verification, combine, and archive open time.
- `coordination`: JSON-only metrics for the audit-coordination contrast. The happy path shows all
  parties responding with no slashing; the missed-response path shows one party's mock bond
  decreasing from `100` to `90`.
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
