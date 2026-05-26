use miden_node_private_tx::mock::{MOCK_THRESHOLD_SCHEME_ID, MockThresholdAdapter};
use miden_node_private_tx::{
    ArchiveAssociatedData, ArchiveRecordAssociatedData, ArchiveRecordKey, ChainId,
    EncryptedPrivateTxPayload, EncryptedPrivateTxRecord, PRIVATE_TX_VERSION,
    PrivateTxEncryptionError, PrivateTxRecord, PrivateTxRecordMetadata,
    SubmissionEncryptionAssociatedData, SubmissionPayloadAssociatedData, ThresholdBackend,
    ThresholdError, ThresholdShareCombiner, ThresholdShareProducer, ValidatorId,
    ViewingGroupPublicKey, ViewingKeyShare, ViewingPartyId, ViewingPartyPublicShare, ViewingPolicy,
    archive_associated_data, archive_associated_data_for_record, decrypt_submission_payload,
    encrypt_submission_payload, open_private_tx_record, private_tx_record_identity,
    seal_private_tx_record, submission_associated_data_for_encryption,
    submission_associated_data_for_payload,
};
use miden_protocol::crypto::dsa::eddsa_25519_sha512::SecretKey;
use miden_protocol::crypto::ies::{SealingKey, UnsealingKey};
use miden_protocol::transaction::TransactionId;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::{Hasher, Word};

// Crate-internal e2e: client/validator/auditor flows without node-runtime wiring.

const PRIVATE_PAYLOAD: &[u8] = b"serialized-transaction-inputs";
const AUDIT_REQUEST_SEED: &[u8] = b"audit-request-1";

#[test]
fn private_tx_flow_roundtrips() {
    let fixture = Fixture::new();
    let backend = MockThresholdAdapter;
    let viewing_group = ViewingGroup::new(&fixture.viewing_policy);

    let wire_payload = client_encrypts_private_payload(&fixture);
    let archive = validator_decrypts_and_archives(
        &fixture,
        &backend,
        &viewing_group.group_public_key,
        &wire_payload,
    );

    let opened = auditor_decrypts_archive(&backend, &viewing_group, &archive);
    let expected = expected_private_tx_record(&fixture, PRIVATE_PAYLOAD.to_vec());

    assert_eq!(opened, expected);
}

#[test]
fn submission_payload_rejects_substituted_public_metadata() {
    let fixture = Fixture::new();
    let wire_payload = client_encrypts_private_payload(&fixture);
    let payload = EncryptedPrivateTxPayload::read_from_bytes(&wire_payload).unwrap();
    let wrong_tx_ad = submission_associated_data_for_payload(SubmissionPayloadAssociatedData {
        chain_id: &fixture.chain_id,
        tx_id: tx_id(101),
        validator_id: &fixture.validator_id,
        payload: &payload,
    });

    assert_eq!(
        decrypt_submission_payload(&fixture.unsealing_key, &payload, &wrong_tx_ad).unwrap_err(),
        PrivateTxEncryptionError::DecryptionFailed
    );
}

#[test]
fn archive_record_rejects_substituted_public_envelope() {
    let fixture = Fixture::new();
    let backend = MockThresholdAdapter;
    let viewing_group = ViewingGroup::new(&fixture.viewing_policy);
    let wire_payload = client_encrypts_private_payload(&fixture);
    let archive = validator_decrypts_and_archives(
        &fixture,
        &backend,
        &viewing_group.group_public_key,
        &wire_payload,
    );

    let mut substituted = archive.record.clone();
    substituted.tx_id = tx_id(101);
    // Partial substitution is enough: changing any AD field must break record decryption.
    let substituted_ad =
        archive_associated_data_for_record(ArchiveRecordAssociatedData { record: &substituted });
    let record_key = ArchiveRecordKey::from_bytes(&archive.record_key_bytes).unwrap();

    assert_eq!(
        open_private_tx_record(&record_key, &archive.record.record_ciphertext, &substituted_ad)
            .unwrap_err(),
        PrivateTxEncryptionError::DecryptionFailed
    );
}

#[test]
fn audit_rejects_wrong_identity() {
    let fixture = Fixture::new();
    let backend = MockThresholdAdapter;
    let viewing_group = ViewingGroup::new(&fixture.viewing_policy);
    let wire_payload = client_encrypts_private_payload(&fixture);
    let archive = validator_decrypts_and_archives(
        &fixture,
        &backend,
        &viewing_group.group_public_key,
        &wire_payload,
    );
    let archive_ad =
        archive_associated_data_for_record(ArchiveRecordAssociatedData { record: &archive.record });
    let wrong_identity = private_tx_record_identity(&fixture.chain_id, tx_id(101));
    let (transport_public_key, _) =
        MockThresholdAdapter::audit_transport_keypair(AUDIT_REQUEST_SEED);

    assert_eq!(
        backend
            .produce_decryption_response(
                &viewing_group.key_shares[0],
                &wrong_identity,
                &archive_ad,
                &transport_public_key,
                &archive.record.data_key_protection,
            )
            .unwrap_err(),
        ThresholdError::IdentityMismatch
    );
}

#[test]
fn audit_rejects_below_threshold_response_count() {
    let fixture = Fixture::new();
    let backend = MockThresholdAdapter;
    let viewing_group = ViewingGroup::new(&fixture.viewing_policy);
    let wire_payload = client_encrypts_private_payload(&fixture);
    let archive = validator_decrypts_and_archives(
        &fixture,
        &backend,
        &viewing_group.group_public_key,
        &wire_payload,
    );
    let archive_ad =
        archive_associated_data_for_record(ArchiveRecordAssociatedData { record: &archive.record });
    let (transport_public_key, transport_secret) =
        MockThresholdAdapter::audit_transport_keypair(AUDIT_REQUEST_SEED);
    let one_response = [backend
        .produce_decryption_response(
            &viewing_group.key_shares[0],
            &archive.record.identity,
            &archive_ad,
            &transport_public_key,
            &archive.record.data_key_protection,
        )
        .unwrap()];

    assert_eq!(
        backend
            .combine_responses(
                &one_response,
                fixture.viewing_policy.threshold,
                &archive.record.identity,
                &archive_ad,
                &transport_secret,
            )
            .unwrap_err(),
        ThresholdError::InsufficientResponses
    );
}

struct Fixture {
    chain_id: ChainId,
    tx_id: TransactionId,
    validator_id: ValidatorId,
    validator_encryption_key_id: Word,
    tee_attestation_id: Word,
    public_tx_hash: Word,
    sealing_key: SealingKey,
    unsealing_key: UnsealingKey,
    viewing_policy: ViewingPolicy,
}

impl Fixture {
    fn new() -> Self {
        let mut rng = rand::rng();
        let validator_secret_key = SecretKey::with_rng(&mut rng);
        let validator_public_key = validator_secret_key.public_key();
        let validator_public_key_bytes = validator_public_key.to_bytes();
        let sealing_key = SealingKey::X25519XChaCha20Poly1305(validator_public_key);
        let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(validator_secret_key);
        let validator_id = ValidatorId::new("validator-1").unwrap();
        let validator_encryption_key_id = word(20);
        let mut attestation_bytes = Vec::new();
        attestation_bytes.extend_from_slice(b"mock-attestation");
        attestation_bytes.extend_from_slice(&validator_public_key_bytes);

        Self {
            chain_id: ChainId::new("miden-devnet").unwrap(),
            tx_id: tx_id(100),
            validator_id,
            validator_encryption_key_id,
            tee_attestation_id: Hasher::hash(&attestation_bytes),
            public_tx_hash: Hasher::hash(b"public-proven-transaction"),
            sealing_key,
            unsealing_key,
            viewing_policy: ViewingPolicy {
                version: PRIVATE_TX_VERSION,
                viewing_group_id: word(200),
                threshold: 2,
                parties: vec![
                    ViewingPartyId::new("party-1").unwrap(),
                    ViewingPartyId::new("party-2").unwrap(),
                    ViewingPartyId::new("party-3").unwrap(),
                ],
                scheme_id: MOCK_THRESHOLD_SCHEME_ID,
            },
        }
    }
}

struct ViewingGroup {
    threshold: u16,
    group_public_key: ViewingGroupPublicKey,
    key_shares: Vec<ViewingKeyShare>,
    public_shares: Vec<ViewingPartyPublicShare>,
}

impl ViewingGroup {
    fn new(policy: &ViewingPolicy) -> Self {
        let (group_public_key, key_shares, public_shares) =
            MockThresholdAdapter::bootstrap_viewing_group(policy).unwrap();
        Self {
            threshold: policy.threshold,
            group_public_key,
            key_shares,
            public_shares,
        }
    }
}

struct ArchiveOutput {
    record: EncryptedPrivateTxRecord,
    record_key_bytes: Vec<u8>,
}

fn client_encrypts_private_payload(fixture: &Fixture) -> Vec<u8> {
    let submission_ad =
        submission_associated_data_for_encryption(SubmissionEncryptionAssociatedData {
            chain_id: &fixture.chain_id,
            tx_id: fixture.tx_id,
            validator_id: &fixture.validator_id,
            validator_encryption_key_id: fixture.validator_encryption_key_id,
        });

    encrypt_submission_payload(
        &fixture.sealing_key,
        fixture.validator_encryption_key_id,
        PRIVATE_PAYLOAD,
        &submission_ad,
    )
    .unwrap()
    .to_bytes()
}

fn validator_decrypts_and_archives<B: ThresholdBackend>(
    fixture: &Fixture,
    backend: &B,
    group_public_key: &ViewingGroupPublicKey,
    wire_payload: &[u8],
) -> ArchiveOutput {
    let payload = EncryptedPrivateTxPayload::read_from_bytes(wire_payload).unwrap();
    let submission_ad = submission_associated_data_for_payload(SubmissionPayloadAssociatedData {
        chain_id: &fixture.chain_id,
        tx_id: fixture.tx_id,
        validator_id: &fixture.validator_id,
        payload: &payload,
    });
    let private_payload =
        decrypt_submission_payload(&fixture.unsealing_key, &payload, &submission_ad).unwrap();
    let record = expected_private_tx_record(fixture, private_payload);
    let identity = private_tx_record_identity(&fixture.chain_id, fixture.tx_id);
    let archive_ad = archive_associated_data(ArchiveAssociatedData {
        chain_id: &fixture.chain_id,
        tx_id: fixture.tx_id,
        viewing_group_id: group_public_key.viewing_group_id,
        identity: &identity,
        validator_id: &fixture.validator_id,
        validator_encryption_key_id: fixture.validator_encryption_key_id,
        tee_attestation_id: fixture.tee_attestation_id,
    });
    let record_key = ArchiveRecordKey::generate();
    let record_key_bytes = record_key.to_bytes();
    let record_ciphertext =
        seal_private_tx_record(&record_key, &record.to_bytes(), &archive_ad).unwrap();
    let data_key_protection = backend
        .encrypt_record_key(group_public_key, &identity, &archive_ad, &record_key_bytes)
        .unwrap();

    ArchiveOutput {
        record: EncryptedPrivateTxRecord {
            version: PRIVATE_TX_VERSION,
            chain_id: fixture.chain_id.clone(),
            tx_id: fixture.tx_id,
            viewing_group_id: group_public_key.viewing_group_id,
            identity,
            validator_id: fixture.validator_id.clone(),
            validator_encryption_key_id: fixture.validator_encryption_key_id,
            tee_attestation_id: fixture.tee_attestation_id,
            record_ciphertext,
            data_key_protection,
        },
        record_key_bytes,
    }
}

fn auditor_decrypts_archive<B: ThresholdBackend>(
    backend: &B,
    viewing_group: &ViewingGroup,
    archive: &ArchiveOutput,
) -> PrivateTxRecord {
    let stored_record = archive.record.to_bytes();
    let record = EncryptedPrivateTxRecord::read_from_bytes(&stored_record).unwrap();
    let archive_ad =
        archive_associated_data_for_record(ArchiveRecordAssociatedData { record: &record });
    let (transport_public_key, transport_secret) =
        MockThresholdAdapter::audit_transport_keypair(AUDIT_REQUEST_SEED);
    let responses = viewing_group
        .key_shares
        .iter()
        .take(usize::from(viewing_group.threshold))
        .map(|share| {
            backend
                .produce_decryption_response(
                    share,
                    &record.identity,
                    &archive_ad,
                    &transport_public_key,
                    &record.data_key_protection,
                )
                .unwrap()
        })
        .collect::<Vec<_>>();

    for (response, public_share) in responses.iter().zip(viewing_group.public_shares.iter()) {
        backend
            .verify_decryption_response(
                response,
                &record.identity,
                &archive_ad,
                &transport_public_key,
                public_share,
            )
            .unwrap();
    }

    let unlock = backend
        .combine_responses(
            &responses,
            viewing_group.threshold,
            &record.identity,
            &archive_ad,
            &transport_secret,
        )
        .unwrap();
    let record_key = ArchiveRecordKey::from_bytes(&unlock.record_key).unwrap();
    let plaintext =
        open_private_tx_record(&record_key, &record.record_ciphertext, &archive_ad).unwrap();
    PrivateTxRecord::read_from_bytes(&plaintext).unwrap()
}

fn expected_private_tx_record(fixture: &Fixture, transaction_inputs: Vec<u8>) -> PrivateTxRecord {
    PrivateTxRecord::new(
        PrivateTxRecordMetadata {
            version: PRIVATE_TX_VERSION,
            chain_id: fixture.chain_id.clone(),
            tx_id: fixture.tx_id,
            validator_id: fixture.validator_id.clone(),
            validator_encryption_key_id: fixture.validator_encryption_key_id,
            tee_attestation_id: fixture.tee_attestation_id,
            public_tx_hash: fixture.public_tx_hash,
        },
        transaction_inputs,
    )
}

fn word(seed: u32) -> Word {
    Word::from([seed, seed + 1, seed + 2, seed + 3])
}

fn tx_id(seed: u32) -> TransactionId {
    TransactionId::read_from_bytes(&word(seed).to_bytes()).unwrap()
}
