//! Runs the happy-path private validator PoC flow with the golden-rs adapter.
//!
//! The output is machine-readable `key=value` data. Sizes are serialized byte counts; timings are
//! wall-clock milliseconds for the in-process demo stages.

use std::time::Instant;

use miden_node_private_tx::{
    ArchiveAssociatedData, ArchiveRecordKey, ChainId, EncryptedPrivateTxPayload,
    EncryptedPrivateTxRecord, PRIVATE_TX_VERSION, PrivateTxRecord, PrivateTxRecordMetadata,
    SubmissionEncryptionAssociatedData, SubmissionPayloadAssociatedData, ThresholdRecordEncryptor,
    ValidatorId, ViewingGroupPublicKey, ViewingGroupSetup, ViewingKeyShare, ViewingPartyId,
    ViewingPartyPublicShare, ViewingPolicy, archive_associated_data, decrypt_submission_payload,
    encrypt_submission_payload, private_tx_record_identity, seal_private_tx_record,
    submission_associated_data_for_encryption, submission_associated_data_for_payload,
};
use miden_node_private_tx_golden::{
    GOLDEN_THRESHOLD_SCHEME_ID, GoldenThresholdAdapter, decrypt_private_tx_archive_record,
};
use miden_protocol::crypto::dsa::eddsa_25519_sha512::SecretKey;
use miden_protocol::crypto::ies::{SealingKey, UnsealingKey};
use miden_protocol::transaction::TransactionId;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::{Hasher, Word};

const PRIVATE_PAYLOAD: &[u8] =
    b"demo serialized TransactionInputs: consumed-note-1 produced-note-1";

type DemoResult<T> = Result<T, Box<dyn std::error::Error>>;

fn main() -> DemoResult<()> {
    let demo_started = Instant::now();
    let fixture = Fixture::new()?;
    let adapter = GoldenThresholdAdapter;

    let dkg_started = Instant::now();
    let viewing_group = ViewingGroup::setup(&adapter, &fixture.viewing_policy)?;
    let dkg_duration = dkg_started.elapsed();

    let client_started = Instant::now();
    let wire_payload = client_encrypts_private_payload(&fixture)?;
    let client_duration = client_started.elapsed();

    let validator_started = Instant::now();
    let archive = validator_decrypts_and_archives(
        &fixture,
        &adapter,
        &viewing_group.group_public_key,
        &wire_payload,
    )?;
    let validator_duration = validator_started.elapsed();

    let audit_started = Instant::now();
    let audit = decrypt_private_tx_archive_record(
        &archive.record,
        viewing_group.threshold,
        &viewing_group.key_shares,
        &viewing_group.public_shares,
    )?;
    let audit_duration = audit_started.elapsed();

    let expected = expected_private_tx_record(&fixture, PRIVATE_PAYLOAD.to_vec());
    assert_eq!(audit.record, expected);

    let wrapped_key_bytes = archive.wrapped_key_bytes;
    println!("private validator golden-rs demo");
    println!(
        "participants={} threshold={}",
        viewing_group.key_shares.len(),
        viewing_group.threshold
    );
    println!("submission_payload_bytes={}", wire_payload.len());
    println!("archive_record_bytes={}", archive.record.to_bytes().len());
    println!("archive_ciphertext_bytes={}", archive.record.record_ciphertext.len());
    println!("wrapped_key_bytes={wrapped_key_bytes}");
    println!("audit_responses_count={}", audit.response_count);
    println!("audit_response_bytes_total={}", audit.response_bytes_total);
    println!("audit_response_bytes_avg={}", audit.response_bytes_total / audit.response_count);
    println!("dkg_ms={}", dkg_duration.as_millis());
    println!("client_encrypt_ms={}", client_duration.as_millis());
    println!("validator_archive_ms={}", validator_duration.as_millis());
    println!("audit_decrypt_ms={}", audit_duration.as_millis());
    println!("total_ms={}", demo_started.elapsed().as_millis());

    Ok(())
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
    fn new() -> DemoResult<Self> {
        let validator_secret_key = SecretKey::new();
        let validator_public_key = validator_secret_key.public_key();
        let validator_public_key_bytes = validator_public_key.to_bytes();
        let mut attestation_bytes = Vec::new();
        attestation_bytes.extend_from_slice(b"demo-attestation");
        attestation_bytes.extend_from_slice(&validator_public_key_bytes);

        Ok(Self {
            chain_id: ChainId::new("miden-devnet")?,
            tx_id: tx_id(100)?,
            validator_id: ValidatorId::new("validator-1")?,
            validator_encryption_key_id: word(20),
            tee_attestation_id: Hasher::hash(&attestation_bytes),
            public_tx_hash: Hasher::hash(b"demo-public-proven-transaction"),
            sealing_key: SealingKey::X25519XChaCha20Poly1305(validator_public_key),
            unsealing_key: UnsealingKey::X25519XChaCha20Poly1305(validator_secret_key),
            viewing_policy: ViewingPolicy {
                version: PRIVATE_TX_VERSION,
                viewing_group_id: word(200),
                threshold: 2,
                parties: vec![
                    ViewingPartyId::new("party-1")?,
                    ViewingPartyId::new("party-2")?,
                    ViewingPartyId::new("party-3")?,
                ],
                scheme_id: GOLDEN_THRESHOLD_SCHEME_ID,
            },
        })
    }
}

struct ViewingGroup {
    threshold: u16,
    group_public_key: ViewingGroupPublicKey,
    key_shares: Vec<ViewingKeyShare>,
    public_shares: Vec<ViewingPartyPublicShare>,
}

impl ViewingGroup {
    fn setup(adapter: &GoldenThresholdAdapter, policy: &ViewingPolicy) -> DemoResult<Self> {
        let local_participants = policy
            .parties
            .iter()
            .enumerate()
            .map(|(index, party_id)| {
                GoldenThresholdAdapter::generate_local_participant(
                    party_id.clone(),
                    u32::try_from(index + 1).expect("demo participant index fits in u32"),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let session = GoldenThresholdAdapter::dkg_session(
            policy.viewing_group_id,
            policy.threshold,
            local_participants
                .iter()
                .map(|participant| participant.public.clone())
                .collect(),
        )?;
        let dealings = local_participants
            .iter()
            .map(|participant| adapter.create_dkg_dealing(&session, participant))
            .collect::<Result<Vec<_>, _>>()?;

        for dealing in &dealings {
            adapter.verify_dkg_dealing(&session, &dealing.public)?;
        }

        let key_shares = local_participants
            .iter()
            .enumerate()
            .map(|(index, participant)| {
                let peer_dealings = dealings
                    .iter()
                    .enumerate()
                    .filter(|(peer_index, _)| *peer_index != index)
                    .map(|(_, dealing)| dealing.public.clone())
                    .collect::<Vec<_>>();
                adapter.complete_dkg(
                    &session,
                    participant,
                    &dealings[index].private,
                    &peer_dealings,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let group_public_key = GoldenThresholdAdapter::viewing_group_public_key(&key_shares[0])?;
        let public_shares = key_shares
            .iter()
            .map(GoldenThresholdAdapter::viewing_party_public_share)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            threshold: policy.threshold,
            group_public_key,
            key_shares,
            public_shares,
        })
    }
}

struct ArchiveOutput {
    record: EncryptedPrivateTxRecord,
    wrapped_key_bytes: usize,
}

fn client_encrypts_private_payload(fixture: &Fixture) -> DemoResult<Vec<u8>> {
    let submission_ad =
        submission_associated_data_for_encryption(SubmissionEncryptionAssociatedData {
            chain_id: &fixture.chain_id,
            tx_id: fixture.tx_id,
            validator_id: &fixture.validator_id,
            validator_encryption_key_id: fixture.validator_encryption_key_id,
        });

    Ok(encrypt_submission_payload(
        &fixture.sealing_key,
        fixture.validator_encryption_key_id,
        PRIVATE_PAYLOAD,
        &submission_ad,
    )?
    .to_bytes())
}

fn validator_decrypts_and_archives(
    fixture: &Fixture,
    adapter: &GoldenThresholdAdapter,
    group_public_key: &ViewingGroupPublicKey,
    wire_payload: &[u8],
) -> DemoResult<ArchiveOutput> {
    let payload = EncryptedPrivateTxPayload::read_from_bytes(wire_payload)?;
    let submission_ad = submission_associated_data_for_payload(SubmissionPayloadAssociatedData {
        chain_id: &fixture.chain_id,
        tx_id: fixture.tx_id,
        validator_id: &fixture.validator_id,
        payload: &payload,
    });
    let private_payload =
        decrypt_submission_payload(&fixture.unsealing_key, &payload, &submission_ad)?;
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
    let record_ciphertext = seal_private_tx_record(&record_key, &record.to_bytes(), &archive_ad)?;
    let data_key_protection =
        adapter.encrypt_record_key(group_public_key, &identity, &archive_ad, &record_key_bytes)?;
    let wrapped_key_bytes = data_key_protection.to_bytes().len();

    Ok(ArchiveOutput {
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
        wrapped_key_bytes,
    })
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

fn tx_id(seed: u32) -> DemoResult<TransactionId> {
    TransactionId::read_from_bytes(&word(seed).to_bytes()).map_err(Into::into)
}
