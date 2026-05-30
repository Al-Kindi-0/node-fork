use std::sync::atomic::Ordering;

use miden_node_private_tx::{
    ArchiveAssociatedData, ArchiveRecordKey, EncryptedPrivateTxPayload, EncryptedPrivateTxRecord,
    PRIVATE_TX_VERSION, PrivateTxEncryptionError, PrivateTxRecord, PrivateTxRecordMetadata,
    SubmissionPayloadAssociatedData, ThresholdError, archive_associated_data,
    decrypt_submission_payload, private_tx_record_identity, seal_private_tx_record,
    submission_associated_data_for_payload,
};
use miden_node_proto::generated as grpc;
use miden_node_utils::ErrorReport;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::{ProvenTransaction, TransactionId, TransactionInputs};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::{Hasher, Word};
use tonic::Status;

use crate::db::{insert_private_tx_archive_record, insert_transaction};
use crate::server::{
    PrivateTxArchiveWriter, PrivateTxPayloadDecryptor, PrivateTxSubmissionMode, ValidatorServer,
};
use crate::tx_validation::validate_transaction;

#[tonic::async_trait]
impl grpc::server::validator_api::SubmitProvenTransaction for ValidatorServer {
    type Input = Input;
    type Output = ();

    async fn handle(&self, input: Self::Input) -> tonic::Result<Self::Output> {
        // Decode is config-free; public-mode policy is enforced here before transaction parsing.
        input
            .private_inputs
            .reject_if_private_mode_disabled(&self.private_tx_submission)?;

        let tx = ProvenTransaction::read_from_bytes(&input.transaction).map_err(|err| {
            Status::invalid_argument(err.as_report_context("Invalid proven transaction"))
        })?;
        let tx_id = tx.id();
        tracing::Span::current().set_attribute("transaction.id", tx_id);
        // The public tx hash binds the archive record to the submitted proof bytes, while tx_id is
        // the canonical transaction identifier.
        let public_tx_hash = Hasher::hash(&input.transaction);
        let current_block = BlockNumber::from(self.chain_tip.load(Ordering::Relaxed));

        let decoded_inputs = input.private_inputs.into_transaction_inputs(
            &self.private_tx_submission,
            tx_id,
            current_block,
        )?;

        // Validate the transaction.
        let tx_info =
            validate_transaction(tx, decoded_inputs.transaction_inputs)
                .await
                .map_err(|err| {
                    Status::invalid_argument(err.as_report_context("Invalid transaction"))
                })?;
        let archive_record = decoded_inputs
            .archive_source
            .map(|source| self.private_tx_submission.archive_record(tx_id, public_tx_hash, source))
            .transpose()?;

        // Store the validated transaction and its archive record atomically.
        let count = self
            .db
            .transact("insert_transaction_and_private_tx_archive_record", move |conn| {
                let count = insert_transaction(conn, &tx_info)?;
                if let Some(record) = &archive_record {
                    insert_private_tx_archive_record(conn, record)?;
                }
                Ok::<_, miden_node_db::DatabaseError>(count)
            })
            .await
            .map_err(|err| {
                Status::internal(err.as_report_context("Failed to insert transaction"))
            })?;

        self.validated_transactions_count.fetch_add(count as u64, Ordering::Relaxed);
        Ok(())
    }

    fn decode(request: grpc::transaction::ProvenTransaction) -> tonic::Result<Self::Input> {
        // Config-dependent rejection happens in `handle`, where server mode is available.
        let private_inputs = match (request.transaction_inputs, request.encrypted_private_payload) {
            (Some(inputs), None) => SubmittedTransactionInputs::Cleartext(inputs),
            (None, Some(payload)) => SubmittedTransactionInputs::Encrypted(payload),
            (Some(_), Some(_)) => {
                return Err(Status::invalid_argument(
                    "Provide either transaction inputs or encrypted private payload, not both",
                ));
            },
            (None, None) => return Err(Status::invalid_argument("Missing transaction inputs")),
        };

        Ok(Self::Input {
            transaction: request.transaction,
            private_inputs,
        })
    }

    fn encode(output: Self::Output) -> tonic::Result<()> {
        Ok(output)
    }
}

enum SubmittedTransactionInputs {
    Cleartext(Vec<u8>),
    Encrypted(Vec<u8>),
}

impl SubmittedTransactionInputs {
    fn reject_if_private_mode_disabled(&self, mode: &PrivateTxSubmissionMode) -> tonic::Result<()> {
        if matches!(self, Self::Encrypted(_)) && matches!(mode, PrivateTxSubmissionMode::Public) {
            return Err(encrypted_private_payload_unsupported());
        }

        Ok(())
    }

    fn into_transaction_inputs(
        self,
        mode: &PrivateTxSubmissionMode,
        tx_id: TransactionId,
        current_block: BlockNumber,
    ) -> tonic::Result<DecodedTransactionInputs> {
        match self {
            // Private-mode validators still accept cleartext submissions during the PoC migration
            // period. Only encrypted submissions produce archive records.
            Self::Cleartext(inputs) => Ok(DecodedTransactionInputs {
                transaction_inputs: read_transaction_inputs(&inputs)?,
                archive_source: None,
            }),
            Self::Encrypted(payload) => match mode {
                // Defense in depth for callers that skip the handle-level policy check.
                PrivateTxSubmissionMode::Public => Err(encrypted_private_payload_unsupported()),
                PrivateTxSubmissionMode::Private { decryptor, .. } => {
                    decryptor.decrypt(tx_id, &payload, current_block)
                },
            },
        }
    }
}

struct DecodedTransactionInputs {
    transaction_inputs: TransactionInputs,
    archive_source: Option<PrivateTxArchiveSource>,
}

struct PrivateTxArchiveSource {
    plaintext_transaction_inputs: Vec<u8>,
    validator_encryption_key_id: Word,
}

impl PrivateTxPayloadDecryptor {
    fn decrypt(
        &self,
        tx_id: TransactionId,
        encrypted_payload: &[u8],
        current_block: BlockNumber,
    ) -> tonic::Result<DecodedTransactionInputs> {
        let payload = EncryptedPrivateTxPayload::read_from_bytes(encrypted_payload)
            .map_err(|_| Status::invalid_argument("Invalid encrypted private payload"))?;
        let key_ring = self.key_ring()?;
        let unsealing_key = key_ring
            .unsealing_key(payload.validator_encryption_key_id, current_block)
            .ok_or_else(|| {
                tracing::debug!(
                    target: crate::COMPONENT,
                    current_key_id = %key_ring.current_descriptor().encryption_key_id,
                    received_key_id = %payload.validator_encryption_key_id,
                    %current_block,
                    "rejected encrypted private payload for inactive submission key"
                );
                Status::invalid_argument("Invalid encrypted private payload")
            })?;
        let associated_data =
            submission_associated_data_for_payload(SubmissionPayloadAssociatedData {
                chain_id: &self.chain_id,
                tx_id,
                validator_id: &self.validator_id,
                payload: &payload,
            });
        let plaintext = decrypt_submission_payload(unsealing_key, &payload, &associated_data)
            .map_err(|_| Status::invalid_argument("Invalid encrypted private payload"))?;

        Ok(DecodedTransactionInputs {
            transaction_inputs: read_transaction_inputs(&plaintext)?,
            archive_source: Some(PrivateTxArchiveSource {
                plaintext_transaction_inputs: plaintext,
                validator_encryption_key_id: payload.validator_encryption_key_id,
            }),
        })
    }
}

impl PrivateTxSubmissionMode {
    fn archive_record(
        &self,
        tx_id: TransactionId,
        public_tx_hash: Word,
        source: PrivateTxArchiveSource,
    ) -> tonic::Result<EncryptedPrivateTxRecord> {
        match self {
            Self::Public => Err(encrypted_private_payload_unsupported()),
            Self::Private { archive_writer, .. } => {
                // TODO(productionization): threshold wrapping is CPU-bound; move archive creation
                // to a blocking task before using private mode in production.
                archive_writer.archive_record(tx_id, public_tx_hash, source).map_err(|err| {
                    Status::internal(err.as_report_context("Failed to archive private transaction"))
                })
            },
        }
    }
}

impl PrivateTxArchiveWriter {
    fn archive_record(
        &self,
        tx_id: TransactionId,
        public_tx_hash: Word,
        source: PrivateTxArchiveSource,
    ) -> Result<EncryptedPrivateTxRecord, PrivateTxArchiveError> {
        let identity = private_tx_record_identity(&self.chain_id, tx_id);
        let archive_ad = archive_associated_data(ArchiveAssociatedData {
            chain_id: &self.chain_id,
            tx_id,
            viewing_group_id: self.viewing_group_public_key.viewing_group_id,
            identity: &identity,
            validator_id: &self.validator_id,
            validator_encryption_key_id: source.validator_encryption_key_id,
            tee_attestation_id: self.tee_attestation_id,
        });
        let record = PrivateTxRecord::new(
            PrivateTxRecordMetadata {
                version: PRIVATE_TX_VERSION,
                chain_id: self.chain_id.clone(),
                tx_id,
                validator_id: self.validator_id.clone(),
                validator_encryption_key_id: source.validator_encryption_key_id,
                tee_attestation_id: self.tee_attestation_id,
                public_tx_hash,
            },
            source.plaintext_transaction_inputs,
        );
        let record_key = ArchiveRecordKey::generate();
        let record_key_bytes = record_key.to_bytes();
        let record_ciphertext =
            seal_private_tx_record(&record_key, &record.to_bytes(), &archive_ad)?;
        let data_key_protection = self.record_key_encryptor.encrypt_record_key(
            &self.viewing_group_public_key,
            &identity,
            &archive_ad,
            &record_key_bytes,
        )?;

        Ok(EncryptedPrivateTxRecord {
            version: PRIVATE_TX_VERSION,
            chain_id: self.chain_id.clone(),
            tx_id,
            viewing_group_id: self.viewing_group_public_key.viewing_group_id,
            identity,
            validator_id: self.validator_id.clone(),
            validator_encryption_key_id: source.validator_encryption_key_id,
            tee_attestation_id: self.tee_attestation_id,
            record_ciphertext,
            data_key_protection,
        })
    }
}

#[derive(Debug, thiserror::Error)]
enum PrivateTxArchiveError {
    #[error("private transaction record encryption failed")]
    Encryption(#[from] PrivateTxEncryptionError),
    #[error("private transaction record key wrapping failed")]
    Threshold(#[from] ThresholdError),
}

fn read_transaction_inputs(bytes: &[u8]) -> tonic::Result<TransactionInputs> {
    TransactionInputs::read_from_bytes(bytes).map_err(|err| {
        Status::invalid_argument(err.as_report_context("Invalid transaction inputs"))
    })
}

fn encrypted_private_payload_unsupported() -> Status {
    Status::invalid_argument("Encrypted private payloads are not accepted in public validator mode")
}

pub struct Input {
    transaction: Vec<u8>,
    private_inputs: SubmittedTransactionInputs,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use miden_node_private_tx::mock::{MOCK_THRESHOLD_SCHEME_ID, MockThresholdAdapter};
    use miden_node_private_tx::{
        ArchiveRecordAssociatedData, ArchiveRecordKey, ChainId, EncryptedPrivateTxPayload,
        EncryptionSchemeId, PRIVATE_TX_VERSION, PrivateTxRecord, PrivateTxRecordMetadata,
        SubmissionEncryptionAssociatedData, ThresholdShareCombiner, ThresholdShareProducer,
        ThresholdShareVerifier, ValidatorId, ViewingKeyShare, ViewingPartyId,
        ViewingPartyPublicShare, ViewingPolicy, archive_associated_data_for_record,
        encrypt_submission_payload, open_private_tx_record, private_tx_record_identity,
        submission_associated_data_for_encryption, submission_key_id,
    };
    use miden_protocol::account::{Account, AccountCode, AccountStorage};
    use miden_protocol::asset::AssetVault;
    use miden_protocol::block::{BlockHeader, BlockNumber};
    use miden_protocol::crypto::dsa::eddsa_25519_sha512::SecretKey;
    use miden_protocol::crypto::ies::{SealingKey, UnsealingKey};
    use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;
    use miden_protocol::transaction::{
        InputNotes, PartialBlockchain, TransactionId, TransactionInputs,
    };
    use miden_protocol::utils::serde::{Deserializable, Serializable};
    use miden_protocol::{Hasher, ONE, Word};

    use crate::server::{
        PrivateTxArchiveConfig, PrivateTxSubmissionConfig, PrivateTxSubmissionMode, ValidatorServer,
    };
    use miden_node_proto::generated as grpc;

    #[test]
    fn decode_accepts_encrypted_private_payload_without_transaction_decode() {
        let request = request_with_encrypted_payload(Some(Vec::new()));

        let err = decode_err("encrypted payload with cleartext inputs", request);
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("either transaction inputs or encrypted private payload"));

        let encrypted_only = request_with_encrypted_payload(None);
        let input =
            <ValidatorServer as grpc::server::validator_api::SubmitProvenTransaction>::decode(
                encrypted_only,
            )
            .unwrap();

        assert!(matches!(input.private_inputs, super::SubmittedTransactionInputs::Encrypted(_)));
    }

    #[test]
    fn public_mode_rejects_encrypted_private_payload_before_transaction_decode() {
        let request = request_with_encrypted_payload(None);
        let input =
            <ValidatorServer as grpc::server::validator_api::SubmitProvenTransaction>::decode(
                request,
            )
            .unwrap();

        let err = input
            .private_inputs
            .reject_if_private_mode_disabled(&PrivateTxSubmissionMode::Public)
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("Encrypted private payloads"));
    }

    #[test]
    fn decode_requires_one_private_input_carrier() {
        let request = grpc::transaction::ProvenTransaction {
            transaction: Vec::new(),
            transaction_inputs: None,
            encrypted_private_payload: None,
        };

        let err = decode_err("missing private input carrier", request);
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("Missing transaction inputs"));
    }

    #[test]
    fn encrypted_payload_decoder_rejects_malformed_payload() {
        let payload = EncryptedPrivateTxPayload {
            version: 1,
            validator_encryption_key_id: Word::empty(),
            scheme_id: EncryptionSchemeId::new(99),
            ciphertext: b"not-a-sealed-message".to_vec(),
        };
        let input = super::SubmittedTransactionInputs::Encrypted(payload.to_bytes());

        let err = match input.into_transaction_inputs(
            &private_tx_submission_mode(
                ChainId::new("miden-devnet").unwrap(),
                ValidatorId::new("validator-1").unwrap(),
                UnsealingKey::X25519XChaCha20Poly1305(SecretKey::new()),
            ),
            tx_id(7),
            BlockNumber::GENESIS,
        ) {
            Ok(_) => panic!("malformed encrypted payload should be rejected"),
            Err(err) => err,
        };

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("Invalid encrypted private payload"));
    }

    #[test]
    fn private_mode_decrypts_encrypted_payload() {
        let chain_id = ChainId::new("miden-devnet").unwrap();
        let validator_id = ValidatorId::new("validator-1").unwrap();
        let tx_id = tx_id(9);
        let secret_key = SecretKey::new();
        let sealing_key = SealingKey::X25519XChaCha20Poly1305(secret_key.public_key());
        let validator_encryption_key_id = submission_key_id(&sealing_key);
        let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_key);
        let expected = transaction_inputs();
        let associated_data =
            submission_associated_data_for_encryption(SubmissionEncryptionAssociatedData {
                chain_id: &chain_id,
                tx_id,
                validator_id: &validator_id,
                validator_encryption_key_id,
            });
        let payload = encrypt_submission_payload(
            &sealing_key,
            validator_encryption_key_id,
            &expected.to_bytes(),
            &associated_data,
        )
        .unwrap();
        let input = super::SubmittedTransactionInputs::Encrypted(payload.to_bytes());
        let mode = PrivateTxSubmissionMode::from(PrivateTxSubmissionConfig::Private {
            chain_id,
            validator_id,
            unsealing_key,
            archive: private_tx_archive_config(&mock_viewing_group()),
        });

        let actual = input.into_transaction_inputs(&mode, tx_id, BlockNumber::GENESIS).unwrap();

        assert_eq!(actual.transaction_inputs, expected);
        let archive_source = actual.archive_source.expect("encrypted inputs should be archived");
        assert_eq!(archive_source.validator_encryption_key_id, validator_encryption_key_id);
        assert_eq!(archive_source.plaintext_transaction_inputs, expected.to_bytes());
    }

    #[test]
    fn private_mode_decrypts_draining_submission_key() {
        let chain_id = ChainId::new("miden-devnet").unwrap();
        let validator_id = ValidatorId::new("validator-1").unwrap();
        let tx_id = tx_id(10);
        let old_secret_key = SecretKey::new();
        let old_sealing_key = SealingKey::X25519XChaCha20Poly1305(old_secret_key.public_key());
        let old_key_id = submission_key_id(&old_sealing_key);
        let old_unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(old_secret_key);
        let mode =
            private_tx_submission_mode(chain_id.clone(), validator_id.clone(), old_unsealing_key);
        let descriptor = rotate_submission_key_for_test(
            &mode,
            UnsealingKey::X25519XChaCha20Poly1305(SecretKey::new()),
            BlockNumber::from(20),
            BlockNumber::MAX,
            BlockNumber::from(30),
        );
        assert_ne!(descriptor.encryption_key_id, old_key_id);
        let expected = transaction_inputs();
        let input = encrypted_inputs(
            &chain_id,
            &validator_id,
            tx_id,
            &old_sealing_key,
            old_key_id,
            &expected,
        );

        let actual = input.into_transaction_inputs(&mode, tx_id, BlockNumber::from(25)).unwrap();

        assert_eq!(actual.transaction_inputs, expected);
        assert_eq!(actual.archive_source.unwrap().validator_encryption_key_id, old_key_id);
    }

    #[test]
    fn private_mode_rejects_destroyed_submission_key() {
        let chain_id = ChainId::new("miden-devnet").unwrap();
        let validator_id = ValidatorId::new("validator-1").unwrap();
        let tx_id = tx_id(12);
        let old_secret_key = SecretKey::new();
        let old_sealing_key = SealingKey::X25519XChaCha20Poly1305(old_secret_key.public_key());
        let old_key_id = submission_key_id(&old_sealing_key);
        let old_unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(old_secret_key);
        let mode =
            private_tx_submission_mode(chain_id.clone(), validator_id.clone(), old_unsealing_key);
        rotate_submission_key_for_test(
            &mode,
            UnsealingKey::X25519XChaCha20Poly1305(SecretKey::new()),
            BlockNumber::from(20),
            BlockNumber::MAX,
            BlockNumber::from(30),
        );
        let input = encrypted_inputs(
            &chain_id,
            &validator_id,
            tx_id,
            &old_sealing_key,
            old_key_id,
            &transaction_inputs(),
        );

        let err = match input.into_transaction_inputs(&mode, tx_id, BlockNumber::from(30)) {
            Ok(_) => panic!("payload for a destroyed submission key should be rejected"),
            Err(err) => err,
        };

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("Invalid encrypted private payload"));
    }

    #[test]
    fn private_mode_enforces_current_submission_key_validity_window() {
        let chain_id = ChainId::new("miden-devnet").unwrap();
        let validator_id = ValidatorId::new("validator-1").unwrap();
        let tx_id = tx_id(13);
        let mode = private_tx_submission_mode(
            chain_id.clone(),
            validator_id.clone(),
            UnsealingKey::X25519XChaCha20Poly1305(SecretKey::new()),
        );
        let next_secret_key = SecretKey::new();
        let next_sealing_key = SealingKey::X25519XChaCha20Poly1305(next_secret_key.public_key());
        let next_key_id = submission_key_id(&next_sealing_key);
        let descriptor = rotate_submission_key_for_test(
            &mode,
            UnsealingKey::X25519XChaCha20Poly1305(next_secret_key),
            BlockNumber::from(20),
            BlockNumber::from(25),
            BlockNumber::from(30),
        );
        assert_eq!(descriptor.encryption_key_id, next_key_id);

        let before_valid = encrypted_inputs(
            &chain_id,
            &validator_id,
            tx_id,
            &next_sealing_key,
            next_key_id,
            &transaction_inputs(),
        );
        let err = match before_valid.into_transaction_inputs(&mode, tx_id, BlockNumber::from(19)) {
            Ok(_) => panic!("submission key should not be accepted before valid_from"),
            Err(err) => err,
        };
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let active = encrypted_inputs(
            &chain_id,
            &validator_id,
            tx_id,
            &next_sealing_key,
            next_key_id,
            &transaction_inputs(),
        );
        active.into_transaction_inputs(&mode, tx_id, BlockNumber::from(20)).unwrap();

        let expired = encrypted_inputs(
            &chain_id,
            &validator_id,
            tx_id,
            &next_sealing_key,
            next_key_id,
            &transaction_inputs(),
        );
        let err = match expired.into_transaction_inputs(&mode, tx_id, BlockNumber::from(26)) {
            Ok(_) => panic!("submission key should not be accepted after valid_until"),
            Err(err) => err,
        };
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn private_mode_rejects_payload_for_other_submission_key() {
        let chain_id = ChainId::new("miden-devnet").unwrap();
        let validator_id = ValidatorId::new("validator-1").unwrap();
        let tx_id = tx_id(10);
        let secret_key = SecretKey::new();
        let sealing_key = SealingKey::X25519XChaCha20Poly1305(secret_key.public_key());
        let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_key);
        let payload_key_id = Word::from([99u32, 98, 97, 96]);
        let associated_data =
            submission_associated_data_for_encryption(SubmissionEncryptionAssociatedData {
                chain_id: &chain_id,
                tx_id,
                validator_id: &validator_id,
                validator_encryption_key_id: payload_key_id,
            });
        let payload = encrypt_submission_payload(
            &sealing_key,
            payload_key_id,
            &transaction_inputs().to_bytes(),
            &associated_data,
        )
        .unwrap();
        let input = super::SubmittedTransactionInputs::Encrypted(payload.to_bytes());
        let mode = PrivateTxSubmissionMode::from(PrivateTxSubmissionConfig::Private {
            chain_id,
            validator_id,
            unsealing_key,
            archive: private_tx_archive_config(&mock_viewing_group()),
        });

        let err = match input.into_transaction_inputs(&mode, tx_id, BlockNumber::GENESIS) {
            Ok(_) => panic!("payload for a different submission key should be rejected"),
            Err(err) => err,
        };

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("Invalid encrypted private payload"));
    }

    #[test]
    fn private_mode_archives_encrypted_payload_source() {
        let chain_id = ChainId::new("miden-devnet").unwrap();
        let validator_id = ValidatorId::new("validator-1").unwrap();
        let tx_id = tx_id(11);
        let public_tx_hash = Hasher::hash(b"public-proven-transaction");
        let validator_encryption_key_id = word(30);
        let transaction_inputs = transaction_inputs().to_bytes();
        let viewing_group = mock_viewing_group();
        let mode = private_tx_submission_mode_with_archive(
            chain_id.clone(),
            validator_id.clone(),
            UnsealingKey::X25519XChaCha20Poly1305(SecretKey::new()),
            private_tx_archive_config(&viewing_group),
        );

        let record = mode
            .archive_record(
                tx_id,
                public_tx_hash,
                super::PrivateTxArchiveSource {
                    plaintext_transaction_inputs: transaction_inputs.clone(),
                    validator_encryption_key_id,
                },
            )
            .unwrap();

        assert_eq!(record.chain_id, chain_id);
        assert_eq!(record.tx_id, tx_id);
        assert_eq!(record.viewing_group_id, viewing_group.viewing_group_id);
        assert_eq!(record.identity, private_tx_record_identity(&record.chain_id, tx_id));
        assert_eq!(record.validator_id, validator_id);
        assert_eq!(record.validator_encryption_key_id, validator_encryption_key_id);
        assert_eq!(record.tee_attestation_id, word(60));

        let archive_ad =
            archive_associated_data_for_record(ArchiveRecordAssociatedData { record: &record });
        let adapter = MockThresholdAdapter;
        let (transport_public, transport_secret) =
            MockThresholdAdapter::audit_transport_keypair(b"validator-archive-test");
        let responses = viewing_group
            .key_shares
            .iter()
            .take(usize::from(viewing_group.threshold))
            .map(|key_share| {
                adapter.produce_decryption_response(
                    key_share,
                    &record.identity,
                    &archive_ad,
                    &transport_public,
                    &record.data_key_protection,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        for (response, public_share) in responses.iter().zip(viewing_group.public_shares.iter()) {
            adapter
                .verify_decryption_response(
                    response,
                    &record.identity,
                    &archive_ad,
                    &transport_public,
                    public_share,
                )
                .unwrap();
        }
        let unlock = adapter
            .combine_responses(
                &record.data_key_protection,
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
        let opened = PrivateTxRecord::read_from_bytes(&plaintext).unwrap();
        let expected = PrivateTxRecord::new(
            PrivateTxRecordMetadata {
                version: PRIVATE_TX_VERSION,
                chain_id: record.chain_id.clone(),
                tx_id,
                validator_id: record.validator_id.clone(),
                validator_encryption_key_id,
                tee_attestation_id: record.tee_attestation_id,
                public_tx_hash,
            },
            transaction_inputs,
        );

        assert_eq!(opened, expected);
    }

    #[test]
    fn private_submission_mode_debug_redacts_decryptor_key() {
        let debug = format!(
            "{:?}",
            private_tx_submission_mode(
                ChainId::new("miden-devnet").unwrap(),
                ValidatorId::new("validator-1").unwrap(),
                UnsealingKey::X25519XChaCha20Poly1305(SecretKey::new()),
            )
        );

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("SecretKey"));
        assert!(!debug.contains("UnsealingKey"));
    }

    fn encrypted_inputs(
        chain_id: &ChainId,
        validator_id: &ValidatorId,
        tx_id: TransactionId,
        sealing_key: &SealingKey,
        validator_encryption_key_id: Word,
        transaction_inputs: &TransactionInputs,
    ) -> super::SubmittedTransactionInputs {
        let associated_data =
            submission_associated_data_for_encryption(SubmissionEncryptionAssociatedData {
                chain_id,
                tx_id,
                validator_id,
                validator_encryption_key_id,
            });
        let payload = encrypt_submission_payload(
            sealing_key,
            validator_encryption_key_id,
            &transaction_inputs.to_bytes(),
            &associated_data,
        )
        .unwrap();

        super::SubmittedTransactionInputs::Encrypted(payload.to_bytes())
    }

    fn rotate_submission_key_for_test(
        mode: &PrivateTxSubmissionMode,
        next_unsealing_key: UnsealingKey,
        valid_from: BlockNumber,
        valid_until: BlockNumber,
        destroy_previous_at: BlockNumber,
    ) -> miden_node_private_tx::PrivateValidatorDescriptor {
        match mode {
            PrivateTxSubmissionMode::Private { decryptor, .. } => decryptor
                .rotate_submission_key_for_test(
                    next_unsealing_key,
                    valid_from,
                    valid_until,
                    destroy_previous_at,
                )
                .unwrap(),
            PrivateTxSubmissionMode::Public => panic!("private mode expected"),
        }
    }

    fn request_with_encrypted_payload(
        transaction_inputs: Option<Vec<u8>>,
    ) -> grpc::transaction::ProvenTransaction {
        grpc::transaction::ProvenTransaction {
            transaction: Vec::new(),
            transaction_inputs,
            encrypted_private_payload: Some(b"encrypted".to_vec()),
        }
    }

    fn private_tx_submission_mode(
        chain_id: ChainId,
        validator_id: ValidatorId,
        unsealing_key: UnsealingKey,
    ) -> PrivateTxSubmissionMode {
        private_tx_submission_mode_with_archive(
            chain_id,
            validator_id,
            unsealing_key,
            private_tx_archive_config(&mock_viewing_group()),
        )
    }

    fn private_tx_submission_mode_with_archive(
        chain_id: ChainId,
        validator_id: ValidatorId,
        unsealing_key: UnsealingKey,
        archive: PrivateTxArchiveConfig,
    ) -> PrivateTxSubmissionMode {
        PrivateTxSubmissionMode::from(PrivateTxSubmissionConfig::Private {
            chain_id,
            validator_id,
            unsealing_key,
            archive,
        })
    }

    fn private_tx_archive_config(viewing_group: &MockViewingGroup) -> PrivateTxArchiveConfig {
        PrivateTxArchiveConfig {
            tee_attestation_id: word(60),
            viewing_group_public_key: viewing_group.group_public_key.clone(),
            record_key_encryptor: Arc::new(MockThresholdAdapter),
        }
    }

    struct MockViewingGroup {
        threshold: u16,
        viewing_group_id: Word,
        group_public_key: miden_node_private_tx::ViewingGroupPublicKey,
        key_shares: Vec<ViewingKeyShare>,
        public_shares: Vec<ViewingPartyPublicShare>,
    }

    fn mock_viewing_group() -> MockViewingGroup {
        let policy = ViewingPolicy {
            version: PRIVATE_TX_VERSION,
            viewing_group_id: word(50),
            threshold: 2,
            parties: vec![
                ViewingPartyId::new("party-1").unwrap(),
                ViewingPartyId::new("party-2").unwrap(),
                ViewingPartyId::new("party-3").unwrap(),
            ],
            scheme_id: MOCK_THRESHOLD_SCHEME_ID,
        };
        let (group_public_key, key_shares, public_shares) =
            MockThresholdAdapter::bootstrap_viewing_group(&policy).unwrap();

        MockViewingGroup {
            threshold: policy.threshold,
            viewing_group_id: policy.viewing_group_id,
            group_public_key,
            key_shares,
            public_shares,
        }
    }

    fn transaction_inputs() -> TransactionInputs {
        let account = Account::new_existing(
            ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
            AssetVault::mock(),
            AccountStorage::mock(),
            AccountCode::mock(),
            ONE,
        );
        let blockchain = PartialBlockchain::default();
        let block_header = BlockHeader::mock(
            0,
            Some(blockchain.peaks().hash_peaks()),
            None,
            std::slice::from_ref(&account),
            Word::empty(),
        );

        TransactionInputs::new(
            (&account).into(),
            block_header,
            blockchain,
            InputNotes::new(Vec::new()).unwrap(),
        )
        .unwrap()
    }

    fn tx_id(seed: u32) -> TransactionId {
        TransactionId::read_from_bytes(&word(seed).to_bytes()).unwrap()
    }

    fn word(seed: u32) -> Word {
        Word::from([seed, seed + 1, seed + 2, seed + 3])
    }

    fn decode_err(case: &str, request: grpc::transaction::ProvenTransaction) -> tonic::Status {
        match <ValidatorServer as grpc::server::validator_api::SubmitProvenTransaction>::decode(
            request,
        ) {
            Ok(_) => panic!("{case} should be rejected"),
            Err(err) => err,
        }
    }
}
