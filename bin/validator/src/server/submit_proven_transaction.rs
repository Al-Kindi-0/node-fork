use std::sync::atomic::Ordering;

use miden_node_private_tx::{
    EncryptedPrivateTxPayload, SubmissionPayloadAssociatedData, decrypt_submission_payload,
    submission_associated_data_for_payload,
};
use miden_node_proto::generated as grpc;
use miden_node_utils::ErrorReport;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::transaction::{ProvenTransaction, TransactionId, TransactionInputs};
use miden_tx::utils::serde::Deserializable;
use tonic::Status;

use crate::db::insert_transaction;
use crate::server::{PrivateTxPayloadDecryptor, PrivateTxSubmissionMode, ValidatorServer};
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

        let inputs = input
            .private_inputs
            .into_transaction_inputs(&self.private_tx_submission, tx_id)?;

        // Validate the transaction.
        let tx_info = validate_transaction(tx, inputs).await.map_err(|err| {
            Status::invalid_argument(err.as_report_context("Invalid transaction"))
        })?;

        // Store the validated transaction.
        let count = self
            .db
            .transact("insert_transaction", move |conn| insert_transaction(conn, &tx_info))
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
    ) -> tonic::Result<TransactionInputs> {
        match self {
            Self::Cleartext(inputs) => read_transaction_inputs(&inputs),
            Self::Encrypted(payload) => match mode {
                // Defense in depth for callers that skip the handle-level policy check.
                PrivateTxSubmissionMode::Public => Err(encrypted_private_payload_unsupported()),
                PrivateTxSubmissionMode::Private(decryptor) => decryptor.decrypt(tx_id, &payload),
            },
        }
    }
}

impl PrivateTxPayloadDecryptor {
    fn decrypt(
        &self,
        tx_id: TransactionId,
        encrypted_payload: &[u8],
    ) -> tonic::Result<TransactionInputs> {
        let payload = EncryptedPrivateTxPayload::read_from_bytes(encrypted_payload)
            .map_err(|_| Status::invalid_argument("Invalid encrypted private payload"))?;
        let associated_data =
            submission_associated_data_for_payload(SubmissionPayloadAssociatedData {
                chain_id: &self.chain_id,
                tx_id,
                validator_id: &self.validator_id,
                payload: &payload,
            });
        let plaintext = decrypt_submission_payload(&self.unsealing_key, &payload, &associated_data)
            .map_err(|_| Status::invalid_argument("Invalid encrypted private payload"))?;

        read_transaction_inputs(&plaintext)
    }
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
    use miden_node_private_tx::{
        ChainId,
        EncryptedPrivateTxPayload,
        EncryptionSchemeId,
        SubmissionEncryptionAssociatedData,
        ValidatorId,
        encrypt_submission_payload,
        submission_associated_data_for_encryption,
    };
    use miden_protocol::account::{Account, AccountCode, AccountStorage};
    use miden_protocol::asset::AssetVault;
    use miden_protocol::block::BlockHeader;
    use miden_protocol::crypto::dsa::eddsa_25519_sha512::SecretKey;
    use miden_protocol::crypto::ies::{SealingKey, UnsealingKey};
    use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;
    use miden_protocol::transaction::{
        InputNotes,
        PartialBlockchain,
        TransactionId,
        TransactionInputs,
    };
    use miden_protocol::utils::serde::{Deserializable, Serializable};
    use miden_protocol::{ONE, Word};

    use crate::server::{
        PrivateTxPayloadDecryptor,
        PrivateTxSubmissionConfig,
        PrivateTxSubmissionMode,
        ValidatorServer,
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

        let err = input
            .into_transaction_inputs(
                &PrivateTxSubmissionMode::Private(private_tx_decryptor()),
                tx_id(7),
            )
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("Invalid encrypted private payload"));
    }

    #[test]
    fn private_mode_decrypts_encrypted_payload() {
        let chain_id = ChainId::new("miden-devnet").unwrap();
        let validator_id = ValidatorId::new("validator-1").unwrap();
        let tx_id = tx_id(9);
        let validator_encryption_key_id = word(30);
        let secret_key = SecretKey::new();
        let sealing_key = SealingKey::X25519XChaCha20Poly1305(secret_key.public_key());
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
        });

        let actual = input.into_transaction_inputs(&mode, tx_id).unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn private_submission_mode_debug_redacts_decryptor_key() {
        let debug = format!("{:?}", PrivateTxSubmissionMode::Private(private_tx_decryptor()));

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("SecretKey"));
        assert!(!debug.contains("UnsealingKey"));
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

    fn private_tx_decryptor() -> PrivateTxPayloadDecryptor {
        PrivateTxPayloadDecryptor::new(
            ChainId::new("miden-devnet").unwrap(),
            ValidatorId::new("validator-1").unwrap(),
            UnsealingKey::X25519XChaCha20Poly1305(SecretKey::new()),
        )
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
