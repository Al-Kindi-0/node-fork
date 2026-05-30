use miden_node_private_tx::{
    SignedSubmissionKey, submission_key_commitment, verify_signed_submission_key,
};
use miden_node_proto::generated as grpc;
use miden_protocol::utils::serde::Serializable;

use crate::COMPONENT;
use crate::server::{PrivateTxSubmissionMode, ValidatorServer};

#[tonic::async_trait]
impl grpc::server::validator_api::GetSubmissionKey for ValidatorServer {
    type Input = ();
    type Output = SignedSubmissionKey;

    fn decode(_request: ()) -> tonic::Result<Self::Input> {
        Ok(())
    }

    fn encode(output: Self::Output) -> tonic::Result<grpc::validator::PrivateTxSubmissionKey> {
        Ok(grpc::validator::PrivateTxSubmissionKey { signed_key: output.to_bytes() })
    }

    #[tracing::instrument(target = COMPONENT, skip_all)]
    async fn handle(&self, _input: Self::Input) -> tonic::Result<Self::Output> {
        let descriptor = match &self.private_tx_submission {
            PrivateTxSubmissionMode::Public => {
                return Err(tonic::Status::failed_precondition(
                    "Private transaction submission is not enabled",
                ));
            },
            PrivateTxSubmissionMode::Private { decryptor, .. } => {
                decryptor.current_submission_key_descriptor().clone()
            },
        };

        let commitment = submission_key_commitment(&descriptor);
        let signature = self.signer.sign_commitment(commitment).await.map_err(|err| {
            tonic::Status::internal(format!("Failed to sign submission key: {err}"))
        })?;
        let signed_key = SignedSubmissionKey::new(descriptor, signature);

        debug_assert!(
            verify_signed_submission_key(
                &signed_key,
                &signed_key.descriptor.chain_id,
                &signed_key.descriptor.validator_id,
                signed_key.descriptor.valid_from,
                &self.signer.public_key(),
            )
            .is_ok()
        );

        Ok(signed_key)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use miden_node_private_tx::{
        ChainId, PrivateValidatorDescriptor, SignedSubmissionKey, SubmissionKeyVerificationError,
        ValidatorId, ViewingGroupPublicKey, submission_key_id, verify_signed_submission_key,
    };
    use miden_node_private_tx_golden::GoldenThresholdAdapter;
    use miden_node_proto::generated::validator::api_server;
    use miden_protocol::Word;
    use miden_protocol::block::BlockNumber;
    use miden_protocol::crypto::dsa::eddsa_25519_sha512::SecretKey as X25519SecretKey;
    use miden_protocol::crypto::ies::{SealingKey, UnsealingKey};
    use miden_protocol::utils::serde::{Deserializable, Serializable};

    use crate::server::tests::TestValidator;
    use crate::server::{
        PrivateTxArchiveConfig, PrivateTxSubmissionConfig, PrivateTxSubmissionMode,
    };

    #[tokio::test]
    async fn get_submission_key_rejects_public_mode() {
        let validator = TestValidator::new().await;

        let request = tonic::Request::new(());
        let err = api_server::Api::get_submission_key(&validator.server, request)
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("not enabled"));
    }

    #[tokio::test]
    async fn get_submission_key_returns_signed_descriptor() {
        let chain_id = ChainId::new("miden-devnet").unwrap();
        let validator_id = ValidatorId::new("validator-1").unwrap();
        let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(X25519SecretKey::new());
        let sealing_key = sealing_key_for(&unsealing_key);
        let expected_key_id = submission_key_id(&sealing_key);
        let validator = TestValidator::with_private_submission(private_config(
            chain_id.clone(),
            validator_id.clone(),
            unsealing_key,
        ))
        .await;

        let request = tonic::Request::new(());
        let response = api_server::Api::get_submission_key(&validator.server, request)
            .await
            .unwrap()
            .into_inner();
        let signed_key = SignedSubmissionKey::read_from_bytes(&response.signed_key).unwrap();

        let descriptor = verify_signed_submission_key(
            &signed_key,
            &chain_id,
            &validator_id,
            BlockNumber::GENESIS,
            &validator.server.signer.public_key(),
        )
        .unwrap();

        assert_eq!(descriptor.chain_id, chain_id);
        assert_eq!(descriptor.validator_id, validator_id);
        assert_eq!(descriptor.encryption_key_id, expected_key_id);
        assert_eq!(
            SealingKey::read_from_bytes(&descriptor.encryption_public_key).unwrap(),
            sealing_key
        );
    }

    #[tokio::test]
    async fn signed_submission_key_rejects_wrong_chain() {
        let chain_id = ChainId::new("miden-devnet").unwrap();
        let validator_id = ValidatorId::new("validator-1").unwrap();
        let validator = TestValidator::with_private_submission(private_config(
            chain_id.clone(),
            validator_id.clone(),
            UnsealingKey::X25519XChaCha20Poly1305(X25519SecretKey::new()),
        ))
        .await;

        let response =
            api_server::Api::get_submission_key(&validator.server, tonic::Request::new(()))
                .await
                .unwrap()
                .into_inner();
        let signed_key = SignedSubmissionKey::read_from_bytes(&response.signed_key).unwrap();

        let err = verify_signed_submission_key(
            &signed_key,
            &ChainId::new("other-chain").unwrap(),
            &validator_id,
            BlockNumber::GENESIS,
            &validator.server.signer.public_key(),
        )
        .unwrap_err();

        assert_eq!(err, SubmissionKeyVerificationError::ChainIdMismatch);
    }

    #[tokio::test]
    async fn get_submission_key_returns_current_key_after_rotation() {
        let chain_id = ChainId::new("miden-devnet").unwrap();
        let validator_id = ValidatorId::new("validator-1").unwrap();
        let initial_unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(X25519SecretKey::new());
        let initial_key_id = submission_key_id(&sealing_key_for(&initial_unsealing_key));
        let next_secret_key = X25519SecretKey::new();
        let next_sealing_key = SealingKey::X25519XChaCha20Poly1305(next_secret_key.public_key());
        let next_key_id = submission_key_id(&next_sealing_key);
        let mut validator = TestValidator::with_private_submission(private_config(
            chain_id.clone(),
            validator_id.clone(),
            initial_unsealing_key,
        ))
        .await;

        match &mut validator.server.private_tx_submission {
            PrivateTxSubmissionMode::Private { decryptor, .. } => {
                let rotated_key_id = decryptor.rotate_submission_key_for_test(
                    UnsealingKey::X25519XChaCha20Poly1305(next_secret_key),
                    BlockNumber::from(10),
                    BlockNumber::MAX,
                    BlockNumber::from(20),
                );
                assert_eq!(rotated_key_id, next_key_id);
            },
            PrivateTxSubmissionMode::Public => panic!("private mode expected"),
        }

        let response =
            api_server::Api::get_submission_key(&validator.server, tonic::Request::new(()))
                .await
                .unwrap()
                .into_inner();
        let signed_key = SignedSubmissionKey::read_from_bytes(&response.signed_key).unwrap();
        let descriptor = verify_signed_submission_key(
            &signed_key,
            &chain_id,
            &validator_id,
            BlockNumber::from(10),
            &validator.server.signer.public_key(),
        )
        .unwrap();

        assert_ne!(descriptor.encryption_key_id, initial_key_id);
        assert_eq!(descriptor.encryption_key_id, next_key_id);
        assert_eq!(
            SealingKey::read_from_bytes(&descriptor.encryption_public_key).unwrap(),
            next_sealing_key
        );
    }

    #[test]
    fn signed_submission_key_rejects_expired_descriptor() {
        let signer = miden_protocol::testing::random_secret_key::random_secret_key();
        let chain_id = ChainId::new("miden-devnet").unwrap();
        let validator_id = ValidatorId::new("validator-1").unwrap();
        let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(X25519SecretKey::new());
        let sealing_key = sealing_key_for(&unsealing_key);
        let descriptor = PrivateValidatorDescriptor {
            version: miden_node_private_tx::PRIVATE_TX_VERSION,
            chain_id: chain_id.clone(),
            validator_id: validator_id.clone(),
            encryption_key_id: submission_key_id(&sealing_key),
            encryption_public_key: sealing_key.to_bytes(),
            attestation_evidence: miden_node_private_tx::AttestationEvidence::none(),
            valid_from: BlockNumber::from(1),
            valid_until: BlockNumber::from(2),
        };
        let commitment = miden_node_private_tx::submission_key_commitment(&descriptor);
        let signed_key = SignedSubmissionKey::new(descriptor, signer.sign(commitment));

        let err = verify_signed_submission_key(
            &signed_key,
            &chain_id,
            &validator_id,
            BlockNumber::from(3),
            &signer.public_key(),
        )
        .unwrap_err();

        assert_eq!(err, SubmissionKeyVerificationError::Expired);
    }

    fn private_config(
        chain_id: ChainId,
        validator_id: ValidatorId,
        unsealing_key: UnsealingKey,
    ) -> PrivateTxSubmissionConfig {
        PrivateTxSubmissionConfig::Private {
            chain_id,
            validator_id,
            unsealing_key,
            archive: PrivateTxArchiveConfig {
                tee_attestation_id: Word::from([1u32, 2, 3, 4]),
                viewing_group_public_key: ViewingGroupPublicKey {
                    viewing_group_id: Word::from([5u32, 6, 7, 8]),
                    bytes: Vec::new(),
                },
                record_key_encryptor: Arc::new(GoldenThresholdAdapter),
            },
        }
    }

    fn sealing_key_for(unsealing_key: &UnsealingKey) -> SealingKey {
        match unsealing_key {
            UnsealingKey::X25519XChaCha20Poly1305(key) => {
                SealingKey::X25519XChaCha20Poly1305(key.public_key())
            },
            _ => panic!("test only uses X25519+XChaCha20-Poly1305"),
        }
    }
}
