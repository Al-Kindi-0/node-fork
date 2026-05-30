use std::sync::atomic::Ordering;

use miden_node_private_tx::SignedSubmissionKey;
use miden_node_proto::generated as grpc;
use miden_protocol::block::BlockNumber;
use miden_protocol::utils::serde::Serializable;

use crate::COMPONENT;
use crate::server::{PrivateTxSubmissionMode, ValidatorServer};

pub struct RotateSubmissionKeyInput {
    valid_from: BlockNumber,
    valid_until: BlockNumber,
    destroy_previous_at: BlockNumber,
}

#[tonic::async_trait]
impl grpc::server::validator_api::RotateSubmissionKey for ValidatorServer {
    type Input = RotateSubmissionKeyInput;
    type Output = SignedSubmissionKey;

    fn decode(request: grpc::validator::RotateSubmissionKeyRequest) -> tonic::Result<Self::Input> {
        Ok(RotateSubmissionKeyInput {
            valid_from: BlockNumber::from(request.valid_from),
            valid_until: BlockNumber::from(request.valid_until),
            destroy_previous_at: BlockNumber::from(request.destroy_previous_at),
        })
    }

    fn encode(output: Self::Output) -> tonic::Result<grpc::validator::PrivateTxSubmissionKey> {
        Ok(grpc::validator::PrivateTxSubmissionKey { signed_key: output.to_bytes() })
    }

    #[tracing::instrument(
        target = COMPONENT,
        skip_all,
        fields(
            valid_from = %input.valid_from,
            valid_until = %input.valid_until,
            destroy_previous_at = %input.destroy_previous_at,
        ),
        err
    )]
    async fn handle(&self, input: Self::Input) -> tonic::Result<Self::Output> {
        let _permit = self.submission_key_rotation_semaphore.acquire().await.map_err(|_| {
            tonic::Status::internal("submission key rotation semaphore is unavailable")
        })?;

        let decryptor = match &self.private_tx_submission {
            PrivateTxSubmissionMode::Public => {
                return Err(tonic::Status::failed_precondition(
                    "Private transaction submission is not enabled",
                ));
            },
            PrivateTxSubmissionMode::Private { decryptor, .. } => decryptor,
        };
        let pending = decryptor.prepare_submission_key_rotation(
            input.valid_from,
            input.valid_until,
            input.destroy_previous_at,
        )?;

        let signed_key = self.sign_submission_key_descriptor(pending.descriptor().clone()).await?;
        let current_block = BlockNumber::from(self.chain_tip.load(Ordering::Relaxed));
        decryptor.install_submission_key_rotation(pending, current_block)?;

        Ok(signed_key)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use miden_node_private_tx::{
        ChainId, SignedSubmissionKey, ValidatorId, ViewingGroupPublicKey, submission_key_id,
        verify_signed_submission_key,
    };
    use miden_node_private_tx_golden::GoldenThresholdAdapter;
    use miden_node_proto::generated::validator::api_server;
    use miden_protocol::Word;
    use miden_protocol::block::BlockNumber;
    use miden_protocol::crypto::dsa::eddsa_25519_sha512::SecretKey as X25519SecretKey;
    use miden_protocol::crypto::ies::{SealingKey, UnsealingKey};
    use miden_protocol::utils::serde::Deserializable;

    use crate::server::tests::TestValidator;
    use crate::server::{PrivateTxArchiveConfig, PrivateTxSubmissionConfig};

    #[tokio::test]
    async fn rotate_submission_key_rejects_public_mode() {
        let validator = TestValidator::new().await;

        let err = api_server::Api::rotate_submission_key(
            &validator.server,
            tonic::Request::new(rotation_request(10, 40, 30)),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("not enabled"));
    }

    #[tokio::test]
    async fn rotate_submission_key_returns_signed_current_descriptor() {
        let chain_id = ChainId::new("miden-devnet").unwrap();
        let validator_id = ValidatorId::new("validator-1").unwrap();
        let initial_unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(X25519SecretKey::new());
        let initial_key_id = submission_key_id(&sealing_key_for(&initial_unsealing_key));
        let validator = TestValidator::with_private_submission(private_config(
            chain_id.clone(),
            validator_id.clone(),
            initial_unsealing_key,
        ))
        .await;

        let rotated = api_server::Api::rotate_submission_key(
            &validator.server,
            tonic::Request::new(rotation_request(10, 40, 30)),
        )
        .await
        .unwrap()
        .into_inner();
        let signed_key = SignedSubmissionKey::read_from_bytes(&rotated.signed_key).unwrap();
        let descriptor = verify_signed_submission_key(
            &signed_key,
            &chain_id,
            &validator_id,
            BlockNumber::from(10),
            &validator.server.signer.public_key(),
        )
        .unwrap();

        assert_ne!(descriptor.encryption_key_id, initial_key_id);
        assert_eq!(descriptor.valid_from, BlockNumber::from(10));
        assert_eq!(descriptor.valid_until, BlockNumber::from(40));

        let discovered =
            api_server::Api::get_submission_key(&validator.server, tonic::Request::new(()))
                .await
                .unwrap()
                .into_inner();
        let discovered = SignedSubmissionKey::read_from_bytes(&discovered.signed_key).unwrap();
        assert_eq!(discovered.descriptor.encryption_key_id, descriptor.encryption_key_id);
    }

    #[tokio::test]
    async fn rotate_submission_key_rejects_invalid_window() {
        let chain_id = ChainId::new("miden-devnet").unwrap();
        let validator_id = ValidatorId::new("validator-1").unwrap();
        let validator = TestValidator::with_private_submission(private_config(
            chain_id,
            validator_id,
            UnsealingKey::X25519XChaCha20Poly1305(X25519SecretKey::new()),
        ))
        .await;

        let err = api_server::Api::rotate_submission_key(
            &validator.server,
            tonic::Request::new(rotation_request(40, 10, 30)),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let err = api_server::Api::rotate_submission_key(
            &validator.server,
            tonic::Request::new(rotation_request(10, 40, 0)),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let err = api_server::Api::rotate_submission_key(
            &validator.server,
            tonic::Request::new(rotation_request(30, 40, 20)),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    fn rotation_request(
        valid_from: u32,
        valid_until: u32,
        destroy_previous_at: u32,
    ) -> miden_node_proto::generated::validator::RotateSubmissionKeyRequest {
        miden_node_proto::generated::validator::RotateSubmissionKeyRequest {
            valid_from,
            valid_until,
            destroy_previous_at,
        }
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
                tee_attestation_id: Word::default(),
                viewing_group_public_key: ViewingGroupPublicKey {
                    viewing_group_id: Word::from([10u32, 11, 12, 13]),
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
            _ => panic!("test uses X25519+XChaCha20-Poly1305"),
        }
    }
}
