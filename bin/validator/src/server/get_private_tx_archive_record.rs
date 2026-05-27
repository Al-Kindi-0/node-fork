use miden_node_private_tx::EncryptedPrivateTxRecord;
use miden_node_proto::generated as grpc;
use miden_node_utils::ErrorReport;
use miden_protocol::transaction::TransactionId;
use miden_protocol::utils::serde::Serializable;

use crate::COMPONENT;
use crate::db::load_private_tx_archive_record;
use crate::server::ValidatorServer;

#[tonic::async_trait]
impl grpc::server::validator_api::GetPrivateTxArchiveRecord for ValidatorServer {
    type Input = TransactionId;
    type Output = EncryptedPrivateTxRecord;

    fn decode(
        request: grpc::validator::PrivateTxArchiveRecordRequest,
    ) -> tonic::Result<Self::Input> {
        let transaction_id = request
            .transaction_id
            .ok_or_else(|| tonic::Status::invalid_argument("Missing transaction id"))?;

        transaction_id.try_into().map_err(tonic::Status::from)
    }

    fn encode(output: Self::Output) -> tonic::Result<grpc::validator::PrivateTxArchiveRecord> {
        Ok(grpc::validator::PrivateTxArchiveRecord { record: output.to_bytes() })
    }

    #[tracing::instrument(target = COMPONENT, skip_all, fields(tx_id = %tx_id))]
    async fn handle(&self, tx_id: Self::Input) -> tonic::Result<Self::Output> {
        self.db
            .query("load_private_tx_archive_record", move |conn| {
                load_private_tx_archive_record(conn, tx_id)
            })
            .await
            .map_err(|err| {
                tonic::Status::internal(
                    err.as_report_context("Failed to load private transaction archive record"),
                )
            })?
            .ok_or_else(|| tonic::Status::not_found("Private transaction archive record not found"))
    }
}

#[cfg(test)]
mod tests {
    use miden_node_private_tx::{
        ArchiveAssociatedData, ArchiveRecordKey, ChainId, DataKeyProtection,
        EncryptedPrivateTxRecord, PRIVATE_TX_VERSION, PrivateTxRecord, PrivateTxRecordMetadata,
        ThresholdRecordEncryptor, ThresholdSchemeId, ValidatorId, ViewingGroupPublicKey,
        ViewingGroupSetup, ViewingKeyShare, ViewingPartyId, ViewingPartyPublicShare,
        archive_associated_data, private_tx_record_identity, seal_private_tx_record,
    };
    use miden_node_private_tx_golden::{GoldenThresholdAdapter, decrypt_private_tx_archive_record};
    use miden_node_proto::generated::validator::api_server;
    use miden_node_proto::generated::{self as grpc};
    use miden_protocol::Word;
    use miden_protocol::transaction::TransactionId;
    use miden_protocol::utils::serde::{Deserializable, Serializable};

    use crate::db::insert_private_tx_archive_record;
    use crate::server::ValidatorServer;
    use crate::server::tests::TestValidator;

    #[test]
    fn decode_rejects_missing_transaction_id() {
        let request = grpc::validator::PrivateTxArchiveRecordRequest { transaction_id: None };

        let err =
            <ValidatorServer as grpc::server::validator_api::GetPrivateTxArchiveRecord>::decode(
                request,
            )
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("Missing transaction id"));
    }

    #[test]
    fn decode_rejects_malformed_transaction_id() {
        let request = grpc::validator::PrivateTxArchiveRecordRequest {
            transaction_id: Some(grpc::transaction::TransactionId {
                id: Some(grpc::primitives::Digest { d0: u64::MAX, d1: 0, d2: 0, d3: 0 }),
            }),
        };

        let err =
            <ValidatorServer as grpc::server::validator_api::GetPrivateTxArchiveRecord>::decode(
                request,
            )
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn get_private_tx_archive_record_returns_stored_record() {
        let validator = TestValidator::new().await;
        let record = archive_record(1);
        validator
            .db()
            .transact("insert_private_tx_archive_record", {
                let record = record.clone();
                move |conn| insert_private_tx_archive_record(conn, &record)
            })
            .await
            .unwrap();

        let request = tonic::Request::new(grpc::validator::PrivateTxArchiveRecordRequest {
            transaction_id: Some((&record.tx_id).into()),
        });
        let response = api_server::Api::get_private_tx_archive_record(&validator.server, request)
            .await
            .unwrap()
            .into_inner();

        assert_eq!(EncryptedPrivateTxRecord::read_from_bytes(&response.record).unwrap(), record);
    }

    #[tokio::test]
    async fn fetched_private_tx_archive_record_can_be_audited() {
        let validator = TestValidator::new().await;
        let adapter = GoldenThresholdAdapter;
        let viewing_group = golden_viewing_group(&adapter);
        let (record, expected_private_record) = golden_archive_record(&adapter, &viewing_group);
        validator
            .db()
            .transact("insert_private_tx_archive_record", {
                let record = record.clone();
                move |conn| insert_private_tx_archive_record(conn, &record)
            })
            .await
            .unwrap();

        let request = tonic::Request::new(grpc::validator::PrivateTxArchiveRecordRequest {
            transaction_id: Some((&record.tx_id).into()),
        });
        let response = api_server::Api::get_private_tx_archive_record(&validator.server, request)
            .await
            .unwrap()
            .into_inner();
        let fetched = EncryptedPrivateTxRecord::read_from_bytes(&response.record).unwrap();

        let audit = decrypt_private_tx_archive_record(
            &fetched,
            viewing_group.threshold,
            &viewing_group.key_shares,
            &viewing_group.public_shares,
        )
        .unwrap();

        assert_eq!(fetched, record);
        assert_eq!(audit.record, expected_private_record);
    }

    #[tokio::test]
    async fn get_private_tx_archive_record_returns_not_found() {
        let validator = TestValidator::new().await;

        let request = tonic::Request::new(grpc::validator::PrivateTxArchiveRecordRequest {
            transaction_id: Some(tx_id(9).into()),
        });
        let err = api_server::Api::get_private_tx_archive_record(&validator.server, request)
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::NotFound);
        assert!(err.message().contains("not found"));
    }

    fn archive_record(seed: u32) -> EncryptedPrivateTxRecord {
        let chain_id = ChainId::new("miden-devnet").unwrap();
        let validator_id = ValidatorId::new("validator-1").unwrap();
        let tx_id = tx_id(seed);
        let identity = private_tx_record_identity(&chain_id, tx_id);

        EncryptedPrivateTxRecord {
            version: PRIVATE_TX_VERSION,
            chain_id,
            tx_id,
            viewing_group_id: word(seed + 10),
            identity,
            validator_id,
            validator_encryption_key_id: word(seed + 20),
            tee_attestation_id: word(seed + 30),
            record_ciphertext: b"ciphertext".to_vec(),
            data_key_protection: DataKeyProtection::ThresholdWrappedKey {
                scheme_id: ThresholdSchemeId::new(1),
                wrapped_key: b"wrapped-key".to_vec(),
            },
        }
    }

    struct GoldenViewingGroup {
        threshold: u16,
        group_public_key: ViewingGroupPublicKey,
        key_shares: Vec<ViewingKeyShare>,
        public_shares: Vec<ViewingPartyPublicShare>,
    }

    fn golden_viewing_group(adapter: &GoldenThresholdAdapter) -> GoldenViewingGroup {
        let local_participants = vec![
            GoldenThresholdAdapter::generate_local_participant(
                ViewingPartyId::new("party-1").unwrap(),
                1,
            )
            .unwrap(),
            GoldenThresholdAdapter::generate_local_participant(
                ViewingPartyId::new("party-2").unwrap(),
                2,
            )
            .unwrap(),
            GoldenThresholdAdapter::generate_local_participant(
                ViewingPartyId::new("party-3").unwrap(),
                3,
            )
            .unwrap(),
        ];
        let threshold = 2;
        let session = GoldenThresholdAdapter::dkg_session(
            word(100),
            threshold,
            local_participants
                .iter()
                .map(|participant| participant.public.clone())
                .collect(),
        )
        .unwrap();
        let dealings = local_participants
            .iter()
            .map(|participant| adapter.create_dkg_dealing(&session, participant).unwrap())
            .collect::<Vec<_>>();

        for dealing in &dealings {
            adapter.verify_dkg_dealing(&session, &dealing.public).unwrap();
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
                adapter
                    .complete_dkg(&session, participant, &dealings[index].private, &peer_dealings)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let group_public_key =
            GoldenThresholdAdapter::viewing_group_public_key(&key_shares[0]).unwrap();
        let public_shares = key_shares
            .iter()
            .map(GoldenThresholdAdapter::viewing_party_public_share)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        GoldenViewingGroup {
            threshold,
            group_public_key,
            key_shares,
            public_shares,
        }
    }

    fn golden_archive_record(
        adapter: &GoldenThresholdAdapter,
        viewing_group: &GoldenViewingGroup,
    ) -> (EncryptedPrivateTxRecord, PrivateTxRecord) {
        let chain_id = ChainId::new("miden-devnet").unwrap();
        let validator_id = ValidatorId::new("validator-1").unwrap();
        let tx_id = tx_id(42);
        let validator_encryption_key_id = word(120);
        let tee_attestation_id = word(130);
        let public_tx_hash = word(140);
        let identity = private_tx_record_identity(&chain_id, tx_id);
        let archive_ad = archive_associated_data(ArchiveAssociatedData {
            chain_id: &chain_id,
            tx_id,
            viewing_group_id: viewing_group.group_public_key.viewing_group_id,
            identity: &identity,
            validator_id: &validator_id,
            validator_encryption_key_id,
            tee_attestation_id,
        });
        let private_record = PrivateTxRecord::new(
            PrivateTxRecordMetadata {
                version: PRIVATE_TX_VERSION,
                chain_id: chain_id.clone(),
                tx_id,
                validator_id: validator_id.clone(),
                validator_encryption_key_id,
                tee_attestation_id,
                public_tx_hash,
            },
            b"serialized-transaction-inputs".to_vec(),
        );
        let record_key = ArchiveRecordKey::generate();
        let record_key_bytes = record_key.to_bytes();
        let record_ciphertext =
            seal_private_tx_record(&record_key, &private_record.to_bytes(), &archive_ad).unwrap();
        let data_key_protection = adapter
            .encrypt_record_key(
                &viewing_group.group_public_key,
                &identity,
                &archive_ad,
                &record_key_bytes,
            )
            .unwrap();

        (
            EncryptedPrivateTxRecord {
                version: PRIVATE_TX_VERSION,
                chain_id,
                tx_id,
                viewing_group_id: viewing_group.group_public_key.viewing_group_id,
                identity,
                validator_id,
                validator_encryption_key_id,
                tee_attestation_id,
                record_ciphertext,
                data_key_protection,
            },
            private_record,
        )
    }

    fn tx_id(seed: u32) -> TransactionId {
        TransactionId::read_from_bytes(&word(seed).to_bytes()).unwrap()
    }

    fn word(seed: u32) -> Word {
        Word::from([seed, seed + 1, seed + 2, seed + 3])
    }
}
