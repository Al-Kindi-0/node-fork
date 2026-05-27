use miden_node_private_tx::{
    ArchiveAssociatedData, ArchiveRecordAssociatedData, ArchiveRecordKey, AuditCoordinator,
    AuditRequest, AuditTransportPublicKey, AuditorId, ChainId, EncryptedPrivateTxRecord,
    InMemoryAuditCoordinator, PRIVATE_TX_VERSION, PrivateTxRecord, PrivateTxRecordMetadata,
    ThresholdError, ThresholdRecordEncryptor, ThresholdShareCombiner, ThresholdShareProducer,
    ThresholdShareVerifier, ValidatorId, ViewingGroupPublicKey, ViewingGroupSetup, ViewingKeyShare,
    ViewingPartyId, ViewingPartyPublicShare, archive_associated_data,
    archive_associated_data_for_record, open_private_tx_record, private_tx_record_identity,
    seal_private_tx_record,
};
use miden_node_private_tx_golden::{
    AuditOrchestratorError, GoldenThresholdAdapter, decrypt_private_tx_archive_record,
};
use miden_protocol::Word;
use miden_protocol::transaction::TransactionId;
use miden_protocol::utils::serde::{Deserializable, Serializable};

#[test]
fn golden_adapter_dkg_and_audit_flow_roundtrips() {
    let adapter = GoldenThresholdAdapter;
    let viewing_group = setup_viewing_group(&adapter);

    let identity = b"miden:private-tx-record:v1:devnet:tx-1";
    let associated_data = b"archive-associated-data";
    let record_key = b"archive-record-key";
    let protection = adapter
        .encrypt_record_key(&viewing_group.group_public_key, identity, associated_data, record_key)
        .unwrap();
    let (transport_public_key, transport_secret) =
        GoldenThresholdAdapter::audit_transport_keypair();
    let responses = viewing_group
        .key_shares
        .iter()
        .take(usize::from(viewing_group.threshold))
        .map(|share| {
            adapter
                .produce_decryption_response(
                    share,
                    identity,
                    associated_data,
                    &transport_public_key,
                    &protection,
                )
                .unwrap()
        })
        .collect::<Vec<_>>();

    for (response, public_share) in responses.iter().zip(viewing_group.public_shares.iter()) {
        adapter
            .verify_decryption_response(
                response,
                identity,
                associated_data,
                &transport_public_key,
                public_share,
            )
            .unwrap();
    }
    assert_eq!(
        adapter
            .verify_decryption_response(
                &responses[0],
                identity,
                b"wrong-associated-data",
                &transport_public_key,
                &viewing_group.public_shares[0],
            )
            .unwrap_err(),
        ThresholdError::AssociatedDataMismatch
    );
    assert_eq!(
        adapter
            .combine_responses(
                &protection,
                &responses[..1],
                viewing_group.threshold,
                identity,
                associated_data,
                &transport_secret,
            )
            .unwrap_err(),
        ThresholdError::InsufficientResponses
    );
    assert_eq!(
        adapter
            .combine_responses(
                &protection,
                &responses,
                viewing_group.threshold,
                identity,
                b"wrong-associated-data",
                &transport_secret,
            )
            .unwrap_err(),
        ThresholdError::AssociatedDataMismatch
    );

    let unlock = adapter
        .combine_responses(
            &protection,
            &responses,
            viewing_group.threshold,
            identity,
            associated_data,
            &transport_secret,
        )
        .unwrap();

    assert_eq!(unlock.record_key, record_key);
}

#[test]
fn golden_audit_orchestrator_decrypts_archive_record() {
    let adapter = GoldenThresholdAdapter;
    let viewing_group = setup_viewing_group(&adapter);
    let (encrypted_record, expected_record) = archive_record(&adapter, &viewing_group);

    let audit = decrypt_private_tx_archive_record(
        &encrypted_record,
        viewing_group.threshold,
        &viewing_group.key_shares,
        &viewing_group.public_shares,
    )
    .unwrap();

    assert_eq!(audit.record, expected_record);
    assert_eq!(audit.response_count, usize::from(viewing_group.threshold));
    assert!(audit.response_bytes_total > 0);
}

#[test]
fn golden_audit_orchestrator_rejects_missing_public_share() {
    let adapter = GoldenThresholdAdapter;
    let viewing_group = setup_viewing_group(&adapter);
    let (encrypted_record, _) = archive_record(&adapter, &viewing_group);
    let missing_party = viewing_group.key_shares[0].party_id.clone();
    let public_shares = viewing_group.public_shares[1..].to_vec();

    let err = decrypt_private_tx_archive_record(
        &encrypted_record,
        viewing_group.threshold,
        &viewing_group.key_shares,
        &public_shares,
    )
    .unwrap_err();

    match err {
        AuditOrchestratorError::MissingPublicShare(party_id) => {
            assert_eq!(party_id, missing_party);
        },
        other => panic!("expected missing public share error, got {other:?}"),
    }
}

#[test]
fn golden_audit_orchestrator_rejects_zero_threshold() {
    let adapter = GoldenThresholdAdapter;
    let viewing_group = setup_viewing_group(&adapter);
    let (encrypted_record, _) = archive_record(&adapter, &viewing_group);

    let err = decrypt_private_tx_archive_record(
        &encrypted_record,
        0,
        &viewing_group.key_shares,
        &viewing_group.public_shares,
    )
    .unwrap_err();

    match err {
        AuditOrchestratorError::Threshold(ThresholdError::InvalidThreshold) => {},
        other => panic!("expected invalid threshold error, got {other:?}"),
    }
}

#[test]
fn audit_coordination_drives_golden_audit_flow_to_completion() {
    let adapter = GoldenThresholdAdapter;
    let viewing_group = setup_viewing_group(&adapter);
    let (encrypted_record, expected_record) = archive_record(&adapter, &viewing_group);
    let coordinator = InMemoryAuditCoordinator::new(100);
    let auditor_id = AuditorId::new("auditor-1").unwrap();
    coordinator.authorize_auditor(auditor_id.clone()).unwrap();

    let (transport_public_key, transport_secret) =
        GoldenThresholdAdapter::audit_transport_keypair();
    let request = audit_request(
        auditor_id.clone(),
        &encrypted_record,
        &viewing_group,
        transport_public_key.clone(),
        105,
    );
    let request_id = coordinator.request_audit(request).unwrap();
    let archive_ad = archive_associated_data_for_record(ArchiveRecordAssociatedData {
        record: &encrypted_record,
    });

    for key_share in &viewing_group.key_shares {
        let response = adapter
            .produce_decryption_response(
                key_share,
                &encrypted_record.identity,
                &archive_ad,
                &transport_public_key,
                &encrypted_record.data_key_protection,
            )
            .unwrap();
        coordinator.submit_response(request_id, &key_share.party_id, response).unwrap();
    }

    let responses = coordinator.fetch_responses(request_id).unwrap();
    assert_eq!(responses.responses.len(), viewing_group.key_shares.len());
    for response in &responses.responses {
        adapter
            .verify_decryption_response(
                response,
                &encrypted_record.identity,
                &archive_ad,
                &transport_public_key,
                public_share_for(&viewing_group.public_shares, &response.party_id),
            )
            .unwrap();
    }

    let threshold_responses = usize::from(viewing_group.threshold);
    let unlock = adapter
        .combine_responses(
            &encrypted_record.data_key_protection,
            &responses.responses[..threshold_responses],
            viewing_group.threshold,
            &encrypted_record.identity,
            &archive_ad,
            &transport_secret,
        )
        .unwrap();
    let record_key = ArchiveRecordKey::from_bytes(&unlock.record_key).unwrap();
    let plaintext =
        open_private_tx_record(&record_key, &encrypted_record.record_ciphertext, &archive_ad)
            .unwrap();
    assert_eq!(PrivateTxRecord::read_from_bytes(&plaintext).unwrap(), expected_record);

    coordinator.advance_block(5).unwrap();
    let settlement = coordinator.settle(request_id).unwrap();
    assert_eq!(settlement.responded_parties.len(), viewing_group.key_shares.len());
    assert!(settlement.slashed_parties.is_empty());
}

#[test]
fn audit_coordination_settles_below_threshold_with_slashing() {
    let adapter = GoldenThresholdAdapter;
    let viewing_group = setup_viewing_group(&adapter);
    let (encrypted_record, _) = archive_record(&adapter, &viewing_group);
    let coordinator = InMemoryAuditCoordinator::new(100);
    let auditor_id = AuditorId::new("auditor-1").unwrap();
    coordinator.authorize_auditor(auditor_id.clone()).unwrap();

    let (transport_public_key, transport_secret) =
        GoldenThresholdAdapter::audit_transport_keypair();
    let request = audit_request(
        auditor_id,
        &encrypted_record,
        &viewing_group,
        transport_public_key.clone(),
        106,
    );
    let request_id = coordinator.request_audit(request).unwrap();
    let archive_ad = archive_associated_data_for_record(ArchiveRecordAssociatedData {
        record: &encrypted_record,
    });
    let key_share = &viewing_group.key_shares[0];
    let response = adapter
        .produce_decryption_response(
            key_share,
            &encrypted_record.identity,
            &archive_ad,
            &transport_public_key,
            &encrypted_record.data_key_protection,
        )
        .unwrap();
    coordinator.submit_response(request_id, &key_share.party_id, response).unwrap();

    let responses = coordinator.fetch_responses(request_id).unwrap();
    assert_eq!(
        adapter
            .combine_responses(
                &encrypted_record.data_key_protection,
                &responses.responses,
                viewing_group.threshold,
                &encrypted_record.identity,
                &archive_ad,
                &transport_secret,
            )
            .unwrap_err(),
        ThresholdError::InsufficientResponses
    );

    coordinator.advance_block(6).unwrap();
    let settlement = coordinator.settle(request_id).unwrap();
    assert_eq!(settlement.responded_parties, vec![key_share.party_id.clone()]);
    assert_eq!(
        settlement.slashed_parties,
        viewing_group
            .key_shares
            .iter()
            .skip(1)
            .map(|share| share.party_id.clone())
            .collect::<Vec<_>>()
    );
}

struct ViewingGroup {
    threshold: u16,
    group_public_key: ViewingGroupPublicKey,
    key_shares: Vec<ViewingKeyShare>,
    public_shares: Vec<ViewingPartyPublicShare>,
}

fn setup_viewing_group(adapter: &GoldenThresholdAdapter) -> ViewingGroup {
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
        word(1),
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

    ViewingGroup {
        threshold,
        group_public_key,
        key_shares,
        public_shares,
    }
}

fn archive_record(
    adapter: &GoldenThresholdAdapter,
    viewing_group: &ViewingGroup,
) -> (EncryptedPrivateTxRecord, PrivateTxRecord) {
    let chain_id = ChainId::new("miden-devnet").unwrap();
    let tx_id = tx_id(100);
    let validator_id = ValidatorId::new("validator-1").unwrap();
    let validator_encryption_key_id = word(20);
    let tee_attestation_id = word(30);
    let public_tx_hash = word(40);
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

fn audit_request(
    auditor_id: AuditorId,
    encrypted_record: &EncryptedPrivateTxRecord,
    viewing_group: &ViewingGroup,
    transport_public_key: AuditTransportPublicKey,
    deadline_block: u64,
) -> AuditRequest {
    AuditRequest {
        auditor_id,
        tx_id: encrypted_record.tx_id,
        viewing_group_id: encrypted_record.viewing_group_id,
        identity: encrypted_record.identity.clone(),
        transport_public_key,
        parties: viewing_group.key_shares.iter().map(|share| share.party_id.clone()).collect(),
        deadline_block,
    }
}

fn public_share_for<'a>(
    public_shares: &'a [ViewingPartyPublicShare],
    party_id: &ViewingPartyId,
) -> &'a ViewingPartyPublicShare {
    public_shares
        .iter()
        .find(|public_share| &public_share.party_id == party_id)
        .unwrap()
}

fn tx_id(seed: u32) -> TransactionId {
    TransactionId::read_from_bytes(&word(seed).to_bytes()).unwrap()
}

fn word(seed: u32) -> Word {
    Word::from([seed, seed + 1, seed + 2, seed + 3])
}
