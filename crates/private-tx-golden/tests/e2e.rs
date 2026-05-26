use miden_node_private_tx::{
    ThresholdError, ThresholdRecordEncryptor, ThresholdShareCombiner, ThresholdShareProducer,
    ThresholdShareVerifier, ViewingGroupSetup, ViewingPartyId,
};
use miden_node_private_tx_golden::GoldenThresholdAdapter;
use miden_protocol::Word;

#[test]
fn golden_adapter_dkg_and_audit_flow_roundtrips() {
    let adapter = GoldenThresholdAdapter;
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
    let session = GoldenThresholdAdapter::dkg_session(
        word(1),
        2,
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

    let identity = b"miden:private-tx-record:v1:devnet:tx-1";
    let associated_data = b"archive-associated-data";
    let record_key = b"archive-record-key";
    let protection = adapter
        .encrypt_record_key(&group_public_key, identity, associated_data, record_key)
        .unwrap();
    let (transport_public_key, transport_secret) =
        GoldenThresholdAdapter::audit_transport_keypair();
    let responses = key_shares
        .iter()
        .take(usize::from(session.threshold()))
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

    for (response, public_share) in responses.iter().zip(public_shares.iter()) {
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
                &public_shares[0],
            )
            .unwrap_err(),
        ThresholdError::AssociatedDataMismatch
    );
    assert_eq!(
        adapter
            .combine_responses(
                &protection,
                &responses[..1],
                session.threshold(),
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
                session.threshold(),
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
            session.threshold(),
            identity,
            associated_data,
            &transport_secret,
        )
        .unwrap();

    assert_eq!(unlock.record_key, record_key);
}

fn word(seed: u32) -> Word {
    Word::from([seed, seed + 1, seed + 2, seed + 3])
}
