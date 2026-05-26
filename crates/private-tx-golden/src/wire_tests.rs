use ark_bls12_381::G1Affine;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use golden_dkg::threshold::ibe::ibe_encrypt;
use golden_dkg::threshold::types::{GroupInfo, KeyShare};
use golden_dkg::types::{Participant, Scalar, SessionId};
use miden_node_private_tx::ThresholdError;
use miden_protocol::{Hasher, Word};
use rand08::rngs::OsRng;

use crate::wire::*;

fn random_scalar() -> Scalar {
    let mut rng = OsRng;
    Scalar::rand(&mut rng)
}

#[test]
fn dkg_session_params_roundtrip_and_reject_trailing_bytes() {
    let mut rng = OsRng;
    let session_id = SessionId::random(&mut rng);
    let beta = Scalar::rand(&mut rng);
    let mut bytes = write_dkg_session_params(session_id, beta);

    let params = read_dkg_session_params(&bytes).unwrap();
    assert_eq!(params.session_id, session_id);
    assert_eq!(params.beta, beta);

    bytes.push(0);
    assert_eq!(read_dkg_session_params(&bytes).unwrap_err(), ThresholdError::MalformedMaterial);
}

#[test]
fn public_participant_rejects_zero_node_id() {
    let mut rng = OsRng;
    let participant = Participant::new(1, &mut rng);
    let bytes = write_public_participant(0, participant.pk, &participant.pok);

    assert_eq!(read_public_participant(&bytes).unwrap_err(), ThresholdError::MalformedMaterial);
}

#[test]
fn public_participant_rejects_tampered_pok() {
    let mut rng = OsRng;
    let participant = Participant::new(1, &mut rng);
    let mut proof = participant.pok.clone();
    proof.response += Scalar::from(1u64);
    let bytes = write_public_participant(participant.id, participant.pk, &proof);

    assert_eq!(read_public_participant(&bytes).unwrap_err(), ThresholdError::VerificationFailed);
}

#[test]
fn key_share_roundtrips() {
    let group_info = GroupInfo {
        public_key: (G1Affine::generator() * random_scalar()).into_affine(),
        threshold: 2,
        num_nodes: 3,
    };
    let share = KeyShare {
        id: 1,
        secret: random_scalar(),
        group_info: group_info.clone(),
    };

    let decoded = read_key_share(&write_key_share(&share)).unwrap();
    assert_eq!(decoded.id, share.id);
    assert_eq!(decoded.secret, share.secret);
    assert_eq!(decoded.group_info.public_key, group_info.public_key);
    assert_eq!(decoded.group_info.threshold, group_info.threshold);
    assert_eq!(decoded.group_info.num_nodes, group_info.num_nodes);
}

#[test]
fn wrapped_key_rejects_trailing_bytes() {
    let group_info = GroupInfo {
        public_key: (G1Affine::generator() * random_scalar()).into_affine(),
        threshold: 2,
        num_nodes: 3,
    };
    let mut rng = OsRng;
    let identity = b"identity";
    let associated_data_hash = Hasher::hash(b"ad");
    let wrapped = WrappedKey {
        viewing_group_id: Word::from([1_u32, 2, 3, 4]),
        identity: identity.to_vec(),
        associated_data_hash,
        group_info: group_info.clone(),
        ciphertext: ibe_encrypt(
            &group_info.public_key,
            &effective_identity(identity, associated_data_hash),
            b"record-key",
            &mut rng,
        ),
    };
    let mut bytes = write_wrapped_key(&wrapped);
    assert!(read_wrapped_key(&bytes).is_ok());

    bytes.push(0);
    assert_eq!(read_wrapped_key(&bytes).unwrap_err(), ThresholdError::MalformedMaterial);
}
