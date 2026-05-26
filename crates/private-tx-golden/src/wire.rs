use std::collections::HashMap;

use ark_bls12_381::{Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use golden_dkg::schnorr_pok;
use golden_dkg::threshold::ibe::{
    EncryptedKeyShare, IBECiphertext, TransportPublicKey, TransportSecretKey,
};
use golden_dkg::threshold::types::{GroupInfo, KeyShare};
use golden_dkg::types::{
    Ciphertext, DkgConfig, DkgDealing as GoldenDkgDealing, MessageHeader, NodeId, Participant,
    Round0Msg, Scalar, SecretScalar, SessionId,
};
use miden_node_private_tx::{
    DataKeyProtection, DkgLocalParticipant, DkgParticipant, DkgSession, ThresholdError,
    ViewingPartyId,
};
use miden_protocol::utils::serde::{
    ByteReader, ByteWriter, Deserializable, Serializable, SliceReader,
};
use miden_protocol::{Hasher, Word};

use crate::{GOLDEN_THRESHOLD_SCHEME_ID, GOLDEN_WIRE_VERSION};

const DKG_SESSION_PARAMS_DOMAIN: &str = "miden:private-validator:golden:dkg-session:v1";
const EFFECTIVE_IDENTITY_DOMAIN: &str = "miden:private-validator:golden:identity:v1";
const PUBLIC_PARTICIPANT_DOMAIN: &str = "miden:private-validator:golden:participant-public:v1";
const LOCAL_PARTICIPANT_DOMAIN: &str = "miden:private-validator:golden:participant-local:v1";
const ROUND0_DOMAIN: &str = "miden:private-validator:golden:round0:v1";
const DKG_DEALING_DOMAIN: &str = "miden:private-validator:golden:dkg-dealing:v1";
const GROUP_INFO_DOMAIN: &str = "miden:private-validator:golden:group-info:v1";
const KEY_SHARE_DOMAIN: &str = "miden:private-validator:golden:key-share:v1";
const PARTY_PUBLIC_SHARE_DOMAIN: &str = "miden:private-validator:golden:party-public-share:v1";
const TRANSPORT_PUBLIC_DOMAIN: &str = "miden:private-validator:golden:transport-public:v1";
const TRANSPORT_SECRET_DOMAIN: &str = "miden:private-validator:golden:transport-secret:v1";
const WRAPPED_KEY_DOMAIN: &str = "miden:private-validator:golden:wrapped-key:v1";
const RESPONSE_DOMAIN: &str = "miden:private-validator:golden:response:v1";

#[derive(Clone, Debug)]
pub(crate) struct PublicParticipant {
    pub(crate) node_id: NodeId,
    pub(crate) public_key: G1Affine,
}

#[derive(Clone, Debug)]
pub(crate) struct DkgSessionParams {
    pub(crate) session_id: SessionId,
    pub(crate) beta: Scalar,
}

#[derive(Clone, Debug)]
pub(crate) struct PartyPublicShare {
    pub(crate) node_id: NodeId,
    pub(crate) public_key: G1Affine,
}

#[derive(Clone, Debug)]
pub(crate) struct WrappedKey {
    pub(crate) viewing_group_id: Word,
    pub(crate) identity: Vec<u8>,
    pub(crate) associated_data_hash: Word,
    pub(crate) group_info: GroupInfo,
    pub(crate) ciphertext: IBECiphertext,
}

#[derive(Clone, Debug)]
pub(crate) struct ResponseBytes {
    pub(crate) wrapped_key_digest: Word,
    pub(crate) associated_data_hash: Word,
    pub(crate) transport_key_digest: Word,
    pub(crate) encrypted_share: EncryptedKeyShare,
}

pub(crate) fn validate_node_id(node_id: NodeId) -> Result<(), ThresholdError> {
    if node_id == 0 {
        Err(ThresholdError::MalformedMaterial)
    } else {
        Ok(())
    }
}

pub(crate) fn ensure_local_participant_matches_public(
    local: &Participant,
    participant: &DkgLocalParticipant,
) -> Result<(), ThresholdError> {
    let public = read_public_participant(&participant.public.public_key)?;
    if local.id == public.node_id && local.pk == public.public_key {
        Ok(())
    } else {
        Err(ThresholdError::VerificationFailed)
    }
}

pub(crate) fn ensure_session_contains_participant(
    session: &DkgSession,
    participant: &DkgParticipant,
) -> Result<(), ThresholdError> {
    if session.participants().iter().any(|candidate| candidate == participant) {
        Ok(())
    } else {
        Err(ThresholdError::VerificationFailed)
    }
}

pub(crate) fn session_participant_by_party_id<'a>(
    session: &'a DkgSession,
    party_id: &ViewingPartyId,
) -> Result<&'a DkgParticipant, ThresholdError> {
    session
        .participants()
        .iter()
        .find(|participant| &participant.party_id == party_id)
        .ok_or(ThresholdError::VerificationFailed)
}

pub(crate) fn peers_from_session(
    session: &DkgSession,
) -> Result<HashMap<NodeId, G1Affine>, ThresholdError> {
    let mut peers = HashMap::new();
    for participant in session.participants() {
        let public = read_public_participant(&participant.public_key)?;
        validate_node_id(public.node_id)?;
        if peers.insert(public.node_id, public.public_key).is_some() {
            return Err(ThresholdError::DuplicateParticipant);
        }
    }
    Ok(peers)
}

pub(crate) fn dkg_config(session: &DkgSession) -> Result<DkgConfig, ThresholdError> {
    let params = read_dkg_session_params(session.session_id())?;
    Ok(DkgConfig {
        n: u32::try_from(session.participants().len())
            .map_err(|_| ThresholdError::MalformedMaterial)?,
        t: u32::from(session.threshold()),
        beta: params.beta,
        session_id: params.session_id,
    })
}

pub(crate) fn ensure_wrapped_context(
    wrapped: &WrappedKey,
    viewing_group_id: Word,
    identity: &[u8],
    associated_data: &[u8],
) -> Result<(), ThresholdError> {
    if wrapped.viewing_group_id != viewing_group_id {
        return Err(ThresholdError::ViewingGroupMismatch);
    }
    if wrapped.identity != identity {
        return Err(ThresholdError::IdentityMismatch);
    }
    if wrapped.associated_data_hash != Hasher::hash(associated_data) {
        return Err(ThresholdError::AssociatedDataMismatch);
    }
    Ok(())
}

pub(crate) fn effective_identity(identity: &[u8], associated_data_hash: Word) -> Vec<u8> {
    let mut bytes = Vec::new();
    EFFECTIVE_IDENTITY_DOMAIN.write_into(&mut bytes);
    identity.write_into(&mut bytes);
    associated_data_hash.write_into(&mut bytes);
    bytes
}

pub(crate) fn transport_public_from_secret(secret: &TransportSecretKey) -> TransportPublicKey {
    TransportPublicKey((G2Affine::generator() * secret.0).into_affine())
}

pub(crate) fn read_data_key_protection(
    data_key_protection: &DataKeyProtection,
) -> Result<WrappedKey, ThresholdError> {
    match data_key_protection {
        DataKeyProtection::ThresholdWrappedKey { scheme_id, wrapped_key } => {
            if *scheme_id != GOLDEN_THRESHOLD_SCHEME_ID {
                return Err(ThresholdError::UnsupportedScheme);
            }
            read_wrapped_key(wrapped_key)
        },
    }
}

pub(crate) fn write_dkg_session_params(session_id: SessionId, beta: Scalar) -> Vec<u8> {
    let mut target = Vec::new();
    write_header(&mut target, DKG_SESSION_PARAMS_DOMAIN);
    session_id.0.to_vec().write_into(&mut target);
    write_fr(&beta, &mut target);
    target
}

pub(crate) fn read_dkg_session_params(bytes: &[u8]) -> Result<DkgSessionParams, ThresholdError> {
    read_exact(bytes, |source| {
        read_header(source, DKG_SESSION_PARAMS_DOMAIN)?;
        Ok(DkgSessionParams {
            session_id: SessionId(read_fixed_32(source)?),
            beta: read_fr(source)?,
        })
    })
}

pub(crate) fn write_public_participant(
    node_id: NodeId,
    public_key: G1Affine,
    proof: &schnorr_pok::SchnorrPoK,
) -> Vec<u8> {
    let mut target = Vec::new();
    write_header(&mut target, PUBLIC_PARTICIPANT_DOMAIN);
    target.write_u32(node_id);
    write_g1(&public_key, &mut target);
    write_schnorr_pok(proof, &mut target);
    target
}

pub(crate) fn read_public_participant(bytes: &[u8]) -> Result<PublicParticipant, ThresholdError> {
    read_exact(bytes, |source| {
        read_header(source, PUBLIC_PARTICIPANT_DOMAIN)?;
        let node_id = source.read_u32().map_err(|_| ThresholdError::MalformedMaterial)?;
        validate_node_id(node_id)?;
        let public_key = read_g1(source)?;
        let proof = read_schnorr_pok(source)?;
        if !schnorr_pok::verify(public_key, &proof) {
            return Err(ThresholdError::VerificationFailed);
        }
        Ok(PublicParticipant { node_id, public_key })
    })
}

pub(crate) fn write_local_participant(participant: &Participant) -> Vec<u8> {
    let mut target = Vec::new();
    write_header(&mut target, LOCAL_PARTICIPANT_DOMAIN);
    target.write_u32(participant.id);
    write_fr(&participant.sk.inner(), &mut target);
    write_g1(&participant.pk, &mut target);
    write_schnorr_pok(&participant.pok, &mut target);
    target
}

pub(crate) fn read_local_participant(bytes: &[u8]) -> Result<Participant, ThresholdError> {
    read_exact(bytes, |source| {
        read_header(source, LOCAL_PARTICIPANT_DOMAIN)?;
        let id = source.read_u32().map_err(|_| ThresholdError::MalformedMaterial)?;
        validate_node_id(id)?;
        let sk = read_fr(source)?;
        let pk = read_g1(source)?;
        let pok = read_schnorr_pok(source)?;
        if (G1Affine::generator() * sk).into_affine() != pk || !schnorr_pok::verify(pk, &pok) {
            return Err(ThresholdError::VerificationFailed);
        }
        Ok(Participant { id, sk: SecretScalar::new(sk), pk, pok })
    })
}

pub(crate) fn write_round0(message: &Round0Msg) -> Vec<u8> {
    let mut target = Vec::new();
    write_header(&mut target, ROUND0_DOMAIN);
    write_message_header(&message.dkg_header, &mut target);
    write_node_map(&message.evrf_proofs, &mut target, write_evrf_proof);
    target.write_bool(message.batch_evrf_proof.is_some());
    if let Some(proof) = &message.batch_evrf_proof {
        write_evrf_proof(proof, &mut target);
    }
    target
}

pub(crate) fn read_round0(bytes: &[u8]) -> Result<Round0Msg, ThresholdError> {
    read_exact(bytes, |source| {
        read_header(source, ROUND0_DOMAIN)?;
        let dkg_header = read_message_header(source)?;
        let evrf_proofs = read_node_map(source, read_evrf_proof)?;
        let has_batch = source.read_bool().map_err(|_| ThresholdError::MalformedMaterial)?;
        let batch_evrf_proof = if has_batch {
            Some(read_evrf_proof(source)?)
        } else {
            None
        };
        Ok(Round0Msg {
            dkg_header,
            evrf_proofs,
            batch_evrf_proof,
        })
    })
}

pub(crate) fn write_dkg_dealing(dealing: &GoldenDkgDealing) -> Vec<u8> {
    let mut target = Vec::new();
    write_header(&mut target, DKG_DEALING_DOMAIN);
    write_round0(&dealing.message).write_into(&mut target);
    write_fr(&dealing.private_share, &mut target);
    write_g1_vec(&dealing.own_vss_commitment, &mut target);
    target
}

pub(crate) fn read_dkg_dealing(bytes: &[u8]) -> Result<GoldenDkgDealing, ThresholdError> {
    read_exact(bytes, |source| {
        read_header(source, DKG_DEALING_DOMAIN)?;
        let message_bytes: Vec<u8> = read(source)?;
        let message = read_round0(&message_bytes)?;
        let private_share = read_fr(source)?;
        let own_vss_commitment = read_g1_vec(source)?;
        Ok(GoldenDkgDealing {
            message,
            private_share,
            own_vss_commitment,
        })
    })
}

pub(crate) fn write_group_info(group_info: &GroupInfo) -> Vec<u8> {
    let mut target = Vec::new();
    write_header(&mut target, GROUP_INFO_DOMAIN);
    write_g1(&group_info.public_key, &mut target);
    target.write_u32(group_info.threshold);
    target.write_u32(group_info.num_nodes);
    target
}

pub(crate) fn read_group_info(bytes: &[u8]) -> Result<GroupInfo, ThresholdError> {
    read_exact(bytes, |source| {
        read_header(source, GROUP_INFO_DOMAIN)?;
        Ok(GroupInfo {
            public_key: read_g1(source)?,
            threshold: source.read_u32().map_err(|_| ThresholdError::MalformedMaterial)?,
            num_nodes: source.read_u32().map_err(|_| ThresholdError::MalformedMaterial)?,
        })
    })
}

pub(crate) fn write_key_share(key_share: &KeyShare) -> Vec<u8> {
    let mut target = Vec::new();
    write_header(&mut target, KEY_SHARE_DOMAIN);
    target.write_u32(key_share.id);
    write_fr(&key_share.secret, &mut target);
    write_group_info(&key_share.group_info).write_into(&mut target);
    target
}

pub(crate) fn read_key_share(bytes: &[u8]) -> Result<KeyShare, ThresholdError> {
    read_exact(bytes, |source| {
        read_header(source, KEY_SHARE_DOMAIN)?;
        let id = source.read_u32().map_err(|_| ThresholdError::MalformedMaterial)?;
        validate_node_id(id)?;
        let secret = read_fr(source)?;
        let group_info_bytes: Vec<u8> = read(source)?;
        let group_info = read_group_info(&group_info_bytes)?;
        Ok(KeyShare { id, secret, group_info })
    })
}

pub(crate) fn write_party_public_share(node_id: NodeId, public_key: G1Affine) -> Vec<u8> {
    let mut target = Vec::new();
    write_header(&mut target, PARTY_PUBLIC_SHARE_DOMAIN);
    target.write_u32(node_id);
    write_g1(&public_key, &mut target);
    target
}

pub(crate) fn read_party_public_share(bytes: &[u8]) -> Result<PartyPublicShare, ThresholdError> {
    read_exact(bytes, |source| {
        read_header(source, PARTY_PUBLIC_SHARE_DOMAIN)?;
        let node_id = source.read_u32().map_err(|_| ThresholdError::MalformedMaterial)?;
        validate_node_id(node_id)?;
        Ok(PartyPublicShare { node_id, public_key: read_g1(source)? })
    })
}

pub(crate) fn write_transport_public_key(public_key: &TransportPublicKey) -> Vec<u8> {
    let mut target = Vec::new();
    write_header(&mut target, TRANSPORT_PUBLIC_DOMAIN);
    write_g2(&public_key.0, &mut target);
    target
}

pub(crate) fn read_transport_public_key(
    bytes: &[u8],
) -> Result<TransportPublicKey, ThresholdError> {
    read_exact(bytes, |source| {
        read_header(source, TRANSPORT_PUBLIC_DOMAIN)?;
        Ok(TransportPublicKey(read_g2(source)?))
    })
}

pub(crate) fn write_transport_secret_key(secret_key: &TransportSecretKey) -> Vec<u8> {
    let mut target = Vec::new();
    write_header(&mut target, TRANSPORT_SECRET_DOMAIN);
    write_fr(&secret_key.0, &mut target);
    target
}

pub(crate) fn read_transport_secret_key(
    bytes: &[u8],
) -> Result<TransportSecretKey, ThresholdError> {
    read_exact(bytes, |source| {
        read_header(source, TRANSPORT_SECRET_DOMAIN)?;
        Ok(TransportSecretKey(read_fr(source)?))
    })
}

pub(crate) fn write_wrapped_key(wrapped: &WrappedKey) -> Vec<u8> {
    let mut target = Vec::new();
    write_header(&mut target, WRAPPED_KEY_DOMAIN);
    wrapped.viewing_group_id.write_into(&mut target);
    wrapped.identity.write_into(&mut target);
    wrapped.associated_data_hash.write_into(&mut target);
    write_group_info(&wrapped.group_info).write_into(&mut target);
    write_ibe_ciphertext(&wrapped.ciphertext, &mut target);
    target
}

pub(crate) fn read_wrapped_key(bytes: &[u8]) -> Result<WrappedKey, ThresholdError> {
    read_exact(bytes, |source| {
        read_header(source, WRAPPED_KEY_DOMAIN)?;
        Ok(WrappedKey {
            viewing_group_id: read(source)?,
            identity: read(source)?,
            associated_data_hash: read(source)?,
            group_info: {
                let bytes: Vec<u8> = read(source)?;
                read_group_info(&bytes)?
            },
            ciphertext: read_ibe_ciphertext(source)?,
        })
    })
}

pub(crate) fn write_response(response: &ResponseBytes) -> Vec<u8> {
    let mut target = Vec::new();
    write_header(&mut target, RESPONSE_DOMAIN);
    response.wrapped_key_digest.write_into(&mut target);
    response.associated_data_hash.write_into(&mut target);
    response.transport_key_digest.write_into(&mut target);
    write_encrypted_key_share(&response.encrypted_share, &mut target);
    target
}

pub(crate) fn read_response(bytes: &[u8]) -> Result<ResponseBytes, ThresholdError> {
    read_exact(bytes, |source| {
        read_header(source, RESPONSE_DOMAIN)?;
        Ok(ResponseBytes {
            wrapped_key_digest: read(source)?,
            associated_data_hash: read(source)?,
            transport_key_digest: read(source)?,
            encrypted_share: read_encrypted_key_share(source)?,
        })
    })
}

pub(crate) fn write_message_header<W: ByteWriter>(header: &MessageHeader, target: &mut W) {
    header.session_id.0.to_vec().write_into(target);
    target.write_u32(header.from);
    header.random_msg.to_vec().write_into(target);
    write_g1_vec(&header.vss_commitment, target);
    write_node_map(&header.ciphertexts, target, write_ciphertext);
}

pub(crate) fn read_message_header<R: ByteReader>(
    source: &mut R,
) -> Result<MessageHeader, ThresholdError> {
    let session_id = SessionId(read_fixed_32(source)?);
    let from = source.read_u32().map_err(|_| ThresholdError::MalformedMaterial)?;
    let random_msg = read_fixed_32(source)?;
    let vss_commitment = read_g1_vec(source)?;
    let ciphertexts = read_node_map(source, read_ciphertext)?;
    Ok(MessageHeader {
        session_id,
        from,
        random_msg,
        vss_commitment,
        ciphertexts,
    })
}

pub(crate) fn write_ciphertext<W: ByteWriter>(ciphertext: &Ciphertext, target: &mut W) {
    write_g1(&ciphertext.r_commitment, target);
    write_fr(&ciphertext.encrypted_share, target);
}

pub(crate) fn read_ciphertext<R: ByteReader>(source: &mut R) -> Result<Ciphertext, ThresholdError> {
    Ok(Ciphertext {
        r_commitment: read_g1(source)?,
        encrypted_share: read_fr(source)?,
    })
}

pub(crate) fn write_evrf_proof<W: ByteWriter>(
    proof: &golden_dkg::zk_evrf::EVRFProof,
    target: &mut W,
) {
    proof.proof_bytes.write_into(target);
    target.write_u64(usize_to_u64(proof.num_constraints));
    target.write_u64(usize_to_u64(proof.num_vars));
    target.write_u64(usize_to_u64(proof.num_inputs));
    target.write_bool(proof.is_batch);
}

pub(crate) fn read_evrf_proof<R: ByteReader>(
    source: &mut R,
) -> Result<golden_dkg::zk_evrf::EVRFProof, ThresholdError> {
    Ok(golden_dkg::zk_evrf::EVRFProof {
        proof_bytes: read(source)?,
        num_constraints: read_usize(source)?,
        num_vars: read_usize(source)?,
        num_inputs: read_usize(source)?,
        is_batch: source.read_bool().map_err(|_| ThresholdError::MalformedMaterial)?,
    })
}

pub(crate) fn write_schnorr_pok<W: ByteWriter>(proof: &schnorr_pok::SchnorrPoK, target: &mut W) {
    write_g1(&proof.commitment, target);
    write_fr(&proof.response, target);
}

pub(crate) fn read_schnorr_pok<R: ByteReader>(
    source: &mut R,
) -> Result<schnorr_pok::SchnorrPoK, ThresholdError> {
    Ok(schnorr_pok::SchnorrPoK {
        commitment: read_g1(source)?,
        response: read_fr(source)?,
    })
}

pub(crate) fn write_ibe_ciphertext<W: ByteWriter>(ciphertext: &IBECiphertext, target: &mut W) {
    write_g1(&ciphertext.u, target);
    ciphertext.v.write_into(target);
    ciphertext.w.write_into(target);
}

pub(crate) fn read_ibe_ciphertext<R: ByteReader>(
    source: &mut R,
) -> Result<IBECiphertext, ThresholdError> {
    Ok(IBECiphertext {
        u: read_g1(source)?,
        v: read(source)?,
        w: read(source)?,
    })
}

pub(crate) fn write_encrypted_key_share<W: ByteWriter>(share: &EncryptedKeyShare, target: &mut W) {
    target.write_u32(share.signer);
    write_g1(&share.c1, target);
    write_g2(&share.c2, target);
    write_g2(&share.c3, target);
}

pub(crate) fn read_encrypted_key_share<R: ByteReader>(
    source: &mut R,
) -> Result<EncryptedKeyShare, ThresholdError> {
    Ok(EncryptedKeyShare {
        signer: source.read_u32().map_err(|_| ThresholdError::MalformedMaterial)?,
        c1: read_g1(source)?,
        c2: read_g2(source)?,
        c3: read_g2(source)?,
    })
}

pub(crate) fn write_node_map<T, W, F>(map: &HashMap<NodeId, T>, target: &mut W, write_value: F)
where
    W: ByteWriter,
    F: Fn(&T, &mut W),
{
    target.write_u32(len_to_u32(map.len()));
    let mut entries = map.iter().collect::<Vec<_>>();
    entries.sort_by_key(|(node_id, _)| **node_id);
    for (node_id, value) in entries {
        target.write_u32(*node_id);
        write_value(value, target);
    }
}

pub(crate) fn read_node_map<T, R, F>(
    source: &mut R,
    read_value: F,
) -> Result<HashMap<NodeId, T>, ThresholdError>
where
    R: ByteReader,
    F: Fn(&mut R) -> Result<T, ThresholdError>,
{
    let len = source.read_u32().map_err(|_| ThresholdError::MalformedMaterial)?;
    let mut map = HashMap::new();
    for _ in 0..len {
        let node_id = source.read_u32().map_err(|_| ThresholdError::MalformedMaterial)?;
        let value = read_value(source)?;
        if map.insert(node_id, value).is_some() {
            return Err(ThresholdError::MalformedMaterial);
        }
    }
    Ok(map)
}

pub(crate) fn write_g1_vec<W: ByteWriter>(values: &[G1Affine], target: &mut W) {
    target.write_u32(len_to_u32(values.len()));
    for value in values {
        write_g1(value, target);
    }
}

pub(crate) fn read_g1_vec<R: ByteReader>(source: &mut R) -> Result<Vec<G1Affine>, ThresholdError> {
    let len = source.read_u32().map_err(|_| ThresholdError::MalformedMaterial)?;
    let mut values =
        Vec::with_capacity(usize::try_from(len).map_err(|_| ThresholdError::MalformedMaterial)?);
    for _ in 0..len {
        values.push(read_g1(source)?);
    }
    Ok(values)
}

pub(crate) fn write_header<W: ByteWriter>(target: &mut W, domain: &str) {
    domain.write_into(target);
    target.write_u16(GOLDEN_WIRE_VERSION);
}

pub(crate) fn read_header<R: ByteReader>(
    source: &mut R,
    expected_domain: &str,
) -> Result<(), ThresholdError> {
    let domain: String = read(source)?;
    let version = source.read_u16().map_err(|_| ThresholdError::MalformedMaterial)?;
    if domain == expected_domain && version == GOLDEN_WIRE_VERSION {
        Ok(())
    } else {
        Err(ThresholdError::MalformedMaterial)
    }
}

pub(crate) fn write_g1<W: ByteWriter>(value: &G1Affine, target: &mut W) {
    write_ark(value, target);
}

pub(crate) fn read_g1<R: ByteReader>(source: &mut R) -> Result<G1Affine, ThresholdError> {
    read_ark(source)
}

pub(crate) fn write_g2<W: ByteWriter>(value: &G2Affine, target: &mut W) {
    write_ark(value, target);
}

pub(crate) fn read_g2<R: ByteReader>(source: &mut R) -> Result<G2Affine, ThresholdError> {
    read_ark(source)
}

pub(crate) fn write_fr<W: ByteWriter>(value: &Fr, target: &mut W) {
    write_ark(value, target);
}

pub(crate) fn read_fr<R: ByteReader>(source: &mut R) -> Result<Fr, ThresholdError> {
    read_ark(source)
}

pub(crate) fn write_ark<T, W>(value: &T, target: &mut W)
where
    T: CanonicalSerialize,
    W: ByteWriter,
{
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .expect("arkworks canonical serialization should not fail for Vec");
    bytes.write_into(target);
}

pub(crate) fn read_ark<T, R>(source: &mut R) -> Result<T, ThresholdError>
where
    T: CanonicalDeserialize,
    R: ByteReader,
{
    let bytes: Vec<u8> = read(source)?;
    T::deserialize_compressed(bytes.as_slice()).map_err(|_| ThresholdError::MalformedMaterial)
}

pub(crate) fn read<T, R>(source: &mut R) -> Result<T, ThresholdError>
where
    T: Deserializable,
    R: ByteReader,
{
    source.read().map_err(|_| ThresholdError::MalformedMaterial)
}

pub(crate) fn read_usize<R: ByteReader>(source: &mut R) -> Result<usize, ThresholdError> {
    let value = source.read_u64().map_err(|_| ThresholdError::MalformedMaterial)?;
    usize::try_from(value).map_err(|_| ThresholdError::MalformedMaterial)
}

pub(crate) fn len_to_u32(len: usize) -> u32 {
    u32::try_from(len).expect("golden adapter wire collection length exceeds u32")
}

pub(crate) fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).expect("usize does not fit in u64")
}

pub(crate) fn read_fixed_32<R: ByteReader>(source: &mut R) -> Result<[u8; 32], ThresholdError> {
    let bytes: Vec<u8> = read(source)?;
    bytes.try_into().map_err(|_| ThresholdError::MalformedMaterial)
}

pub(crate) fn read_exact<T>(
    bytes: &[u8],
    read_value: impl FnOnce(&mut SliceReader<'_>) -> Result<T, ThresholdError>,
) -> Result<T, ThresholdError> {
    let mut source = SliceReader::new(bytes);
    let value = read_value(&mut source)?;
    if source.has_more_bytes() {
        return Err(ThresholdError::MalformedMaterial);
    }
    Ok(value)
}
