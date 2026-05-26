#![forbid(unsafe_code)]

//! golden-rs threshold adapter for private validator transaction records.

use std::collections::{BTreeSet, HashMap};

mod compat;
mod wire;
#[cfg(test)]
mod wire_tests;

use ark_bls12_381::G1Affine;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use compat::verify_dealing;
use golden_dkg::dkg;
use golden_dkg::threshold::ibe::{
    combine_encrypted_shares, decrypt_vetkey, encrypt_key_share, ibe_decrypt, ibe_encrypt,
    transport_keygen, verify_encrypted_key_share, verify_encrypted_vetkey,
};
use golden_dkg::threshold::types::{GroupInfo, KeyShare};
use golden_dkg::types::{NodeId, Participant, Scalar, SessionId};
use miden_node_private_tx::{
    AuditTransportPublicKey, AuditTransportSecret, DataKeyProtection, DecryptionResponse,
    DkgDealing, DkgLocalParticipant, DkgParticipant, DkgPrivateDealing, DkgPublicDealing,
    DkgSession, RecordKeyUnlockMaterial, ThresholdError, ThresholdRecordEncryptor,
    ThresholdSchemeId, ThresholdShareCombiner, ThresholdShareProducer, ThresholdShareVerifier,
    ViewingGroupPublicKey, ViewingGroupSetup, ViewingKeyShare, ViewingPartyId,
    ViewingPartyPublicShare,
};
use miden_protocol::utils::serde::Serializable;
use miden_protocol::{Hasher, Word};
use rand08::rngs::OsRng;
use wire::{
    ResponseBytes, WrappedKey, dkg_config, effective_identity,
    ensure_local_participant_matches_public, ensure_session_contains_participant,
    ensure_wrapped_context, peers_from_session, read_data_key_protection, read_dkg_dealing,
    read_group_info, read_key_share, read_local_participant, read_party_public_share,
    read_public_participant, read_response, read_round0, read_transport_public_key,
    read_transport_secret_key, session_participant_by_party_id, transport_public_from_secret,
    validate_node_id, write_dkg_dealing, write_dkg_session_params, write_group_info,
    write_key_share, write_local_participant, write_party_public_share, write_public_participant,
    write_response, write_round0, write_transport_public_key, write_transport_secret_key,
    write_wrapped_key,
};

const GOLDEN_THRESHOLD_SCHEME_RAW: u16 = 2;
const GOLDEN_WIRE_VERSION: u16 = 1;

/// Threshold scheme identifier used by the golden-rs adapter.
pub const GOLDEN_THRESHOLD_SCHEME_ID: ThresholdSchemeId =
    ThresholdSchemeId::new(GOLDEN_THRESHOLD_SCHEME_RAW);

/// Adapter implementing private-tx threshold traits with golden-rs DKG and vetKeys IBE.
#[derive(Clone, Copy, Debug, Default)]
pub struct GoldenThresholdAdapter;

impl GoldenThresholdAdapter {
    /// Creates a DKG session carrying golden-rs session material.
    ///
    /// The embedded golden-rs session id and `beta` parameter are sampled once and then shared by
    /// every party through the returned `DkgSession`.
    pub fn dkg_session(
        viewing_group_id: Word,
        threshold: u16,
        participants: Vec<DkgParticipant>,
    ) -> Result<DkgSession, ThresholdError> {
        let mut rng = OsRng;
        let session_id = SessionId::random(&mut rng);
        let beta = Scalar::rand(&mut rng);
        DkgSession::with_session_id(
            viewing_group_id,
            threshold,
            participants,
            write_dkg_session_params(session_id, beta),
        )
    }

    /// Generates a local DKG participant with a fresh golden-rs identity key and Schnorr PoK.
    pub fn generate_local_participant(
        party_id: ViewingPartyId,
        node_id: NodeId,
    ) -> Result<DkgLocalParticipant, ThresholdError> {
        validate_node_id(node_id)?;

        let mut rng = OsRng;
        let participant = Participant::new(node_id, &mut rng);
        let public = DkgParticipant {
            party_id,
            public_key: write_public_participant(node_id, participant.pk, &participant.pok),
        };
        let secret = write_local_participant(&participant);

        Ok(DkgLocalParticipant { public, secret })
    }

    /// Generates the auditor's ephemeral transport keypair for one audit request.
    pub fn audit_transport_keypair() -> (AuditTransportPublicKey, AuditTransportSecret) {
        let mut rng = OsRng;
        let (public, secret) = transport_keygen(&mut rng);
        (
            AuditTransportPublicKey {
                bytes: write_transport_public_key(&public),
            },
            AuditTransportSecret {
                bytes: write_transport_secret_key(&secret),
            },
        )
    }

    /// Extracts the group public key bytes from a completed golden-rs key share.
    pub fn viewing_group_public_key(
        key_share: &ViewingKeyShare,
    ) -> Result<ViewingGroupPublicKey, ThresholdError> {
        let share = read_key_share(&key_share.bytes)?;
        Ok(ViewingGroupPublicKey {
            viewing_group_id: key_share.viewing_group_id,
            bytes: write_group_info(&share.group_info),
        })
    }

    /// Derives the public verification share corresponding to a completed key share.
    pub fn viewing_party_public_share(
        key_share: &ViewingKeyShare,
    ) -> Result<ViewingPartyPublicShare, ThresholdError> {
        let share = read_key_share(&key_share.bytes)?;
        let public_share = (G1Affine::generator() * share.secret).into_affine();
        Ok(ViewingPartyPublicShare {
            viewing_group_id: key_share.viewing_group_id,
            party_id: key_share.party_id.clone(),
            bytes: write_party_public_share(share.id, public_share),
        })
    }
}

impl ViewingGroupSetup for GoldenThresholdAdapter {
    fn create_dkg_dealing(
        &self,
        session: &DkgSession,
        participant: &DkgLocalParticipant,
    ) -> Result<DkgDealing, ThresholdError> {
        let local = read_local_participant(&participant.secret)?;
        ensure_local_participant_matches_public(&local, participant)?;
        ensure_session_contains_participant(session, &participant.public)?;

        let peers = peers_from_session(session)?;
        let config = dkg_config(session)?;
        let mut rng = OsRng;
        let dealing = dkg::create_dealing(&local, &config, &peers, &mut rng)
            .map_err(|_| ThresholdError::VerificationFailed)?;

        DkgDealing::new(
            DkgPublicDealing {
                party_id: participant.public.party_id.clone(),
                bytes: write_round0(&dealing.message),
            },
            DkgPrivateDealing {
                party_id: participant.public.party_id.clone(),
                bytes: write_dkg_dealing(&dealing),
            },
        )
    }

    fn verify_dkg_dealing(
        &self,
        session: &DkgSession,
        dealing: &DkgPublicDealing,
    ) -> Result<(), ThresholdError> {
        let round0 = read_round0(&dealing.bytes)?;
        let sender = session_participant_by_party_id(session, &dealing.party_id)?;
        let sender_public = read_public_participant(&sender.public_key)?;
        if sender_public.node_id != round0.dkg_header.from {
            return Err(ThresholdError::VerificationFailed);
        }

        let peers = peers_from_session(session)?;
        let config = dkg_config(session)?;
        verify_dealing(&round0, &peers, &config)
    }

    fn complete_dkg(
        &self,
        session: &DkgSession,
        participant: &DkgLocalParticipant,
        own_dealing: &DkgPrivateDealing,
        peer_dealings: &[DkgPublicDealing],
    ) -> Result<ViewingKeyShare, ThresholdError> {
        let local = read_local_participant(&participant.secret)?;
        ensure_local_participant_matches_public(&local, participant)?;
        ensure_session_contains_participant(session, &participant.public)?;
        if own_dealing.party_id != participant.public.party_id {
            return Err(ThresholdError::VerificationFailed);
        }

        let peers = peers_from_session(session)?;
        let config = dkg_config(session)?;
        let own = read_dkg_dealing(&own_dealing.bytes)?;
        let mut received = HashMap::new();
        for dealing in peer_dealings {
            let round0 = read_round0(&dealing.bytes)?;
            let sender = session_participant_by_party_id(session, &dealing.party_id)?;
            let sender_public = read_public_participant(&sender.public_key)?;
            if sender_public.node_id != round0.dkg_header.from {
                return Err(ThresholdError::VerificationFailed);
            }
            if round0.dkg_header.from != local.id {
                verify_dealing(&round0, &peers, &config)?;
                if received.insert(round0.dkg_header.from, round0).is_some() {
                    return Err(ThresholdError::DuplicateParticipant);
                }
            }
        }
        if received.len() + 1 != session.participants().len() {
            return Err(ThresholdError::VerificationFailed);
        }

        let output = dkg::complete(&local, &own, &received, &peers, &config)
            .map_err(|_| ThresholdError::VerificationFailed)?;
        let group_info = GroupInfo {
            public_key: output.public_key,
            threshold: u32::from(session.threshold()),
            num_nodes: u32::try_from(session.participants().len())
                .map_err(|_| ThresholdError::MalformedMaterial)?,
        };
        let key_share = KeyShare {
            id: local.id,
            secret: output.secret_share,
            group_info,
        };

        Ok(ViewingKeyShare {
            viewing_group_id: session.viewing_group_id(),
            party_id: participant.public.party_id.clone(),
            bytes: write_key_share(&key_share),
        })
    }
}

impl ThresholdRecordEncryptor for GoldenThresholdAdapter {
    fn encrypt_record_key(
        &self,
        group_public_key: &ViewingGroupPublicKey,
        identity: &[u8],
        associated_data: &[u8],
        record_key: &[u8],
    ) -> Result<DataKeyProtection, ThresholdError> {
        let group_info = read_group_info(&group_public_key.bytes)?;
        let associated_data_hash = Hasher::hash(associated_data);
        let effective_identity = effective_identity(identity, associated_data_hash);
        let mut rng = OsRng;
        let ciphertext =
            ibe_encrypt(&group_info.public_key, &effective_identity, record_key, &mut rng);
        let wrapped = WrappedKey {
            viewing_group_id: group_public_key.viewing_group_id,
            identity: identity.to_vec(),
            associated_data_hash,
            group_info,
            ciphertext,
        };

        Ok(DataKeyProtection::ThresholdWrappedKey {
            scheme_id: GOLDEN_THRESHOLD_SCHEME_ID,
            wrapped_key: write_wrapped_key(&wrapped),
        })
    }
}

impl ThresholdShareProducer for GoldenThresholdAdapter {
    fn produce_decryption_response(
        &self,
        key_share: &ViewingKeyShare,
        identity: &[u8],
        associated_data: &[u8],
        request_transport_key: &AuditTransportPublicKey,
        data_key_protection: &DataKeyProtection,
    ) -> Result<DecryptionResponse, ThresholdError> {
        let wrapped = read_data_key_protection(data_key_protection)?;
        ensure_wrapped_context(&wrapped, key_share.viewing_group_id, identity, associated_data)?;

        let share = read_key_share(&key_share.bytes)?;
        if share.group_info.public_key != wrapped.group_info.public_key {
            return Err(ThresholdError::ViewingGroupMismatch);
        }

        let transport_public_key = read_transport_public_key(&request_transport_key.bytes)?;
        let mut rng = OsRng;
        let encrypted_share = encrypt_key_share(
            &share,
            &effective_identity(identity, wrapped.associated_data_hash),
            &transport_public_key,
            &mut rng,
        );
        let response = ResponseBytes {
            wrapped_key_digest: Hasher::hash(&data_key_protection.to_bytes()),
            associated_data_hash: wrapped.associated_data_hash,
            transport_key_digest: Hasher::hash(&request_transport_key.bytes),
            encrypted_share,
        };

        Ok(DecryptionResponse {
            viewing_group_id: key_share.viewing_group_id,
            party_id: key_share.party_id.clone(),
            identity: identity.to_vec(),
            bytes: write_response(&response),
        })
    }
}

impl ThresholdShareVerifier for GoldenThresholdAdapter {
    fn verify_decryption_response(
        &self,
        response: &DecryptionResponse,
        identity: &[u8],
        associated_data: &[u8],
        request_transport_key: &AuditTransportPublicKey,
        party_public_share: &ViewingPartyPublicShare,
    ) -> Result<(), ThresholdError> {
        if response.identity != identity {
            return Err(ThresholdError::IdentityMismatch);
        }
        if response.viewing_group_id != party_public_share.viewing_group_id
            || response.party_id != party_public_share.party_id
        {
            return Err(ThresholdError::ViewingGroupMismatch);
        }

        let response_bytes = read_response(&response.bytes)?;
        let associated_data_hash = Hasher::hash(associated_data);
        if response_bytes.associated_data_hash != associated_data_hash {
            return Err(ThresholdError::AssociatedDataMismatch);
        }
        if response_bytes.transport_key_digest != Hasher::hash(&request_transport_key.bytes) {
            return Err(ThresholdError::VerificationFailed);
        }

        let transport_public_key = read_transport_public_key(&request_transport_key.bytes)?;
        let public_share = read_party_public_share(&party_public_share.bytes)?;
        if public_share.node_id != response_bytes.encrypted_share.signer {
            return Err(ThresholdError::VerificationFailed);
        }
        if verify_encrypted_key_share(
            &response_bytes.encrypted_share,
            &effective_identity(identity, associated_data_hash),
            &transport_public_key,
            &public_share.public_key,
        ) {
            Ok(())
        } else {
            Err(ThresholdError::VerificationFailed)
        }
    }
}

impl ThresholdShareCombiner for GoldenThresholdAdapter {
    fn combine_responses(
        &self,
        data_key_protection: &DataKeyProtection,
        responses: &[DecryptionResponse],
        threshold: u16,
        identity: &[u8],
        associated_data: &[u8],
        request_transport_secret: &AuditTransportSecret,
    ) -> Result<RecordKeyUnlockMaterial, ThresholdError> {
        if threshold == 0 {
            return Err(ThresholdError::InvalidThreshold);
        }
        let wrapped = read_data_key_protection(data_key_protection)?;
        ensure_wrapped_context(&wrapped, wrapped.viewing_group_id, identity, associated_data)?;

        let transport_secret = read_transport_secret_key(&request_transport_secret.bytes)?;
        let transport_public_key = transport_public_from_secret(&transport_secret);
        let transport_public_bytes = write_transport_public_key(&transport_public_key);
        let transport_key_digest = Hasher::hash(&transport_public_bytes);
        let wrapped_key_digest = Hasher::hash(&data_key_protection.to_bytes());
        let mut parties = BTreeSet::new();
        let mut signers = BTreeSet::new();
        let mut encrypted_shares = Vec::new();

        for response in responses {
            if response.identity != identity {
                return Err(ThresholdError::IdentityMismatch);
            }
            if response.viewing_group_id != wrapped.viewing_group_id {
                return Err(ThresholdError::ViewingGroupMismatch);
            }
            parties.insert(response.party_id.clone());

            let response_bytes = read_response(&response.bytes)?;
            if response_bytes.wrapped_key_digest != wrapped_key_digest {
                return Err(ThresholdError::VerificationFailed);
            }
            if response_bytes.associated_data_hash != wrapped.associated_data_hash {
                return Err(ThresholdError::AssociatedDataMismatch);
            }
            if response_bytes.transport_key_digest != transport_key_digest {
                return Err(ThresholdError::VerificationFailed);
            }
            if !signers.insert(response_bytes.encrypted_share.signer) {
                return Err(ThresholdError::VerificationFailed);
            }
            encrypted_shares.push(response_bytes.encrypted_share);
        }

        if parties.len() < usize::from(threshold) || signers.len() < usize::from(threshold) {
            return Err(ThresholdError::InsufficientResponses);
        }

        let effective_identity = effective_identity(identity, wrapped.associated_data_hash);
        let encrypted_vetkey = combine_encrypted_shares(&encrypted_shares, usize::from(threshold));
        if !verify_encrypted_vetkey(
            &encrypted_vetkey,
            &effective_identity,
            &transport_public_key,
            &wrapped.group_info.public_key,
        ) {
            return Err(ThresholdError::VerificationFailed);
        }

        let vetkey = decrypt_vetkey(
            &encrypted_vetkey,
            &transport_secret,
            &effective_identity,
            &wrapped.group_info.public_key,
        )
        .ok_or(ThresholdError::VerificationFailed)?;
        let record_key =
            ibe_decrypt(&vetkey, &wrapped.ciphertext).ok_or(ThresholdError::VerificationFailed)?;

        Ok(RecordKeyUnlockMaterial { record_key })
    }
}
