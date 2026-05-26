use std::{collections::BTreeSet, fmt};

use miden_protocol::utils::serde::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
use miden_protocol::{Hasher, Word};

use crate::envelope::DataKeyProtection;
use crate::types::ViewingPartyId;

const DKG_SESSION_DOMAIN: &str = "miden:private-validator:dkg-session:v1";

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum ThresholdError {
    #[error("threshold must be greater than zero")]
    InvalidThreshold,
    #[error("threshold exceeds participant count")]
    ThresholdExceedsParticipantCount,
    #[error("viewing group contains a duplicate participant")]
    DuplicateParticipant,
    #[error("not enough threshold responses")]
    InsufficientResponses,
    #[error("threshold response verification failed")]
    VerificationFailed,
    #[error("threshold material is malformed")]
    MalformedMaterial,
    #[error("threshold material does not match the requested identity")]
    IdentityMismatch,
    #[error("threshold material does not match the requested associated data")]
    AssociatedDataMismatch,
    #[error("threshold material does not match the viewing group")]
    ViewingGroupMismatch,
    #[error("unsupported threshold scheme")]
    UnsupportedScheme,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DkgParticipant {
    pub party_id: ViewingPartyId,
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DkgSession {
    viewing_group_id: Word,
    threshold: u16,
    participants: Vec<DkgParticipant>,
    session_id: Vec<u8>,
}

impl DkgSession {
    pub fn new(
        viewing_group_id: Word,
        threshold: u16,
        participants: Vec<DkgParticipant>,
    ) -> Result<Self, ThresholdError> {
        validate_dkg_session_parts(threshold, &participants)?;

        let session_id = deterministic_dkg_session_id(viewing_group_id, threshold, &participants);

        Ok(Self {
            viewing_group_id,
            threshold,
            participants,
            session_id,
        })
    }

    pub fn viewing_group_id(&self) -> Word {
        self.viewing_group_id
    }

    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    pub fn participants(&self) -> &[DkgParticipant] {
        &self.participants
    }

    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DkgDealingBytes {
    pub party_id: ViewingPartyId,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewingGroupPublicKey {
    pub viewing_group_id: Word,
    pub bytes: Vec<u8>,
}

// TODO(productionization): zeroize secret-bearing threshold material.
#[derive(Clone, PartialEq, Eq)]
pub struct ViewingKeyShare {
    pub viewing_group_id: Word,
    pub party_id: ViewingPartyId,
    pub bytes: Vec<u8>,
}

impl fmt::Debug for ViewingKeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ViewingKeyShare")
            .field("viewing_group_id", &self.viewing_group_id)
            .field("party_id", &self.party_id)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewingPartyPublicShare {
    pub viewing_group_id: Word,
    pub party_id: ViewingPartyId,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditTransportPublicKey {
    pub bytes: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AuditTransportSecret {
    pub bytes: Vec<u8>,
}

impl fmt::Debug for AuditTransportSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditTransportSecret").field("bytes", &"<redacted>").finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptionResponse {
    pub viewing_group_id: Word,
    pub party_id: ViewingPartyId,
    pub identity: Vec<u8>,
    pub bytes: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct RecordKeyUnlockMaterial {
    pub record_key: Vec<u8>,
}

impl fmt::Debug for RecordKeyUnlockMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordKeyUnlockMaterial")
            .field("record_key", &"<redacted>")
            .finish()
    }
}

pub trait ViewingGroupSetup {
    fn create_dkg_dealing(
        &self,
        session: &DkgSession,
        participant: &DkgParticipant,
    ) -> Result<DkgDealingBytes, ThresholdError>;

    fn verify_dkg_dealing(
        &self,
        session: &DkgSession,
        dealing: &DkgDealingBytes,
    ) -> Result<(), ThresholdError>;

    fn complete_dkg(
        &self,
        session: &DkgSession,
        participant: &DkgParticipant,
        own_dealing: &DkgDealingBytes,
        peer_dealings: &[DkgDealingBytes],
    ) -> Result<ViewingKeyShare, ThresholdError>;
}

pub trait ThresholdRecordEncryptor {
    fn encrypt_record_key(
        &self,
        group_public_key: &ViewingGroupPublicKey,
        identity: &[u8],
        associated_data: &[u8],
        record_key: &[u8],
    ) -> Result<DataKeyProtection, ThresholdError>;
}

pub trait ThresholdShareProducer {
    fn produce_decryption_response(
        &self,
        key_share: &ViewingKeyShare,
        identity: &[u8],
        associated_data: &[u8],
        request_transport_key: &AuditTransportPublicKey,
        data_key_protection: &DataKeyProtection,
    ) -> Result<DecryptionResponse, ThresholdError>;
}

pub trait ThresholdShareVerifier {
    fn verify_decryption_response(
        &self,
        response: &DecryptionResponse,
        identity: &[u8],
        associated_data: &[u8],
        request_transport_key: &AuditTransportPublicKey,
        party_public_share: &ViewingPartyPublicShare,
    ) -> Result<(), ThresholdError>;
}

pub trait ThresholdShareCombiner {
    fn combine_responses(
        &self,
        responses: &[DecryptionResponse],
        threshold: u16,
        identity: &[u8],
        associated_data: &[u8],
        request_transport_secret: &AuditTransportSecret,
    ) -> Result<RecordKeyUnlockMaterial, ThresholdError>;
}

/// Full threshold adapter surface used by private transaction archive/audit flows.
///
/// `ViewingGroupSetup` is included for real-backend DKG setup even when a test uses prebuilt
/// mock group material.
pub trait ThresholdBackend:
    ViewingGroupSetup
    + ThresholdRecordEncryptor
    + ThresholdShareProducer
    + ThresholdShareVerifier
    + ThresholdShareCombiner
{
}

impl<T> ThresholdBackend for T where
    T: ViewingGroupSetup
        + ThresholdRecordEncryptor
        + ThresholdShareProducer
        + ThresholdShareVerifier
        + ThresholdShareCombiner
{
}

pub(crate) fn validate_threshold(threshold: u16) -> Result<(), ThresholdError> {
    if threshold == 0 {
        Err(ThresholdError::InvalidThreshold)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_threshold_count(threshold: u16, count: usize) -> Result<(), ThresholdError> {
    validate_threshold(threshold)?;
    if usize::from(threshold) > count {
        Err(ThresholdError::ThresholdExceedsParticipantCount)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_viewing_parties(
    threshold: u16,
    parties: &[ViewingPartyId],
) -> Result<(), ThresholdError> {
    validate_threshold_count(threshold, parties.len())?;

    let mut seen = BTreeSet::new();
    for party in parties {
        if !seen.insert(party) {
            return Err(ThresholdError::DuplicateParticipant);
        }
    }

    Ok(())
}

pub(crate) fn validate_dkg_session(session: &DkgSession) -> Result<(), ThresholdError> {
    validate_dkg_session_parts(session.threshold, &session.participants)
}

fn validate_dkg_session_parts(
    threshold: u16,
    participants: &[DkgParticipant],
) -> Result<(), ThresholdError> {
    validate_threshold_count(threshold, participants.len())?;

    let mut seen = BTreeSet::new();
    for participant in participants {
        if !seen.insert(participant.party_id.clone()) {
            return Err(ThresholdError::DuplicateParticipant);
        }
    }

    Ok(())
}

fn deterministic_dkg_session_id(
    viewing_group_id: Word,
    threshold: u16,
    participants: &[DkgParticipant],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    DKG_SESSION_DOMAIN.write_into(&mut bytes);
    viewing_group_id.write_into(&mut bytes);
    bytes.write_u16(threshold);
    participants.write_into(&mut bytes);
    Hasher::hash(&bytes).to_bytes()
}

impl Serializable for DkgParticipant {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.party_id.write_into(target);
        self.public_key.write_into(target);
    }
}

impl Deserializable for DkgParticipant {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            party_id: source.read()?,
            public_key: source.read()?,
        })
    }
}

impl Serializable for DkgSession {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.viewing_group_id.write_into(target);
        target.write_u16(self.threshold);
        self.participants.write_into(target);
        self.session_id.write_into(target);
    }
}

impl Deserializable for DkgSession {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let viewing_group_id: Word = source.read()?;
        let threshold: u16 = source.read()?;
        let participants: Vec<DkgParticipant> = source.read()?;
        let session_id: Vec<u8> = source.read()?;

        validate_dkg_session_parts(threshold, &participants)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;

        let expected_session_id =
            deterministic_dkg_session_id(viewing_group_id, threshold, &participants);
        if session_id != expected_session_id {
            return Err(DeserializationError::InvalidValue("invalid DKG session id".to_string()));
        }

        Ok(Self {
            viewing_group_id,
            threshold,
            participants,
            session_id,
        })
    }
}

impl Serializable for DkgDealingBytes {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.party_id.write_into(target);
        self.bytes.write_into(target);
    }
}

impl Deserializable for DkgDealingBytes {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            party_id: source.read()?,
            bytes: source.read()?,
        })
    }
}

impl Serializable for ViewingGroupPublicKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.viewing_group_id.write_into(target);
        self.bytes.write_into(target);
    }
}

impl Deserializable for ViewingGroupPublicKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            viewing_group_id: source.read()?,
            bytes: source.read()?,
        })
    }
}

impl Serializable for ViewingKeyShare {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.viewing_group_id.write_into(target);
        self.party_id.write_into(target);
        self.bytes.write_into(target);
    }
}

impl Deserializable for ViewingKeyShare {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            viewing_group_id: source.read()?,
            party_id: source.read()?,
            bytes: source.read()?,
        })
    }
}

impl Serializable for ViewingPartyPublicShare {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.viewing_group_id.write_into(target);
        self.party_id.write_into(target);
        self.bytes.write_into(target);
    }
}

impl Deserializable for ViewingPartyPublicShare {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            viewing_group_id: source.read()?,
            party_id: source.read()?,
            bytes: source.read()?,
        })
    }
}

impl Serializable for AuditTransportPublicKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.bytes.write_into(target);
    }
}

impl Deserializable for AuditTransportPublicKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self { bytes: source.read()? })
    }
}

impl Serializable for AuditTransportSecret {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.bytes.write_into(target);
    }
}

impl Deserializable for AuditTransportSecret {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self { bytes: source.read()? })
    }
}

impl Serializable for DecryptionResponse {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.viewing_group_id.write_into(target);
        self.party_id.write_into(target);
        self.identity.write_into(target);
        self.bytes.write_into(target);
    }
}

impl Deserializable for DecryptionResponse {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            viewing_group_id: source.read()?,
            party_id: source.read()?,
            identity: source.read()?,
            bytes: source.read()?,
        })
    }
}

impl Serializable for RecordKeyUnlockMaterial {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.record_key.write_into(target);
    }
}

impl Deserializable for RecordKeyUnlockMaterial {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self { record_key: source.read()? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::word;

    fn participant(id: &str) -> DkgParticipant {
        DkgParticipant {
            party_id: ViewingPartyId::new(id).unwrap(),
            public_key: format!("{id}-public-key").into_bytes(),
        }
    }

    #[test]
    fn dkg_session_constructor_is_deterministic() {
        let participants = vec![participant("party-1"), participant("party-2")];

        let first = DkgSession::new(word(1), 2, participants.clone()).unwrap();
        let second = DkgSession::new(word(1), 2, participants).unwrap();

        assert_eq!(first.session_id(), second.session_id());
    }

    #[test]
    fn dkg_session_rejects_invalid_participant_sets() {
        assert_eq!(
            DkgSession::new(word(1), 0, vec![participant("party-1")]).unwrap_err(),
            ThresholdError::InvalidThreshold
        );
        assert_eq!(
            DkgSession::new(word(1), 2, vec![participant("party-1")]).unwrap_err(),
            ThresholdError::ThresholdExceedsParticipantCount
        );
        assert_eq!(
            DkgSession::new(word(1), 1, vec![participant("party-1"), participant("party-1")])
                .unwrap_err(),
            ThresholdError::DuplicateParticipant
        );
    }

    #[test]
    fn dkg_session_deserialization_rejects_invalid_session_id() {
        let participants = vec![participant("party-1"), participant("party-2")];
        let session = DkgSession::new(word(1), 2, participants).unwrap();
        let mut bytes = session.to_bytes();
        let last = bytes.last_mut().unwrap();
        *last ^= 1;

        assert!(matches!(
            DkgSession::read_from_bytes(&bytes),
            Err(DeserializationError::InvalidValue(_))
        ));
    }

    #[test]
    fn secret_threshold_material_has_redacted_debug() {
        let share = ViewingKeyShare {
            viewing_group_id: word(1),
            party_id: ViewingPartyId::new("party-1").unwrap(),
            bytes: b"secret-share".to_vec(),
        };
        let transport_secret = AuditTransportSecret { bytes: b"transport-secret".to_vec() };
        let unlock = RecordKeyUnlockMaterial { record_key: b"record-key".to_vec() };

        assert!(!format!("{share:?}").contains("secret-share"));
        assert!(!format!("{transport_secret:?}").contains("transport-secret"));
        assert!(!format!("{unlock:?}").contains("record-key"));
    }
}
