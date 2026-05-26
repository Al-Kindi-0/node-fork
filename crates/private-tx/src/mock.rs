//! Test adapters for private validator flows.
//!
//! They preserve binding checks and data flow, but provide no TEE attestation
//! or threshold security.

use std::collections::BTreeSet;

use miden_protocol::utils::serde::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, SliceReader,
};
use miden_protocol::{Hasher, Word};

use crate::envelope::{DataKeyProtection, ViewingPolicy};
use crate::tee::{
    AttestationEvidence, AttestationVerifier, EnclaveIdentity, TeeError, TeeKeyProvider,
};
use crate::threshold::{
    AuditTransportPublicKey, AuditTransportSecret, DecryptionResponse, DkgDealingBytes,
    DkgParticipant, DkgSession, RecordKeyUnlockMaterial, ThresholdError, ThresholdRecordEncryptor,
    ThresholdShareCombiner, ThresholdShareProducer, ThresholdShareVerifier, ViewingGroupPublicKey,
    ViewingGroupSetup, ViewingKeyShare, ViewingPartyPublicShare, validate_dkg_session,
    validate_threshold, validate_viewing_parties,
};
use crate::types::{TeeSchemeId, ThresholdSchemeId, ValidatorId};

const MOCK_TEE_SCHEME_RAW: u16 = u16::MAX;
const MOCK_THRESHOLD_SCHEME_RAW: u16 = u16::MAX - 1;
const MOCK_ATTESTED_PUBLIC_KEY_DIGEST_DOMAIN: &str =
    "miden:private-validator:mock:attested-public-key-digest:v1";
const MOCK_WRAPPED_KEY_DOMAIN: &str = "miden:private-validator:mock:wrapped-key:v1";
const MOCK_RESPONSE_DOMAIN: &str = "miden:private-validator:mock:response:v1";

pub const MOCK_TEE_SCHEME_ID: TeeSchemeId = TeeSchemeId::new(MOCK_TEE_SCHEME_RAW);
pub const MOCK_THRESHOLD_SCHEME_ID: ThresholdSchemeId =
    ThresholdSchemeId::new(MOCK_THRESHOLD_SCHEME_RAW);

/// Test helper acting as both attestor and verifier. Production splits those roles.
#[derive(Clone, Debug)]
pub struct MockTee {
    validator_id: ValidatorId,
    encryption_key_id: Word,
    encryption_public_key: Vec<u8>,
    measurement: Vec<u8>,
}

impl MockTee {
    pub fn new(
        validator_id: ValidatorId,
        encryption_key_id: Word,
        encryption_public_key: Vec<u8>,
        measurement: Vec<u8>,
    ) -> Self {
        Self {
            validator_id,
            encryption_key_id,
            encryption_public_key,
            measurement,
        }
    }
}

impl TeeKeyProvider for MockTee {
    fn encryption_public_key(&self) -> &[u8] {
        &self.encryption_public_key
    }

    fn encryption_key_id(&self) -> Word {
        self.encryption_key_id
    }
}

impl crate::tee::Attestor for MockTee {
    fn attest(&self, public_key: &[u8]) -> Result<AttestationEvidence, TeeError> {
        let mut evidence = Vec::new();
        self.validator_id.write_into(&mut evidence);
        self.measurement.write_into(&mut evidence);
        public_key.write_into(&mut evidence);

        Ok(AttestationEvidence {
            tee_scheme_id: MOCK_TEE_SCHEME_ID,
            evidence,
        })
    }
}

impl AttestationVerifier for MockTee {
    fn verify(&self, evidence: &AttestationEvidence) -> Result<EnclaveIdentity, TeeError> {
        if evidence.tee_scheme_id != MOCK_TEE_SCHEME_ID {
            return Err(TeeError::VerificationFailed);
        }

        let mut source = SliceReader::new(&evidence.evidence);
        let validator_id =
            ValidatorId::read_from(&mut source).map_err(|_| TeeError::VerificationFailed)?;
        let measurement =
            Vec::<u8>::read_from(&mut source).map_err(|_| TeeError::VerificationFailed)?;
        let public_key =
            Vec::<u8>::read_from(&mut source).map_err(|_| TeeError::VerificationFailed)?;
        if source.has_more_bytes() {
            return Err(TeeError::VerificationFailed);
        }

        Ok(EnclaveIdentity {
            tee_scheme_id: MOCK_TEE_SCHEME_ID,
            validator_id,
            measurement,
            attested_public_key_digest: mock_attested_public_key_digest(&public_key),
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MockThresholdAdapter;

impl MockThresholdAdapter {
    pub fn bootstrap_viewing_group(
        policy: &ViewingPolicy,
    ) -> Result<
        (ViewingGroupPublicKey, Vec<ViewingKeyShare>, Vec<ViewingPartyPublicShare>),
        ThresholdError,
    > {
        validate_viewing_parties(policy.threshold, &policy.parties)?;

        let group_public_key = ViewingGroupPublicKey {
            viewing_group_id: policy.viewing_group_id,
            bytes: prefixed_bytes(b"mock-viewing-group-pk", &policy.viewing_group_id.to_bytes()),
        };

        let key_shares = policy
            .parties
            .iter()
            .map(|party_id| ViewingKeyShare {
                viewing_group_id: policy.viewing_group_id,
                party_id: party_id.clone(),
                bytes: prefixed_bytes(b"mock-key-share", party_id.as_str().as_bytes()),
            })
            .collect();

        let public_shares = policy
            .parties
            .iter()
            .map(|party_id| ViewingPartyPublicShare {
                viewing_group_id: policy.viewing_group_id,
                party_id: party_id.clone(),
                bytes: prefixed_bytes(b"mock-public-share", party_id.as_str().as_bytes()),
            })
            .collect();

        Ok((group_public_key, key_shares, public_shares))
    }

    pub fn audit_transport_keypair(seed: &[u8]) -> (AuditTransportPublicKey, AuditTransportSecret) {
        let bytes = prefixed_bytes(b"mock-audit-transport", seed);
        (AuditTransportPublicKey { bytes: bytes.clone() }, AuditTransportSecret { bytes })
    }
}

impl ViewingGroupSetup for MockThresholdAdapter {
    fn create_dkg_dealing(
        &self,
        session: &DkgSession,
        participant: &DkgParticipant,
    ) -> Result<DkgDealingBytes, ThresholdError> {
        ensure_participant(session, participant)?;

        let mut bytes = Vec::new();
        session.viewing_group_id().write_into(&mut bytes);
        participant.party_id.write_into(&mut bytes);
        participant.public_key.write_into(&mut bytes);
        session.session_id().write_into(&mut bytes);

        Ok(DkgDealingBytes {
            party_id: participant.party_id.clone(),
            bytes,
        })
    }

    fn verify_dkg_dealing(
        &self,
        session: &DkgSession,
        dealing: &DkgDealingBytes,
    ) -> Result<(), ThresholdError> {
        validate_dkg_session(session)?;
        if !session
            .participants()
            .iter()
            .any(|participant| participant.party_id == dealing.party_id)
        {
            return Err(ThresholdError::VerificationFailed);
        }
        if dealing.bytes.is_empty() {
            return Err(ThresholdError::VerificationFailed);
        }
        Ok(())
    }

    fn complete_dkg(
        &self,
        session: &DkgSession,
        participant: &DkgParticipant,
        own_dealing: &DkgDealingBytes,
        peer_dealings: &[DkgDealingBytes],
    ) -> Result<ViewingKeyShare, ThresholdError> {
        ensure_participant(session, participant)?;
        self.verify_dkg_dealing(session, own_dealing)?;
        for dealing in peer_dealings {
            self.verify_dkg_dealing(session, dealing)?;
        }

        Ok(ViewingKeyShare {
            viewing_group_id: session.viewing_group_id(),
            party_id: participant.party_id.clone(),
            bytes: prefixed_bytes(
                b"mock-completed-dkg-share",
                participant.party_id.as_str().as_bytes(),
            ),
        })
    }
}

impl ThresholdRecordEncryptor for MockThresholdAdapter {
    fn encrypt_record_key(
        &self,
        group_public_key: &ViewingGroupPublicKey,
        identity: &[u8],
        associated_data: &[u8],
        record_key: &[u8],
    ) -> Result<DataKeyProtection, ThresholdError> {
        let wrapped = MockWrappedKey {
            viewing_group_id: group_public_key.viewing_group_id,
            identity: identity.to_vec(),
            associated_data: associated_data.to_vec(),
            record_key: record_key.to_vec(),
        };

        Ok(DataKeyProtection::ThresholdWrappedKey {
            scheme_id: MOCK_THRESHOLD_SCHEME_ID,
            wrapped_key: wrapped.to_bytes(),
        })
    }
}

impl ThresholdShareProducer for MockThresholdAdapter {
    fn produce_decryption_response(
        &self,
        key_share: &ViewingKeyShare,
        identity: &[u8],
        associated_data: &[u8],
        request_transport_key: &AuditTransportPublicKey,
        data_key_protection: &DataKeyProtection,
    ) -> Result<DecryptionResponse, ThresholdError> {
        let wrapped_key = extract_mock_wrapped_key(data_key_protection)?;
        if wrapped_key.viewing_group_id != key_share.viewing_group_id {
            return Err(ThresholdError::ViewingGroupMismatch);
        }
        if wrapped_key.identity != identity {
            return Err(ThresholdError::IdentityMismatch);
        }
        if wrapped_key.associated_data != associated_data {
            return Err(ThresholdError::AssociatedDataMismatch);
        }

        let response = MockResponseBytes {
            transport_key: request_transport_key.bytes.clone(),
            wrapped_key: data_key_protection.to_bytes(),
        };

        Ok(DecryptionResponse {
            viewing_group_id: key_share.viewing_group_id,
            party_id: key_share.party_id.clone(),
            identity: identity.to_vec(),
            bytes: response.to_bytes(),
        })
    }
}

impl ThresholdShareVerifier for MockThresholdAdapter {
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

        let response_bytes = read_mock_response_bytes(&response.bytes)?;
        if response_bytes.transport_key != request_transport_key.bytes {
            return Err(ThresholdError::VerificationFailed);
        }

        let wrapped_key = extract_mock_wrapped_key_from_bytes(&response_bytes.wrapped_key)?;
        if wrapped_key.identity != identity {
            return Err(ThresholdError::IdentityMismatch);
        }
        if wrapped_key.associated_data != associated_data {
            return Err(ThresholdError::AssociatedDataMismatch);
        }

        Ok(())
    }
}

impl ThresholdShareCombiner for MockThresholdAdapter {
    fn combine_responses(
        &self,
        responses: &[DecryptionResponse],
        threshold: u16,
        identity: &[u8],
        associated_data: &[u8],
        request_transport_secret: &AuditTransportSecret,
    ) -> Result<RecordKeyUnlockMaterial, ThresholdError> {
        validate_threshold(threshold)?;

        let distinct_parties = responses
            .iter()
            .map(|response| response.party_id.clone())
            .collect::<BTreeSet<_>>();
        if distinct_parties.len() < usize::from(threshold) {
            return Err(ThresholdError::InsufficientResponses);
        }

        let first = responses.first().ok_or(ThresholdError::InsufficientResponses)?;
        let response_bytes = read_mock_response_bytes(&first.bytes)?;
        if response_bytes.transport_key != request_transport_secret.bytes {
            return Err(ThresholdError::VerificationFailed);
        }

        let wrapped_key = extract_mock_wrapped_key_from_bytes(&response_bytes.wrapped_key)?;
        if wrapped_key.identity != identity {
            return Err(ThresholdError::IdentityMismatch);
        }
        if wrapped_key.associated_data != associated_data {
            return Err(ThresholdError::AssociatedDataMismatch);
        }

        Ok(RecordKeyUnlockMaterial { record_key: wrapped_key.record_key })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MockWrappedKey {
    viewing_group_id: Word,
    identity: Vec<u8>,
    associated_data: Vec<u8>,
    record_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MockResponseBytes {
    transport_key: Vec<u8>,
    wrapped_key: Vec<u8>,
}

impl Serializable for MockWrappedKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        MOCK_WRAPPED_KEY_DOMAIN.write_into(target);
        self.viewing_group_id.write_into(target);
        self.identity.write_into(target);
        self.associated_data.write_into(target);
        self.record_key.write_into(target);
    }
}

impl Deserializable for MockWrappedKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let domain = String::read_from(source)?;
        if domain != MOCK_WRAPPED_KEY_DOMAIN {
            return Err(DeserializationError::InvalidValue(
                "invalid mock wrapped key domain".to_string(),
            ));
        }

        Ok(Self {
            viewing_group_id: source.read()?,
            identity: source.read()?,
            associated_data: source.read()?,
            record_key: source.read()?,
        })
    }
}

impl Serializable for MockResponseBytes {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        MOCK_RESPONSE_DOMAIN.write_into(target);
        self.transport_key.write_into(target);
        self.wrapped_key.write_into(target);
    }
}

impl Deserializable for MockResponseBytes {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let domain = String::read_from(source)?;
        if domain != MOCK_RESPONSE_DOMAIN {
            return Err(DeserializationError::InvalidValue(
                "invalid mock response domain".to_string(),
            ));
        }

        Ok(Self {
            transport_key: source.read()?,
            wrapped_key: source.read()?,
        })
    }
}

fn extract_mock_wrapped_key(
    data_key_protection: &DataKeyProtection,
) -> Result<MockWrappedKey, ThresholdError> {
    match data_key_protection {
        DataKeyProtection::ThresholdWrappedKey { scheme_id, wrapped_key } => {
            decode_mock_wrapped_key(*scheme_id, wrapped_key)
        },
    }
}

fn extract_mock_wrapped_key_from_bytes(bytes: &[u8]) -> Result<MockWrappedKey, ThresholdError> {
    extract_mock_wrapped_key(&read_exact(bytes)?)
}

fn decode_mock_wrapped_key(
    scheme_id: ThresholdSchemeId,
    wrapped_key: &[u8],
) -> Result<MockWrappedKey, ThresholdError> {
    if scheme_id != MOCK_THRESHOLD_SCHEME_ID {
        return Err(ThresholdError::UnsupportedScheme);
    }

    read_exact(wrapped_key)
}

fn read_mock_response_bytes(bytes: &[u8]) -> Result<MockResponseBytes, ThresholdError> {
    read_exact(bytes)
}

fn read_exact<T: Deserializable>(bytes: &[u8]) -> Result<T, ThresholdError> {
    let mut source = SliceReader::new(bytes);
    let value = T::read_from(&mut source).map_err(|_| ThresholdError::MalformedMaterial)?;
    if source.has_more_bytes() {
        return Err(ThresholdError::MalformedMaterial);
    }

    Ok(value)
}

fn ensure_participant(
    session: &DkgSession,
    participant: &DkgParticipant,
) -> Result<(), ThresholdError> {
    validate_dkg_session(session)?;
    if session
        .participants()
        .iter()
        .any(|candidate| candidate.party_id == participant.party_id)
    {
        Ok(())
    } else {
        Err(ThresholdError::VerificationFailed)
    }
}

fn prefixed_bytes(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(prefix.len() + suffix.len());
    bytes.extend_from_slice(prefix);
    bytes.extend_from_slice(suffix);
    bytes
}

fn mock_attested_public_key_digest(public_key: &[u8]) -> Word {
    let mut bytes = Vec::new();
    MOCK_ATTESTED_PUBLIC_KEY_DIGEST_DOMAIN.write_into(&mut bytes);
    public_key.write_into(&mut bytes);
    Hasher::hash(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee::{AttestationVerifier, Attestor, TeeKeyProvider};
    use crate::test_support::word;
    use crate::threshold::{
        ThresholdRecordEncryptor, ThresholdShareCombiner, ThresholdShareProducer,
        ThresholdShareVerifier,
    };
    use crate::types::PRIVATE_TX_VERSION;

    fn viewing_policy() -> ViewingPolicy {
        ViewingPolicy {
            version: PRIVATE_TX_VERSION,
            viewing_group_id: word(100),
            threshold: 2,
            parties: vec![
                crate::types::ViewingPartyId::new("party-1").unwrap(),
                crate::types::ViewingPartyId::new("party-2").unwrap(),
                crate::types::ViewingPartyId::new("party-3").unwrap(),
            ],
            scheme_id: MOCK_THRESHOLD_SCHEME_ID,
        }
    }

    #[test]
    fn mock_tee_attests_and_verifies_identity() {
        let validator_id = ValidatorId::new("validator-1").unwrap();
        let tee = MockTee::new(
            validator_id.clone(),
            word(20),
            b"validator-encryption-public-key".to_vec(),
            b"mock-measurement".to_vec(),
        );

        let evidence = tee.attest(tee.encryption_public_key()).unwrap();
        let identity = tee.verify(&evidence).unwrap();

        assert_eq!(identity.tee_scheme_id, MOCK_TEE_SCHEME_ID);
        assert_eq!(identity.validator_id, validator_id);
        assert_eq!(identity.measurement, b"mock-measurement");
        assert_eq!(
            identity.attested_public_key_digest,
            mock_attested_public_key_digest(tee.encryption_public_key())
        );
        assert_eq!(tee.encryption_key_id(), word(20));
    }

    #[test]
    fn mock_viewing_group_rejects_invalid_threshold_policy() {
        let mut policy = viewing_policy();
        policy.threshold = 4;
        assert_eq!(
            MockThresholdAdapter::bootstrap_viewing_group(&policy).unwrap_err(),
            ThresholdError::ThresholdExceedsParticipantCount
        );

        let mut policy = viewing_policy();
        policy.parties.push(policy.parties[0].clone());
        assert_eq!(
            MockThresholdAdapter::bootstrap_viewing_group(&policy).unwrap_err(),
            ThresholdError::DuplicateParticipant
        );
    }

    #[test]
    fn mock_threshold_unlocks_record_key_through_audit_transport() {
        let policy = viewing_policy();
        let (group_public_key, key_shares, public_shares) =
            MockThresholdAdapter::bootstrap_viewing_group(&policy).unwrap();
        let adapter = MockThresholdAdapter;
        let identity = b"tx:100";
        let associated_data = b"archive-ad";
        let record_key = b"private-record-key";
        let protection = adapter
            .encrypt_record_key(&group_public_key, identity, associated_data, record_key)
            .unwrap();
        let (transport_public_key, transport_secret) =
            MockThresholdAdapter::audit_transport_keypair(b"audit-request-1");

        let responses = key_shares
            .iter()
            .take(2)
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

        let unlock = adapter
            .combine_responses(
                &responses,
                policy.threshold,
                identity,
                associated_data,
                &transport_secret,
            )
            .unwrap();
        assert_eq!(unlock.record_key, record_key);

        let one_response = &responses[..1];
        assert_eq!(
            adapter
                .combine_responses(
                    one_response,
                    policy.threshold,
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
                    &responses,
                    policy.threshold,
                    identity,
                    b"different-ad",
                    &transport_secret,
                )
                .unwrap_err(),
            ThresholdError::AssociatedDataMismatch
        );
    }
}
