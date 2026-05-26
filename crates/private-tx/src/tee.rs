use miden_protocol::Word;
use miden_protocol::utils::serde::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};

use crate::types::{TeeSchemeId, ValidatorId};

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum TeeError {
    #[error("TEE attestation verification failed")]
    VerificationFailed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationEvidence {
    pub tee_scheme_id: TeeSchemeId,
    pub evidence: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnclaveIdentity {
    pub tee_scheme_id: TeeSchemeId,
    pub validator_id: ValidatorId,
    pub measurement: Vec<u8>,
    pub attested_public_key_digest: Word,
}

pub trait TeeKeyProvider {
    fn encryption_public_key(&self) -> &[u8];

    fn encryption_key_id(&self) -> Word;
}

pub trait Attestor {
    fn attest(&self, public_key: &[u8]) -> Result<AttestationEvidence, TeeError>;
}

pub trait AttestationVerifier {
    fn verify(&self, evidence: &AttestationEvidence) -> Result<EnclaveIdentity, TeeError>;
}

impl Serializable for AttestationEvidence {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.tee_scheme_id.write_into(target);
        self.evidence.write_into(target);
    }
}

impl Deserializable for AttestationEvidence {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            tee_scheme_id: source.read()?,
            evidence: source.read()?,
        })
    }
}

impl Serializable for EnclaveIdentity {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.tee_scheme_id.write_into(target);
        self.validator_id.write_into(target);
        self.measurement.write_into(target);
        self.attested_public_key_digest.write_into(target);
    }
}

impl Deserializable for EnclaveIdentity {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            tee_scheme_id: source.read()?,
            validator_id: source.read()?,
            measurement: source.read()?,
            attested_public_key_digest: source.read()?,
        })
    }
}
