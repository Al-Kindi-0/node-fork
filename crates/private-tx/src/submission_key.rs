use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_protocol::crypto::ies::{IesScheme, SealingKey};
use miden_protocol::utils::serde::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
use miden_protocol::{Hasher, Word};

use crate::envelope::PrivateValidatorDescriptor;
use crate::types::{ChainId, PRIVATE_TX_VERSION, ValidatorId};

const SUBMISSION_KEY_DOMAIN: &str = "miden:private-tx:submission-key:v1";

/// Validator-signed descriptor for the public key clients use to encrypt private submissions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedSubmissionKey {
    /// Public submission-key descriptor and validity window.
    pub descriptor: PrivateValidatorDescriptor,
    /// Signature over [`submission_key_commitment`] using the validator identity key.
    pub signature: Signature,
}

/// Reasons a client rejects a signed submission-key descriptor.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SubmissionKeyVerificationError {
    #[error("unsupported submission key descriptor version {0}")]
    UnsupportedVersion(u16),
    #[error("submission key descriptor chain id mismatch")]
    ChainIdMismatch,
    #[error("submission key descriptor validator id mismatch")]
    ValidatorIdMismatch,
    #[error("submission key descriptor validity range is invalid")]
    InvalidValidityRange,
    #[error("submission key descriptor is not yet valid")]
    NotYetValid,
    #[error("submission key descriptor has expired")]
    Expired,
    #[error("submission key descriptor signature is invalid")]
    InvalidSignature,
    #[error("submission key descriptor public key is malformed")]
    MalformedEncryptionPublicKey,
    #[error("submission key descriptor encryption scheme is unsupported")]
    UnsupportedEncryptionScheme,
    #[error("submission key descriptor key id does not match its public key")]
    EncryptionKeyIdMismatch,
}

impl SignedSubmissionKey {
    /// Creates a signed descriptor from a descriptor and its validator signature.
    pub fn new(descriptor: PrivateValidatorDescriptor, signature: Signature) -> Self {
        Self { descriptor, signature }
    }
}

/// Computes the key id from the serialized submission public key.
pub fn submission_key_id(sealing_key: &SealingKey) -> Word {
    Hasher::hash(&sealing_key.to_bytes())
}

/// Computes the domain-separated commitment signed by the validator identity key.
pub fn submission_key_commitment(descriptor: &PrivateValidatorDescriptor) -> Word {
    let mut target = Vec::new();
    SUBMISSION_KEY_DOMAIN.write_into(&mut target);
    descriptor.write_into(&mut target);
    Hasher::hash(&target)
}

/// Verifies a signed submission-key descriptor for the expected validator context.
///
/// The returned descriptor is valid for `current_block`, bound to the expected chain and validator,
/// signed by `validator_public_key`, and internally consistent: the public key bytes are parseable,
/// use the supported submission-encryption scheme, and hash to the advertised key id.
pub fn verify_signed_submission_key<'a>(
    signed_key: &'a SignedSubmissionKey,
    expected_chain_id: &ChainId,
    expected_validator_id: &ValidatorId,
    current_block: BlockNumber,
    validator_public_key: &PublicKey,
) -> Result<&'a PrivateValidatorDescriptor, SubmissionKeyVerificationError> {
    let descriptor = &signed_key.descriptor;

    if descriptor.version != PRIVATE_TX_VERSION {
        return Err(SubmissionKeyVerificationError::UnsupportedVersion(descriptor.version));
    }
    if &descriptor.chain_id != expected_chain_id {
        return Err(SubmissionKeyVerificationError::ChainIdMismatch);
    }
    if &descriptor.validator_id != expected_validator_id {
        return Err(SubmissionKeyVerificationError::ValidatorIdMismatch);
    }
    if descriptor.valid_from > descriptor.valid_until {
        return Err(SubmissionKeyVerificationError::InvalidValidityRange);
    }
    if current_block < descriptor.valid_from {
        return Err(SubmissionKeyVerificationError::NotYetValid);
    }
    if current_block > descriptor.valid_until {
        return Err(SubmissionKeyVerificationError::Expired);
    }

    let commitment = submission_key_commitment(descriptor);
    if !signed_key.signature.verify(commitment, validator_public_key) {
        return Err(SubmissionKeyVerificationError::InvalidSignature);
    }

    let sealing_key = SealingKey::read_from_bytes(&descriptor.encryption_public_key)
        .map_err(|_| SubmissionKeyVerificationError::MalformedEncryptionPublicKey)?;
    if sealing_key.scheme() != IesScheme::X25519XChaCha20Poly1305 {
        return Err(SubmissionKeyVerificationError::UnsupportedEncryptionScheme);
    }
    if submission_key_id(&sealing_key) != descriptor.encryption_key_id {
        return Err(SubmissionKeyVerificationError::EncryptionKeyIdMismatch);
    }

    Ok(descriptor)
}

impl Serializable for SignedSubmissionKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.descriptor.write_into(target);
        self.signature.write_into(target);
    }
}

impl Deserializable for SignedSubmissionKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            descriptor: source.read()?,
            signature: source.read()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee::AttestationEvidence;
    use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SecretKey;
    use miden_protocol::crypto::dsa::eddsa_25519_sha512::SecretKey as X25519SecretKey;
    use miden_protocol::utils::serde::{Deserializable, Serializable};

    #[test]
    fn signed_submission_key_roundtrips() {
        let key = signed_key();
        let bytes = key.to_bytes();

        assert_eq!(SignedSubmissionKey::read_from_bytes(&bytes).unwrap(), key);
    }

    #[test]
    fn signed_submission_key_verifies() {
        let secret_key = SecretKey::new();
        let descriptor = descriptor();
        let signature = secret_key.sign(submission_key_commitment(&descriptor));
        let signed_key = SignedSubmissionKey::new(descriptor.clone(), signature);

        let verified = verify_signed_submission_key(
            &signed_key,
            &descriptor.chain_id,
            &descriptor.validator_id,
            BlockNumber::from(20),
            &secret_key.public_key(),
        )
        .unwrap();

        assert_eq!(verified, &descriptor);
    }

    #[test]
    fn signed_submission_key_rejects_bad_signature() {
        let signing_key = SecretKey::new();
        let other_key = SecretKey::new();
        let descriptor = descriptor();
        let signed_key = SignedSubmissionKey::new(
            descriptor.clone(),
            signing_key.sign(submission_key_commitment(&descriptor)),
        );

        let err = verify_signed_submission_key(
            &signed_key,
            &descriptor.chain_id,
            &descriptor.validator_id,
            BlockNumber::from(20),
            &other_key.public_key(),
        )
        .unwrap_err();

        assert_eq!(err, SubmissionKeyVerificationError::InvalidSignature);
    }

    #[test]
    fn signed_submission_key_rejects_malformed_public_key() {
        let key = signing_key();
        let mut descriptor = descriptor();
        descriptor.encryption_public_key = b"not-a-sealing-key".to_vec();
        let signed_key = SignedSubmissionKey::new(
            descriptor.clone(),
            key.sign(submission_key_commitment(&descriptor)),
        );

        let err = verify_signed_submission_key(
            &signed_key,
            &descriptor.chain_id,
            &descriptor.validator_id,
            BlockNumber::from(20),
            &key.public_key(),
        )
        .unwrap_err();

        assert_eq!(err, SubmissionKeyVerificationError::MalformedEncryptionPublicKey);
    }

    #[test]
    fn signed_submission_key_rejects_unsupported_public_key_scheme() {
        let key = signing_key();
        let mut descriptor = descriptor();
        let sealing_key = SealingKey::K256XChaCha20Poly1305(key.public_key());
        descriptor.encryption_key_id = submission_key_id(&sealing_key);
        descriptor.encryption_public_key = sealing_key.to_bytes();
        let signed_key = SignedSubmissionKey::new(
            descriptor.clone(),
            key.sign(submission_key_commitment(&descriptor)),
        );

        let err = verify_signed_submission_key(
            &signed_key,
            &descriptor.chain_id,
            &descriptor.validator_id,
            BlockNumber::from(20),
            &key.public_key(),
        )
        .unwrap_err();

        assert_eq!(err, SubmissionKeyVerificationError::UnsupportedEncryptionScheme);
    }

    #[test]
    fn signed_submission_key_rejects_key_id_mismatch() {
        let key = signing_key();
        let mut descriptor = descriptor();
        descriptor.encryption_key_id = Word::empty();
        let signed_key = SignedSubmissionKey::new(
            descriptor.clone(),
            key.sign(submission_key_commitment(&descriptor)),
        );

        let err = verify_signed_submission_key(
            &signed_key,
            &descriptor.chain_id,
            &descriptor.validator_id,
            BlockNumber::from(20),
            &key.public_key(),
        )
        .unwrap_err();

        assert_eq!(err, SubmissionKeyVerificationError::EncryptionKeyIdMismatch);
    }

    #[test]
    fn signed_submission_key_rejects_wrong_context() {
        let signed_key = signed_key();

        let err = verify_signed_submission_key(
            &signed_key,
            &ChainId::new("other-chain").unwrap(),
            &signed_key.descriptor.validator_id,
            BlockNumber::from(20),
            &signing_key().public_key(),
        )
        .unwrap_err();
        assert_eq!(err, SubmissionKeyVerificationError::ChainIdMismatch);

        let err = verify_signed_submission_key(
            &signed_key,
            &signed_key.descriptor.chain_id,
            &ValidatorId::new("other-validator").unwrap(),
            BlockNumber::from(20),
            &signing_key().public_key(),
        )
        .unwrap_err();
        assert_eq!(err, SubmissionKeyVerificationError::ValidatorIdMismatch);
    }

    #[test]
    fn signed_submission_key_rejects_invalid_validity_window() {
        let signed_key = signed_key();

        let err = verify_signed_submission_key(
            &signed_key,
            &signed_key.descriptor.chain_id,
            &signed_key.descriptor.validator_id,
            BlockNumber::from(9),
            &signing_key().public_key(),
        )
        .unwrap_err();
        assert_eq!(err, SubmissionKeyVerificationError::NotYetValid);

        let err = verify_signed_submission_key(
            &signed_key,
            &signed_key.descriptor.chain_id,
            &signed_key.descriptor.validator_id,
            BlockNumber::from(31),
            &signing_key().public_key(),
        )
        .unwrap_err();
        assert_eq!(err, SubmissionKeyVerificationError::Expired);

        let key = signing_key();
        let mut descriptor = descriptor();
        descriptor.valid_from = BlockNumber::from(31);
        let signed_key = SignedSubmissionKey::new(
            descriptor.clone(),
            key.sign(submission_key_commitment(&descriptor)),
        );
        let err = verify_signed_submission_key(
            &signed_key,
            &signed_key.descriptor.chain_id,
            &signed_key.descriptor.validator_id,
            BlockNumber::from(31),
            &key.public_key(),
        )
        .unwrap_err();
        assert_eq!(err, SubmissionKeyVerificationError::InvalidValidityRange);
    }

    fn signed_key() -> SignedSubmissionKey {
        let key = signing_key();
        let descriptor = descriptor();
        let signature = key.sign(submission_key_commitment(&descriptor));
        SignedSubmissionKey::new(descriptor, signature)
    }

    fn signing_key() -> SecretKey {
        SecretKey::read_from_bytes(&[
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ])
        .unwrap()
    }

    fn descriptor() -> PrivateValidatorDescriptor {
        let submission_key =
            SealingKey::X25519XChaCha20Poly1305(X25519SecretKey::new().public_key());

        PrivateValidatorDescriptor {
            version: PRIVATE_TX_VERSION,
            chain_id: ChainId::new("miden-devnet").unwrap(),
            validator_id: ValidatorId::new("validator-1").unwrap(),
            encryption_key_id: submission_key_id(&submission_key),
            encryption_public_key: submission_key.to_bytes(),
            attestation_evidence: AttestationEvidence::none(),
            valid_from: BlockNumber::from(10),
            valid_until: BlockNumber::from(30),
        }
    }
}
