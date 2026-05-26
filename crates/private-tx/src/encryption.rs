use std::fmt;

use miden_crypto::aead::xchacha::{EncryptedData, SecretKey as XChaChaSecretKey};
use miden_protocol::Word;
use miden_protocol::crypto::ies::{IesScheme, SealedMessage, SealingKey, UnsealingKey};
use miden_protocol::utils::serde::{Deserializable, Serializable};

use crate::envelope::EncryptedPrivateTxPayload;
use crate::types::{EncryptionSchemeId, PRIVATE_TX_VERSION};

const X25519_XCHACHA20_POLY1305_SCHEME_RAW: u16 = IesScheme::X25519XChaCha20Poly1305 as u16;

const SUBMISSION_ENCRYPTION_SCHEME_ID: EncryptionSchemeId =
    EncryptionSchemeId::new(X25519_XCHACHA20_POLY1305_SCHEME_RAW);
const ARCHIVE_RECORD_KEY_BYTES: usize = 32;

pub struct ArchiveRecordKey(XChaChaSecretKey);

impl ArchiveRecordKey {
    pub fn generate() -> Self {
        Self(XChaChaSecretKey::new())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PrivateTxEncryptionError> {
        if bytes.len() != ARCHIVE_RECORD_KEY_BYTES {
            return Err(PrivateTxEncryptionError::MalformedKey);
        }

        XChaChaSecretKey::read_from_bytes_with_budget(bytes, ARCHIVE_RECORD_KEY_BYTES)
            .map(Self)
            .map_err(|_| PrivateTxEncryptionError::MalformedKey)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

impl fmt::Debug for ArchiveRecordKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ArchiveRecordKey(..)")
    }
}

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateTxEncryptionError {
    #[error("unsupported private transaction encryption scheme")]
    UnsupportedScheme,
    #[error("private transaction encryption failed")]
    EncryptionFailed,
    #[error("private transaction decryption failed")]
    DecryptionFailed,
    #[error("private transaction ciphertext is malformed")]
    MalformedCiphertext,
    #[error("private transaction key material is malformed")]
    MalformedKey,
}

pub fn encrypt_submission_payload(
    sealing_key: &SealingKey,
    validator_encryption_key_id: Word,
    plaintext_transaction_inputs: &[u8],
    associated_data: &[u8],
) -> Result<EncryptedPrivateTxPayload, PrivateTxEncryptionError> {
    if sealing_key.scheme() != IesScheme::X25519XChaCha20Poly1305 {
        return Err(PrivateTxEncryptionError::UnsupportedScheme);
    }

    let mut rng = rand::rng();
    let sealed = sealing_key
        .seal_bytes_with_associated_data(&mut rng, plaintext_transaction_inputs, associated_data)
        .map_err(|_| PrivateTxEncryptionError::EncryptionFailed)?;

    Ok(EncryptedPrivateTxPayload {
        version: PRIVATE_TX_VERSION,
        validator_encryption_key_id,
        scheme_id: SUBMISSION_ENCRYPTION_SCHEME_ID,
        ciphertext: sealed.to_bytes(),
    })
}

pub fn decrypt_submission_payload(
    unsealing_key: &UnsealingKey,
    payload: &EncryptedPrivateTxPayload,
    associated_data: &[u8],
) -> Result<Vec<u8>, PrivateTxEncryptionError> {
    if payload.scheme_id != SUBMISSION_ENCRYPTION_SCHEME_ID
        || unsealing_key.scheme() != IesScheme::X25519XChaCha20Poly1305
    {
        return Err(PrivateTxEncryptionError::UnsupportedScheme);
    }

    let sealed =
        SealedMessage::read_from_bytes_with_budget(&payload.ciphertext, payload.ciphertext.len())
            .map_err(|_| PrivateTxEncryptionError::MalformedCiphertext)?;

    unsealing_key
        .unseal_bytes_with_associated_data(sealed, associated_data)
        .map_err(|_| PrivateTxEncryptionError::DecryptionFailed)
}

pub fn seal_private_tx_record(
    record_key: &ArchiveRecordKey,
    plaintext_record: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, PrivateTxEncryptionError> {
    record_key
        .0
        .encrypt_bytes_with_associated_data(plaintext_record, associated_data)
        .map(|encrypted| encrypted.to_bytes())
        .map_err(|_| PrivateTxEncryptionError::EncryptionFailed)
}

pub fn open_private_tx_record(
    record_key: &ArchiveRecordKey,
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, PrivateTxEncryptionError> {
    let encrypted = EncryptedData::read_from_bytes_with_budget(ciphertext, ciphertext.len())
        .map_err(|_| PrivateTxEncryptionError::MalformedCiphertext)?;

    record_key
        .0
        .decrypt_bytes_with_associated_data(&encrypted, associated_data)
        .map_err(|_| PrivateTxEncryptionError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use miden_protocol::crypto::{
        dsa::eddsa_25519_sha512::SecretKey,
        ies::{SealingKey, UnsealingKey},
    };

    use super::*;
    use crate::test_support::word;

    #[test]
    fn submission_payload_uses_real_ies_and_binds_associated_data() {
        let mut rng = rand::rng();
        let secret_key = SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);
        let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_key);
        let associated_data = b"submission-associated-data";
        let plaintext = b"serialized-transaction-inputs";

        let payload =
            encrypt_submission_payload(&sealing_key, word(20), plaintext, associated_data).unwrap();

        assert_eq!(payload.version, PRIVATE_TX_VERSION);
        assert_eq!(payload.validator_encryption_key_id, word(20));
        assert_eq!(payload.scheme_id, SUBMISSION_ENCRYPTION_SCHEME_ID);
        assert_eq!(
            decrypt_submission_payload(&unsealing_key, &payload, associated_data).unwrap(),
            plaintext
        );
        assert_eq!(
            decrypt_submission_payload(&unsealing_key, &payload, b"different-ad").unwrap_err(),
            PrivateTxEncryptionError::DecryptionFailed
        );
    }

    #[test]
    fn archive_record_uses_real_aead_and_binds_associated_data() {
        let key = ArchiveRecordKey::generate();
        assert_eq!(format!("{key:?}"), "ArchiveRecordKey(..)");
        let key_bytes = key.to_bytes();
        let restored_key = ArchiveRecordKey::from_bytes(&key_bytes).unwrap();
        let associated_data = b"archive-associated-data";
        let plaintext = b"serialized-private-tx-record";

        let sealed = seal_private_tx_record(&restored_key, plaintext, associated_data).unwrap();

        assert_eq!(
            open_private_tx_record(&restored_key, &sealed, associated_data).unwrap(),
            plaintext
        );
        assert_eq!(
            open_private_tx_record(&restored_key, &sealed, b"different-ad").unwrap_err(),
            PrivateTxEncryptionError::DecryptionFailed
        );
    }
}
