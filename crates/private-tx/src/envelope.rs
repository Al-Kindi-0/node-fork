use std::fmt;

use miden_protocol::Word;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::TransactionId;
use miden_protocol::utils::serde::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};

use crate::tee::AttestationEvidence;
use crate::types::{ChainId, EncryptionSchemeId, ThresholdSchemeId, ValidatorId, ViewingPartyId};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateValidatorDescriptor {
    pub version: u16,
    pub validator_id: ValidatorId,
    pub encryption_key_id: Word,
    pub encryption_public_key: Vec<u8>,
    pub attestation_evidence: AttestationEvidence,
    pub valid_from: BlockNumber,
    pub valid_until: BlockNumber,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedPrivateTxPayload {
    pub version: u16,
    pub validator_encryption_key_id: Word,
    pub scheme_id: EncryptionSchemeId,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateTxRecordMetadata {
    pub version: u16,
    pub chain_id: ChainId,
    pub tx_id: TransactionId,
    pub validator_id: ValidatorId,
    pub validator_encryption_key_id: Word,
    pub tee_attestation_id: Word,
    pub public_tx_hash: Word,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateTxRecord {
    pub version: u16,
    pub chain_id: ChainId,
    pub tx_id: TransactionId,
    pub validator_id: ValidatorId,
    pub validator_encryption_key_id: Word,
    pub tee_attestation_id: Word,
    pub public_tx_hash: Word,
    transaction_inputs: Vec<u8>,
}

impl PrivateTxRecord {
    pub fn new(metadata: PrivateTxRecordMetadata, transaction_inputs: Vec<u8>) -> Self {
        Self {
            version: metadata.version,
            chain_id: metadata.chain_id,
            tx_id: metadata.tx_id,
            validator_id: metadata.validator_id,
            validator_encryption_key_id: metadata.validator_encryption_key_id,
            tee_attestation_id: metadata.tee_attestation_id,
            public_tx_hash: metadata.public_tx_hash,
            transaction_inputs,
        }
    }

    pub fn transaction_inputs(&self) -> &[u8] {
        &self.transaction_inputs
    }
}

impl fmt::Debug for PrivateTxRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateTxRecord")
            .field("version", &self.version)
            .field("chain_id", &self.chain_id)
            .field("tx_id", &self.tx_id)
            .field("validator_id", &self.validator_id)
            .field("validator_encryption_key_id", &self.validator_encryption_key_id)
            .field("tee_attestation_id", &self.tee_attestation_id)
            .field("public_tx_hash", &self.public_tx_hash)
            .field("transaction_inputs_len", &self.transaction_inputs.len())
            .finish()
    }
}

// These outer fields intentionally duplicate encrypted record metadata so archive AD can be
// reconstructed before decryption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedPrivateTxRecord {
    pub version: u16,
    pub chain_id: ChainId,
    pub tx_id: TransactionId,
    pub viewing_group_id: Word,
    pub identity: Vec<u8>,
    pub validator_id: ValidatorId,
    pub validator_encryption_key_id: Word,
    pub tee_attestation_id: Word,
    pub record_ciphertext: Vec<u8>,
    pub data_key_protection: DataKeyProtection,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataKeyProtection {
    ThresholdWrappedKey {
        scheme_id: ThresholdSchemeId,
        wrapped_key: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewingPolicy {
    pub version: u16,
    pub viewing_group_id: Word,
    pub threshold: u16,
    pub parties: Vec<ViewingPartyId>,
    pub scheme_id: ThresholdSchemeId,
}

impl Serializable for PrivateValidatorDescriptor {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u16(self.version);
        self.validator_id.write_into(target);
        self.encryption_key_id.write_into(target);
        self.encryption_public_key.write_into(target);
        self.attestation_evidence.write_into(target);
        self.valid_from.write_into(target);
        self.valid_until.write_into(target);
    }
}

impl Deserializable for PrivateValidatorDescriptor {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            version: source.read()?,
            validator_id: source.read()?,
            encryption_key_id: source.read()?,
            encryption_public_key: source.read()?,
            attestation_evidence: source.read()?,
            valid_from: source.read()?,
            valid_until: source.read()?,
        })
    }
}

impl Serializable for EncryptedPrivateTxPayload {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u16(self.version);
        self.validator_encryption_key_id.write_into(target);
        self.scheme_id.write_into(target);
        self.ciphertext.write_into(target);
    }
}

impl Deserializable for EncryptedPrivateTxPayload {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            version: source.read()?,
            validator_encryption_key_id: source.read()?,
            scheme_id: source.read()?,
            ciphertext: source.read()?,
        })
    }
}

impl Serializable for PrivateTxRecord {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u16(self.version);
        self.chain_id.write_into(target);
        self.tx_id.write_into(target);
        self.validator_id.write_into(target);
        self.validator_encryption_key_id.write_into(target);
        self.tee_attestation_id.write_into(target);
        self.public_tx_hash.write_into(target);
        self.transaction_inputs.write_into(target);
    }
}

impl Deserializable for PrivateTxRecord {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            version: source.read()?,
            chain_id: source.read()?,
            tx_id: source.read()?,
            validator_id: source.read()?,
            validator_encryption_key_id: source.read()?,
            tee_attestation_id: source.read()?,
            public_tx_hash: source.read()?,
            transaction_inputs: source.read()?,
        })
    }
}

impl Serializable for EncryptedPrivateTxRecord {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u16(self.version);
        self.chain_id.write_into(target);
        self.tx_id.write_into(target);
        self.viewing_group_id.write_into(target);
        self.identity.write_into(target);
        self.validator_id.write_into(target);
        self.validator_encryption_key_id.write_into(target);
        self.tee_attestation_id.write_into(target);
        self.record_ciphertext.write_into(target);
        self.data_key_protection.write_into(target);
    }
}

impl Deserializable for EncryptedPrivateTxRecord {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            version: source.read()?,
            chain_id: source.read()?,
            tx_id: source.read()?,
            viewing_group_id: source.read()?,
            identity: source.read()?,
            validator_id: source.read()?,
            validator_encryption_key_id: source.read()?,
            tee_attestation_id: source.read()?,
            record_ciphertext: source.read()?,
            data_key_protection: source.read()?,
        })
    }
}

impl Serializable for DataKeyProtection {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            DataKeyProtection::ThresholdWrappedKey { scheme_id, wrapped_key } => {
                target.write_u8(0);
                scheme_id.write_into(target);
                wrapped_key.write_into(target);
            },
        }
    }
}

impl Deserializable for DataKeyProtection {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let tag = source.read::<u8>()?;
        match tag {
            0 => Ok(Self::ThresholdWrappedKey {
                scheme_id: source.read()?,
                wrapped_key: source.read()?,
            }),
            tag => Err(DeserializationError::InvalidValue(format!(
                "unknown data key protection tag {tag}"
            ))),
        }
    }
}

impl Serializable for ViewingPolicy {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u16(self.version);
        self.viewing_group_id.write_into(target);
        target.write_u16(self.threshold);
        self.parties.write_into(target);
        self.scheme_id.write_into(target);
    }
}

impl Deserializable for ViewingPolicy {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            version: source.read()?,
            viewing_group_id: source.read()?,
            threshold: source.read()?,
            parties: source.read()?,
            scheme_id: source.read()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::utils::serde::{Deserializable, Serializable};

    use super::*;
    use crate::mock::MOCK_THRESHOLD_SCHEME_ID;
    use crate::test_support::{tx_id, word};
    use crate::types::PRIVATE_TX_VERSION;

    #[test]
    fn encrypted_private_tx_record_roundtrips_through_miden_serialization() {
        let record = EncryptedPrivateTxRecord {
            version: PRIVATE_TX_VERSION,
            chain_id: ChainId::new("miden-devnet").unwrap(),
            tx_id: tx_id(10),
            viewing_group_id: word(20),
            identity: b"tx:10".to_vec(),
            validator_id: ValidatorId::new("validator-1").unwrap(),
            validator_encryption_key_id: word(30),
            tee_attestation_id: word(40),
            record_ciphertext: b"encrypted-record".to_vec(),
            data_key_protection: DataKeyProtection::ThresholdWrappedKey {
                scheme_id: MOCK_THRESHOLD_SCHEME_ID,
                wrapped_key: b"wrapped-record-key".to_vec(),
            },
        };

        let bytes = record.to_bytes();
        assert_eq!(EncryptedPrivateTxRecord::read_from_bytes(&bytes).unwrap(), record);
    }

    #[test]
    fn private_tx_record_roundtrips_full_transaction_inputs() {
        let record = PrivateTxRecord::new(
            PrivateTxRecordMetadata {
                version: PRIVATE_TX_VERSION,
                chain_id: ChainId::new("miden-devnet").unwrap(),
                tx_id: tx_id(10),
                validator_id: ValidatorId::new("validator-1").unwrap(),
                validator_encryption_key_id: word(20),
                tee_attestation_id: word(30),
                public_tx_hash: word(40),
            },
            b"serialized-transaction-inputs".to_vec(),
        );

        let bytes = record.to_bytes();
        assert_eq!(PrivateTxRecord::read_from_bytes(&bytes).unwrap(), record);
        assert_eq!(record.transaction_inputs(), b"serialized-transaction-inputs");

        let debug = format!("{record:?}");
        assert!(debug.contains("transaction_inputs_len"));
        assert!(!debug.contains("serialized-transaction-inputs"));
    }
}
