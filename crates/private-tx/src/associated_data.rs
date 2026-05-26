use miden_protocol::Word;
use miden_protocol::transaction::TransactionId;
use miden_protocol::utils::serde::{ByteWriter, Serializable};

use crate::envelope::{EncryptedPrivateTxPayload, EncryptedPrivateTxRecord};
use crate::types::{ChainId, PRIVATE_TX_VERSION, ValidatorId};

const SUBMISSION_AD_DOMAIN: &str = "miden:private-validator:submission:v1";
const ARCHIVE_AD_DOMAIN: &str = "miden:private-validator:archive:v1";
const PRIVATE_TX_RECORD_IDENTITY_DOMAIN: &str = "miden:private-tx-record:v1";

#[derive(Clone, Copy, Debug)]
struct SubmissionAssociatedData<'a> {
    pub chain_id: &'a ChainId,
    pub tx_id: TransactionId,
    pub validator_id: &'a ValidatorId,
    pub validator_encryption_key_id: Word,
    pub payload_version: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct SubmissionEncryptionAssociatedData<'a> {
    pub chain_id: &'a ChainId,
    pub tx_id: TransactionId,
    pub validator_id: &'a ValidatorId,
    pub validator_encryption_key_id: Word,
}

#[derive(Clone, Copy, Debug)]
pub struct SubmissionPayloadAssociatedData<'a> {
    pub chain_id: &'a ChainId,
    pub tx_id: TransactionId,
    pub validator_id: &'a ValidatorId,
    pub payload: &'a EncryptedPrivateTxPayload,
}

#[derive(Clone, Copy, Debug)]
pub struct ArchiveAssociatedData<'a> {
    pub chain_id: &'a ChainId,
    pub tx_id: TransactionId,
    pub viewing_group_id: Word,
    pub identity: &'a [u8],
    pub validator_id: &'a ValidatorId,
    pub validator_encryption_key_id: Word,
    pub tee_attestation_id: Word,
}

#[derive(Clone, Copy, Debug)]
pub struct ArchiveRecordAssociatedData<'a> {
    pub record: &'a EncryptedPrivateTxRecord,
}

fn submission_associated_data(input: SubmissionAssociatedData<'_>) -> Vec<u8> {
    let mut target = Vec::new();
    SUBMISSION_AD_DOMAIN.write_into(&mut target);
    input.chain_id.write_into(&mut target);
    input.tx_id.write_into(&mut target);
    input.validator_id.write_into(&mut target);
    input.validator_encryption_key_id.write_into(&mut target);
    target.write_u16(input.payload_version);
    target
}

pub fn submission_associated_data_for_encryption(
    input: SubmissionEncryptionAssociatedData<'_>,
) -> Vec<u8> {
    submission_associated_data(SubmissionAssociatedData {
        chain_id: input.chain_id,
        tx_id: input.tx_id,
        validator_id: input.validator_id,
        validator_encryption_key_id: input.validator_encryption_key_id,
        payload_version: PRIVATE_TX_VERSION,
    })
}

pub fn submission_associated_data_for_payload(
    input: SubmissionPayloadAssociatedData<'_>,
) -> Vec<u8> {
    submission_associated_data(SubmissionAssociatedData {
        chain_id: input.chain_id,
        tx_id: input.tx_id,
        validator_id: input.validator_id,
        validator_encryption_key_id: input.payload.validator_encryption_key_id,
        payload_version: input.payload.version,
    })
}

pub fn archive_associated_data(input: ArchiveAssociatedData<'_>) -> Vec<u8> {
    let mut target = Vec::new();
    ARCHIVE_AD_DOMAIN.write_into(&mut target);
    input.chain_id.write_into(&mut target);
    input.tx_id.write_into(&mut target);
    input.viewing_group_id.write_into(&mut target);
    input.identity.write_into(&mut target);
    input.validator_id.write_into(&mut target);
    input.validator_encryption_key_id.write_into(&mut target);
    input.tee_attestation_id.write_into(&mut target);
    target
}

pub fn archive_associated_data_for_record(input: ArchiveRecordAssociatedData<'_>) -> Vec<u8> {
    archive_associated_data(ArchiveAssociatedData {
        chain_id: &input.record.chain_id,
        tx_id: input.record.tx_id,
        viewing_group_id: input.record.viewing_group_id,
        identity: &input.record.identity,
        validator_id: &input.record.validator_id,
        validator_encryption_key_id: input.record.validator_encryption_key_id,
        tee_attestation_id: input.record.tee_attestation_id,
    })
}

pub fn private_tx_record_identity(chain_id: &ChainId, tx_id: TransactionId) -> Vec<u8> {
    format!("{PRIVATE_TX_RECORD_IDENTITY_DOMAIN}:{chain_id}:{tx_id}").into_bytes()
}

#[cfg(test)]
mod tests {
    use miden_protocol::Hasher;

    use super::*;
    use crate::test_support::{tx_id, word};
    use crate::types::EncryptionSchemeId;

    #[test]
    fn submission_ad_binds_public_transaction_metadata() {
        let chain_id = ChainId::new("miden-devnet").unwrap();
        let validator_id = ValidatorId::new("validator-1").unwrap();

        let original = Hasher::hash(&submission_associated_data_for_encryption(
            SubmissionEncryptionAssociatedData {
                chain_id: &chain_id,
                tx_id: tx_id(10),
                validator_id: &validator_id,
                validator_encryption_key_id: word(20),
            },
        ));

        let changed_tx = Hasher::hash(&submission_associated_data_for_encryption(
            SubmissionEncryptionAssociatedData {
                chain_id: &chain_id,
                tx_id: tx_id(11),
                validator_id: &validator_id,
                validator_encryption_key_id: word(20),
            },
        ));

        let changed_key = Hasher::hash(&submission_associated_data_for_encryption(
            SubmissionEncryptionAssociatedData {
                chain_id: &chain_id,
                tx_id: tx_id(10),
                validator_id: &validator_id,
                validator_encryption_key_id: word(21),
            },
        ));

        assert_ne!(original, changed_tx);
        assert_ne!(original, changed_key);
    }

    #[test]
    fn submission_ad_uses_private_tx_version_for_encryption() {
        let chain_id = ChainId::new("miden-devnet").unwrap();
        let validator_id = ValidatorId::new("validator-1").unwrap();

        assert_eq!(
            submission_associated_data_for_encryption(SubmissionEncryptionAssociatedData {
                chain_id: &chain_id,
                tx_id: tx_id(10),
                validator_id: &validator_id,
                validator_encryption_key_id: word(20),
            }),
            submission_associated_data(SubmissionAssociatedData {
                chain_id: &chain_id,
                tx_id: tx_id(10),
                validator_id: &validator_id,
                validator_encryption_key_id: word(20),
                payload_version: PRIVATE_TX_VERSION,
            })
        );
    }

    #[test]
    fn submission_ad_can_be_constructed_from_payload_envelope() {
        let chain_id = ChainId::new("miden-devnet").unwrap();
        let validator_id = ValidatorId::new("validator-1").unwrap();
        let payload = EncryptedPrivateTxPayload {
            version: PRIVATE_TX_VERSION,
            validator_encryption_key_id: word(20),
            scheme_id: EncryptionSchemeId::new(7),
            ciphertext: b"ciphertext".to_vec(),
        };

        assert_eq!(
            submission_associated_data_for_payload(SubmissionPayloadAssociatedData {
                chain_id: &chain_id,
                tx_id: tx_id(10),
                validator_id: &validator_id,
                payload: &payload,
            }),
            submission_associated_data_for_encryption(SubmissionEncryptionAssociatedData {
                chain_id: &chain_id,
                tx_id: tx_id(10),
                validator_id: &validator_id,
                validator_encryption_key_id: payload.validator_encryption_key_id,
            })
        );
    }

    #[test]
    fn archive_ad_binds_identity_and_viewing_group() {
        let chain_id = ChainId::new("miden-devnet").unwrap();
        let validator_id = ValidatorId::new("validator-1").unwrap();

        let original = Hasher::hash(&archive_associated_data(ArchiveAssociatedData {
            chain_id: &chain_id,
            tx_id: tx_id(10),
            viewing_group_id: word(30),
            identity: b"tx:10",
            validator_id: &validator_id,
            validator_encryption_key_id: word(20),
            tee_attestation_id: word(40),
        }));

        let changed_identity = Hasher::hash(&archive_associated_data(ArchiveAssociatedData {
            chain_id: &chain_id,
            tx_id: tx_id(10),
            viewing_group_id: word(30),
            identity: b"tx:11",
            validator_id: &validator_id,
            validator_encryption_key_id: word(20),
            tee_attestation_id: word(40),
        }));

        let changed_group = Hasher::hash(&archive_associated_data(ArchiveAssociatedData {
            chain_id: &chain_id,
            tx_id: tx_id(10),
            viewing_group_id: word(31),
            identity: b"tx:10",
            validator_id: &validator_id,
            validator_encryption_key_id: word(20),
            tee_attestation_id: word(40),
        }));

        assert_ne!(original, changed_identity);
        assert_ne!(original, changed_group);
    }

    #[test]
    fn archive_ad_can_be_constructed_from_public_record_envelope() {
        let chain_id = ChainId::new("miden-devnet").unwrap();
        let validator_id = ValidatorId::new("validator-1").unwrap();
        let record = EncryptedPrivateTxRecord {
            version: PRIVATE_TX_VERSION,
            chain_id: chain_id.clone(),
            tx_id: tx_id(10),
            viewing_group_id: word(30),
            identity: b"tx:10".to_vec(),
            validator_id: validator_id.clone(),
            validator_encryption_key_id: word(20),
            tee_attestation_id: word(40),
            record_ciphertext: b"encrypted-record".to_vec(),
            data_key_protection: crate::envelope::DataKeyProtection::ThresholdWrappedKey {
                scheme_id: crate::mock::MOCK_THRESHOLD_SCHEME_ID,
                wrapped_key: b"wrapped-record-key".to_vec(),
            },
        };

        assert_eq!(
            archive_associated_data_for_record(ArchiveRecordAssociatedData { record: &record }),
            archive_associated_data(ArchiveAssociatedData {
                chain_id: &chain_id,
                tx_id: tx_id(10),
                viewing_group_id: word(30),
                identity: b"tx:10",
                validator_id: &validator_id,
                validator_encryption_key_id: word(20),
                tee_attestation_id: word(40),
            })
        );
    }

    #[test]
    fn private_tx_record_identity_is_canonical() {
        let chain_id = ChainId::new("miden-devnet").unwrap();
        let tx_id = tx_id(10);

        assert_eq!(
            private_tx_record_identity(&chain_id, tx_id),
            format!("{PRIVATE_TX_RECORD_IDENTITY_DOMAIN}:miden-devnet:{tx_id}").into_bytes()
        );
    }
}
