#![forbid(unsafe_code)]

//! Node-local private validator transaction helpers.
//!
//! This crate holds private validator proof-of-concept code that is not ready
//! for `miden-protocol`.

pub mod associated_data;
pub mod encryption;
pub mod envelope;
pub mod mock;
pub mod tee;
pub mod threshold;
pub mod types;

#[cfg(test)]
mod test_support;

pub use associated_data::{
    ArchiveAssociatedData, ArchiveRecordAssociatedData, SubmissionEncryptionAssociatedData,
    SubmissionPayloadAssociatedData, archive_associated_data, archive_associated_data_for_record,
    private_tx_record_identity, submission_associated_data_for_encryption,
    submission_associated_data_for_payload,
};
pub use encryption::{
    ArchiveRecordKey, PrivateTxEncryptionError, decrypt_submission_payload,
    encrypt_submission_payload, open_private_tx_record, seal_private_tx_record,
};
pub use envelope::{
    DataKeyProtection, EncryptedPrivateTxPayload, EncryptedPrivateTxRecord, PrivateTxRecord,
    PrivateTxRecordMetadata, PrivateValidatorDescriptor, ViewingPolicy,
};
pub use tee::{
    AttestationEvidence, AttestationVerifier, Attestor, EnclaveIdentity, TeeError, TeeKeyProvider,
};
pub use threshold::{
    AuditTransportPublicKey, AuditTransportSecret, DecryptionResponse, DkgDealingBytes,
    DkgParticipant, DkgSession, RecordKeyUnlockMaterial, ThresholdBackend, ThresholdError,
    ThresholdRecordEncryptor, ThresholdShareCombiner, ThresholdShareProducer,
    ThresholdShareVerifier, ViewingGroupPublicKey, ViewingGroupSetup, ViewingKeyShare,
    ViewingPartyPublicShare,
};
pub use types::{
    ChainId, EncryptionSchemeId, PRIVATE_TX_VERSION, TeeSchemeId, ThresholdSchemeId, ValidatorId,
    ViewingPartyId,
};
