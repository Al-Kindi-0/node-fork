use miden_node_private_tx::{
    ArchiveRecordAssociatedData, ArchiveRecordKey, EncryptedPrivateTxRecord,
    PrivateTxEncryptionError, PrivateTxRecord, ThresholdError, ThresholdShareCombiner,
    ThresholdShareProducer, ThresholdShareVerifier, ViewingKeyShare, ViewingPartyId,
    ViewingPartyPublicShare, archive_associated_data_for_record, open_private_tx_record,
};
use miden_protocol::utils::serde::{Deserializable, DeserializationError};

use crate::GoldenThresholdAdapter;

/// Result of an in-process private transaction audit ceremony.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditDecryption {
    /// Decrypted private transaction record.
    pub record: PrivateTxRecord,
    /// Number of threshold responses used by the combiner.
    ///
    /// This equals the requested threshold for a successful ceremony and is returned for demo
    /// measurement output.
    pub response_count: usize,
    /// Total serialized size of all threshold responses.
    pub response_bytes_total: usize,
}

/// Error returned by the in-process audit orchestrator.
#[derive(Debug, thiserror::Error)]
pub enum AuditOrchestratorError {
    #[error("missing public share for viewing party {0}")]
    MissingPublicShare(ViewingPartyId),
    #[error("threshold audit ceremony failed")]
    Threshold(#[from] ThresholdError),
    #[error("private transaction archive decryption failed")]
    Encryption(#[from] PrivateTxEncryptionError),
    #[error("decrypted private transaction record is malformed")]
    RecordDeserialization(#[from] DeserializationError),
}

/// Runs the PoC audit ceremony for one encrypted private transaction archive record.
///
/// The parties are modeled in-process: each selected key share produces one encrypted response for
/// an auditor-generated transport key, the response is verified against that party's public share,
/// and the auditor combines enough responses to recover the per-transaction archive key.
///
/// The helper uses the first `threshold` entries in `key_shares`; callers choose a subset by
/// ordering or filtering that slice.
///
/// Any participating party failure aborts the ceremony. Callers that want fault tolerance should
/// choose or retry subsets outside this helper.
pub fn decrypt_private_tx_archive_record(
    encrypted_record: &EncryptedPrivateTxRecord,
    threshold: u16,
    key_shares: &[ViewingKeyShare],
    public_shares: &[ViewingPartyPublicShare],
) -> Result<AuditDecryption, AuditOrchestratorError> {
    if threshold == 0 {
        return Err(AuditOrchestratorError::Threshold(ThresholdError::InvalidThreshold));
    }

    let adapter = GoldenThresholdAdapter;
    let archive_ad = archive_associated_data_for_record(ArchiveRecordAssociatedData {
        record: encrypted_record,
    });
    let (transport_public_key, transport_secret) =
        GoldenThresholdAdapter::audit_transport_keypair();
    let mut responses = Vec::new();

    for key_share in key_shares.iter().take(usize::from(threshold)) {
        let response = adapter.produce_decryption_response(
            key_share,
            &encrypted_record.identity,
            &archive_ad,
            &transport_public_key,
            &encrypted_record.data_key_protection,
        )?;
        let public_share = public_share_for(public_shares, &key_share.party_id)?;
        adapter.verify_decryption_response(
            &response,
            &encrypted_record.identity,
            &archive_ad,
            &transport_public_key,
            public_share,
        )?;
        responses.push(response);
    }

    let response_bytes_total = responses.iter().map(|response| response.bytes.len()).sum();
    let unlock = adapter.combine_responses(
        &encrypted_record.data_key_protection,
        &responses,
        threshold,
        &encrypted_record.identity,
        &archive_ad,
        &transport_secret,
    )?;
    let record_key = ArchiveRecordKey::from_bytes(&unlock.record_key)?;
    let plaintext =
        open_private_tx_record(&record_key, &encrypted_record.record_ciphertext, &archive_ad)?;

    Ok(AuditDecryption {
        record: PrivateTxRecord::read_from_bytes(&plaintext)?,
        response_count: responses.len(),
        response_bytes_total,
    })
}

fn public_share_for<'a>(
    public_shares: &'a [ViewingPartyPublicShare],
    party_id: &ViewingPartyId,
) -> Result<&'a ViewingPartyPublicShare, AuditOrchestratorError> {
    // PoC viewing groups are small; a linear scan keeps the helper simple and order-independent.
    public_shares
        .iter()
        .find(|public_share| &public_share.party_id == party_id)
        .ok_or_else(|| AuditOrchestratorError::MissingPublicShare(party_id.clone()))
}
