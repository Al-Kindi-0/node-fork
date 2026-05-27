//! Audit coordination primitives for L1-anchored private transaction unlocks.
//!
//! The coordinator models authorization, response collection, and non-responder settlement. It
//! does not perform threshold cryptography or decide governance policy; auditors and viewing
//! parties reconstruct and verify the cryptographic context from archive records.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Mutex;

use miden_protocol::Word;
use miden_protocol::transaction::TransactionId;

use crate::threshold::{AuditTransportPublicKey, DecryptionResponse};
use crate::types::{AuditorId, ViewingPartyId};

/// Opaque audit request identifier assigned by an audit coordinator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuditRequestId(u64);

impl AuditRequestId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for AuditRequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Request to unlock one private transaction archive record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRequest {
    pub auditor_id: AuditorId,
    pub tx_id: TransactionId,
    pub viewing_group_id: Word,
    pub identity: Vec<u8>,
    /// Auditor transport key for encrypted threshold responses.
    ///
    /// The coordinator stores the key but does not verify threshold cryptography. Auditors verify
    /// that submitted responses are bound to this key before combining them.
    pub transport_public_key: AuditTransportPublicKey,
    /// Parties expected to respond.
    ///
    /// The coordinator settles based on who submitted, not on a cryptographic threshold. Combining
    /// responses is the auditor's responsibility.
    pub parties: Vec<ViewingPartyId>,
    /// Exclusive response deadline. Parties must submit while current block is below this value.
    pub deadline_block: u64,
}

/// Pending request visible to an involved viewing party.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingAuditRequest {
    pub request_id: AuditRequestId,
    pub request: AuditRequest,
}

/// Responses submitted for one audit request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditResponses {
    pub request_id: AuditRequestId,
    pub request: AuditRequest,
    pub responses: Vec<DecryptionResponse>,
    pub deadline_passed: bool,
}

/// Settlement result for an audit request.
///
/// The MVP settlement rule only distinguishes submitted from missing responses. It does not prove
/// cryptographic response validity; invalid-response fraud proofs are a production extension.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditSettlement {
    pub request_id: AuditRequestId,
    pub responded_parties: Vec<ViewingPartyId>,
    pub slashed_parties: Vec<ViewingPartyId>,
    pub settled_at_block: u64,
}

/// Current lifecycle state of an audit request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditRequestStatus {
    Open {
        response_count: usize,
        deadline_block: u64,
    },
    DeadlinePassed {
        response_count: usize,
        deadline_block: u64,
    },
    Settled(AuditSettlement),
}

/// Error returned by audit coordination backends.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum AuditCoordinationError {
    #[error("auditor {0} is not authorized")]
    UnauthorizedAuditor(AuditorId),
    #[error("audit request {0} was not found")]
    RequestNotFound(AuditRequestId),
    #[error("audit request must include at least one viewing party")]
    EmptyViewingPartySet,
    #[error("audit request contains duplicate viewing parties")]
    DuplicateViewingParty,
    #[error("audit response deadline must be in the future")]
    DeadlineNotInFuture,
    #[error("audit response deadline has passed")]
    DeadlinePassed,
    #[error("audit response deadline has not passed")]
    DeadlineNotPassed,
    #[error("audit request {0} is already settled")]
    RequestAlreadySettled(AuditRequestId),
    #[error("viewing party {0} is not part of the audit request")]
    PartyNotInRequest(ViewingPartyId),
    #[error("viewing party {0} already submitted an audit response")]
    AlreadyResponded(ViewingPartyId),
    #[error("audit response does not match the request context")]
    ResponseContextMismatch,
    #[error("audit request id space is exhausted")]
    RequestIdExhausted,
    #[error("audit coordinator state is unavailable")]
    CoordinatorUnavailable,
}

/// Minimal coordination surface for L1-anchored audit requests.
///
/// A production implementation would back this trait with an L1 contract. The in-memory
/// implementation below mirrors the MVP semantics: authorized auditors can request a per-tx audit,
/// parties submit encrypted responses before a deadline, and settlement slashes non-responders.
pub trait AuditCoordinator: Send + Sync {
    fn request_audit(
        &self,
        request: AuditRequest,
    ) -> Result<AuditRequestId, AuditCoordinationError>;

    fn request_status(
        &self,
        request_id: AuditRequestId,
    ) -> Result<AuditRequestStatus, AuditCoordinationError>;

    fn pending_requests(
        &self,
        party_id: &ViewingPartyId,
    ) -> Result<Vec<PendingAuditRequest>, AuditCoordinationError>;

    fn submit_response(
        &self,
        request_id: AuditRequestId,
        party_id: &ViewingPartyId,
        response: DecryptionResponse,
    ) -> Result<(), AuditCoordinationError>;

    fn fetch_responses(
        &self,
        request_id: AuditRequestId,
    ) -> Result<AuditResponses, AuditCoordinationError>;

    /// Settles an audit request after its deadline.
    ///
    /// Settlement is intentionally callable by anyone. It is idempotent: repeated calls return the
    /// original settlement.
    fn settle(&self, request_id: AuditRequestId)
    -> Result<AuditSettlement, AuditCoordinationError>;
}

/// In-memory audit coordinator for tests and PoC demos.
///
/// This is not a production substitute for an L1 contract. It tracks authorized auditors, request
/// deadlines, submitted responses, and non-responder slashing with an in-process block counter.
#[derive(Debug)]
pub struct InMemoryAuditCoordinator {
    state: Mutex<CoordinatorState>,
}

#[derive(Debug)]
struct CoordinatorState {
    current_block: u64,
    next_request_id: u64,
    authorized_auditors: BTreeSet<AuditorId>,
    requests: BTreeMap<AuditRequestId, RequestState>,
}

#[derive(Clone, Debug)]
struct RequestState {
    request: AuditRequest,
    responses: BTreeMap<ViewingPartyId, DecryptionResponse>,
    settlement: Option<AuditSettlement>,
}

impl InMemoryAuditCoordinator {
    pub fn new(initial_block: u64) -> Self {
        Self {
            state: Mutex::new(CoordinatorState {
                current_block: initial_block,
                next_request_id: 1,
                authorized_auditors: BTreeSet::new(),
                requests: BTreeMap::new(),
            }),
        }
    }

    pub fn authorize_auditor(&self, auditor_id: AuditorId) -> Result<(), AuditCoordinationError> {
        self.lock_state()?.authorized_auditors.insert(auditor_id);
        Ok(())
    }

    pub fn advance_block(&self, blocks: u64) -> Result<u64, AuditCoordinationError> {
        let mut state = self.lock_state()?;
        state.current_block = state.current_block.saturating_add(blocks);
        Ok(state.current_block)
    }

    pub fn current_block(&self) -> Result<u64, AuditCoordinationError> {
        Ok(self.lock_state()?.current_block)
    }

    fn lock_state(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, CoordinatorState>, AuditCoordinationError> {
        self.state.lock().map_err(|_| AuditCoordinationError::CoordinatorUnavailable)
    }
}

impl AuditCoordinator for InMemoryAuditCoordinator {
    fn request_audit(
        &self,
        request: AuditRequest,
    ) -> Result<AuditRequestId, AuditCoordinationError> {
        validate_request_parties(&request.parties)?;

        let mut state = self.lock_state()?;
        if !state.authorized_auditors.contains(&request.auditor_id) {
            return Err(AuditCoordinationError::UnauthorizedAuditor(request.auditor_id));
        }
        if request.deadline_block <= state.current_block {
            return Err(AuditCoordinationError::DeadlineNotInFuture);
        }

        let request_id = AuditRequestId::new(state.next_request_id);
        state.next_request_id = state
            .next_request_id
            .checked_add(1)
            .ok_or(AuditCoordinationError::RequestIdExhausted)?;
        state.requests.insert(
            request_id,
            RequestState {
                request,
                responses: BTreeMap::new(),
                settlement: None,
            },
        );

        Ok(request_id)
    }

    fn request_status(
        &self,
        request_id: AuditRequestId,
    ) -> Result<AuditRequestStatus, AuditCoordinationError> {
        let state = self.lock_state()?;
        let request_state = state
            .requests
            .get(&request_id)
            .ok_or(AuditCoordinationError::RequestNotFound(request_id))?;
        if let Some(settlement) = &request_state.settlement {
            return Ok(AuditRequestStatus::Settled(settlement.clone()));
        }

        let response_count = request_state.responses.len();
        let deadline_block = request_state.request.deadline_block;
        if state.current_block >= deadline_block {
            Ok(AuditRequestStatus::DeadlinePassed { response_count, deadline_block })
        } else {
            Ok(AuditRequestStatus::Open { response_count, deadline_block })
        }
    }

    fn pending_requests(
        &self,
        party_id: &ViewingPartyId,
    ) -> Result<Vec<PendingAuditRequest>, AuditCoordinationError> {
        let state = self.lock_state()?;
        Ok(state
            .requests
            .iter()
            .filter(|(_, request_state)| {
                request_state.settlement.is_none()
                    && state.current_block < request_state.request.deadline_block
                    && request_state.request.parties.iter().any(|party| party == party_id)
                    && !request_state.responses.contains_key(party_id)
            })
            .map(|(request_id, request_state)| PendingAuditRequest {
                request_id: *request_id,
                request: request_state.request.clone(),
            })
            .collect())
    }

    fn submit_response(
        &self,
        request_id: AuditRequestId,
        party_id: &ViewingPartyId,
        response: DecryptionResponse,
    ) -> Result<(), AuditCoordinationError> {
        let mut state = self.lock_state()?;
        let current_block = state.current_block;
        let request_state = state
            .requests
            .get_mut(&request_id)
            .ok_or(AuditCoordinationError::RequestNotFound(request_id))?;
        if request_state.settlement.is_some() {
            return Err(AuditCoordinationError::RequestAlreadySettled(request_id));
        }
        if current_block >= request_state.request.deadline_block {
            return Err(AuditCoordinationError::DeadlinePassed);
        }
        if !request_state.request.parties.iter().any(|party| party == party_id) {
            return Err(AuditCoordinationError::PartyNotInRequest(party_id.clone()));
        }
        if response.party_id != *party_id
            || response.viewing_group_id != request_state.request.viewing_group_id
            || response.identity != request_state.request.identity
        {
            return Err(AuditCoordinationError::ResponseContextMismatch);
        }
        if request_state.responses.contains_key(party_id) {
            return Err(AuditCoordinationError::AlreadyResponded(party_id.clone()));
        }

        request_state.responses.insert(party_id.clone(), response);
        Ok(())
    }

    fn fetch_responses(
        &self,
        request_id: AuditRequestId,
    ) -> Result<AuditResponses, AuditCoordinationError> {
        let state = self.lock_state()?;
        let request_state = state
            .requests
            .get(&request_id)
            .ok_or(AuditCoordinationError::RequestNotFound(request_id))?;

        Ok(AuditResponses {
            request_id,
            request: request_state.request.clone(),
            responses: request_state.responses.values().cloned().collect(),
            deadline_passed: state.current_block >= request_state.request.deadline_block,
        })
    }

    fn settle(
        &self,
        request_id: AuditRequestId,
    ) -> Result<AuditSettlement, AuditCoordinationError> {
        let mut state = self.lock_state()?;
        let current_block = state.current_block;
        let request_state = state
            .requests
            .get_mut(&request_id)
            .ok_or(AuditCoordinationError::RequestNotFound(request_id))?;
        if let Some(settlement) = &request_state.settlement {
            return Ok(settlement.clone());
        }
        if current_block < request_state.request.deadline_block {
            return Err(AuditCoordinationError::DeadlineNotPassed);
        }

        let mut responded_parties = Vec::new();
        let mut slashed_parties = Vec::new();
        for party in &request_state.request.parties {
            if request_state.responses.contains_key(party) {
                responded_parties.push(party.clone());
            } else {
                slashed_parties.push(party.clone());
            }
        }

        let settlement = AuditSettlement {
            request_id,
            responded_parties,
            slashed_parties,
            settled_at_block: current_block,
        };
        request_state.settlement = Some(settlement.clone());

        Ok(settlement)
    }
}

fn validate_request_parties(parties: &[ViewingPartyId]) -> Result<(), AuditCoordinationError> {
    if parties.is_empty() {
        return Err(AuditCoordinationError::EmptyViewingPartySet);
    }

    // Production L1 backends should enforce a request-size bound tied to gas and calldata limits.
    let mut seen = BTreeSet::new();
    for party in parties {
        if !seen.insert(party) {
            return Err(AuditCoordinationError::DuplicateViewingParty);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use miden_protocol::Word;
    use miden_protocol::transaction::TransactionId;
    use miden_protocol::utils::serde::{Deserializable, Serializable};

    use super::*;

    #[test]
    fn in_memory_coordinator_tracks_request_lifecycle() {
        let coordinator = InMemoryAuditCoordinator::new(10);
        let auditor = auditor_id("auditor-1");
        let request = audit_request(auditor.clone(), 12);
        let party_1 = request.parties[0].clone();
        let party_2 = request.parties[1].clone();
        let party_3 = request.parties[2].clone();

        assert_eq!(
            coordinator.request_audit(request.clone()).unwrap_err(),
            AuditCoordinationError::UnauthorizedAuditor(auditor.clone())
        );

        coordinator.authorize_auditor(auditor).unwrap();
        let request_id = coordinator.request_audit(request.clone()).unwrap();
        assert_eq!(request_id.as_u64(), 1);
        assert_eq!(
            coordinator.request_status(request_id).unwrap(),
            AuditRequestStatus::Open { response_count: 0, deadline_block: 12 }
        );
        assert_eq!(
            coordinator.pending_requests(&party_1).unwrap(),
            vec![PendingAuditRequest { request_id, request: request.clone() }]
        );

        coordinator
            .submit_response(request_id, &party_1, response_for(&request, party_1.clone()))
            .unwrap();
        assert_eq!(coordinator.pending_requests(&party_1).unwrap(), Vec::new());
        assert_eq!(
            coordinator
                .submit_response(request_id, &party_1, response_for(&request, party_1.clone()))
                .unwrap_err(),
            AuditCoordinationError::AlreadyResponded(party_1.clone())
        );
        assert_eq!(coordinator.fetch_responses(request_id).unwrap().responses.len(), 1);

        assert_eq!(coordinator.advance_block(2).unwrap(), 12);
        assert_eq!(coordinator.pending_requests(&party_2).unwrap(), Vec::new());
        assert_eq!(
            coordinator
                .submit_response(request_id, &party_2, response_for(&request, party_2.clone()))
                .unwrap_err(),
            AuditCoordinationError::DeadlinePassed
        );

        let settlement = coordinator.settle(request_id).unwrap();
        assert_eq!(settlement.responded_parties, vec![party_1.clone()]);
        assert_eq!(settlement.slashed_parties, vec![party_2, party_3]);
        assert_eq!(settlement.settled_at_block, 12);
        assert_eq!(
            coordinator.request_status(request_id).unwrap(),
            AuditRequestStatus::Settled(settlement.clone())
        );
        assert_eq!(coordinator.settle(request_id).unwrap(), settlement);
    }

    #[test]
    fn in_memory_coordinator_rejects_duplicate_request_parties() {
        let coordinator = InMemoryAuditCoordinator::new(10);
        let auditor = auditor_id("auditor-1");
        coordinator.authorize_auditor(auditor.clone()).unwrap();

        let mut request = audit_request(auditor, 11);
        request.parties.push(request.parties[0].clone());
        assert_eq!(
            coordinator.request_audit(request).unwrap_err(),
            AuditCoordinationError::DuplicateViewingParty
        );
    }

    #[test]
    fn in_memory_coordinator_rejects_unknown_party_response() {
        let coordinator = InMemoryAuditCoordinator::new(10);
        let auditor = auditor_id("auditor-1");
        coordinator.authorize_auditor(auditor.clone()).unwrap();

        let request = audit_request(auditor, 11);
        let request_id = coordinator.request_audit(request.clone()).unwrap();
        let outsider = party_id("party-4");
        assert_eq!(
            coordinator
                .submit_response(request_id, &outsider, response_for(&request, outsider.clone()))
                .unwrap_err(),
            AuditCoordinationError::PartyNotInRequest(outsider)
        );
    }

    #[test]
    fn in_memory_coordinator_rejects_response_context_mismatch() {
        let coordinator = InMemoryAuditCoordinator::new(10);
        let auditor = auditor_id("auditor-1");
        coordinator.authorize_auditor(auditor.clone()).unwrap();

        let request = audit_request(auditor, 11);
        let request_id = coordinator.request_audit(request.clone()).unwrap();
        let party = request.parties[0].clone();
        let mut bad_response = response_for(&request, party.clone());
        bad_response.identity = b"wrong-identity".to_vec();
        assert_eq!(
            coordinator.submit_response(request_id, &party, bad_response).unwrap_err(),
            AuditCoordinationError::ResponseContextMismatch
        );
    }

    fn audit_request(auditor_id: AuditorId, deadline_block: u64) -> AuditRequest {
        AuditRequest {
            auditor_id,
            tx_id: tx_id(100),
            viewing_group_id: word(1),
            identity: b"miden:private-tx-record:v1:miden-devnet:tx-100".to_vec(),
            transport_public_key: AuditTransportPublicKey {
                bytes: b"audit-transport-public-key".to_vec(),
            },
            parties: vec![party_id("party-1"), party_id("party-2"), party_id("party-3")],
            deadline_block,
        }
    }

    fn response_for(request: &AuditRequest, party_id: ViewingPartyId) -> DecryptionResponse {
        DecryptionResponse {
            viewing_group_id: request.viewing_group_id,
            party_id,
            identity: request.identity.clone(),
            bytes: b"encrypted-response".to_vec(),
        }
    }

    fn auditor_id(value: &str) -> AuditorId {
        AuditorId::new(value).unwrap()
    }

    fn party_id(value: &str) -> ViewingPartyId {
        ViewingPartyId::new(value).unwrap()
    }

    fn tx_id(seed: u32) -> TransactionId {
        TransactionId::read_from_bytes(&word(seed).to_bytes()).unwrap()
    }

    fn word(seed: u32) -> Word {
        Word::from([seed, seed + 1, seed + 2, seed + 3])
    }
}
