use std::fmt::{self, Formatter};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64};
use std::sync::{Arc, RwLock};

use anyhow::Context;
use miden_node_db::Db;
use miden_node_private_tx::{
    AttestationEvidence, ChainId, PRIVATE_TX_VERSION, PrivateValidatorDescriptor,
    SignedSubmissionKey, ThresholdRecordEncryptor, ValidatorId, ViewingGroupPublicKey,
    submission_key_commitment, submission_key_id,
};
use miden_node_proto::generated::validator::api_server;
use miden_node_proto_build::validator_api_descriptor;
use miden_node_utils::clap::GrpcOptionsInternal;
use miden_node_utils::panic::catch_panic_layer_fn;
use miden_node_utils::tracing::grpc::grpc_trace_fn;
use miden_protocol::Word;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::dsa::eddsa_25519_sha512::SecretKey as X25519SecretKey;
use miden_protocol::crypto::ies::{SealingKey, UnsealingKey};
use miden_protocol::utils::serde::Serializable;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Status;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::trace::TraceLayer;

use crate::db::{
    count_signed_blocks, count_validated_transactions, load_chain_tip, load_with_pool_size,
};
use crate::{COMPONENT, ValidatorSigner};

#[cfg(test)]
mod tests;

mod get_private_tx_archive_record;
mod get_submission_key;
mod rotate_submission_key;
mod sign_block;
mod status;
mod submit_proven_transaction;

// VALIDATOR
// ================================================================================

/// The handle into running the gRPC validator server.
///
/// Facilitates the running of the gRPC server which implements the validator API.
pub struct Validator {
    /// The address of the validator component.
    pub address: SocketAddr,
    /// gRPC server options for internal services (timeouts, connection caps).
    ///
    /// If the handler takes longer than this duration, the server cancels the call.
    pub grpc_options: GrpcOptionsInternal,

    /// The signer used to sign blocks.
    pub signer: ValidatorSigner,

    /// The data directory for the validator component's database files.
    pub data_directory: PathBuf,

    /// Maximum number of SQLite connections in the validator database connection pool.
    pub sqlite_connection_pool_size: NonZeroUsize,

    /// Private transaction submission mode.
    pub private_tx_submission: PrivateTxSubmissionConfig,
}

impl Validator {
    /// Serves the validator RPC API.
    ///
    /// Executes in place (i.e. not spawned) and will run indefinitely until a fatal error is
    /// encountered.
    pub async fn serve(self) -> anyhow::Result<()> {
        tracing::info!(target: COMPONENT, endpoint=?self.address, "Initializing server");

        // Initialize database connection.
        let db = load_with_pool_size(
            self.data_directory.join("validator.sqlite3"),
            self.sqlite_connection_pool_size,
        )
        .await
        .context("failed to initialize validator database")?;

        // Load initial metrics from the database for the in-memory counters.
        let (initial_chain_tip, initial_tx_count, initial_block_count) = db
            .query("load_initial_metrics", |conn| {
                let tip = load_chain_tip(conn)?.map_or(0, |h| h.block_num().as_u32());
                let tx_count = u64::try_from(count_validated_transactions(conn)?).unwrap_or(0);
                let block_count = u64::try_from(count_signed_blocks(conn)?).unwrap_or(0);
                Ok::<_, miden_node_db::DatabaseError>((tip, tx_count, block_count))
            })
            .await
            .context("failed to load initial metrics")?;

        let listener = TcpListener::bind(self.address)
            .await
            .context("failed to bind to block producer address")?;

        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_file_descriptor_set(validator_api_descriptor())
            .build_v1()
            .context("failed to build reflection service")?;

        // Build the gRPC server with the API service and trace layer.
        tonic::transport::Server::builder()
            .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
            .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
            .timeout(self.grpc_options.request_timeout)
            .add_service(api_server::ApiServer::new(ValidatorServer::new(
                self.signer,
                db,
                initial_chain_tip,
                initial_tx_count,
                initial_block_count,
                self.private_tx_submission,
            )))
            .add_service(reflection_service)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .context("failed to serve validator API")
    }
}

/// Runtime mode for validator private transaction submissions.
pub enum PrivateTxSubmissionConfig {
    /// Require clear transaction inputs and reject encrypted private payloads.
    Public,
    /// Accept encrypted private payloads, decrypt them, and archive their private inputs.
    Private {
        /// Chain ID bound into the encrypted submission associated data.
        chain_id: ChainId,
        /// Validator ID bound into the encrypted submission associated data.
        validator_id: ValidatorId,
        /// Validator private key used to decrypt submitted private payloads.
        unsealing_key: UnsealingKey,
        /// Archive configuration used after validation succeeds.
        archive: PrivateTxArchiveConfig,
    },
}

/// Configuration for encrypted private transaction archive records.
#[derive(Clone)]
pub struct PrivateTxArchiveConfig {
    /// TEE attestation id bound into archive associated data.
    ///
    /// PoC configuration stand-in until real TEE attestation is wired.
    pub tee_attestation_id: Word,
    /// Threshold viewing group public key used to wrap archive record keys.
    pub viewing_group_public_key: ViewingGroupPublicKey,
    /// Threshold encryptor used to wrap per-transaction archive record keys.
    pub record_key_encryptor: Arc<dyn ThresholdRecordEncryptor + Send + Sync>,
}

impl fmt::Debug for PrivateTxArchiveConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateTxArchiveConfig")
            .field("tee_attestation_id", &self.tee_attestation_id)
            .field("viewing_group_id", &self.viewing_group_public_key.viewing_group_id)
            .field("record_key_encryptor", &"<threshold encryptor>")
            .finish()
    }
}

impl fmt::Debug for PrivateTxSubmissionConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => f.write_str("Public"),
            Self::Private { chain_id, validator_id, archive, .. } => f
                .debug_struct("Private")
                .field("chain_id", chain_id)
                .field("validator_id", validator_id)
                .field("unsealing_key", &"<redacted>")
                .field("archive", archive)
                .finish(),
        }
    }
}

impl Default for PrivateTxSubmissionConfig {
    fn default() -> Self {
        Self::Public
    }
}

pub(crate) struct PrivateTxPayloadDecryptor {
    chain_id: ChainId,
    validator_id: ValidatorId,
    key_ring: RwLock<SubmissionKeyRing>,
}

impl PrivateTxPayloadDecryptor {
    fn new(chain_id: ChainId, validator_id: ValidatorId, unsealing_key: UnsealingKey) -> Self {
        let key_ring = SubmissionKeyRing::single(
            chain_id.clone(),
            validator_id.clone(),
            unsealing_key,
            BlockNumber::GENESIS,
            BlockNumber::MAX,
        );

        Self {
            chain_id,
            validator_id,
            key_ring: RwLock::new(key_ring),
        }
    }

    fn current_submission_key_descriptor(&self) -> tonic::Result<PrivateValidatorDescriptor> {
        Ok(self.key_ring()?.current_descriptor().clone())
    }

    fn prepare_submission_key_rotation(
        &self,
        valid_from: BlockNumber,
        valid_until: BlockNumber,
        destroy_previous_at: BlockNumber,
    ) -> tonic::Result<PendingSubmissionKeyRotation> {
        validate_rotation_window(valid_from, valid_until, destroy_previous_at)?;
        let next_unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(X25519SecretKey::new());
        let next = SubmissionKeySlot::new(
            self.chain_id.clone(),
            self.validator_id.clone(),
            next_unsealing_key,
            valid_from,
            valid_until,
            None,
        );

        Ok(PendingSubmissionKeyRotation { next, destroy_previous_at })
    }

    fn install_submission_key_rotation(
        &self,
        pending: PendingSubmissionKeyRotation,
        current_block: BlockNumber,
    ) -> tonic::Result<PrivateValidatorDescriptor> {
        self.key_ring_mut()?
            .rotate(pending.next, pending.destroy_previous_at, current_block)
    }

    #[cfg(test)]
    fn rotate_submission_key_for_test(
        &self,
        next_unsealing_key: UnsealingKey,
        valid_from: BlockNumber,
        valid_until: BlockNumber,
        destroy_previous_at: BlockNumber,
    ) -> tonic::Result<PrivateValidatorDescriptor> {
        self.rotate_submission_key_with(
            next_unsealing_key,
            valid_from,
            valid_until,
            destroy_previous_at,
        )
    }

    fn rotate_submission_key_with(
        &self,
        next_unsealing_key: UnsealingKey,
        valid_from: BlockNumber,
        valid_until: BlockNumber,
        destroy_previous_at: BlockNumber,
    ) -> tonic::Result<PrivateValidatorDescriptor> {
        validate_rotation_window(valid_from, valid_until, destroy_previous_at)?;
        let next = SubmissionKeySlot::new(
            self.chain_id.clone(),
            self.validator_id.clone(),
            next_unsealing_key,
            valid_from,
            valid_until,
            None,
        );

        self.key_ring_mut()?.rotate(next, destroy_previous_at, BlockNumber::GENESIS)
    }

    fn key_ring(&self) -> tonic::Result<std::sync::RwLockReadGuard<'_, SubmissionKeyRing>> {
        self.key_ring
            .read()
            .map_err(|_| Status::internal("private transaction submission key ring is unavailable"))
    }

    fn key_ring_mut(&self) -> tonic::Result<std::sync::RwLockWriteGuard<'_, SubmissionKeyRing>> {
        self.key_ring
            .write()
            .map_err(|_| Status::internal("private transaction submission key ring is unavailable"))
    }
}

impl fmt::Debug for PrivateTxPayloadDecryptor {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let key_ring = self
            .key_ring
            .read()
            .map(|ring| format!("{ring:?}"))
            .unwrap_or_else(|_| "<unavailable>".to_string());

        f.debug_struct("PrivateTxPayloadDecryptor")
            .field("chain_id", &self.chain_id)
            .field("validator_id", &self.validator_id)
            .field("key_ring", &key_ring)
            .finish()
    }
}

struct SubmissionKeyRing {
    current: SubmissionKeySlot,
    draining: Vec<SubmissionKeySlot>,
}

struct PendingSubmissionKeyRotation {
    next: SubmissionKeySlot,
    destroy_previous_at: BlockNumber,
}

impl PendingSubmissionKeyRotation {
    fn descriptor(&self) -> &PrivateValidatorDescriptor {
        &self.next.descriptor
    }
}

impl SubmissionKeyRing {
    fn single(
        chain_id: ChainId,
        validator_id: ValidatorId,
        unsealing_key: UnsealingKey,
        valid_from: BlockNumber,
        valid_until: BlockNumber,
    ) -> Self {
        Self {
            current: SubmissionKeySlot::new(
                chain_id,
                validator_id,
                unsealing_key,
                valid_from,
                valid_until,
                None,
            ),
            draining: Vec::new(),
        }
    }

    fn current_descriptor(&self) -> &PrivateValidatorDescriptor {
        &self.current.descriptor
    }

    fn unsealing_key(
        &self,
        encryption_key_id: Word,
        current_block: BlockNumber,
    ) -> Option<&UnsealingKey> {
        self.current
            .matches(encryption_key_id)
            .then_some(&self.current)
            .filter(|slot| slot.is_active(current_block))
            .map(|slot| &slot.unsealing_key)
            .or_else(|| {
                self.draining
                    .iter()
                    .find(|slot| slot.matches(encryption_key_id) && slot.is_active(current_block))
                    .map(|slot| &slot.unsealing_key)
            })
    }

    fn rotate(
        &mut self,
        next: SubmissionKeySlot,
        destroy_previous_at: BlockNumber,
        current_block: BlockNumber,
    ) -> tonic::Result<PrivateValidatorDescriptor> {
        validate_rotation_window(
            next.descriptor.valid_from,
            next.descriptor.valid_until,
            destroy_previous_at,
        )?;
        self.prune_destroyed(current_block);

        let valid_from = next.descriptor.valid_from;
        let valid_until = next.descriptor.valid_until;
        let mut previous = std::mem::replace(&mut self.current, next);
        // `destroy_at` is the first block at which the key is no longer accepted.
        // Descriptors use an inclusive `valid_until`, so a demoted key must advertise
        // no later than the block immediately before destruction.
        previous.descriptor.valid_until =
            previous.descriptor.valid_until.min(destroy_previous_at.saturating_sub(1));
        previous.destroy_at = Some(destroy_previous_at);
        let current_key_id = self.current.descriptor.encryption_key_id;
        let current_descriptor = self.current.descriptor.clone();
        self.draining.push(previous);
        self.prune_destroyed(current_block);

        tracing::info!(
            target: COMPONENT,
            %current_key_id,
            %valid_from,
            %valid_until,
            %destroy_previous_at,
            "rotated private transaction submission key"
        );

        Ok(current_descriptor)
    }

    fn prune_destroyed(&mut self, current_block: BlockNumber) {
        let before = self.draining.len();
        self.draining.retain(|slot| !slot.is_prunable(current_block));
        let pruned = before - self.draining.len();
        if pruned > 0 {
            tracing::debug!(
                target: COMPONENT,
                %current_block,
                pruned,
                "pruned destroyed private transaction submission keys"
            );
        }
    }
}

fn validate_rotation_window(
    valid_from: BlockNumber,
    valid_until: BlockNumber,
    destroy_previous_at: BlockNumber,
) -> tonic::Result<()> {
    if valid_from > valid_until {
        return Err(Status::invalid_argument(
            "submission key valid_from must be less than or equal to valid_until",
        ));
    }
    if destroy_previous_at == BlockNumber::GENESIS {
        return Err(Status::invalid_argument(
            "submission key destroy_previous_at must be greater than genesis",
        ));
    }
    if destroy_previous_at < valid_from {
        return Err(Status::invalid_argument(
            "submission key destroy_previous_at must be greater than or equal to valid_from",
        ));
    }

    Ok(())
}

impl fmt::Debug for SubmissionKeyRing {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubmissionKeyRing")
            .field("current_key_id", &self.current.descriptor.encryption_key_id)
            .field("draining_keys", &self.draining.len())
            .field("unsealing_keys", &"<redacted>")
            .finish()
    }
}

struct SubmissionKeySlot {
    descriptor: PrivateValidatorDescriptor,
    unsealing_key: UnsealingKey,
    destroy_at: Option<BlockNumber>,
}

impl SubmissionKeySlot {
    fn new(
        chain_id: ChainId,
        validator_id: ValidatorId,
        unsealing_key: UnsealingKey,
        valid_from: BlockNumber,
        valid_until: BlockNumber,
        destroy_at: Option<BlockNumber>,
    ) -> Self {
        let sealing_key = sealing_key_for_unsealing_key(&unsealing_key);
        let encryption_key_id = submission_key_id(&sealing_key);
        let descriptor = PrivateValidatorDescriptor {
            version: PRIVATE_TX_VERSION,
            chain_id,
            validator_id,
            encryption_key_id,
            encryption_public_key: sealing_key.to_bytes(),
            attestation_evidence: AttestationEvidence::none(),
            valid_from,
            valid_until,
        };

        Self { descriptor, unsealing_key, destroy_at }
    }

    fn matches(&self, encryption_key_id: Word) -> bool {
        self.descriptor.encryption_key_id == encryption_key_id
    }

    fn is_active(&self, current_block: BlockNumber) -> bool {
        self.descriptor.valid_from <= current_block
            && current_block <= self.descriptor.valid_until
            && self.destroy_at.is_none_or(|destroy_at| current_block < destroy_at)
    }

    fn is_prunable(&self, current_block: BlockNumber) -> bool {
        current_block > self.descriptor.valid_until
            || self.destroy_at.is_some_and(|destroy_at| current_block >= destroy_at)
    }
}

pub(crate) struct PrivateTxArchiveWriter {
    chain_id: ChainId,
    validator_id: ValidatorId,
    tee_attestation_id: Word,
    viewing_group_public_key: ViewingGroupPublicKey,
    record_key_encryptor: Arc<dyn ThresholdRecordEncryptor + Send + Sync>,
}

impl PrivateTxArchiveWriter {
    fn new(chain_id: ChainId, validator_id: ValidatorId, archive: PrivateTxArchiveConfig) -> Self {
        Self {
            chain_id,
            validator_id,
            tee_attestation_id: archive.tee_attestation_id,
            viewing_group_public_key: archive.viewing_group_public_key,
            record_key_encryptor: archive.record_key_encryptor,
        }
    }
}

impl fmt::Debug for PrivateTxArchiveWriter {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateTxArchiveWriter")
            .field("chain_id", &self.chain_id)
            .field("validator_id", &self.validator_id)
            .field("tee_attestation_id", &self.tee_attestation_id)
            .field("viewing_group_id", &self.viewing_group_public_key.viewing_group_id)
            .field("record_key_encryptor", &"<threshold encryptor>")
            .finish()
    }
}

pub(crate) enum PrivateTxSubmissionMode {
    Public,
    Private {
        decryptor: PrivateTxPayloadDecryptor,
        archive_writer: PrivateTxArchiveWriter,
    },
}

impl fmt::Debug for PrivateTxSubmissionMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => f.write_str("Public"),
            Self::Private { decryptor, archive_writer } => f
                .debug_struct("Private")
                .field("decryptor", decryptor)
                .field("archive_writer", archive_writer)
                .finish(),
        }
    }
}

impl From<PrivateTxSubmissionConfig> for PrivateTxSubmissionMode {
    fn from(config: PrivateTxSubmissionConfig) -> Self {
        match config {
            PrivateTxSubmissionConfig::Public => Self::Public,
            PrivateTxSubmissionConfig::Private {
                chain_id,
                validator_id,
                unsealing_key,
                archive,
            } => Self::Private {
                decryptor: PrivateTxPayloadDecryptor::new(
                    chain_id.clone(),
                    validator_id.clone(),
                    unsealing_key,
                ),
                archive_writer: PrivateTxArchiveWriter::new(chain_id, validator_id, archive),
            },
        }
    }
}

fn sealing_key_for_unsealing_key(unsealing_key: &UnsealingKey) -> SealingKey {
    match unsealing_key {
        UnsealingKey::K256XChaCha20Poly1305(key) => {
            SealingKey::K256XChaCha20Poly1305(key.public_key())
        },
        UnsealingKey::X25519XChaCha20Poly1305(key) => {
            SealingKey::X25519XChaCha20Poly1305(key.public_key())
        },
        UnsealingKey::K256AeadPoseidon2(key) => SealingKey::K256AeadPoseidon2(key.public_key()),
        UnsealingKey::X25519AeadPoseidon2(key) => SealingKey::X25519AeadPoseidon2(key.public_key()),
    }
}

// VALIDATOR SERVER
// ================================================================================

/// The underlying implementation of the gRPC validator server.
///
/// Implements the gRPC API for the validator.
struct ValidatorServer {
    signer: ValidatorSigner,
    db: Arc<Db>,
    /// Serializes `sign_block` requests so that concurrent calls are processed sequentially,
    /// ensuring consistent chain tip reads and preventing race conditions.
    sign_block_semaphore: Semaphore,
    /// Serializes manual submission-key rotations so the signed descriptor returned to the caller
    /// is the descriptor installed as current.
    submission_key_rotation_semaphore: Semaphore,
    /// In-memory chain tip, updated atomically after each signed block.
    chain_tip: AtomicU32,
    /// In-memory count of validated transactions, incremented after each new insert.
    validated_transactions_count: AtomicU64,
    /// In-memory count of signed blocks, incremented after each signed block.
    signed_blocks_count: AtomicU64,
    /// Controls whether transaction inputs are accepted in clear or encrypted form.
    private_tx_submission: PrivateTxSubmissionMode,
}

impl ValidatorServer {
    fn new(
        signer: ValidatorSigner,
        db: Db,
        initial_chain_tip: u32,
        initial_tx_count: u64,
        initial_block_count: u64,
        private_tx_submission: PrivateTxSubmissionConfig,
    ) -> Self {
        Self {
            signer,
            db: db.into(),
            sign_block_semaphore: Semaphore::new(1),
            submission_key_rotation_semaphore: Semaphore::new(1),
            chain_tip: AtomicU32::new(initial_chain_tip),
            validated_transactions_count: AtomicU64::new(initial_tx_count),
            signed_blocks_count: AtomicU64::new(initial_block_count),
            private_tx_submission: private_tx_submission.into(),
        }
    }

    async fn sign_submission_key_descriptor(
        &self,
        descriptor: PrivateValidatorDescriptor,
    ) -> tonic::Result<SignedSubmissionKey> {
        let commitment = submission_key_commitment(&descriptor);
        let signature = self.signer.sign_commitment(commitment).await.map_err(|err| {
            tonic::Status::internal(format!("Failed to sign submission key: {err}"))
        })?;

        Ok(SignedSubmissionKey::new(descriptor, signature))
    }
}
