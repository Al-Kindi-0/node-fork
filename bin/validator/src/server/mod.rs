use std::fmt::{self, Formatter};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64};

use anyhow::Context;
use miden_node_db::Db;
use miden_node_private_tx::{
    AttestationEvidence, ChainId, PRIVATE_TX_VERSION, PrivateValidatorDescriptor,
    ThresholdRecordEncryptor, ValidatorId, ViewingGroupPublicKey, submission_key_id,
};
use miden_node_proto::generated::validator::api_server;
use miden_node_proto_build::validator_api_descriptor;
use miden_node_utils::clap::GrpcOptionsInternal;
use miden_node_utils::panic::catch_panic_layer_fn;
use miden_node_utils::tracing::grpc::grpc_trace_fn;
use miden_protocol::Word;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::ies::{SealingKey, UnsealingKey};
use miden_protocol::utils::serde::Serializable;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_stream::wrappers::TcpListenerStream;
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
    encryption_key_id: Word,
    unsealing_key: UnsealingKey,
}

impl PrivateTxPayloadDecryptor {
    fn new(
        chain_id: ChainId,
        validator_id: ValidatorId,
        encryption_key_id: Word,
        unsealing_key: UnsealingKey,
    ) -> Self {
        Self {
            chain_id,
            validator_id,
            encryption_key_id,
            unsealing_key,
        }
    }
}

impl fmt::Debug for PrivateTxPayloadDecryptor {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateTxPayloadDecryptor")
            .field("chain_id", &self.chain_id)
            .field("validator_id", &self.validator_id)
            .field("encryption_key_id", &self.encryption_key_id)
            .field("unsealing_key", &"<redacted>")
            .finish()
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
        submission_key_descriptor: PrivateValidatorDescriptor,
    },
}

impl fmt::Debug for PrivateTxSubmissionMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => f.write_str("Public"),
            Self::Private {
                decryptor,
                archive_writer,
                submission_key_descriptor,
            } => f
                .debug_struct("Private")
                .field("decryptor", decryptor)
                .field("archive_writer", archive_writer)
                .field("submission_key_descriptor", submission_key_descriptor)
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
            } => {
                let sealing_key = sealing_key_for_unsealing_key(&unsealing_key);
                let encryption_key_id = submission_key_id(&sealing_key);
                let submission_key_descriptor = PrivateValidatorDescriptor {
                    version: PRIVATE_TX_VERSION,
                    chain_id: chain_id.clone(),
                    validator_id: validator_id.clone(),
                    encryption_key_id,
                    encryption_public_key: sealing_key.to_bytes(),
                    attestation_evidence: AttestationEvidence::none(),
                    valid_from: BlockNumber::GENESIS,
                    valid_until: BlockNumber::MAX,
                };

                Self::Private {
                    decryptor: PrivateTxPayloadDecryptor::new(
                        chain_id.clone(),
                        validator_id.clone(),
                        encryption_key_id,
                        unsealing_key,
                    ),
                    archive_writer: PrivateTxArchiveWriter::new(chain_id, validator_id, archive),
                    submission_key_descriptor,
                }
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
            chain_tip: AtomicU32::new(initial_chain_tip),
            validated_transactions_count: AtomicU64::new(initial_tx_count),
            signed_blocks_count: AtomicU64::new(initial_block_count),
            private_tx_submission: private_tx_submission.into(),
        }
    }
}
