mod bootstrap;
mod start;

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, anyhow, bail};
use clap::Parser;
use miden_node_private_tx::{ChainId, ValidatorId, ViewingGroupPublicKey};
use miden_node_private_tx_golden::GoldenThresholdAdapter;
use miden_node_utils::clap::GrpcOptionsInternal;
use miden_protocol::Word;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SecretKey;
use miden_protocol::crypto::ies::{IesScheme, UnsealingKey};
use miden_protocol::utils::serde::Deserializable;
use miden_validator::{PrivateTxArchiveConfig, PrivateTxSubmissionConfig, ValidatorSigner};

const ENV_DATA_DIRECTORY: &str = "MIDEN_NODE_DATA_DIRECTORY";
const ENV_LISTEN: &str = "MIDEN_NODE_VALIDATOR_LISTEN";
const ENV_KEY: &str = "MIDEN_NODE_VALIDATOR_KEY";
const ENV_KMS_KEY_ID: &str = "MIDEN_NODE_VALIDATOR_KMS_KEY_ID";
const ENV_ENABLE_OTEL: &str = "MIDEN_NODE_ENABLE_OTEL";
const ENV_GENESIS_CONFIG_FILE: &str = "MIDEN_NODE_VALIDATOR_GENESIS_CONFIG_FILE";
const ENV_SQLITE_CONNECTION_POOL_SIZE: &str = "MIDEN_NODE_VALIDATOR_SQLITE_CONNECTION_POOL_SIZE";
const ENV_PRIVATE_TX_CHAIN_ID: &str = "MIDEN_NODE_VALIDATOR_PRIVATE_TX_CHAIN_ID";
const ENV_PRIVATE_TX_VALIDATOR_ID: &str = "MIDEN_NODE_VALIDATOR_PRIVATE_TX_VALIDATOR_ID";
const ENV_PRIVATE_TX_UNSEALING_KEY_FILE: &str =
    "MIDEN_NODE_VALIDATOR_PRIVATE_TX_UNSEALING_KEY_FILE";
const ENV_PRIVATE_TX_TEE_ATTESTATION_ID: &str =
    "MIDEN_NODE_VALIDATOR_PRIVATE_TX_TEE_ATTESTATION_ID";
const ENV_PRIVATE_TX_VIEWING_GROUP_PUBLIC_KEY_FILE: &str =
    "MIDEN_NODE_VALIDATOR_PRIVATE_TX_VIEWING_GROUP_PUBLIC_KEY_FILE";

/// A predefined, insecure validator key for development purposes.
pub(crate) const INSECURE_KEY_HEX: &str =
    "0101010101010101010101010101010101010101010101010101010101010101";

// VALIDATOR COMMAND
// ================================================================================================

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub enum ValidatorCommand {
    /// Bootstraps the genesis block.
    ///
    /// Creates accounts from the genesis configuration, builds and signs the genesis block,
    /// and writes the signed block and account secret files to disk. Also initializes the
    /// validator's database with the genesis block as the chain tip.
    Bootstrap {
        /// Directory in which to write the genesis block file.
        #[arg(long, value_name = "DIR")]
        genesis_block_directory: PathBuf,
        /// Directory to write the account secret files (.mac) to.
        #[arg(long, value_name = "DIR")]
        accounts_directory: PathBuf,
        /// Directory in which to store the validator's database.
        #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
        data_directory: PathBuf,
        /// Maximum number of SQLite connections in the validator database connection pool.
        #[arg(
            long = "sqlite.connection_pool_size",
            env = ENV_SQLITE_CONNECTION_POOL_SIZE,
            default_value_t = miden_node_db::default_connection_pool_size(),
            value_name = "NUM"
        )]
        sqlite_connection_pool_size: NonZeroUsize,
        /// Use the given configuration file to construct the genesis state from.
        #[arg(long, env = ENV_GENESIS_CONFIG_FILE, value_name = "GENESIS_CONFIG")]
        genesis_config_file: Option<PathBuf>,
        /// Configuration for the Validator key used to sign the genesis block.
        #[command(flatten)]
        validator_key: ValidatorKey,
    },

    /// Starts the validator component.
    Start {
        /// Socket address at which to serve the gRPC API.
        #[arg(long = "listen", env = ENV_LISTEN, value_name = "LISTEN")]
        listen: std::net::SocketAddr,

        /// Enables the exporting of traces for OpenTelemetry.
        ///
        /// This can be further configured using environment variables as defined in the official
        /// OpenTelemetry documentation. See our operator manual for further details.
        #[arg(long = "enable-otel", default_value_t = false, env = ENV_ENABLE_OTEL, value_name = "BOOL")]
        enable_otel: bool,

        #[command(flatten)]
        grpc_options: GrpcOptionsInternal,

        /// Maximum number of SQLite connections in the validator database connection pool.
        #[arg(
            long = "sqlite.connection_pool_size",
            env = ENV_SQLITE_CONNECTION_POOL_SIZE,
            default_value_t = miden_node_db::default_connection_pool_size(),
            value_name = "NUM"
        )]
        sqlite_connection_pool_size: NonZeroUsize,

        /// Directory in which to store the validator's data.
        #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
        data_directory: PathBuf,

        #[command(flatten)]
        private_tx: PrivateTxConfig,

        /// Insecure, hex-encoded validator secret key for development and testing purposes.
        ///
        /// If not provided, a predefined key is used.
        ///
        /// Cannot be used with `key.kms-id`.
        #[arg(
            long = "key.hex",
            env = ENV_KEY,
            value_name = "VALIDATOR_KEY",
            default_value = INSECURE_KEY_HEX,
            group = "key"
        )]
        validator_key: String,

        /// Key ID for the KMS key used by validator to sign blocks.
        ///
        /// Cannot be used with `key.hex`.
        #[arg(
            long = "key.kms-id",
            env = ENV_KMS_KEY_ID,
            value_name = "VALIDATOR_KMS_KEY_ID",
            group = "key"
        )]
        kms_key_id: Option<String>,
    },
}

impl ValidatorCommand {
    pub async fn handle(self) -> anyhow::Result<()> {
        match self {
            Self::Bootstrap {
                genesis_block_directory,
                accounts_directory,
                data_directory,
                sqlite_connection_pool_size,
                genesis_config_file,
                validator_key,
            } => {
                bootstrap::bootstrap(
                    &genesis_block_directory,
                    &accounts_directory,
                    &data_directory,
                    sqlite_connection_pool_size,
                    genesis_config_file.as_ref(),
                    validator_key,
                )
                .await
            },
            Self::Start {
                listen,
                grpc_options,
                validator_key,
                data_directory,
                kms_key_id,
                sqlite_connection_pool_size,
                private_tx,
                ..
            } => {
                let address = listen;
                let private_tx_submission = private_tx.into_submission_config()?;

                if let Some(kms_key_id) = kms_key_id {
                    let signer = ValidatorSigner::new_kms(kms_key_id).await?;
                    start::start(
                        address,
                        grpc_options,
                        signer,
                        data_directory,
                        sqlite_connection_pool_size,
                        private_tx_submission,
                    )
                    .await
                } else {
                    let signer = SecretKey::read_from_bytes(hex::decode(validator_key)?.as_ref())?;
                    let signer = ValidatorSigner::new_local(signer);
                    start::start(
                        address,
                        grpc_options,
                        signer,
                        data_directory,
                        sqlite_connection_pool_size,
                        private_tx_submission,
                    )
                    .await
                }
            },
        }
    }

    pub fn is_open_telemetry_enabled(&self) -> bool {
        match self {
            Self::Start { enable_otel, .. } => *enable_otel,
            Self::Bootstrap { .. } => false,
        }
    }
}

// PRIVATE TX CONFIG
// ================================================================================================

#[derive(clap::Args, Debug, Default)]
pub struct PrivateTxConfig {
    /// Chain ID to bind encrypted private transaction payloads to.
    #[arg(long = "private-tx.chain-id", env = ENV_PRIVATE_TX_CHAIN_ID, value_name = "CHAIN_ID")]
    chain_id: Option<String>,

    /// Validator ID to bind encrypted private transaction payloads to.
    #[arg(
        long = "private-tx.validator-id",
        env = ENV_PRIVATE_TX_VALIDATOR_ID,
        value_name = "VALIDATOR_ID"
    )]
    validator_id: Option<String>,

    /// File containing a Miden-serialized private transaction unsealing key.
    #[arg(
        long = "private-tx.unsealing-key-file",
        env = ENV_PRIVATE_TX_UNSEALING_KEY_FILE,
        value_name = "FILE"
    )]
    unsealing_key_file: Option<PathBuf>,

    /// TEE attestation ID to bind encrypted archive records to.
    #[arg(
        long = "private-tx.tee-attestation-id",
        env = ENV_PRIVATE_TX_TEE_ATTESTATION_ID,
        value_name = "WORD"
    )]
    tee_attestation_id: Option<String>,

    /// File containing the Miden-serialized threshold viewing group public key.
    #[arg(
        long = "private-tx.viewing-group-public-key-file",
        env = ENV_PRIVATE_TX_VIEWING_GROUP_PUBLIC_KEY_FILE,
        value_name = "FILE"
    )]
    viewing_group_public_key_file: Option<PathBuf>,
}

impl PrivateTxConfig {
    fn into_submission_config(self) -> anyhow::Result<PrivateTxSubmissionConfig> {
        match (
            self.chain_id,
            self.validator_id,
            self.unsealing_key_file,
            self.tee_attestation_id,
            self.viewing_group_public_key_file,
        ) {
            (None, None, None, None, None) => Ok(PrivateTxSubmissionConfig::Public),
            (
                Some(chain_id),
                Some(validator_id),
                Some(unsealing_key_file),
                Some(tee_attestation_id),
                Some(viewing_group_public_key_file),
            ) => {
                let chain_id = ChainId::new(chain_id)?;
                let validator_id = ValidatorId::new(validator_id)?;
                let bytes = fs_err::read(&unsealing_key_file).with_context(|| {
                    format!(
                        "failed to read private tx unsealing key file {}",
                        unsealing_key_file.display()
                    )
                })?;
                let unsealing_key = UnsealingKey::read_from_bytes(&bytes).with_context(|| {
                    format!(
                        "failed to parse private tx unsealing key from {}",
                        unsealing_key_file.display()
                    )
                })?;
                if unsealing_key.scheme() != IesScheme::X25519XChaCha20Poly1305 {
                    bail!(
                        "private tx unsealing key must use {}, got {}",
                        IesScheme::X25519XChaCha20Poly1305,
                        unsealing_key.scheme()
                    );
                }
                let tee_attestation_id = parse_word(&tee_attestation_id).with_context(|| {
                    format!("failed to parse private tx tee attestation id {tee_attestation_id}")
                })?;
                let bytes = fs_err::read(&viewing_group_public_key_file).with_context(|| {
                    format!(
                        "failed to read private tx viewing group public key file {}",
                        viewing_group_public_key_file.display()
                    )
                })?;
                let viewing_group_public_key = ViewingGroupPublicKey::read_from_bytes(&bytes)
                    .with_context(|| {
                        format!(
                            "failed to parse private tx viewing group public key from {}",
                            viewing_group_public_key_file.display()
                        )
                    })?;

                Ok(PrivateTxSubmissionConfig::Private {
                    chain_id,
                    validator_id,
                    unsealing_key,
                    archive: PrivateTxArchiveConfig {
                        tee_attestation_id,
                        viewing_group_public_key,
                        record_key_encryptor: Arc::new(GoldenThresholdAdapter),
                    },
                })
            },
            _ => bail!(
                "private tx mode requires --private-tx.chain-id, \
                 --private-tx.validator-id, --private-tx.unsealing-key-file, \
                 --private-tx.tee-attestation-id, and \
                 --private-tx.viewing-group-public-key-file"
            ),
        }
    }
}

fn parse_word(value: &str) -> anyhow::Result<Word> {
    Word::parse(value).map_err(|err| anyhow!("{err}"))
}

// VALIDATOR KEY
// ================================================================================================

/// Configuration for the Validator key used to sign blocks.
#[derive(clap::Args)]
#[group(required = false, multiple = false)]
pub struct ValidatorKey {
    /// Insecure, hex-encoded validator secret key for development and testing purposes.
    ///
    /// If not provided, a predefined key is used.
    ///
    /// Cannot be used with `validator.key.kms-id`.
    #[arg(
        long = "validator.key.hex",
        env = ENV_KEY,
        value_name = "VALIDATOR_KEY",
        default_value = INSECURE_KEY_HEX,
    )]
    pub validator_key: String,
    /// Key ID for the KMS key used by validator to sign blocks.
    ///
    /// Cannot be used with `validator.key.hex`.
    #[arg(
        long = "validator.key.kms-id",
        env = ENV_KMS_KEY_ID,
        value_name = "VALIDATOR_KMS_KEY_ID",
    )]
    pub validator_kms_key_id: Option<String>,
}

impl ValidatorKey {
    pub async fn into_signer(self) -> anyhow::Result<ValidatorSigner> {
        if let Some(kms_key_id) = self.validator_kms_key_id {
            Ok(ValidatorSigner::new_kms(kms_key_id).await?)
        } else {
            let signer = SecretKey::read_from_bytes(hex::decode(self.validator_key)?.as_ref())?;
            Ok(ValidatorSigner::new_local(signer))
        }
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::crypto::dsa::{
        ecdsa_k256_keccak::SecretKey as K256SecretKey,
        eddsa_25519_sha512::SecretKey as X25519SecretKey,
    };
    use miden_protocol::utils::serde::Serializable;

    use super::*;

    #[test]
    fn private_tx_config_defaults_to_public_mode() {
        let config = PrivateTxConfig::default().into_submission_config().unwrap();

        assert!(matches!(config, PrivateTxSubmissionConfig::Public));
    }

    #[test]
    fn private_tx_config_requires_all_private_fields() {
        let config = PrivateTxConfig {
            chain_id: Some("miden-devnet".to_string()),
            validator_id: None,
            unsealing_key_file: None,
            tee_attestation_id: None,
            viewing_group_public_key_file: None,
        };

        let err = config.into_submission_config().unwrap_err();

        assert!(err.to_string().contains("--private-tx.chain-id"));
        assert!(err.to_string().contains("--private-tx.validator-id"));
        assert!(err.to_string().contains("--private-tx.unsealing-key-file"));
        assert!(err.to_string().contains("--private-tx.tee-attestation-id"));
        assert!(err.to_string().contains("--private-tx.viewing-group-public-key-file"));
    }

    #[test]
    fn private_tx_config_loads_private_mode_files() {
        let temp_dir = tempfile::tempdir().unwrap();
        let key_path = temp_dir.path().join("unsealing.key");
        let viewing_group_path = temp_dir.path().join("viewing-group-pk");
        let key = UnsealingKey::X25519XChaCha20Poly1305(X25519SecretKey::new());
        fs_err::write(&key_path, key.to_bytes()).unwrap();
        let viewing_group_public_key = viewing_group_public_key();
        fs_err::write(&viewing_group_path, viewing_group_public_key.to_bytes()).unwrap();
        let config = private_tx_config_with_paths(key_path, viewing_group_path);

        let config = config.into_submission_config().unwrap();

        let PrivateTxSubmissionConfig::Private {
            chain_id,
            validator_id,
            unsealing_key,
            archive,
        } = config
        else {
            panic!("expected private mode config");
        };
        assert_eq!(chain_id.as_str(), "miden-devnet");
        assert_eq!(validator_id.as_str(), "validator-1");
        assert_eq!(unsealing_key.scheme(), IesScheme::X25519XChaCha20Poly1305);
        assert_eq!(archive.tee_attestation_id, word(7));
        assert_eq!(archive.viewing_group_public_key, viewing_group_public_key);
    }

    #[test]
    fn private_tx_config_rejects_missing_unsealing_key_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let key_path = temp_dir.path().join("missing.key");
        let viewing_group_path = temp_dir.path().join("viewing-group-pk");
        let config = private_tx_config_with_paths(key_path.clone(), viewing_group_path);

        let err = config.into_submission_config().unwrap_err();
        let message = err.to_string();

        assert!(message.contains("failed to read private tx unsealing key file"));
        assert!(message.contains(&key_path.display().to_string()));
    }

    #[test]
    fn private_tx_config_rejects_malformed_unsealing_key_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let key_path = temp_dir.path().join("malformed.key");
        fs_err::write(&key_path, b"not-a-key").unwrap();
        let viewing_group_path = temp_dir.path().join("viewing-group-pk");
        let config = private_tx_config_with_paths(key_path.clone(), viewing_group_path);

        let err = config.into_submission_config().unwrap_err();
        let message = err.to_string();

        assert!(message.contains("failed to parse private tx unsealing key"));
        assert!(message.contains(&key_path.display().to_string()));
    }

    #[test]
    fn private_tx_config_rejects_unsupported_unsealing_key_scheme() {
        let temp_dir = tempfile::tempdir().unwrap();
        let key_path = temp_dir.path().join("k256.key");
        let key = UnsealingKey::K256XChaCha20Poly1305(K256SecretKey::new());
        fs_err::write(&key_path, key.to_bytes()).unwrap();
        let viewing_group_path = temp_dir.path().join("viewing-group-pk");
        let config = private_tx_config_with_paths(key_path, viewing_group_path);

        let err = config.into_submission_config().unwrap_err();
        let message = err.to_string();

        assert!(message.contains("private tx unsealing key must use"));
        assert!(message.contains("X25519+XChaCha20-Poly1305"));
        assert!(message.contains("K256+XChaCha20-Poly1305"));
    }

    #[test]
    fn private_tx_config_rejects_malformed_viewing_group_public_key_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let key_path = temp_dir.path().join("unsealing.key");
        let viewing_group_path = temp_dir.path().join("malformed-viewing-group-pk");
        let key = UnsealingKey::X25519XChaCha20Poly1305(X25519SecretKey::new());
        fs_err::write(&key_path, key.to_bytes()).unwrap();
        fs_err::write(&viewing_group_path, b"not-a-viewing-group-public-key").unwrap();
        let config = private_tx_config_with_paths(key_path, viewing_group_path.clone());

        let err = config.into_submission_config().unwrap_err();
        let message = err.to_string();

        assert!(message.contains("failed to parse private tx viewing group public key"));
        assert!(message.contains(&viewing_group_path.display().to_string()));
    }

    fn private_tx_config_with_paths(
        key_path: PathBuf,
        viewing_group_path: PathBuf,
    ) -> PrivateTxConfig {
        PrivateTxConfig {
            chain_id: Some("miden-devnet".to_string()),
            validator_id: Some("validator-1".to_string()),
            unsealing_key_file: Some(key_path),
            tee_attestation_id: Some(word(7).to_hex()),
            viewing_group_public_key_file: Some(viewing_group_path),
        }
    }

    fn viewing_group_public_key() -> ViewingGroupPublicKey {
        ViewingGroupPublicKey {
            viewing_group_id: word(20),
            bytes: b"viewing-group-public-key".to_vec(),
        }
    }

    fn word(seed: u32) -> Word {
        Word::from([seed, seed + 1, seed + 2, seed + 3])
    }
}
