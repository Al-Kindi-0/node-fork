use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;

use anyhow::Context;
use miden_node_utils::clap::GrpcOptionsInternal;
use miden_validator::{PrivateTxSubmissionConfig, Validator, ValidatorSigner};

// Starts the validator component.
pub async fn start(
    address: SocketAddr,
    grpc_options: GrpcOptionsInternal,
    signer: ValidatorSigner,
    data_directory: PathBuf,
    sqlite_connection_pool_size: NonZeroUsize,
    private_tx_submission: PrivateTxSubmissionConfig,
) -> anyhow::Result<()> {
    Validator {
        address,
        grpc_options,
        signer,
        data_directory,
        sqlite_connection_pool_size,
        private_tx_submission,
    }
    .serve()
    .await
    .context("failed while serving validator component")
}
