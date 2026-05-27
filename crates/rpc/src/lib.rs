mod server;
#[cfg(test)]
mod tests;

pub use server::{PrivateTxSubmissionConfig, Rpc};

// CONSTANTS
// =================================================================================================
pub const COMPONENT: &str = "miden-rpc";
