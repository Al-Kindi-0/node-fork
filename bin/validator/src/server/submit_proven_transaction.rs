use std::sync::atomic::Ordering;

use miden_node_proto::generated as grpc;
use miden_node_utils::ErrorReport;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::transaction::{ProvenTransaction, TransactionInputs};
use miden_tx::utils::serde::Deserializable;
use tonic::Status;

use crate::db::insert_transaction;
use crate::server::ValidatorServer;
use crate::tx_validation::validate_transaction;

#[tonic::async_trait]
impl grpc::server::validator_api::SubmitProvenTransaction for ValidatorServer {
    type Input = Input;
    type Output = ();

    async fn handle(&self, input: Self::Input) -> tonic::Result<Self::Output> {
        tracing::Span::current().set_attribute("transaction.id", input.tx.id());

        // Validate the transaction.
        let tx_info = validate_transaction(input.tx, input.inputs).await.map_err(|err| {
            Status::invalid_argument(err.as_report_context("Invalid transaction"))
        })?;

        // Store the validated transaction.
        let count = self
            .db
            .transact("insert_transaction", move |conn| insert_transaction(conn, &tx_info))
            .await
            .map_err(|err| {
                Status::internal(err.as_report_context("Failed to insert transaction"))
            })?;

        self.validated_transactions_count.fetch_add(count as u64, Ordering::Relaxed);
        Ok(())
    }

    fn decode(request: grpc::transaction::ProvenTransaction) -> tonic::Result<Self::Input> {
        if request.encrypted_private_payload.is_some() {
            return Err(Status::invalid_argument(
                "Encrypted private payloads are not accepted in public validator mode",
            ));
        }

        let tx = ProvenTransaction::read_from_bytes(&request.transaction).map_err(|err| {
            Status::invalid_argument(err.as_report_context("Invalid proven transaction"))
        })?;

        let inputs = request
            .transaction_inputs
            .ok_or(Status::invalid_argument("Missing transaction inputs"))?;
        let inputs = TransactionInputs::read_from_bytes(&inputs).map_err(|err| {
            Status::invalid_argument(err.as_report_context("Invalid transaction inputs"))
        })?;

        Ok(Self::Input { tx, inputs })
    }

    fn encode(output: Self::Output) -> tonic::Result<()> {
        Ok(output)
    }
}

pub struct Input {
    tx: ProvenTransaction,
    inputs: TransactionInputs,
}

#[cfg(test)]
mod tests {
    use crate::server::ValidatorServer;
    use miden_node_proto::generated as grpc;

    #[test]
    fn public_mode_rejects_encrypted_private_payload() {
        let request = request_with_encrypted_payload(Some(Vec::new()));

        let err = decode_err("encrypted payload with cleartext inputs", request);
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("Encrypted private payloads"));

        let encrypted_only = request_with_encrypted_payload(None);

        let err = decode_err("encrypted payload without cleartext inputs", encrypted_only);
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("Encrypted private payloads"));
    }

    fn request_with_encrypted_payload(
        transaction_inputs: Option<Vec<u8>>,
    ) -> grpc::transaction::ProvenTransaction {
        grpc::transaction::ProvenTransaction {
            transaction: Vec::new(),
            transaction_inputs,
            encrypted_private_payload: Some(b"encrypted".to_vec()),
        }
    }

    fn decode_err(case: &str, request: grpc::transaction::ProvenTransaction) -> tonic::Status {
        match <ValidatorServer as grpc::server::validator_api::SubmitProvenTransaction>::decode(
            request,
        ) {
            Ok(_) => panic!("{case} should be rejected"),
            Err(err) => err,
        }
    }
}
