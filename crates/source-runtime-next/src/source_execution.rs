//! Credential-free source execution protocol for the standalone worker.
//!
//! The wire messages mirror the canonical `cerebro.v1` protobuf definitions.
//! The Go host owns credentials and all network I/O.

#[path = "source_execution/azure_authorization_policy.rs"]
mod azure_authorization_policy;
#[path = "source_execution/contract.rs"]
mod contract;
#[path = "source_execution/dispatcher.rs"]
mod dispatcher;
#[path = "source_execution/error.rs"]
mod error;
#[path = "source_execution/wire.rs"]
mod wire;

#[allow(unused_imports)]
pub use contract::{
    MAX_CONTEXT_IDENTIFIER_BYTES, MAX_CURSOR_BYTES, MAX_RECORD_PAYLOAD_BYTES,
    MAX_RECORDS_PER_RESULT, canonical_plan_digest, canonical_request_intent_digest,
    canonical_result_digest, response_digest, tenant_scoped_event_id,
    validate_and_deduplicate_records, validate_cursor, validate_decode_result,
    validate_execution_context, validate_http_request, validate_safe_receipt,
};
#[allow(unused_imports)]
pub use dispatcher::{
    SourceExecutionAdapter, SourceExecutionDispatcher, dispatch_decode_bytes, dispatch_plan_bytes,
};
pub use error::SourceExecutionError;
#[allow(unused_imports)]
pub use wire::{
    SourceExecutionPlanV1, SourceWorkerDecodeRequestV1, SourceWorkerDecodeResultV1,
    SourceWorkerExecutionContextV1, SourceWorkerHttpRequestV1, SourceWorkerPlanRequestV1,
    SourceWorkerRecordV1, SourceWorkerSafeReceiptV1,
};

/// Dispatches one encoded request plan through the closed adapter registry.
pub fn plan(input: &[u8]) -> Result<Vec<u8>, SourceExecutionError> {
    dispatch_plan_bytes(input)
}

/// Dispatches one encoded provider response through the closed adapter registry.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, SourceExecutionError> {
    dispatch_decode_bytes(input)
}

#[cfg(test)]
#[path = "source_execution/tests.rs"]
mod tests;
