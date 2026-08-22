//! Credential-free source execution protocol for the standalone worker.
//!
//! The wire messages mirror the canonical `cerebro.v1` protobuf definitions.
//! The Go host owns credentials and all network I/O.

use base64::{Engine as _, prelude::BASE64_STANDARD};
use prost::Message;
use serde::{Deserialize, Serialize};

#[path = "source_execution/azure_authorization_policy.rs"]
mod azure_authorization_policy;
#[path = "source_execution/contract.rs"]
mod contract;
#[path = "source_execution/dispatcher.rs"]
mod dispatcher;
#[path = "source_execution/error.rs"]
mod error;
#[path = "source_execution/jumpcloud.rs"]
mod jumpcloud;
#[path = "source_execution/runtime.rs"]
mod runtime;
#[path = "source_execution/wire.rs"]
mod wire;

#[allow(unused_imports)]
pub use contract::{
    MAX_CONTEXT_IDENTIFIER_BYTES, MAX_CURSOR_BYTES, MAX_PUBLIC_CONFIG_BYTES,
    MAX_PUBLIC_CONFIG_ENTRIES, MAX_RECORD_PAYLOAD_BYTES, MAX_RECORDS_PER_RESULT,
    MAX_REQUEST_BODY_BYTES, MAX_SAFE_HEADER_BYTES, MAX_SAFE_HEADER_ENTRIES, canonical_plan_digest,
    canonical_request_intent_digest, canonical_response_headers_digest, canonical_result_digest,
    response_digest, tenant_scoped_event_id, validate_and_deduplicate_records, validate_cursor,
    validate_declared_headers, validate_decode_envelope, validate_decode_result,
    validate_execution_context, validate_http_execution, validate_http_request,
    validate_public_config, validate_response_headers, validate_runtime_metadata,
    validate_safe_receipt,
};
#[allow(unused_imports)]
pub use dispatcher::{
    SourceExecutionAdapter, SourceExecutionDispatcher, compile_plan_bytes, dispatch_decode_bytes,
    dispatch_decode_v2_bytes, dispatch_plan_bytes, dispatch_plan_v2_bytes,
};
pub use error::SourceExecutionError;
pub use runtime::{build_execution_context, seal_page_program, seal_page_program_v2};
#[allow(unused_imports)]
pub use wire::{
    SourceExecutionContextRequestV1, SourceExecutionLifecycleDecisionV1,
    SourceExecutionLifecycleEnvelopeV2, SourceExecutionLifecycleRequestV1, SourceExecutionPlanV1,
    SourceExecutionSelectionRequestV1, SourceWorkerDecodeEnvelopeV2, SourceWorkerDecodeOutputV2,
    SourceWorkerDecodeRequestV1, SourceWorkerDecodeResultV1, SourceWorkerExecutionContextV1,
    SourceWorkerHttpExecutionV2, SourceWorkerHttpRequestV1, SourceWorkerPlanEnvelopeV2,
    SourceWorkerPlanRequestV1, SourceWorkerRecordV1, SourceWorkerRuntimeMetadataV2,
    SourceWorkerSafeReceiptV1,
};

/// Compiles an exact plan through the closed Rust source-family registry.
pub fn compile(input: &[u8]) -> Result<Vec<u8>, SourceExecutionError> {
    compile_plan_bytes(input)
}

#[derive(Deserialize)]
struct SelectionControl {
    source_id: String,
    family_id: String,
}

#[derive(Deserialize)]
struct ContextControl {
    tenant_id: String,
    runtime_id: String,
    prior_cursor: String,
    page_number: u32,
    runtime_generation: u64,
    lease_generation: u64,
    observed_at_unix_millis: i64,
    #[serde(default)]
    public_config: std::collections::HashMap<String, String>,
    #[serde(default)]
    prior_terminal_watermark_unix_millis: i64,
    #[serde(default)]
    prior_checkpoint: String,
}

#[derive(Deserialize)]
struct LifecycleControl {
    plan: String,
    context: String,
    receipt: String,
    result: String,
    current_lease_generation: u64,
    #[serde(default)]
    public_config: std::collections::HashMap<String, String>,
    #[serde(default)]
    prior_terminal_watermark_unix_millis: i64,
    #[serde(default)]
    prior_checkpoint: String,
}

#[derive(Serialize)]
struct LifecycleDecisionControl {
    transition_digest: String,
    admitted_records: Vec<String>,
    checkpoint_cursor: String,
    checkpoint_watermark_unix_millis: i64,
}

/// Decodes the private bounded registry-control envelope used by the Go bridge.
pub fn compile_control(input: &[u8]) -> Result<Vec<u8>, SourceExecutionError> {
    let request = serde_json::from_slice::<SelectionControl>(input)
        .map_err(|_| SourceExecutionError::Protobuf)?;
    Ok(SourceExecutionDispatcher
        .compile_plan(&SourceExecutionSelectionRequestV1 {
            source_id: request.source_id,
            family_id: request.family_id,
        })?
        .encode_to_vec())
}

/// Decodes trusted context inputs from the private bounded bridge envelope.
pub fn context_control(input: &[u8]) -> Result<Vec<u8>, SourceExecutionError> {
    let request = serde_json::from_slice::<ContextControl>(input)
        .map_err(|_| SourceExecutionError::Protobuf)?;
    Ok(build_execution_context(&SourceExecutionContextRequestV1 {
        tenant_id: request.tenant_id,
        runtime_id: request.runtime_id,
        prior_cursor: request.prior_cursor,
        page_number: request.page_number,
        runtime_generation: request.runtime_generation,
        lease_generation: request.lease_generation,
        observed_at_unix_millis: request.observed_at_unix_millis,
        public_config: request.public_config,
        prior_terminal_watermark_unix_millis: request.prior_terminal_watermark_unix_millis,
        prior_checkpoint: request.prior_checkpoint,
    })?
    .encode_to_vec())
}

/// Seals one complete ordered page program for the private bridge.
pub fn transition_control(input: &[u8]) -> Result<Vec<u8>, SourceExecutionError> {
    let control = serde_json::from_slice::<LifecycleControl>(input)
        .map_err(|_| SourceExecutionError::Protobuf)?;
    let decode = |value: &str| {
        BASE64_STANDARD
            .decode(value)
            .map_err(|_| SourceExecutionError::Protobuf)
    };
    let request = SourceExecutionLifecycleRequestV1 {
        plan: Some(
            SourceExecutionPlanV1::decode(decode(&control.plan)?.as_slice())
                .map_err(|_| SourceExecutionError::Protobuf)?,
        ),
        context: Some(
            SourceWorkerExecutionContextV1::decode(decode(&control.context)?.as_slice())
                .map_err(|_| SourceExecutionError::Protobuf)?,
        ),
        receipt: Some(
            SourceWorkerSafeReceiptV1::decode(decode(&control.receipt)?.as_slice())
                .map_err(|_| SourceExecutionError::Protobuf)?,
        ),
        result: Some(
            SourceWorkerDecodeResultV1::decode(decode(&control.result)?.as_slice())
                .map_err(|_| SourceExecutionError::Protobuf)?,
        ),
        current_lease_generation: control.current_lease_generation,
    };
    let metadata = SourceWorkerRuntimeMetadataV2 {
        public_config: control.public_config,
        prior_terminal_watermark_unix_millis: control.prior_terminal_watermark_unix_millis,
        prior_checkpoint: control.prior_checkpoint,
    };
    let decision = if metadata.public_config.is_empty()
        && metadata.prior_terminal_watermark_unix_millis == 0
        && metadata.prior_checkpoint.is_empty()
    {
        seal_page_program(&request)?
    } else {
        seal_page_program_v2(&SourceExecutionLifecycleEnvelopeV2 {
            request: Some(request),
            metadata: Some(metadata),
        })?
    };
    serde_json::to_vec(&LifecycleDecisionControl {
        transition_digest: decision.transition_digest_sha256,
        admitted_records: decision
            .admitted_records
            .into_iter()
            .map(|record| BASE64_STANDARD.encode(record.encode_to_vec()))
            .collect(),
        checkpoint_cursor: decision.checkpoint_cursor,
        checkpoint_watermark_unix_millis: decision.checkpoint_watermark_unix_millis,
    })
    .map_err(|_| SourceExecutionError::InternalRuntime)
}

/// Dispatches one encoded request plan through the closed adapter registry.
pub fn plan(input: &[u8]) -> Result<Vec<u8>, SourceExecutionError> {
    dispatch_plan_bytes(input)
}

/// Dispatches one additive metadata-aware plan through the closed registry.
pub fn plan_v2(input: &[u8]) -> Result<Vec<u8>, SourceExecutionError> {
    dispatch_plan_v2_bytes(input)
}

/// Dispatches one encoded provider response through the closed adapter registry.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, SourceExecutionError> {
    dispatch_decode_bytes(input)
}

/// Dispatches one bounded metadata-aware response through the closed registry.
pub fn decode_v2(input: &[u8]) -> Result<Vec<u8>, SourceExecutionError> {
    dispatch_decode_v2_bytes(input)
}

/// Constructs one trusted execution context with a Rust-owned logical page ID.
pub fn context(input: &[u8]) -> Result<Vec<u8>, SourceExecutionError> {
    runtime::context_bytes(input)
}

/// Seals the digest-bound durable page program.
pub fn transition(input: &[u8]) -> Result<Vec<u8>, SourceExecutionError> {
    runtime::transition_bytes(input)
}

#[cfg(test)]
#[path = "source_execution/tests.rs"]
mod tests;
