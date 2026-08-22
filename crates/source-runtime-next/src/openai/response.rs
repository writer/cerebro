//! OpenAI page and canonical record types.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use super::{OpenAiError, request::OpenAiKernel};

/// Proposed Go-compatible durable progress after a decoded page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OpenAiCheckpoint {
    /// Exact provider continuation; absent on a terminal page.
    pub cursor_opaque: Option<String>,
    /// Last accepted provider identity for idempotent restart accounting.
    pub last_provider_id: Option<String>,
    /// Provider occurrence time in Unix milliseconds.
    pub watermark_unix_millis: i64,
}

/// One tenant-scoped, contract-valid OpenAI provider record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OpenAiRecord {
    /// Stable tenant-scoped event identity matching the Go oracle contract.
    pub event_id: String,
    /// Trusted tenant identity.
    pub tenant_id: String,
    /// Always `openai`.
    pub source_id: String,
    /// Exact source family.
    pub family: String,
    /// Exact emitted event kind.
    pub provider_kind: String,
    /// Exact emitted event schema.
    pub schema_ref: String,
    /// Stable provider identity within the family and request scope.
    pub provider_id: String,
    /// Provider occurrence time, or the trusted observation time.
    pub occurred_at_unix_millis: i64,
    /// Deterministic normalized event attributes.
    pub attributes: BTreeMap<String, String>,
    /// Original provider object with trusted path scope injected when absent.
    pub payload: Value,
}

/// One bounded OpenAI provider page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OpenAiPage {
    /// Accepted records after deterministic deduplication.
    pub records: Vec<OpenAiRecord>,
    /// Exact provider continuation, unchanged for Go rollback compatibility.
    pub next_cursor: Option<String>,
    /// Proposed durable progress; the kernel never commits it.
    pub proposed_checkpoint: Option<OpenAiCheckpoint>,
}

impl OpenAiKernel {
    /// Decode one bounded provider response into canonical records and proposed progress.
    pub fn decode(
        &self,
        input: &super::OpenAiRequestInput,
        status_code: u16,
        response_body: &[u8],
        observed_at_unix_millis: i64,
    ) -> Result<OpenAiPage, OpenAiError> {
        super::normalize::decode_page(
            self,
            input,
            status_code,
            response_body,
            observed_at_unix_millis,
        )
    }
}
