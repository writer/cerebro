use std::collections::HashMap;

use prost::Message;

/// Compiled credential-free contract for one provider operation.
#[derive(Clone, PartialEq, Message)]
pub struct SourceExecutionPlanV1 {
    /// Stable compiled-plan identifier.
    #[prost(string, tag = "1")]
    pub plan_id: String,
    /// Catalog source identifier.
    #[prost(string, tag = "2")]
    pub source_id: String,
    /// Catalog family identifier.
    #[prost(string, tag = "3")]
    pub family_id: String,
    /// Registered credential-free kernel identifier.
    #[prost(string, tag = "4")]
    pub provider_kernel: String,
    /// HTTP method allowed by the plan.
    #[prost(string, tag = "5")]
    pub method: String,
    /// Exact provider origin allowed by the plan.
    #[prost(string, tag = "6")]
    pub origin: String,
    /// Exact provider path allowed by the plan.
    #[prost(string, tag = "7")]
    pub path: String,
    /// Provider response record selector.
    #[prost(string, tag = "8")]
    pub record_selector: String,
    /// Provider field used for stable identity.
    #[prost(string, tag = "9")]
    pub id_field: String,
    /// Stable identity used only for a declared singleton response.
    #[prost(string, tag = "10")]
    pub singleton_fallback_id: String,
    /// Maximum provider response bytes accepted by the host and adapter.
    #[prost(uint64, tag = "11")]
    pub max_response_bytes: u64,
    /// Canonical Cerebro event kind.
    #[prost(string, tag = "12")]
    pub event_kind: String,
    /// Canonical event schema reference.
    #[prost(string, tag = "13")]
    pub schema_ref: String,
    /// Attributes required before append admission.
    #[prost(string, repeated, tag = "14")]
    pub required_attributes: Vec<String>,
    /// Payload fields required before append admission.
    #[prost(string, repeated, tag = "15")]
    pub required_payload_fields: Vec<String>,
    /// Lowercase SHA-256 of the plan with this field cleared.
    #[prost(string, tag = "16")]
    pub plan_digest_sha256: String,
}

/// Trusted host identity and fencing state for one bounded provider page.
#[derive(Clone, PartialEq, Message)]
pub struct SourceWorkerExecutionContextV1 {
    /// Authenticated tenant identifier; provider data cannot override it.
    #[prost(string, tag = "1")]
    pub tenant_id: String,
    /// Durable source-runtime instance identifier.
    #[prost(string, tag = "2")]
    pub runtime_id: String,
    /// Stable logical page identifier for retries and restart.
    #[prost(string, tag = "3")]
    pub logical_page_id: String,
    /// Validated cursor committed by the preceding page, if any.
    #[prost(string, tag = "4")]
    pub prior_cursor: String,
    /// Runtime authority generation captured by the host.
    #[prost(uint64, tag = "5")]
    pub runtime_generation: u64,
    /// Current lease generation captured by the host.
    #[prost(uint64, tag = "6")]
    pub lease_generation: u64,
    /// Host-captured observation timestamp used for deterministic fallback.
    #[prost(int64, tag = "7")]
    pub observed_at_unix_millis: i64,
}

/// Closed request-planning input for a registered source adapter.
#[derive(Clone, PartialEq, Message)]
pub struct SourceWorkerPlanRequestV1 {
    /// Exact catalog-compiled plan.
    #[prost(message, optional, tag = "1")]
    pub plan: Option<SourceExecutionPlanV1>,
    /// Trusted host execution context.
    #[prost(message, optional, tag = "2")]
    pub context: Option<SourceWorkerExecutionContextV1>,
}

/// Credential-free HTTP operation description returned to the trusted host.
#[derive(Clone, PartialEq, Message)]
pub struct SourceWorkerHttpRequestV1 {
    /// Stable compiled-plan identifier.
    #[prost(string, tag = "1")]
    pub plan_id: String,
    /// HTTP method.
    #[prost(string, tag = "2")]
    pub method: String,
    /// Origin-restricted provider URL without credentials.
    #[prost(string, tag = "3")]
    pub url: String,
    /// Provider response media type.
    #[prost(string, tag = "4")]
    pub accept: String,
    /// Maximum response bytes the host may return.
    #[prost(uint64, tag = "5")]
    pub max_response_bytes: u64,
    /// Exact compiled-plan digest.
    #[prost(string, tag = "6")]
    pub plan_digest_sha256: String,
    /// Digest binding this request to its plan and execution context.
    #[prost(string, tag = "7")]
    pub request_intent_digest: String,
}

/// Bounded provider response and safe host evidence supplied for decoding.
#[derive(Clone, PartialEq, Message)]
pub struct SourceWorkerDecodeRequestV1 {
    /// Exact catalog-compiled plan.
    #[prost(message, optional, tag = "1")]
    pub plan: Option<SourceExecutionPlanV1>,
    /// Host-observed provider status.
    #[prost(uint32, tag = "2")]
    pub status_code: u32,
    /// Bounded provider response bytes.
    #[prost(bytes = "vec", tag = "3")]
    pub response_body: Vec<u8>,
    /// Legacy page binding retained for wire compatibility; must equal context.
    #[prost(string, tag = "4")]
    pub logical_page_id: String,
    /// Request intent returned by planning and recorded by the host.
    #[prost(string, tag = "5")]
    pub request_intent_digest: String,
    /// Provider-safe host receipt with no secret or response content.
    #[prost(message, optional, tag = "6")]
    pub receipt: Option<SourceWorkerSafeReceiptV1>,
    /// Trusted host execution context.
    #[prost(message, optional, tag = "7")]
    pub context: Option<SourceWorkerExecutionContextV1>,
}

/// Provider-safe evidence binding a response to one fenced execution.
#[derive(Clone, PartialEq, Message)]
pub struct SourceWorkerSafeReceiptV1 {
    /// Exact compiled-plan digest.
    #[prost(string, tag = "1")]
    pub plan_digest_sha256: String,
    /// Stable logical page identifier.
    #[prost(string, tag = "2")]
    pub logical_page_id: String,
    /// Exact request-intent digest.
    #[prost(string, tag = "3")]
    pub request_intent_digest: String,
    /// Runtime authority generation used for the request.
    #[prost(uint64, tag = "4")]
    pub runtime_generation: u64,
    /// Lease generation used for the request.
    #[prost(uint64, tag = "5")]
    pub lease_generation: u64,
    /// Non-secret operation identifier for one credential redemption.
    #[prost(string, tag = "6")]
    pub credential_operation: String,
    /// Host-observed provider status.
    #[prost(uint32, tag = "7")]
    pub status_code: u32,
    /// Host-observed provider response length.
    #[prost(uint64, tag = "8")]
    pub response_bytes: u64,
    /// Lowercase SHA-256 of the provider response bytes.
    #[prost(string, tag = "9")]
    pub response_sha256: String,
    /// Authenticated tenant identifier used for the request.
    #[prost(string, tag = "10")]
    pub tenant_id: String,
    /// Durable source-runtime identifier used for the request.
    #[prost(string, tag = "11")]
    pub runtime_id: String,
    /// Host-captured observation timestamp used for the request.
    #[prost(int64, tag = "12")]
    pub observed_at_unix_millis: i64,
}

/// One normalized provider record ready for host append admission.
#[derive(Clone, PartialEq, Message)]
pub struct SourceWorkerRecordV1 {
    /// Stable provider object identifier.
    #[prost(string, tag = "1")]
    pub provider_id: String,
    /// Canonical event attributes.
    #[prost(map = "string, string", tag = "2")]
    pub attributes: HashMap<String, String>,
    /// Canonical JSON event payload.
    #[prost(bytes = "vec", tag = "3")]
    pub payload_json: Vec<u8>,
    /// Deterministic tenant-scoped event identifier.
    #[prost(string, tag = "4")]
    pub event_id: String,
    /// Provider occurrence time or the bound host-observed fallback.
    #[prost(int64, tag = "5")]
    pub occurred_at_unix_millis: i64,
}

/// Normalized result bound to one exact fenced execution and provider page.
#[derive(Clone, PartialEq, Message)]
pub struct SourceWorkerDecodeResultV1 {
    /// Stable compiled-plan identifier.
    #[prost(string, tag = "1")]
    pub plan_id: String,
    /// Exact compiled-plan digest.
    #[prost(string, tag = "2")]
    pub plan_digest_sha256: String,
    /// Stable logical page identifier.
    #[prost(string, tag = "3")]
    pub logical_page_id: String,
    /// Exact request-intent digest.
    #[prost(string, tag = "4")]
    pub request_intent_digest: String,
    /// Validated, deduplicated canonical records.
    #[prost(message, repeated, tag = "5")]
    pub records: Vec<SourceWorkerRecordV1>,
    /// Validated continuation cursor; empty means terminal.
    #[prost(string, tag = "6")]
    pub next_cursor: String,
    /// Digest binding records and continuation to the safe receipt.
    #[prost(string, tag = "7")]
    pub result_digest_sha256: String,
    /// Authenticated tenant identifier.
    #[prost(string, tag = "8")]
    pub tenant_id: String,
    /// Durable source-runtime identifier.
    #[prost(string, tag = "9")]
    pub runtime_id: String,
    /// Runtime authority generation.
    #[prost(uint64, tag = "10")]
    pub runtime_generation: u64,
    /// Lease generation.
    #[prost(uint64, tag = "11")]
    pub lease_generation: u64,
    /// Bound host observation timestamp.
    #[prost(int64, tag = "12")]
    pub observed_at_unix_millis: i64,
}

/// Trusted inputs used by Rust to construct a stable execution context.
#[derive(Clone, PartialEq, Message)]
pub struct SourceExecutionContextRequestV1 {
    /// Authenticated tenant identifier.
    #[prost(string, tag = "1")]
    pub tenant_id: String,
    /// Durable source-runtime identifier.
    #[prost(string, tag = "2")]
    pub runtime_id: String,
    /// Last durably committed provider cursor.
    #[prost(string, tag = "3")]
    pub prior_cursor: String,
    /// One-based page number within the current execution.
    #[prost(uint32, tag = "4")]
    pub page_number: u32,
    /// Current source authority generation.
    #[prost(uint64, tag = "5")]
    pub runtime_generation: u64,
    /// Current exclusive lease generation.
    #[prost(uint64, tag = "6")]
    pub lease_generation: u64,
    /// Host-captured observation time.
    #[prost(int64, tag = "7")]
    pub observed_at_unix_millis: i64,
}

/// Public source and family selected through the closed Rust registry.
#[derive(Clone, PartialEq, Message)]
pub struct SourceExecutionSelectionRequestV1 {
    /// Catalog source identifier.
    #[prost(string, tag = "1")]
    pub source_id: String,
    /// Catalog family identifier.
    #[prost(string, tag = "2")]
    pub family_id: String,
}

/// Inputs Rust binds into one immutable durable page program.
#[derive(Clone, PartialEq, Message)]
pub struct SourceExecutionLifecycleRequestV1 {
    /// Exact catalog-compiled plan.
    #[prost(message, optional, tag = "1")]
    pub plan: Option<SourceExecutionPlanV1>,
    /// Trusted execution context minted by Rust.
    #[prost(message, optional, tag = "2")]
    pub context: Option<SourceWorkerExecutionContextV1>,
    /// Provider-safe host receipt.
    #[prost(message, optional, tag = "3")]
    pub receipt: Option<SourceWorkerSafeReceiptV1>,
    /// Validated normalized page result.
    #[prost(message, optional, tag = "4")]
    pub result: Option<SourceWorkerDecodeResultV1>,
    /// Lease generation captured by the durable lease adapter.
    #[prost(uint64, tag = "5")]
    pub current_lease_generation: u64,
}

/// Rust-authoritative append, projection, and checkpoint program for one page.
#[derive(Clone, PartialEq, Message)]
pub struct SourceExecutionLifecycleDecisionV1 {
    /// Digest binding the complete ordered page program.
    #[prost(string, tag = "1")]
    pub transition_digest_sha256: String,
    /// Validated records that must be appended and projected in order.
    #[prost(message, repeated, tag = "2")]
    pub admitted_records: Vec<SourceWorkerRecordV1>,
    /// Cursor that the atomic commit may persist after projection succeeds.
    #[prost(string, tag = "3")]
    pub checkpoint_cursor: String,
    /// Watermark that the atomic commit may persist after projection succeeds.
    #[prost(int64, tag = "4")]
    pub checkpoint_watermark_unix_millis: i64,
}
