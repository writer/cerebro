use std::collections::HashMap;

use prost::Message;

#[derive(Clone, PartialEq, Message)]
pub(super) struct SourceExecutionPlanV1 {
    #[prost(string, tag = "1")]
    pub(super) plan_id: String,
    #[prost(string, tag = "2")]
    pub(super) source_id: String,
    #[prost(string, tag = "3")]
    pub(super) family_id: String,
    #[prost(string, tag = "4")]
    pub(super) provider_kernel: String,
    #[prost(string, tag = "5")]
    pub(super) method: String,
    #[prost(string, tag = "6")]
    pub(super) origin: String,
    #[prost(string, tag = "7")]
    pub(super) path: String,
    #[prost(string, tag = "8")]
    pub(super) record_selector: String,
    #[prost(string, tag = "9")]
    pub(super) id_field: String,
    #[prost(string, tag = "10")]
    pub(super) singleton_fallback_id: String,
    #[prost(uint64, tag = "11")]
    pub(super) max_response_bytes: u64,
    #[prost(string, tag = "12")]
    pub(super) event_kind: String,
    #[prost(string, tag = "13")]
    pub(super) schema_ref: String,
    #[prost(string, repeated, tag = "14")]
    pub(super) required_attributes: Vec<String>,
    #[prost(string, repeated, tag = "15")]
    pub(super) required_payload_fields: Vec<String>,
    #[prost(string, tag = "16")]
    pub(super) plan_digest_sha256: String,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct SourceWorkerHttpRequestV1 {
    #[prost(string, tag = "1")]
    pub(super) plan_id: String,
    #[prost(string, tag = "2")]
    pub(super) method: String,
    #[prost(string, tag = "3")]
    pub(super) url: String,
    #[prost(string, tag = "4")]
    pub(super) accept: String,
    #[prost(uint64, tag = "5")]
    pub(super) max_response_bytes: u64,
    #[prost(string, tag = "6")]
    pub(super) plan_digest_sha256: String,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct SourceWorkerDecodeRequestV1 {
    #[prost(message, optional, tag = "1")]
    pub(super) plan: Option<SourceExecutionPlanV1>,
    #[prost(uint32, tag = "2")]
    pub(super) status_code: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub(super) response_body: Vec<u8>,
    #[prost(string, tag = "4")]
    pub(super) logical_page_id: String,
    #[prost(string, tag = "5")]
    pub(super) request_intent_digest: String,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct SourceWorkerRecordV1 {
    #[prost(string, tag = "1")]
    pub(super) provider_id: String,
    #[prost(map = "string, string", tag = "2")]
    pub(super) attributes: HashMap<String, String>,
    #[prost(bytes = "vec", tag = "3")]
    pub(super) payload_json: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct SourceWorkerDecodeResultV1 {
    #[prost(string, tag = "1")]
    pub(super) plan_id: String,
    #[prost(string, tag = "2")]
    pub(super) plan_digest_sha256: String,
    #[prost(string, tag = "3")]
    pub(super) logical_page_id: String,
    #[prost(string, tag = "4")]
    pub(super) request_intent_digest: String,
    #[prost(message, repeated, tag = "5")]
    pub(super) records: Vec<SourceWorkerRecordV1>,
    #[prost(string, tag = "6")]
    pub(super) next_cursor: String,
    #[prost(string, tag = "7")]
    pub(super) result_digest_sha256: String,
}
