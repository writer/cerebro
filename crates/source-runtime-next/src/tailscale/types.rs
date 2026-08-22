use std::collections::BTreeMap;

use serde_json::Value;

use super::TailscaleFamily;

/// One credential-free Tailscale request plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleRequest {
    pub(super) family: TailscaleFamily,
    pub(super) url: reqwest::Url,
    pub(super) cursor: Option<String>,
    pub(super) page_size: usize,
}

/// One normalized tenant-scoped Tailscale event candidate.
#[derive(Debug, Clone, PartialEq)]
pub struct TailscaleRecord {
    /// Authenticated tenant scope.
    pub tenant_id: String,
    /// Provider family.
    pub family: TailscaleFamily,
    /// Stable tenant-, request-, family-, and provider-scoped identity.
    pub event_id: String,
    /// Exact event kind.
    pub kind: String,
    /// Exact schema reference.
    pub schema_ref: String,
    /// Normalized observation time.
    pub occurred_at: String,
    /// Canonical Go-compatible attributes.
    pub attributes: BTreeMap<String, String>,
    /// Canonical provider payload with no credential or tenant material.
    pub payload: Value,
}

/// Bounded normalized response page.
#[derive(Debug, Clone, PartialEq)]
pub struct TailscalePage {
    /// Accepted records after deterministic deduplication.
    pub records: Vec<TailscaleRecord>,
    /// Validated continuation proposed to the durable host.
    pub next_cursor: Option<String>,
}

/// Non-secret response metadata supplied by the trusted host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TailscaleResponseMetadata {
    /// Provider continuation extracted from a response header, when present.
    pub next_cursor: Option<String>,
    /// Parsed Retry-After seconds.
    pub retry_after_seconds: Option<u64>,
}

/// Candidate checkpoint; the durable host persists it only after append and projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleCheckpointCandidate {
    /// Authenticated tenant scope.
    pub tenant_id: String,
    /// Family whose progress is advancing.
    pub family: TailscaleFamily,
    /// Validated continuation.
    pub cursor: Option<String>,
    /// Greatest accepted observation time, preserving a prior watermark.
    pub watermark: Option<String>,
}

/// Closed Tailscale kernel for one tenant, tailnet, and family.
#[derive(Debug, Clone)]
pub struct TailscaleKernel {
    pub(super) base_url: reqwest::Url,
    pub(super) tenant_id: String,
    pub(super) tailnet: String,
    pub(super) family: TailscaleFamily,
    pub(super) page_size: usize,
    pub(super) observed_at: String,
}
