use std::collections::BTreeMap;

use reqwest::Url;
use serde_json::Value;

use super::{AnthropicAuthentication, AnthropicFamily};

/// Provider selectors and required path identifiers for one bounded operation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AnthropicScope {
    /// Values substituted into declared provider path parameters.
    pub path_parameters: BTreeMap<String, String>,
    /// Values copied into declared provider query parameters.
    pub query_parameters: BTreeMap<String, String>,
}

/// One credential-free Anthropic GET operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnthropicRequest {
    pub(super) url: Url,
    pub(super) operation_path: String,
    pub(super) family: AnthropicFamily,
    pub(super) cursor: Option<String>,
    pub(super) authentication: AnthropicAuthentication,
}

/// One normalized, tenant-scoped Anthropic event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnthropicRecord {
    /// Tenant from the authenticated runtime context, never the provider payload.
    pub tenant_id: String,
    /// Go-compatible deterministic event identity.
    pub event_id: String,
    /// Provider-owned stable identity selected by the family contract.
    pub provider_id: String,
    /// Exact emitted event kind.
    pub provider_kind: String,
    /// Exact admitted event schema.
    pub schema_ref: String,
    /// Canonical scalar attributes admitted by the source contract.
    pub fields: BTreeMap<String, String>,
    /// Canonical provider payload with trusted path scope injected.
    pub payload: Value,
    /// Provider timestamp, or the trusted observation time when absent.
    pub occurred_at: String,
}

/// One bounded Anthropic provider page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnthropicPage {
    /// Normalized records in provider order after exact duplicate collapse.
    pub records: Vec<AnthropicRecord>,
    /// Validated provider continuation to plan the next request.
    pub next_cursor: Option<String>,
    /// Cursor eligible for durable persistence after append and projection commit.
    pub checkpoint_cursor: Option<String>,
    /// Last accepted occurrence time for restart and parity receipts.
    pub watermark: Option<String>,
}

/// Provider-specific credential-free request and response kernel.
#[derive(Clone, Debug)]
pub struct AnthropicKernel {
    pub(super) base_url: Url,
    pub(super) tenant_id: String,
    pub(super) family: AnthropicFamily,
    pub(super) scope: AnthropicScope,
    pub(super) page_size: usize,
}
