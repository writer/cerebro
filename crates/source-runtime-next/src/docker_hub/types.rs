use std::collections::BTreeMap;

use reqwest::Url;
use serde_json::Value;

use super::DockerHubFamily;

/// One credential-free Docker Hub request plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerHubRequest {
    pub(super) url: Url,
    pub(super) family: DockerHubFamily,
}

/// One normalized tenant-scoped Docker Hub event candidate.
#[derive(Clone, Debug, PartialEq)]
pub struct DockerHubRecord {
    /// Authenticated tenant scope.
    pub tenant_id: String,
    /// Stable Go-compatible tenant- and provider-scoped event identity.
    pub event_id: String,
    /// Stable provider namespace/name identity.
    pub provider_id: String,
    /// Exact family.
    pub family: DockerHubFamily,
    /// Exact event kind.
    pub kind: String,
    /// Exact schema reference.
    pub schema_ref: String,
    /// Normalized RFC3339 occurrence time.
    pub occurred_at: String,
    /// Deterministic projection attributes.
    pub attributes: BTreeMap<String, String>,
    /// Credential-free normalized provider payload.
    pub payload: Value,
}

/// One bounded normalized Docker Hub page.
#[derive(Clone, Debug, PartialEq)]
pub struct DockerHubPage {
    /// The accepted repository record.
    pub records: Vec<DockerHubRecord>,
    /// Repository detail reads are terminal and never emit a cursor.
    pub next_cursor: Option<String>,
}

/// Validated checkpoint candidate for post-append/project persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerHubCheckpointCandidate {
    /// Authenticated tenant scope.
    pub tenant_id: String,
    /// Selected family.
    pub family: DockerHubFamily,
    /// Terminal continuation state.
    pub cursor: Option<String>,
    /// Provider observation watermark.
    pub watermark: String,
}

/// Closed Docker Hub kernel for one tenant and repository.
#[derive(Clone, Debug)]
pub struct DockerHubKernel {
    pub(super) base_url: Url,
    pub(super) tenant_id: String,
    pub(super) namespace: String,
    pub(super) repository: String,
    pub(super) family: DockerHubFamily,
}
