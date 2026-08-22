use std::{collections::BTreeMap, str::FromStr};

use reqwest::Url;
use serde_json::Value;

use super::GitHubError;

/// One bespoke GitHub source-catalog family.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GitHubFamily {
    /// Organization audit log.
    Audit,
    /// Organization or singleton repository inventory.
    Repository,
    /// Repository Dependabot alerts.
    DependabotAlert,
    /// Organization members, outside collaborators, and installations.
    OrganizationInventory,
    /// Repository pull requests.
    PullRequest,
    /// Organization secret-scanning alerts.
    SecretScanningAlert,
}

impl GitHubFamily {
    /// Source-catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Audit => "audit",
            Self::Repository => "repository",
            Self::DependabotAlert => "dependabot_alert",
            Self::OrganizationInventory => "org_inventory",
            Self::PullRequest => "pull_request",
            Self::SecretScanningAlert => "secret_scanning_alert",
        }
    }
}

impl FromStr for GitHubFamily {
    type Err = GitHubError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "audit" => Ok(Self::Audit),
            "repository" => Ok(Self::Repository),
            "dependabot_alert" => Ok(Self::DependabotAlert),
            "org_inventory" => Ok(Self::OrganizationInventory),
            "pull_request" => Ok(Self::PullRequest),
            "secret_scanning_alert" => Ok(Self::SecretScanningAlert),
            _ => Err(GitHubError::InvalidFamily),
        }
    }
}

/// Public, non-secret family selectors.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GitHubFilters {
    /// Audit inclusion mode (`all`, `web`, or `git`).
    pub audit_include: Option<String>,
    /// GitHub audit phrase expression.
    pub audit_phrase: Option<String>,
    /// Audit ordering (`asc` or `desc`).
    pub audit_order: Option<String>,
    /// Pull-request state (`all`, `open`, or `closed`).
    pub pull_request_state: Option<String>,
    /// Dependabot state (`auto_dismissed`, `dismissed`, `fixed`, or `open`).
    pub dependabot_state: Option<String>,
    /// Secret-scanning state (`open` or `resolved`).
    pub secret_scanning_state: Option<String>,
}

/// Exact bounded operation selected by a planned request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitHubRequestKind {
    /// Primary family request.
    Family,
    /// `/users/{actor}` audit-actor lookup.
    AuditActor,
    /// `/users/{owner}/repos` fallback after organization lookup returns 404.
    RepositoryUserFallback,
}

/// Provider continuation metadata admitted from response headers.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GitHubContinuation {
    /// Opaque GitHub `after`, cursor, or next-page token.
    pub after: Option<String>,
    /// Positive GitHub page number when the API returns page pagination.
    pub page: Option<u32>,
}

/// Public audit-actor lookup result. It contains no token or private provider data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubActorResolution {
    /// Requested actor login.
    pub actor: String,
    /// Resolved GitHub actor type, or `Unresolved` after a 404.
    pub actor_type: String,
    /// Positive provider user ID when resolved.
    pub actor_id: Option<i64>,
    /// Public provider email when present.
    pub actor_email: Option<String>,
}

/// One credential-free GitHub request description.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubRequest {
    pub(super) url: Url,
    pub(super) kind: GitHubRequestKind,
    pub(super) family: GitHubFamily,
    pub(super) stage: &'static str,
    pub(super) cursor: Option<String>,
}

/// One normalized, tenant-scoped GitHub event candidate.
#[derive(Clone, Debug, PartialEq)]
pub struct GitHubRecord {
    /// Tenant from authenticated runtime context, never provider JSON.
    pub tenant_id: String,
    /// Deterministic tenant- and provider-identity-scoped event ID.
    pub event_id: String,
    /// Source identifier.
    pub source_id: String,
    /// Exact event kind.
    pub kind: String,
    /// Exact schema reference.
    pub schema_ref: String,
    /// Source family.
    pub family: String,
    /// Stable provider identity before tenant scoping.
    pub provider_id: String,
    /// Normalized RFC3339 occurrence time.
    pub occurred_at: String,
    /// Go-compatible projection attributes.
    pub attributes: BTreeMap<String, String>,
    /// Go-compatible normalized payload.
    pub payload: Value,
}

/// One bounded normalized GitHub page.
#[derive(Clone, Debug, PartialEq)]
pub struct GitHubPage {
    /// Accepted normalized records in provider order.
    pub records: Vec<GitHubRecord>,
    /// Validated durable cursor. The host persists it only after append and projection succeed.
    pub next_cursor: Option<String>,
}

/// Validated durable progress candidate returned to the trusted host.
///
/// The host may persist this only after every accepted record is appended and
/// projected under the same live lease generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubCheckpointCandidate {
    /// Authenticated tenant scope.
    pub tenant_id: String,
    /// Source family whose progress is represented.
    pub family: GitHubFamily,
    /// Next validated provider cursor, or `None` for a terminal page.
    pub cursor: Option<String>,
    /// Highest normalized occurrence time seen so far.
    pub watermark: Option<String>,
}

/// Provider-specific credential-free GitHub kernel.
#[derive(Clone, Debug)]
pub struct GitHubKernel {
    pub(super) base_url: Url,
    pub(super) tenant_id: String,
    pub(super) owner: String,
    pub(super) repository: Option<String>,
    pub(super) family: GitHubFamily,
    pub(super) filters: GitHubFilters,
    pub(super) per_page: usize,
}
