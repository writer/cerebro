use std::{collections::BTreeMap, error::Error, fmt, str::FromStr};

use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A SentinelOne runtime family with a provider-owned collection contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SentinelOneFamily {
    /// Management-console and endpoint activity records.
    Activity,
    /// Managed endpoint agents.
    Agent,
    /// Installed applications collected through per-agent fanout.
    Application,
    /// Threat-detection exclusions.
    Exclusion,
    /// Endpoint groups.
    Group,
    /// Tenant sites.
    Site,
    /// Threat detections.
    Threat,
}

impl SentinelOneFamily {
    /// Return the source-catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Activity => "activity",
            Self::Agent => "agent",
            Self::Application => "application",
            Self::Exclusion => "exclusion",
            Self::Group => "group",
            Self::Site => "site",
            Self::Threat => "threat",
        }
    }

    /// Return the emitted provider kind.
    pub const fn provider_kind(self) -> &'static str {
        match self {
            Self::Application => "sentinelone.application_inventory",
            Self::Activity => "sentinelone.activity",
            Self::Agent => "sentinelone.agent",
            Self::Exclusion => "sentinelone.exclusion",
            Self::Group => "sentinelone.group",
            Self::Site => "sentinelone.site",
            Self::Threat => "sentinelone.threat",
        }
    }

    pub(crate) const fn schema_ref(self) -> &'static str {
        match self {
            Self::Application => "sentinelone/application_inventory/v1",
            Self::Activity => "sentinelone/activity/v1",
            Self::Agent => "sentinelone/agent/v1",
            Self::Exclusion => "sentinelone/exclusion/v1",
            Self::Group => "sentinelone/group/v1",
            Self::Site => "sentinelone/site/v1",
            Self::Threat => "sentinelone/threat/v1",
        }
    }

    pub(crate) const fn event_id_family(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Activity => "activity",
            Self::Agent => "agent",
            Self::Exclusion => "exclusion",
            Self::Group => "group",
            Self::Site => "site",
            Self::Threat => "threat",
        }
    }

    pub(super) const fn path(self) -> &'static str {
        match self {
            Self::Activity => "/web/api/v2.1/activities",
            Self::Agent => "/web/api/v2.1/agents",
            Self::Application => "/web/api/v2.1/agents/applications",
            Self::Exclusion => "/web/api/v2.1/exclusions",
            Self::Group => "/web/api/v2.1/groups",
            Self::Site => "/web/api/v2.1/sites",
            Self::Threat => "/web/api/v2.1/threats",
        }
    }
}

impl FromStr for SentinelOneFamily {
    type Err = SentinelOneError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "activity" => Ok(Self::Activity),
            "agent" => Ok(Self::Agent),
            "application" => Ok(Self::Application),
            "exclusion" => Ok(Self::Exclusion),
            "group" => Ok(Self::Group),
            "site" => Ok(Self::Site),
            "threat" => Ok(Self::Threat),
            _ => Err(SentinelOneError::InvalidFamily),
        }
    }
}

/// Optional provider filters accepted by SentinelOne collection families.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SentinelOneFilters {
    /// Restrict agents, groups, threats, or activities to one site.
    pub site_id: Option<String>,
    /// Restrict agents or activities to one group.
    pub group_id: Option<String>,
    /// Restrict application inventory to one agent and skip agent discovery.
    pub agent_id: Option<String>,
    /// Inclusive provider timestamp lower bound for activity or threat reads.
    pub since: Option<String>,
    /// Inclusive provider timestamp upper bound for activity or threat reads.
    pub until: Option<String>,
    /// Restrict activity reads to one provider activity type.
    pub activity_type: Option<String>,
}

/// One credential-free HTTP request planned by the SentinelOne kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SentinelOneRequest {
    pub(super) url: Url,
    pub(super) family: SentinelOneFamily,
    pub(super) stage: RequestStage,
    pub(super) application_state: Option<ApplicationCursor>,
    pub(super) kernel_fingerprint: [u8; 32],
}

impl SentinelOneRequest {
    /// Return the exact provider URL. The caller must authorize this URL before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return the required `Authorization` scheme without credential material.
    pub const fn authorization_scheme(&self) -> &'static str {
        "ApiToken"
    }

    /// Return the required response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }
}

/// One normalized provider record produced by the SentinelOne kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SentinelOneRecord {
    /// Source-catalog family identifier.
    pub family: String,
    /// Emitted provider kind.
    pub provider_kind: String,
    /// Stable provider-owned identity, scoped by agent for applications.
    pub provider_id: String,
    /// Flattened scalar fields used by source mapping.
    pub fields: BTreeMap<String, String>,
    /// Original provider record, with no credentials added.
    pub payload: Value,
}

/// A bounded SentinelOne page and its opaque continuation cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SentinelOnePage {
    /// Normalized records in provider order, or stable identity order for applications.
    pub records: Vec<SentinelOneRecord>,
    /// Provider or versioned fanout cursor for the next read.
    pub next_cursor: Option<String>,
}

/// Result of decoding one SentinelOne response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SentinelOneOutcome {
    /// Application collection resolved an agent and requires one bounded follow-up request.
    Request(SentinelOneRequest),
    /// The provider response completed one source-runtime page.
    Page(SentinelOnePage),
}

/// Safe SentinelOne kernel failures. Messages never include credential values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SentinelOneError {
    /// Family identifier is not one of the seven supported contracts.
    InvalidFamily,
    /// Base URL is not a secure provider origin.
    InvalidBaseUrl,
    /// Page size is outside the provider's 1 through 200 bound.
    InvalidPageSize,
    /// A time filter was supplied to a family that does not support it.
    UnsupportedTimeFilter,
    /// An activity-type filter was supplied to a non-activity family.
    UnsupportedActivityFilter,
    /// A caller attempted to resume a configured agent with a provider cursor.
    ConfiguredAgentCursor,
    /// A versioned application cursor names a different configured agent.
    CursorParentMismatch,
    /// A provider or versioned application cursor is malformed or exceeds its bound.
    InvalidCursor,
    /// A fanout cursor omitted its parent agent.
    CursorParentRequired,
    /// Response JSON does not match the SentinelOne list envelope.
    InvalidResponse,
    /// A provider record omitted its stable identity.
    MissingRecordIdentity,
    /// Agent discovery omitted the agent identity needed for fanout.
    MissingAgentIdentity,
    /// Application response decoding lost its request-bound fanout state.
    MissingApplicationState,
    /// Application inventory returned colliding stable identities for one agent.
    DuplicateApplicationIdentity,
    /// A request was decoded by a kernel configured for another family or origin.
    RequestScopeMismatch,
}

impl fmt::Display for SentinelOneError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "sentinelone family is invalid",
            Self::InvalidBaseUrl => "sentinelone base URL must be a secure origin",
            Self::InvalidPageSize => "sentinelone page size must be between 1 and 200",
            Self::UnsupportedTimeFilter => {
                "sentinelone time filters require the activity or threat family"
            }
            Self::UnsupportedActivityFilter => {
                "sentinelone activity type filter requires the activity family"
            }
            Self::ConfiguredAgentCursor => {
                "sentinelone configured-agent reads reject provider cursors"
            }
            Self::CursorParentMismatch => {
                "sentinelone application cursor parent does not match configured agent"
            }
            Self::InvalidCursor => "sentinelone cursor is invalid",
            Self::CursorParentRequired => "sentinelone application cursor parent is required",
            Self::InvalidResponse => "sentinelone response does not match the list contract",
            Self::MissingRecordIdentity => "sentinelone record identity is missing",
            Self::MissingAgentIdentity => "sentinelone agent identity is missing",
            Self::MissingApplicationState => "sentinelone application request state is missing",
            Self::DuplicateApplicationIdentity => {
                "sentinelone application identity is empty or duplicated"
            }
            Self::RequestScopeMismatch => {
                "sentinelone request family or origin does not match the kernel"
            }
        })
    }
}

impl Error for SentinelOneError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RequestStage {
    Direct,
    ResolveAgent,
    Applications,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct ApplicationCursor {
    pub(super) parent_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(super) next_parent_cursor: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(super) after_record_id: String,
}
