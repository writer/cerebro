//! Closed PagerDuty family, plan, record, and page contracts.

use std::{collections::BTreeMap, str::FromStr};

use serde_json::Value;

use super::PagerDutyError;

/// PagerDuty responder-topology families preserved from the Go source oracle.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PagerDutyFamily {
    /// PagerDuty responders.
    User,
    /// PagerDuty teams.
    Team,
    /// PagerDuty incident-routing services.
    Service,
    /// PagerDuty responder schedules.
    Schedule,
    /// PagerDuty escalation policies.
    EscalationPolicy,
    /// PagerDuty service integrations.
    Integration,
    /// PagerDuty integration vendors.
    Vendor,
}

impl PagerDutyFamily {
    /// Every family in deterministic catalog order.
    pub const ALL: [Self; 7] = [
        Self::User,
        Self::Team,
        Self::Service,
        Self::Schedule,
        Self::EscalationPolicy,
        Self::Integration,
        Self::Vendor,
    ];

    /// Exact source-family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Team => "team",
            Self::Service => "service",
            Self::Schedule => "schedule",
            Self::EscalationPolicy => "escalation_policy",
            Self::Integration => "integration",
            Self::Vendor => "vendor",
        }
    }

    /// Exact provider response-array key.
    pub const fn response_key(self) -> &'static str {
        match self {
            Self::User => "users",
            Self::Team => "teams",
            Self::Service => "services",
            Self::Schedule => "schedules",
            Self::EscalationPolicy => "escalation_policies",
            Self::Integration => "integrations",
            Self::Vendor => "vendors",
        }
    }

    /// Exact event kind admitted for this family.
    pub const fn event_kind(self) -> &'static str {
        match self {
            Self::User => "pagerduty.user",
            Self::Team => "pagerduty.team",
            Self::Service => "pagerduty.service",
            Self::Schedule => "pagerduty.schedule",
            Self::EscalationPolicy => "pagerduty.escalation_policy",
            Self::Integration => "pagerduty.integration",
            Self::Vendor => "pagerduty.vendor",
        }
    }

    /// Exact source schema admitted for this family.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::User => "pagerduty/user/v1",
            Self::Team => "pagerduty/team/v1",
            Self::Service => "pagerduty/service/v1",
            Self::Schedule => "pagerduty/schedule/v1",
            Self::EscalationPolicy => "pagerduty/escalation_policy/v1",
            Self::Integration => "pagerduty/integration/v1",
            Self::Vendor => "pagerduty/vendor/v1",
        }
    }

    /// Tenant-scoped provider-object URN kind used by the Go projector.
    pub const fn urn_kind(self) -> &'static str {
        match self {
            Self::User => "pagerduty_user",
            Self::Team => "pagerduty_team",
            Self::Service => "pagerduty_service",
            Self::Schedule => "pagerduty_schedule",
            Self::EscalationPolicy => "pagerduty_escalation_policy",
            Self::Integration => "pagerduty_integration",
            Self::Vendor => "pagerduty_vendor",
        }
    }

    /// Family-specific provider identity attribute required by the event contract.
    pub const fn identity_attribute(self) -> &'static str {
        match self {
            Self::User => "user_id",
            Self::Team => "team_id",
            Self::Service => "service_id",
            Self::Schedule => "schedule_id",
            Self::EscalationPolicy => "escalation_policy_id",
            Self::Integration => "integration_id",
            Self::Vendor => "vendor_id",
        }
    }

    /// Closed request path template.
    pub const fn path_template(self) -> &'static str {
        match self {
            Self::User => "/users",
            Self::Team => "/teams",
            Self::Service => "/services",
            Self::Schedule => "/schedules",
            Self::EscalationPolicy => "/escalation_policies",
            Self::Integration => "/services/{service_id}/integrations",
            Self::Vendor => "/vendors",
        }
    }
}

impl FromStr for PagerDutyFamily {
    type Err = PagerDutyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "user" => Ok(Self::User),
            "team" => Ok(Self::Team),
            "service" => Ok(Self::Service),
            "schedule" => Ok(Self::Schedule),
            "escalation_policy" => Ok(Self::EscalationPolicy),
            "integration" => Ok(Self::Integration),
            "vendor" => Ok(Self::Vendor),
            _ => Err(PagerDutyError::InvalidFamily),
        }
    }
}

/// Provider-local bounded configuration that contains no credential values.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PagerDutyFilters {
    /// Service fan-out scope for the integration family.
    pub service_ids: Vec<String>,
}

/// Closed runtime definition for one PagerDuty family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PagerDutyPlan {
    /// Source ID.
    pub source_id: &'static str,
    /// Family ID.
    pub family_id: &'static str,
    /// HTTP method.
    pub method: &'static str,
    /// Authentication header applied only by the trusted host.
    pub auth_header: &'static str,
    /// Exact PagerDuty authentication scheme metadata without credential bytes.
    pub auth_scheme: &'static str,
    /// Allowed provider origin.
    pub origin: String,
    /// Closed request path template.
    pub path_template: &'static str,
    /// Response-array selector.
    pub record_selector: String,
    /// Stable provider identity field.
    pub id_field: &'static str,
    /// Provider offset parameter.
    pub offset_param: &'static str,
    /// Provider page-size parameter.
    pub page_size_param: &'static str,
    /// Provider continuation flag.
    pub has_more_key: &'static str,
    /// Optional plural config field that drives bounded path fan-out.
    pub fanout_config_key: Option<&'static str>,
    /// Event kind.
    pub event_kind: &'static str,
    /// Event schema reference.
    pub schema_ref: &'static str,
    /// Required normalized attributes.
    pub required_attributes: Vec<&'static str>,
    /// Required payload fields.
    pub required_payload_fields: Vec<&'static str>,
    /// Response byte ceiling.
    pub max_response_bytes: usize,
    /// Record-count ceiling.
    pub max_records_per_page: usize,
}

/// One normalized PagerDuty provider record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PagerDutyRecord {
    /// Closed family.
    pub family: PagerDutyFamily,
    /// Tenant bound by the execution context.
    pub tenant_id: String,
    /// Stable provider identity.
    pub provider_id: String,
    /// Go-compatible tenant- and request-scope-bound event identity.
    pub event_id: String,
    /// Exact event kind.
    pub event_kind: String,
    /// Exact event schema.
    pub schema_ref: String,
    /// Deterministic normalized attributes.
    pub attributes: BTreeMap<String, String>,
    /// Provider occurrence time or caller-supplied observation time.
    pub occurred_at: String,
    /// Exact raw provider object.
    pub payload: Value,
}

/// One bounded PagerDuty page and its proposed progress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PagerDutyPage {
    /// Deduplicated records in provider order.
    pub records: Vec<PagerDutyRecord>,
    /// Exact Go-compatible continuation, when another provider or fan-out page remains.
    pub next_cursor: Option<String>,
    /// Proposed durable cursor. The host commits it only after append and projection.
    pub checkpoint_cursor: Option<String>,
}
