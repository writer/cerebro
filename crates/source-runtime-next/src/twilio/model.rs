//! Public Twilio family, page, and record contracts.

use std::{collections::BTreeMap, str::FromStr};

use serde_json::Value;

use super::TwilioError;

/// Twilio inventory families owned by the Go source catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TwilioFamily {
    /// Twilio accounts.
    Accounts,
    /// Twilio account API keys.
    Keys,
    /// Twilio monitor audit events.
    AuditEvents,
}

impl TwilioFamily {
    /// Return the exact source-catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accounts => "accounts",
            Self::Keys => "keys",
            Self::AuditEvents => "audit_events",
        }
    }

    /// Return the exact provider kind emitted by the Go source.
    pub const fn provider_kind(self) -> &'static str {
        match self {
            Self::Accounts => "twilio.accounts",
            Self::Keys => "twilio.keys",
            Self::AuditEvents => "twilio.audit_events",
        }
    }

    /// Return the exact schema reference emitted by the Go source.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::Accounts => "twilio/accounts/v1",
            Self::Keys => concat!("twilio/", "keys", "/v1"),
            Self::AuditEvents => "twilio/audit_events/v1",
        }
    }

    pub(super) const fn response_keys(self) -> &'static [&'static str] {
        match self {
            Self::Accounts => &[
                "data",
                "items",
                "results",
                "records",
                "accounts",
                "accountss",
            ],
            Self::Keys => &["data", "items", "results", "records", "keys", "keyss"],
            Self::AuditEvents => &[
                "data",
                "items",
                "results",
                "records",
                "audit_events",
                "audit_eventss",
                "auditevents",
                "auditeventss",
            ],
        }
    }
}

impl FromStr for TwilioFamily {
    type Err = TwilioError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "accounts" => Ok(Self::Accounts),
            "keys" => Ok(Self::Keys),
            "audit_events" => Ok(Self::AuditEvents),
            _ => Err(TwilioError::InvalidFamily),
        }
    }
}

/// Provider-local Twilio selectors.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TwilioFilters {
    /// Config-bound account parent required by the keys family.
    pub account_sid: Option<String>,
}

/// One normalized Twilio provider record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TwilioRecord {
    /// Source-catalog family identifier.
    pub family: String,
    /// Exact provider kind.
    pub provider_kind: String,
    /// Exact source schema reference.
    pub schema_ref: String,
    /// Configured source tenant bound to this normalization.
    pub tenant_id: String,
    /// Stable provider identity selected in Go order.
    pub provider_id: String,
    /// Go-compatible tenant, scope, family, and provider event identity.
    pub event_id: String,
    /// Portable normalized attributes.
    pub fields: BTreeMap<String, String>,
    /// UTC provider occurrence time or observation fallback.
    pub occurred_at: String,
    /// Exact raw provider object.
    pub payload: Value,
}

/// One bounded Twilio page and its opaque continuation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TwilioPage {
    /// Deduplicated records in provider order.
    pub records: Vec<TwilioRecord>,
    /// Exact bounded provider continuation.
    pub next_cursor: Option<String>,
}
