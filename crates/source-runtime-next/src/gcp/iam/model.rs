//! Public GCP IAM family, request, page, and record contracts.

use std::{collections::BTreeMap, str::FromStr};

use reqwest::Url;
use serde_json::Value;

use super::GcpIamError;

/// GCP IAM inventory families with a shared provider-owned page contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcpIamFamily {
    /// IAM service accounts in one project.
    ServiceAccount,
    /// User-managed and system-managed keys for one service account.
    ServiceAccountKey,
}

impl GcpIamFamily {
    /// Return the source-catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServiceAccount => "service_account",
            Self::ServiceAccountKey => "service_account_key",
        }
    }

    /// Return the exact provider kind emitted by the Go source.
    pub const fn provider_kind(self) -> &'static str {
        match self {
            Self::ServiceAccount => "gcp.service_account",
            Self::ServiceAccountKey => "gcp.service_account_key",
        }
    }

    /// Return the exact schema reference emitted by the Go source.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::ServiceAccount => "gcp/service_account/v1",
            Self::ServiceAccountKey => "gcp/service_account_key/v1",
        }
    }

    pub(super) const fn response_field(self) -> &'static str {
        match self {
            Self::ServiceAccount => "accounts",
            Self::ServiceAccountKey => "keys",
        }
    }
}

impl FromStr for GcpIamFamily {
    type Err = GcpIamError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "service_account" => Ok(Self::ServiceAccount),
            "service_account_key" => Ok(Self::ServiceAccountKey),
            _ => Err(GcpIamError::InvalidFamily),
        }
    }
}

/// Provider-local selectors for GCP IAM inventory.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GcpIamFilters {
    /// One config-bound parent email required by the service-account-key family.
    /// This kernel does not perform parent discovery or fanout.
    pub service_account_email: Option<String>,
}

/// One credential-free IAM API request planned by the GCP kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpIamRequest {
    pub(super) url: Url,
    pub(super) family: GcpIamFamily,
}

impl GcpIamRequest {
    /// Return the exact provider URL. The caller must authorize it before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return the required authorization scheme without credential material.
    pub const fn authorization_scheme(&self) -> &'static str {
        "Bearer"
    }

    /// Return the required response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }
}

/// One normalized GCP IAM provider record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpIamRecord {
    /// Source-catalog family identifier.
    pub family: String,
    /// Emitted provider kind.
    pub provider_kind: String,
    /// Exact provider schema reference.
    pub schema_ref: String,
    /// Configured source tenant bound to this normalization.
    pub tenant_id: String,
    /// Provider identity used as the Go source's URN suffix.
    pub provider_id: String,
    /// Exact sanitized event identity emitted by the Go source.
    pub event_id: String,
    /// Portable scalar attributes used by source mapping.
    pub fields: BTreeMap<String, String>,
    /// Go-compatible UTC occurrence time bound to this observation.
    pub occurred_at: String,
    /// Go-compatible payload envelope containing provider raw and source scope.
    pub payload: Value,
}

/// One bounded GCP IAM page and its opaque provider cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpIamPage {
    /// Normalized records in provider order.
    pub records: Vec<GcpIamRecord>,
    /// Exact nextPageToken supplied by the provider.
    pub next_cursor: Option<String>,
}
