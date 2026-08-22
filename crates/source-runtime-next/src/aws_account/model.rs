use std::{collections::BTreeMap, error::Error, fmt};

use reqwest::Url;
use serde_json::Value;

pub(super) const FAMILY: &str = "account_contact";
pub(super) const PROVIDER_KIND: &str = "aws.account_contact";
pub(super) const SCHEMA_REF: &str = "aws/account_contact/v1";
pub(super) const SIGNING_SERVICE: &str = "account";
pub(super) const SECURITY_CONTACT_TYPE: &str = "SECURITY";
pub(super) const MAX_RESPONSE_BYTES: usize = 64 * 1024;
pub(super) const MAX_JSON_DEPTH: usize = 16;

/// Purpose of one AWS account-contact provider request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AwsAccountContactRequestKind {
    /// Read primary account contact information.
    PrimaryContact,
    /// Read the security alternate contact.
    SecurityAlternateContact,
}

impl AwsAccountContactRequestKind {
    pub(super) const fn path(self) -> &'static str {
        match self {
            Self::PrimaryContact => "/getContactInformation",
            Self::SecurityAlternateContact => "/getAlternateContact",
        }
    }

    pub(super) const fn body(self) -> &'static [u8] {
        match self {
            Self::PrimaryContact => b"{}",
            Self::SecurityAlternateContact => br#"{"AlternateContactType":"SECURITY"}"#,
        }
    }
}

/// One credential-free AWS Account service request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsAccountContactRequest {
    pub(super) url: Url,
    pub(super) account_id: String,
    pub(super) signing_region: String,
    pub(super) kind: AwsAccountContactRequestKind,
    pub(super) primary_contact_configured: Option<bool>,
}

impl AwsAccountContactRequest {
    /// Return the exact provider URL. The trusted host must authorize it before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return the provider request purpose.
    pub const fn kind(&self) -> AwsAccountContactRequestKind {
        self.kind
    }

    /// Return the exact HTTP method.
    pub const fn method(&self) -> &'static str {
        "POST"
    }

    /// Return the exact credential-free JSON request body.
    pub const fn body(&self) -> &'static [u8] {
        self.kind.body()
    }

    /// Return the required request media type.
    pub const fn content_type(&self) -> &'static str {
        "application/json"
    }

    /// Return the required response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }

    /// Return the AWS Signature Version 4 service name.
    pub const fn signing_service(&self) -> &'static str {
        SIGNING_SERVICE
    }

    /// Return the AWS Signature Version 4 region.
    pub fn signing_region(&self) -> &str {
        &self.signing_region
    }
}

/// One normalized AWS account-contact posture record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsAccountContactRecord {
    /// Source-catalog family identifier.
    pub family: String,
    /// Emitted provider kind.
    pub provider_kind: String,
    /// Versioned provider schema reference.
    pub schema_ref: String,
    /// Stable Go-compatible provider identity, scoped by AWS account.
    ///
    /// The trusted host supplies the authenticated tenant on the event
    /// envelope; canonical Cerebro identity is therefore tenant plus this
    /// provider identity, never a tenant value read from provider data.
    pub provider_id: String,
    /// Portable scalar attributes used by source mapping.
    pub fields: BTreeMap<String, String>,
    /// Redacted normalized provider posture with no raw contact values.
    pub payload: Value,
}

/// Complete non-paginated AWS account-contact response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsAccountContactPage {
    /// The single account posture record.
    pub records: Vec<AwsAccountContactRecord>,
    /// AWS Account contact APIs expose no continuation cursor.
    pub next_cursor: Option<String>,
    /// Go-compatible durable checkpoint cursor proposed after commit.
    pub checkpoint_cursor: String,
}

/// Result of decoding one AWS account-contact provider response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwsAccountContactOutcome {
    /// Primary posture is known and the security-contact request is required.
    Request(AwsAccountContactRequest),
    /// Both contact-posture requests are complete.
    Page(AwsAccountContactPage),
}

/// Safe AWS account-contact kernel failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwsAccountContactError {
    /// Base URL is not a secure provider origin.
    InvalidBaseUrl,
    /// Account identity is not exactly twelve ASCII digits.
    InvalidAccountId,
    /// Signing region is empty or contains an unsafe character.
    InvalidSigningRegion,
    /// This full-snapshot family received a continuation cursor.
    CursorNotSupported,
    /// Durable checkpoint cursor does not match the configured AWS account.
    InvalidCheckpoint,
    /// Response exceeds the provider-local byte limit.
    ResponseTooLarge,
    /// Response exceeds the provider-local JSON nesting limit.
    ResponseTooDeep,
    /// Response JSON does not match the selected AWS Account operation.
    InvalidResponse,
    /// A request was not issued by this origin, account, region, or stage.
    RequestScopeMismatch,
    /// A request carries state that is invalid for its operation stage.
    RequestStageMismatch,
    /// The provider rejected the operation credential or request signature.
    AuthenticationRejected {
        /// HTTP status returned by the provider.
        status: u16,
        /// Safe Smithy provider error identifier, when available.
        code: Option<String>,
    },
    /// The credential lacks an AWS Account action required by this family.
    RequiredScopeMissing {
        /// HTTP status returned by the provider.
        status: u16,
        /// Safe Smithy provider error identifier, when available.
        code: Option<String>,
    },
    /// The provider exhausted the caller's request budget.
    RateLimited {
        /// HTTP status returned by the provider.
        status: u16,
        /// Safe Smithy provider error identifier, when available.
        code: Option<String>,
    },
    /// The AWS Account service returned a retryable server failure.
    ProviderUnavailable {
        /// HTTP status returned by the provider.
        status: u16,
        /// Safe Smithy provider error identifier, when available.
        code: Option<String>,
    },
    /// The provider returned another non-success status.
    UnexpectedProviderStatus {
        /// HTTP status returned by the provider.
        status: u16,
        /// Safe Smithy provider error identifier, when available.
        code: Option<String>,
    },
}

impl AwsAccountContactError {
    /// Return the next valid operator action for a typed provider failure.
    pub const fn operator_action(&self) -> Option<&'static str> {
        match self {
            Self::AuthenticationRejected { .. } => {
                Some("repair AWS credential binding or request signing")
            }
            Self::RequiredScopeMissing { .. } => {
                Some("grant account:GetContactInformation and account:GetAlternateContact")
            }
            Self::RateLimited { .. } | Self::ProviderUnavailable { .. } => {
                Some("retry the same checkpoint later")
            }
            Self::UnexpectedProviderStatus { .. } => {
                Some("inspect the bounded provider status and contract revision")
            }
            _ => None,
        }
    }

    /// Report whether retrying the identical progress input may succeed unchanged.
    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::ProviderUnavailable { .. }
        )
    }
}

impl fmt::Display for AwsAccountContactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBaseUrl => formatter.write_str("invalid AWS Account service base URL"),
            Self::InvalidAccountId => formatter.write_str("invalid AWS account identifier"),
            Self::InvalidSigningRegion => formatter.write_str("invalid AWS signing region"),
            Self::CursorNotSupported => {
                formatter.write_str("AWS account-contact family does not paginate")
            }
            Self::InvalidCheckpoint => {
                formatter.write_str("invalid AWS account-contact checkpoint")
            }
            Self::ResponseTooLarge => {
                formatter.write_str("AWS Account service response exceeds 65536 bytes")
            }
            Self::ResponseTooDeep => {
                formatter.write_str("AWS Account service response exceeds 16 JSON levels")
            }
            Self::InvalidResponse => formatter.write_str("invalid AWS Account service response"),
            Self::RequestScopeMismatch => {
                formatter.write_str("AWS account-contact request scope mismatch")
            }
            Self::RequestStageMismatch => {
                formatter.write_str("AWS account-contact request stage mismatch")
            }
            Self::AuthenticationRejected { status, code } => {
                write!(
                    formatter,
                    "AWS Account authentication rejected with HTTP {status}"
                )?;
                write_safe_code(formatter, code)?;
                Ok(())
            }
            Self::RequiredScopeMissing { status, code } => {
                write!(
                    formatter,
                    "AWS Account required scope missing with HTTP {status}"
                )?;
                write_safe_code(formatter, code)?;
                Ok(())
            }
            Self::RateLimited { status, code } => {
                write!(formatter, "AWS Account rate limited with HTTP {status}")?;
                write_safe_code(formatter, code)?;
                Ok(())
            }
            Self::ProviderUnavailable { status, code } => {
                write!(
                    formatter,
                    "AWS Account service unavailable with HTTP {status}"
                )?;
                write_safe_code(formatter, code)?;
                Ok(())
            }
            Self::UnexpectedProviderStatus { status, code } => {
                write!(formatter, "AWS Account service returned HTTP {status}")?;
                write_safe_code(formatter, code)?;
                Ok(())
            }
        }
    }
}

fn write_safe_code(formatter: &mut fmt::Formatter<'_>, code: &Option<String>) -> fmt::Result {
    if let Some(code) = code {
        write!(formatter, " ({code})")?;
    }
    Ok(())
}

impl Error for AwsAccountContactError {}
