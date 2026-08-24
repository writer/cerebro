//! Provider-local Twilio source-execution adapter core.

use std::{error::Error, fmt};

use time::OffsetDateTime;

use super::{TwilioError, TwilioFamily, TwilioFilters, TwilioKernel, TwilioPage, TwilioRequest};

const DEFAULT_ORIGIN: &str = "https://api.twilio.com";
const MAX_RESPONSE_BYTES: u64 = 8 << 20;
const PAGE_SIZE: usize = 100;

/// Provider-local family adapter used by the canonical source-execution edge.
///
/// The authenticated tenant and provider origin are supplied by the trusted
/// host. This type accepts no credential value and performs no network I/O.
#[derive(Clone, Debug)]
pub(crate) struct TwilioFamilyAdapter {
    kernel: TwilioKernel,
    family: TwilioFamily,
}

impl TwilioFamilyAdapter {
    pub(crate) const fn source_id() -> &'static str {
        "twilio"
    }

    pub(crate) const fn family_id(&self) -> &'static str {
        self.family.as_str()
    }

    pub(crate) const fn provider_kernel(&self) -> &'static str {
        self.family.provider_kind()
    }

    pub(crate) const fn path(&self) -> &'static str {
        match self.family {
            TwilioFamily::Accounts => "/2010-04-01/Accounts.json",
            TwilioFamily::Keys => "/2010-04-01/Accounts/{account_sid}/Keys.json",
            TwilioFamily::AuditEvents => "/v1/Events",
        }
    }

    pub(crate) const fn default_origin() -> &'static str {
        DEFAULT_ORIGIN
    }

    pub(crate) const fn max_response_bytes() -> u64 {
        MAX_RESPONSE_BYTES
    }

    /// Name of the operation-scoped credential application owned by the host.
    pub(crate) const fn credential_operation() -> &'static str {
        "twilio.basic"
    }

    /// Provider authorization scheme applied by the host after request planning.
    pub(crate) const fn credential_scheme() -> &'static str {
        "Basic"
    }

    /// Build a family adapter for authenticated execution scope.
    pub(crate) fn new(
        origin: &str,
        tenant_id: &str,
        family: TwilioFamily,
    ) -> Result<Self, TwilioFamilyAdapterError> {
        let kernel = TwilioKernel::new(
            Some(origin),
            tenant_id,
            family,
            TwilioFilters::default(),
            Some(PAGE_SIZE),
        )?;
        Ok(Self { kernel, family })
    }

    /// Produce one deterministic credential-free provider request.
    pub(crate) fn plan(
        &self,
        prior_cursor: Option<&str>,
    ) -> Result<TwilioRequest, TwilioFamilyAdapterError> {
        self.kernel
            .plan(canonical_prior_cursor(prior_cursor)?)
            .map_err(Into::into)
    }

    /// Decode one host-bounded provider response for the same planned cursor.
    pub(crate) fn decode(
        &self,
        prior_cursor: Option<&str>,
        status_code: u32,
        response_body: &[u8],
        observed_at: OffsetDateTime,
    ) -> Result<TwilioPage, TwilioFamilyAdapterError> {
        validate_status(status_code)?;
        if response_body.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(TwilioFamilyAdapterError::Kernel(
                TwilioError::ResponseTooLarge,
            ));
        }
        let request = self.kernel.plan(canonical_prior_cursor(prior_cursor)?)?;
        self.kernel
            .decode(&request, response_body, observed_at)
            .map_err(Into::into)
    }
}

/// Stable, provider-local execution failures mapped closed at the shared edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TwilioFamilyAdapterError {
    AuthenticationRejected,
    RequiredScopeMissing,
    ProviderTimeout,
    RateLimited,
    ProviderUnavailable,
    UnexpectedStatus(u32),
    Kernel(TwilioError),
}

impl TwilioFamilyAdapterError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::AuthenticationRejected => "twilio.authentication_rejected",
            Self::RequiredScopeMissing => "twilio.required_scope_missing",
            Self::ProviderTimeout => "twilio.provider_timeout",
            Self::RateLimited => "twilio.rate_limited",
            Self::ProviderUnavailable => "twilio.provider_unavailable",
            Self::UnexpectedStatus(_) => "twilio.unexpected_status",
            Self::Kernel(TwilioError::ResponseTooLarge) => "twilio.response_too_large",
            Self::Kernel(TwilioError::InvalidCursor) => "twilio.invalid_cursor",
            Self::Kernel(TwilioError::ConflictingProviderIdentity) => {
                "twilio.conflicting_provider_identity"
            }
            Self::Kernel(_) => "twilio.invalid_provider_response",
        }
    }

    pub(crate) const fn retryable(self) -> bool {
        matches!(
            self,
            Self::ProviderTimeout | Self::RateLimited | Self::ProviderUnavailable
        )
    }

    pub(crate) const fn operator_action(self) -> &'static str {
        match self {
            Self::AuthenticationRejected => "repair credential binding",
            Self::RequiredScopeMissing => "grant required provider scope",
            Self::ProviderTimeout | Self::RateLimited | Self::ProviderUnavailable => "retry later",
            Self::UnexpectedStatus(_) => "inspect provider status",
            Self::Kernel(TwilioError::InvalidCursor) => "restart collection from a valid cursor",
            Self::Kernel(_) => "inspect quarantined provider records",
        }
    }
}

impl From<TwilioError> for TwilioFamilyAdapterError {
    fn from(value: TwilioError) -> Self {
        Self::Kernel(value)
    }
}

impl fmt::Display for TwilioFamilyAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedStatus(status) => {
                write!(
                    formatter,
                    "{}: provider returned HTTP {status}",
                    self.code()
                )
            }
            Self::Kernel(error) => write!(formatter, "{}: {error}", self.code()),
            _ => formatter.write_str(self.code()),
        }
    }
}

impl Error for TwilioFamilyAdapterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Kernel(error) => Some(error),
            _ => None,
        }
    }
}

fn validate_status(status_code: u32) -> Result<(), TwilioFamilyAdapterError> {
    match status_code {
        200 => Ok(()),
        401 => Err(TwilioFamilyAdapterError::AuthenticationRejected),
        403 => Err(TwilioFamilyAdapterError::RequiredScopeMissing),
        408 => Err(TwilioFamilyAdapterError::ProviderTimeout),
        429 => Err(TwilioFamilyAdapterError::RateLimited),
        500..=599 => Err(TwilioFamilyAdapterError::ProviderUnavailable),
        status => Err(TwilioFamilyAdapterError::UnexpectedStatus(status)),
    }
}

fn canonical_prior_cursor(
    prior_cursor: Option<&str>,
) -> Result<Option<&str>, TwilioFamilyAdapterError> {
    match prior_cursor {
        None | Some("") => Ok(None),
        Some(cursor) if cursor.trim() != cursor => Err(TwilioError::InvalidCursor.into()),
        Some(cursor) => Ok(Some(cursor)),
    }
}

mod source_execution;

// The closed shared dispatcher consumes this export without exposing provider
// implementation details outside the crate.
#[allow(unused_imports)]
pub(crate) use source_execution::{
    TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER, TWILIO_AUDIT_EVENTS_SOURCE_EXECUTION_ADAPTER,
};
