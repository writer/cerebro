//! Stable fail-closed Kubernetes kernel errors.

use std::{error::Error, fmt};

/// Stable Kubernetes request, response, identity, and contract failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KubernetesError {
    /// The selected family is not in the checked source contract.
    InvalidFamily,
    /// The catalog family does not match the closed Kubernetes runtime contract.
    InvalidRuntimeDefinition,
    /// The source tenant is missing or invalid.
    MissingTenantId,
    /// A stable cluster identity is required.
    MissingClusterIdentity,
    /// The configured API server is not a closed HTTPS origin.
    InvalidApiServer,
    /// The requested page size is outside the inclusive 1 through 500 bound.
    InvalidPageSize,
    /// The provider continuation is malformed, oversized, or non-round-trippable.
    InvalidCursor,
    /// A request was not created by this exact family kernel.
    RequestScopeMismatch,
    /// The provider rejected authentication.
    AuthenticationRejected,
    /// The provider credential lacks the required Kubernetes RBAC permission.
    PermissionDenied,
    /// The provider asked the caller to retry later.
    RateLimited,
    /// The Kubernetes API server is temporarily unavailable.
    ProviderUnavailable,
    /// The provider returned a status outside the closed contract.
    UnexpectedProviderStatus(u16),
    /// The bounded host response exceeded eight mebibytes.
    ResponseTooLarge,
    /// The page exceeded the configured maximum record count.
    TooManyRecords,
    /// The response did not match the Kubernetes list or version contract.
    MalformedResponse,
    /// A provider object has no stable UID or declared composite fallback.
    MissingStableIdentity,
    /// Two different records reused the same provider identity.
    ConflictingProviderIdentity,
    /// A catalog-required normalized attribute is missing.
    MissingRequiredAttribute(&'static str),
    /// A catalog-required payload field is missing.
    MissingRequiredPayloadField(&'static str),
    /// A provider-controlled identity could not be encoded safely.
    InvalidCanonicalIdentity,
}

impl fmt::Display for KubernetesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFamily => formatter.write_str("kubernetes family is not registered"),
            Self::InvalidRuntimeDefinition => {
                formatter.write_str("kubernetes catalog family does not match the runtime contract")
            }
            Self::MissingTenantId => formatter.write_str("kubernetes tenant_id is required"),
            Self::MissingClusterIdentity => formatter
                .write_str("kubernetes cluster_id or equivalent stable identity is required"),
            Self::InvalidApiServer => {
                formatter.write_str("kubernetes api_server must be a closed HTTPS origin")
            }
            Self::InvalidPageSize => {
                formatter.write_str("kubernetes per_page must be between 1 and 500")
            }
            Self::InvalidCursor => formatter.write_str("kubernetes continuation is invalid"),
            Self::RequestScopeMismatch => {
                formatter.write_str("kubernetes request does not match the kernel")
            }
            Self::AuthenticationRejected => formatter
                .write_str("kubernetes authentication was rejected; repair the credential binding"),
            Self::PermissionDenied => formatter.write_str(
                "kubernetes permission was denied; grant list access for the selected family",
            ),
            Self::RateLimited => formatter
                .write_str("kubernetes request was rate limited; retry after provider backoff"),
            Self::ProviderUnavailable => formatter
                .write_str("kubernetes API server is unavailable; retry the bounded operation"),
            Self::UnexpectedProviderStatus(status) => {
                write!(formatter, "kubernetes returned unexpected status {status}")
            }
            Self::ResponseTooLarge => {
                formatter.write_str("kubernetes response exceeds 8388608 bytes")
            }
            Self::TooManyRecords => {
                formatter.write_str("kubernetes response exceeds the compiled record bound")
            }
            Self::MalformedResponse => {
                formatter.write_str("kubernetes response does not match the selected family")
            }
            Self::MissingStableIdentity => {
                formatter.write_str("kubernetes record has no stable identity")
            }
            Self::ConflictingProviderIdentity => formatter.write_str(
                "kubernetes page contains conflicting records with one provider identity",
            ),
            Self::MissingRequiredAttribute(field) => {
                write!(
                    formatter,
                    "kubernetes record is missing required attribute {field}"
                )
            }
            Self::MissingRequiredPayloadField(field) => {
                write!(
                    formatter,
                    "kubernetes record is missing required payload field {field}"
                )
            }
            Self::InvalidCanonicalIdentity => formatter.write_str(
                "kubernetes tenant or provider identity cannot form a canonical identity",
            ),
        }
    }
}

impl Error for KubernetesError {}
