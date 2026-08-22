use std::{error::Error, fmt};

/// Safe Archetype kernel failures. Messages never include credentials or response bodies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArchetypeError {
    /// Family identifier is not one of the two supported contracts.
    InvalidFamily,
    /// Base URL is not a secure provider origin.
    InvalidBaseUrl,
    /// API prefix is not a normalized absolute request path.
    InvalidApiPrefix,
    /// Fanout concurrency is outside the Go-compatible 1 through 16 bound.
    InvalidFanoutConcurrency,
    /// The trusted runtime context did not bind a tenant identity.
    MissingTenantId,
    /// The explicit observation timestamp is not RFC 3339.
    InvalidObservedAt,
    /// A scan or repository scope ID is zero.
    InvalidScopedId,
    /// Response JSON does not match the selected Archetype contract.
    InvalidResponse,
    /// The provider returned more scans than the fixed page limit.
    ResponseLimitExceeded,
    /// A provider response exceeded the byte limit before decoding.
    ResponseTooLarge,
    /// A provider enrichment response exceeded its record-count limit.
    TooManyRecords,
    /// Provider metadata contained a credential-shaped field name.
    SecretFieldRejected,
    /// A provider identity is missing or outside the Go-compatible positive range.
    MissingRecordIdentity,
    /// One response contains the same identity with conflicting content.
    DuplicateRecordIdentity,
    /// A response record belongs to a different request-bound scan.
    ResponseScopeMismatch,
    /// A request was decoded by a kernel for another origin, purpose, or scope.
    RequestScopeMismatch,
    /// Vulnerability or knowledge fanout was requested for the scan-only family.
    UnsupportedEnrichment,
    /// Scan collection state does not match the configured family.
    CollectionStateMismatch,
}

impl fmt::Display for ArchetypeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "archetype family is invalid",
            Self::InvalidBaseUrl => "archetype base URL must be a secure origin",
            Self::InvalidApiPrefix => "archetype API prefix is invalid",
            Self::InvalidFanoutConcurrency => {
                "archetype fanout concurrency must be between 1 and 16"
            }
            Self::MissingTenantId => "archetype tenant_id is required for event materialization",
            Self::InvalidObservedAt => "archetype observed_at must be an RFC 3339 timestamp",
            Self::InvalidScopedId => "archetype request scope ID must be positive",
            Self::InvalidResponse => "archetype response does not match the selected contract",
            Self::ResponseLimitExceeded => "archetype scan response exceeds the page limit",
            Self::ResponseTooLarge => "archetype response exceeds 8388608 bytes",
            Self::TooManyRecords => "archetype enrichment response exceeds the record limit",
            Self::SecretFieldRejected => {
                "archetype provider metadata contains a credential-shaped field"
            }
            Self::MissingRecordIdentity => {
                "archetype record identity is missing or outside the supported range"
            }
            Self::DuplicateRecordIdentity => "archetype record identity is duplicated",
            Self::ResponseScopeMismatch => {
                "archetype response record does not match the requested scan"
            }
            Self::RequestScopeMismatch => {
                "archetype request origin, purpose, prefix, or scope does not match the kernel"
            }
            Self::UnsupportedEnrichment => "archetype enrichment requires the vulnerability family",
            Self::CollectionStateMismatch => {
                "archetype vulnerability collection state does not match the family"
            }
        })
    }
}

impl Error for ArchetypeError {}
