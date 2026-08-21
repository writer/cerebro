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
    /// A scan or repository scope ID is zero.
    InvalidScopedId,
    /// Response JSON does not match the selected Archetype contract.
    InvalidResponse,
    /// The provider returned more scans than the fixed page limit.
    ResponseLimitExceeded,
    /// A provider record omitted its stable positive identity.
    MissingRecordIdentity,
    /// One response contains colliding stable provider identities.
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
            Self::InvalidScopedId => "archetype request scope ID must be positive",
            Self::InvalidResponse => "archetype response does not match the selected contract",
            Self::ResponseLimitExceeded => "archetype scan response exceeds the page limit",
            Self::MissingRecordIdentity => "archetype record identity is missing",
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
