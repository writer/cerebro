use std::{error::Error, fmt};

#[derive(Clone, Debug, Eq, PartialEq)]
/// Closed, bounded failures emitted by credential-free source adapters.
pub enum SourceExecutionError {
    /// An input or output message is not valid protobuf.
    Protobuf,
    /// No registered adapter exactly matches the compiled plan.
    UnknownAdapter,
    /// Required public source configuration is absent.
    MissingConfiguration,
    /// The trusted host has no credential reference for this operation.
    MissingCredentialReference,
    /// The trusted host could not redeem the referenced credential.
    CredentialUnavailable,
    /// The provider rejected the host-applied authentication.
    AuthenticationRejected,
    /// The credential lacks a required provider permission.
    RequiredProviderScopeMissing,
    /// The trusted host denied the requested provider origin or route.
    EgressDenied,
    /// DNS resolution or connection establishment failed.
    ConnectionFailure,
    /// The provider operation exceeded its deadline.
    ProviderTimeout,
    /// The provider requested a bounded retry after rate limiting.
    ProviderRateLimit,
    /// The provider returned an unrecognized status.
    UnexpectedProviderStatus,
    /// The compiled plan is invalid or has been modified.
    InvalidPlan,
    /// The host-supplied execution context is incomplete or malformed.
    InvalidExecutionContext,
    /// A cursor is oversized, malformed, or unsupported by the family.
    InvalidCursor,
    /// Provider response bytes exceed the compiled plan bound.
    ResponseTooLarge,
    /// Normalized output exceeds the shared record or payload bound.
    ResultTooLarge,
    /// Required host execution identity or safe receipt evidence is absent.
    MissingExecutionIdentity,
    /// Safe receipt tenant or runtime identity differs from trusted context.
    TenantMismatch,
    /// Safe receipt runtime or lease generation differs from trusted context.
    StaleGeneration,
    /// A supplied request, response, or result digest is invalid.
    InvalidDigest,
    /// Provider response bytes are malformed under the registered contract.
    MalformedResponse,
    /// One provider record violates the registered normalization contract.
    InvalidProviderRecord,
    /// A normalized record has no stable provider or tenant-scoped identity.
    MissingStableIdentity,
    /// The same event identity was emitted with conflicting canonical content.
    DuplicateConflict,
    /// A normalized event failed the exact compiled event contract.
    EventContractRejected,
    /// The durable append operation failed.
    AppendFailed,
    /// Projection failed after append admission.
    ProjectionFailed,
    /// The worker no longer owns the runtime lease.
    LeaseLost,
    /// The selected source writer no longer owns authority.
    StaleAuthority,
    /// An unexpected internal runtime condition occurred.
    InternalRuntime,
}

impl SourceExecutionError {
    /// Returns the stable machine-readable error code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Protobuf => "source_worker.protobuf",
            Self::UnknownAdapter => "source_worker.unknown_adapter",
            Self::MissingConfiguration => "source_worker.missing_configuration",
            Self::MissingCredentialReference => "source_worker.missing_credential_reference",
            Self::CredentialUnavailable => "source_worker.credential_unavailable",
            Self::AuthenticationRejected => "source_worker.authentication_rejected",
            Self::RequiredProviderScopeMissing => "source_worker.required_provider_scope_missing",
            Self::EgressDenied => "source_worker.egress_denied",
            Self::ConnectionFailure => "source_worker.connection_failure",
            Self::ProviderTimeout => "source_worker.provider_timeout",
            Self::ProviderRateLimit => "source_worker.provider_rate_limit",
            Self::UnexpectedProviderStatus => "source_worker.unexpected_provider_status",
            Self::InvalidPlan => "source_worker.invalid_plan",
            Self::InvalidExecutionContext => "source_worker.invalid_execution_context",
            Self::InvalidCursor => "source_worker.invalid_cursor",
            Self::ResponseTooLarge => "source_worker.response_too_large",
            Self::ResultTooLarge => "source_worker.result_too_large",
            Self::MissingExecutionIdentity => "source_worker.missing_execution_identity",
            Self::TenantMismatch => "source_worker.tenant_mismatch",
            Self::StaleGeneration => "source_worker.stale_generation",
            Self::InvalidDigest => "source_worker.invalid_digest",
            Self::MalformedResponse => "source_worker.malformed_response",
            Self::InvalidProviderRecord => "source_worker.invalid_provider_record",
            Self::MissingStableIdentity => "source_worker.missing_stable_identity",
            Self::DuplicateConflict => "source_worker.duplicate_conflict",
            Self::EventContractRejected => "source_worker.event_contract_rejected",
            Self::AppendFailed => "source_worker.append_failed",
            Self::ProjectionFailed => "source_worker.projection_failed",
            Self::LeaseLost => "source_worker.lease_lost",
            Self::StaleAuthority => "source_worker.stale_authority",
            Self::InternalRuntime => "source_worker.internal_runtime",
        }
    }

    /// Returns the stable next operator action for this failure class.
    pub const fn operator_action(&self) -> &'static str {
        match self {
            Self::MissingConfiguration | Self::InvalidPlan | Self::UnknownAdapter => {
                "repair_configuration"
            }
            Self::MissingCredentialReference | Self::CredentialUnavailable => {
                "repair_credential_binding"
            }
            Self::AuthenticationRejected => "repair_provider_authentication",
            Self::RequiredProviderScopeMissing => "grant_provider_scope",
            Self::ProviderRateLimit | Self::ProviderTimeout | Self::ConnectionFailure => {
                "retry_later"
            }
            Self::MalformedResponse
            | Self::InvalidProviderRecord
            | Self::MissingStableIdentity
            | Self::DuplicateConflict
            | Self::EventContractRejected => "inspect_quarantined_records",
            Self::LeaseLost | Self::StaleAuthority | Self::StaleGeneration => "restart_collection",
            Self::Protobuf
            | Self::InvalidExecutionContext
            | Self::InvalidCursor
            | Self::UnexpectedProviderStatus
            | Self::ResponseTooLarge
            | Self::ResultTooLarge
            | Self::MissingExecutionIdentity
            | Self::TenantMismatch
            | Self::InvalidDigest
            | Self::EgressDenied
            | Self::AppendFailed
            | Self::ProjectionFailed
            | Self::InternalRuntime => "repair_forward_implementation",
        }
    }
}

impl fmt::Display for SourceExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Protobuf => "source_worker.protobuf: input or output protobuf is invalid",
            Self::UnknownAdapter => "source_worker.unknown_adapter: compiled source family is not registered",
            Self::MissingConfiguration => "source_worker.missing_configuration: required public source configuration is missing",
            Self::MissingCredentialReference => "source_worker.missing_credential_reference: credential reference is missing",
            Self::CredentialUnavailable => "source_worker.credential_unavailable: credential reference cannot be redeemed",
            Self::AuthenticationRejected => "source_worker.authentication_rejected: provider rejected authentication",
            Self::RequiredProviderScopeMissing => "source_worker.required_provider_scope_missing: provider permission is missing",
            Self::EgressDenied => "source_worker.egress_denied: provider origin or route is denied",
            Self::ConnectionFailure => "source_worker.connection_failure: provider connection failed",
            Self::ProviderTimeout => "source_worker.provider_timeout: provider operation timed out",
            Self::ProviderRateLimit => "source_worker.provider_rate_limit: provider requested a bounded retry",
            Self::UnexpectedProviderStatus => "source_worker.unexpected_provider_status: provider response status is not allowed",
            Self::InvalidPlan => "source_worker.invalid_plan: compiled plan is invalid",
            Self::InvalidExecutionContext => "source_worker.invalid_execution_context: trusted execution context is invalid",
            Self::InvalidCursor => "source_worker.invalid_cursor: provider cursor is invalid",
            Self::ResponseTooLarge => "source_worker.response_too_large: provider response exceeds the compiled bound",
            Self::ResultTooLarge => "source_worker.result_too_large: normalized result exceeds the shared bound",
            Self::MissingExecutionIdentity => "source_worker.missing_execution_identity: execution identity or safe receipt is missing",
            Self::TenantMismatch => "source_worker.tenant_mismatch: safe receipt identity differs from trusted context",
            Self::StaleGeneration => "source_worker.stale_generation: safe receipt generation differs from trusted context",
            Self::InvalidDigest => "source_worker.invalid_digest: execution digest is invalid",
            Self::MalformedResponse => "source_worker.malformed_response: provider response is malformed",
            Self::InvalidProviderRecord => "source_worker.invalid_provider_record: provider record violates the compiled contract",
            Self::MissingStableIdentity => "source_worker.missing_stable_identity: normalized record identity is missing",
            Self::DuplicateConflict => "source_worker.duplicate_conflict: duplicate event identity has conflicting content",
            Self::EventContractRejected => "source_worker.event_contract_rejected: normalized event violates the compiled contract",
            Self::AppendFailed => "source_worker.append_failed: durable append failed",
            Self::ProjectionFailed => "source_worker.projection_failed: projection failed",
            Self::LeaseLost => "source_worker.lease_lost: runtime lease is no longer owned",
            Self::StaleAuthority => "source_worker.stale_authority: source writer authority changed",
            Self::InternalRuntime => "source_worker.internal_runtime: internal runtime failure",
        })
    }
}

impl Error for SourceExecutionError {}
