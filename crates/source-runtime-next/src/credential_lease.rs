//! Operation-scoped credential lease references for Rust source execution.
//!
//! A lease is an opaque authority reference, never the credential value. The
//! scope binds the reference to one tenant/runtime/source/family operation and
//! logical page so callers cannot reuse provider access across pages, authority
//! epochs, source replacements, or request-intent changes.

use std::{error::Error, fmt};

use crate::protocol::SourceRuntimeOperation;

/// Monotonic timestamp provider used by deterministic lease validation tests.
pub trait LeaseClock {
    /// Return current milliseconds since Unix epoch.
    fn now_millis(&self) -> i64;
}

impl LeaseClock for i64 {
    fn now_millis(&self) -> i64 {
        *self
    }
}

/// Immutable scope that a credential lease reference may authorize.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialLeaseScope {
    /// Tenant that owns the source runtime.
    pub tenant_id: String,
    /// Durable runtime identifier.
    pub runtime_id: String,
    /// Source identifier.
    pub source_id: String,
    /// Source family identifier.
    pub family_id: String,
    /// Worker operation authorized by this lease.
    pub operation: SourceRuntimeOperation,
    /// Request-intent SHA-256 digest.
    pub request_intent_digest: String,
    /// Logical page identifier.
    pub logical_page_id: String,
    /// Source generation or replacement fence.
    pub source_generation: u64,
    /// Source-family authority epoch.
    pub authority_epoch: u64,
}

impl CredentialLeaseScope {
    /// Build and validate a complete one-operation credential scope.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: impl Into<String>,
        runtime_id: impl Into<String>,
        source_id: impl Into<String>,
        family_id: impl Into<String>,
        operation: SourceRuntimeOperation,
        request_intent_digest: impl Into<String>,
        logical_page_id: impl Into<String>,
        source_generation: u64,
        authority_epoch: u64,
    ) -> Result<Self, CredentialLeaseError> {
        let scope = Self {
            tenant_id: tenant_id.into(),
            runtime_id: runtime_id.into(),
            source_id: source_id.into(),
            family_id: family_id.into(),
            operation,
            request_intent_digest: request_intent_digest.into(),
            logical_page_id: logical_page_id.into(),
            source_generation,
            authority_epoch,
        };
        scope.validate()?;
        Ok(scope)
    }

    fn validate(&self) -> Result<(), CredentialLeaseError> {
        for (field, value) in [
            ("tenant_id", &self.tenant_id),
            ("runtime_id", &self.runtime_id),
            ("source_id", &self.source_id),
            ("family_id", &self.family_id),
            ("request_intent_digest", &self.request_intent_digest),
            ("logical_page_id", &self.logical_page_id),
        ] {
            if value.trim().is_empty()
                || value.trim() != value
                || value.len() > 255
                || value.chars().any(char::is_control)
            {
                return Err(CredentialLeaseError::InvalidScope(field));
            }
        }
        if !is_sha256_hex(&self.request_intent_digest) {
            return Err(CredentialLeaseError::InvalidScope("request_intent_digest"));
        }
        if self.source_generation == 0 || self.authority_epoch == 0 {
            return Err(CredentialLeaseError::InvalidScope("generation_epoch"));
        }
        Ok(())
    }
}

/// Opaque credential lease reference and its deterministic lifetime state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialLeaseReference {
    /// Opaque broker-issued reference, not credential material.
    pub reference_id: String,
    /// Scope authorized by the reference.
    pub scope: CredentialLeaseScope,
    /// Inclusive issue timestamp in milliseconds.
    pub issued_at_millis: i64,
    /// Exclusive expiry timestamp in milliseconds.
    pub expires_at_millis: i64,
    /// Local revocation flag, set after use or authority rollback.
    pub revoked: bool,
}

impl CredentialLeaseReference {
    /// Create a bounded opaque reference for one operation.
    pub fn new(
        reference_id: impl Into<String>,
        scope: CredentialLeaseScope,
        issued_at_millis: i64,
        ttl_millis: i64,
    ) -> Result<Self, CredentialLeaseError> {
        let reference_id = reference_id.into();
        if reference_id.trim().is_empty()
            || reference_id.trim() != reference_id
            || reference_id.len() > 255
            || reference_id.chars().any(char::is_control)
        {
            return Err(CredentialLeaseError::InvalidReference);
        }
        if ttl_millis <= 0 {
            return Err(CredentialLeaseError::InvalidExpiry);
        }
        let expires_at_millis = issued_at_millis
            .checked_add(ttl_millis)
            .ok_or(CredentialLeaseError::InvalidExpiry)?;
        Ok(Self {
            reference_id,
            scope,
            issued_at_millis,
            expires_at_millis,
            revoked: false,
        })
    }

    /// Validate this lease for the requested operation scope.
    pub fn validate_for(
        &self,
        expected: &CredentialLeaseScope,
        clock: &impl LeaseClock,
    ) -> Result<(), CredentialLeaseError> {
        self.scope.validate()?;
        expected.validate()?;
        if self.revoked {
            return Err(CredentialLeaseError::Revoked);
        }
        let now = clock.now_millis();
        if now < self.issued_at_millis || now >= self.expires_at_millis {
            return Err(CredentialLeaseError::Expired);
        }
        if &self.scope != expected {
            return Err(CredentialLeaseError::ScopeMismatch);
        }
        Ok(())
    }

    /// Mark the reference unusable after an operation or rollback.
    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

/// Lease status emitted in safe receipts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialLeaseStatus {
    /// Reference is valid for exactly the requested operation.
    Valid,
    /// Reference was rejected before provider access.
    Rejected(CredentialLeaseError),
}

/// Wrapper used by execution code to validate and consume a lease once.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationScopedCredentialLease {
    reference: CredentialLeaseReference,
    consumed: bool,
}

impl OperationScopedCredentialLease {
    /// Construct a consumable operation-scoped lease from an opaque reference.
    pub fn new(reference: CredentialLeaseReference) -> Self {
        Self {
            reference,
            consumed: false,
        }
    }

    /// Validate the reference, then deterministically revoke it for reuse.
    pub fn consume_for(
        &mut self,
        expected: &CredentialLeaseScope,
        clock: &impl LeaseClock,
    ) -> Result<(), CredentialLeaseError> {
        if self.consumed {
            return Err(CredentialLeaseError::AlreadyConsumed);
        }
        self.reference.validate_for(expected, clock)?;
        self.consumed = true;
        self.reference.revoke();
        Ok(())
    }

    /// Return a redacted, non-secret status for receipts and logs.
    pub fn status_for(
        &self,
        expected: &CredentialLeaseScope,
        clock: &impl LeaseClock,
    ) -> CredentialLeaseStatus {
        match self.reference.validate_for(expected, clock) {
            Ok(()) if !self.consumed => CredentialLeaseStatus::Valid,
            Ok(()) => CredentialLeaseStatus::Rejected(CredentialLeaseError::AlreadyConsumed),
            Err(error) => CredentialLeaseStatus::Rejected(error),
        }
    }
}

/// Credential lease validation failures. These messages intentionally contain
/// only field names and never credential values or provider secret addresses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialLeaseError {
    /// Scope is missing or malformed.
    InvalidScope(&'static str),
    /// Opaque reference identifier is invalid.
    InvalidReference,
    /// Expiry timestamp cannot be represented or is non-positive.
    InvalidExpiry,
    /// Lease is not valid at the current time.
    Expired,
    /// Lease has been revoked after use, rollback, or replacement.
    Revoked,
    /// Lease was already consumed for its single operation.
    AlreadyConsumed,
    /// Lease scope does not match the requested operation.
    ScopeMismatch,
}

impl fmt::Display for CredentialLeaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidScope(field) => {
                write!(formatter, "credential lease scope {field} is invalid")
            }
            Self::InvalidReference => formatter.write_str("credential lease reference is invalid"),
            Self::InvalidExpiry => formatter.write_str("credential lease expiry is invalid"),
            Self::Expired => formatter.write_str("credential lease expired"),
            Self::Revoked => formatter.write_str("credential lease revoked"),
            Self::AlreadyConsumed => formatter.write_str("credential lease already consumed"),
            Self::ScopeMismatch => formatter.write_str("credential lease scope mismatch"),
        }
    }
}

impl Error for CredentialLeaseError {}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> CredentialLeaseScope {
        CredentialLeaseScope::new(
            "tenant-a",
            "runtime-a",
            "source-a",
            "identity_user",
            SourceRuntimeOperation::ReadPage,
            "a".repeat(64),
            "page-0001",
            7,
            3,
        )
        .unwrap()
    }

    #[test]
    fn credential_lease_is_operation_scoped_and_consumed_once() {
        let scope = scope();
        let reference =
            CredentialLeaseReference::new("lease-ref-1", scope.clone(), 1_000, 1_000).unwrap();
        let mut lease = OperationScopedCredentialLease::new(reference);

        assert_eq!(
            lease.status_for(&scope, &1_500),
            CredentialLeaseStatus::Valid
        );
        lease.consume_for(&scope, &1_500).unwrap();
        assert_eq!(
            lease.consume_for(&scope, &1_500),
            Err(CredentialLeaseError::AlreadyConsumed)
        );
        assert_eq!(
            lease.status_for(&scope, &1_500),
            CredentialLeaseStatus::Rejected(CredentialLeaseError::Revoked)
        );
    }

    #[test]
    fn credential_lease_rejects_reuse_after_expiry_replacement_and_rollback() {
        let scope = scope();
        let reference =
            CredentialLeaseReference::new("lease-ref-1", scope.clone(), 1_000, 1_000).unwrap();
        assert_eq!(
            reference.validate_for(&scope, &2_000),
            Err(CredentialLeaseError::Expired)
        );

        let mut other_page = scope.clone();
        other_page.logical_page_id = "page-0002".to_owned();
        assert_eq!(
            reference.validate_for(&other_page, &1_500),
            Err(CredentialLeaseError::ScopeMismatch)
        );

        let mut replacement = scope.clone();
        replacement.source_generation += 1;
        assert_eq!(
            reference.validate_for(&replacement, &1_500),
            Err(CredentialLeaseError::ScopeMismatch)
        );

        let mut rollback = scope.clone();
        rollback.authority_epoch += 1;
        assert_eq!(
            reference.validate_for(&rollback, &1_500),
            Err(CredentialLeaseError::ScopeMismatch)
        );

        let mut discover = scope;
        discover.operation = SourceRuntimeOperation::Discover;
        assert_eq!(
            reference.validate_for(&discover, &1_500),
            Err(CredentialLeaseError::ScopeMismatch)
        );
    }

    #[test]
    fn credential_lease_errors_do_not_disclose_reference_material() {
        let error = CredentialLeaseReference::new(" lease-secret-sentinel ", scope(), 1_000, 1_000)
            .unwrap_err();
        assert_eq!(error, CredentialLeaseError::InvalidReference);
        assert!(!error.to_string().contains("lease-secret-sentinel"));
    }
}
