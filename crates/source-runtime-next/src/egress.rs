//! Explicit provider egress policy for Rust source execution.
//!
//! Fixture and parity modes are offline. Live execution may use only declared
//! provider origins after request-intent and credential-lease scope validation.

use std::{collections::BTreeSet, error::Error, fmt};

use reqwest::Url;

use crate::{
    CredentialLeaseError, CredentialLeaseReference, CredentialLeaseScope, LeaseClock,
    SourceRuntimeOperation,
};

/// Runtime mode for provider egress decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EgressMode {
    /// Fixture executor, no network access.
    Fixture,
    /// Parity/shadow fixture comparison, no provider network access.
    Parity,
    /// Live provider execution, allowlist required.
    Live,
}

/// Request metadata required before provider access is attempted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EgressRequestContext {
    /// Tenant that owns the request.
    pub tenant_id: String,
    /// Durable runtime identifier.
    pub runtime_id: String,
    /// Source identifier.
    pub source_id: String,
    /// Source family identifier.
    pub family_id: String,
    /// Source operation.
    pub operation: SourceRuntimeOperation,
    /// Request-intent digest.
    pub request_intent_digest: String,
    /// Logical page identifier.
    pub logical_page_id: String,
    /// Source generation.
    pub source_generation: u64,
    /// Authority epoch.
    pub authority_epoch: u64,
}

impl EgressRequestContext {
    /// Convert this egress context into the matching credential lease scope.
    pub fn lease_scope(&self) -> Result<CredentialLeaseScope, CredentialLeaseError> {
        CredentialLeaseScope::new(
            self.tenant_id.clone(),
            self.runtime_id.clone(),
            self.source_id.clone(),
            self.family_id.clone(),
            self.operation,
            self.request_intent_digest.clone(),
            self.logical_page_id.clone(),
            self.source_generation,
            self.authority_epoch,
        )
    }
}

/// Explicit allowlist for provider egress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EgressPolicy {
    mode: EgressMode,
    tenant_id: String,
    family_id: String,
    request_intent_digest: String,
    allowed_origins: BTreeSet<String>,
}

impl EgressPolicy {
    /// Create an offline fixture-mode policy.
    pub fn fixture(
        tenant_id: impl Into<String>,
        family_id: impl Into<String>,
        request_intent_digest: impl Into<String>,
    ) -> Self {
        Self {
            mode: EgressMode::Fixture,
            tenant_id: tenant_id.into(),
            family_id: family_id.into(),
            request_intent_digest: request_intent_digest.into(),
            allowed_origins: BTreeSet::new(),
        }
    }

    /// Create an offline parity-mode policy.
    pub fn parity(
        tenant_id: impl Into<String>,
        family_id: impl Into<String>,
        request_intent_digest: impl Into<String>,
    ) -> Self {
        Self {
            mode: EgressMode::Parity,
            tenant_id: tenant_id.into(),
            family_id: family_id.into(),
            request_intent_digest: request_intent_digest.into(),
            allowed_origins: BTreeSet::new(),
        }
    }

    /// Create a live policy with exact allowed URL origins.
    pub fn live(
        tenant_id: impl Into<String>,
        family_id: impl Into<String>,
        request_intent_digest: impl Into<String>,
        allowed_origins: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, EgressPolicyError> {
        let allowed_origins = allowed_origins
            .into_iter()
            .map(|origin| normalize_origin(&origin.into()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        if allowed_origins.is_empty() {
            return Err(EgressPolicyError::EmptyAllowlist);
        }
        Ok(Self {
            mode: EgressMode::Live,
            tenant_id: tenant_id.into(),
            family_id: family_id.into(),
            request_intent_digest: request_intent_digest.into(),
            allowed_origins,
        })
    }

    /// Decide whether one provider request may be sent.
    pub fn decide(
        &self,
        url: &str,
        context: &EgressRequestContext,
        lease: &CredentialLeaseReference,
        clock: &impl LeaseClock,
    ) -> EgressDecision {
        let url = match Url::parse(url) {
            Ok(url) => url,
            Err(_) => return EgressDecision::deny(EgressPolicyError::InvalidUrl),
        };
        if matches!(self.mode, EgressMode::Fixture | EgressMode::Parity) {
            return EgressDecision::deny(EgressPolicyError::OfflineMode);
        }
        if context.tenant_id != self.tenant_id
            || context.family_id != self.family_id
            || context.request_intent_digest != self.request_intent_digest
        {
            return EgressDecision::deny(EgressPolicyError::ContextMismatch);
        }
        let scope = match context.lease_scope() {
            Ok(scope) => scope,
            Err(error) => return EgressDecision::deny(EgressPolicyError::Lease(error)),
        };
        if let Err(error) = lease.validate_for(&scope, clock) {
            return EgressDecision::deny(EgressPolicyError::Lease(error));
        }
        if url.scheme() != "https" && !is_loopback(&url) {
            return EgressDecision::deny(EgressPolicyError::DisallowedScheme);
        }
        let origin = origin_of(&url);
        if !self.allowed_origins.contains(&origin) {
            return EgressDecision::deny(EgressPolicyError::HostNotAllowed);
        }
        EgressDecision::allow(origin)
    }
}

/// Provider egress policy outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EgressDecision {
    /// Decision kind.
    pub kind: EgressDecisionKind,
    /// Safe, credential-free origin when allowed.
    pub origin: Option<String>,
    /// Safe denial reason.
    pub reason: Option<EgressPolicyError>,
}

impl EgressDecision {
    fn allow(origin: String) -> Self {
        Self {
            kind: EgressDecisionKind::Allowed,
            origin: Some(origin),
            reason: None,
        }
    }

    fn deny(reason: EgressPolicyError) -> Self {
        Self {
            kind: EgressDecisionKind::Denied,
            origin: None,
            reason: Some(reason),
        }
    }
}

/// Provider egress decision kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EgressDecisionKind {
    /// Request may be sent.
    Allowed,
    /// Request must fail before network access.
    Denied,
}

/// Safe egress-denial reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EgressPolicyError {
    /// Fixture/parity mode forbids provider egress.
    OfflineMode,
    /// Live mode requires at least one origin.
    EmptyAllowlist,
    /// URL or origin is malformed.
    InvalidUrl,
    /// HTTP scheme is not allowed for non-loopback providers.
    DisallowedScheme,
    /// Host/origin is not allowlisted.
    HostNotAllowed,
    /// Tenant, family, or request-intent scope mismatched policy.
    ContextMismatch,
    /// Credential lease rejected the request.
    Lease(CredentialLeaseError),
}

impl fmt::Display for EgressPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OfflineMode => formatter.write_str("provider egress disabled in offline mode"),
            Self::EmptyAllowlist => formatter.write_str("provider egress allowlist is empty"),
            Self::InvalidUrl => formatter.write_str("provider egress URL is invalid"),
            Self::DisallowedScheme => formatter.write_str("provider egress scheme is not allowed"),
            Self::HostNotAllowed => formatter.write_str("provider egress host is not allowlisted"),
            Self::ContextMismatch => formatter.write_str("provider egress scope mismatch"),
            Self::Lease(error) => write!(
                formatter,
                "provider egress credential lease rejected: {error}"
            ),
        }
    }
}

impl Error for EgressPolicyError {}

fn normalize_origin(value: &str) -> Result<String, EgressPolicyError> {
    let url = Url::parse(value).map_err(|_| EgressPolicyError::InvalidUrl)?;
    if url.scheme() != "https" && !is_loopback(&url) {
        return Err(EgressPolicyError::DisallowedScheme);
    }
    if url.host_str().is_none() {
        return Err(EgressPolicyError::InvalidUrl);
    }
    Ok(origin_of(&url))
}

fn origin_of(url: &Url) -> String {
    match url.port() {
        Some(port) => format!(
            "{}://{}:{port}",
            url.scheme(),
            url.host_str().unwrap_or_default()
        ),
        None => format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default()),
    }
}

fn is_loopback(url: &Url) -> bool {
    matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> String {
        "b".repeat(64)
    }

    fn context() -> EgressRequestContext {
        EgressRequestContext {
            tenant_id: "tenant-a".to_owned(),
            runtime_id: "runtime-a".to_owned(),
            source_id: "source-a".to_owned(),
            family_id: "identity_user".to_owned(),
            operation: SourceRuntimeOperation::ReadPage,
            request_intent_digest: digest(),
            logical_page_id: "page-0001".to_owned(),
            source_generation: 7,
            authority_epoch: 3,
        }
    }

    fn lease() -> CredentialLeaseReference {
        CredentialLeaseReference::new(
            "lease-ref-1",
            context().lease_scope().unwrap(),
            1_000,
            1_000,
        )
        .unwrap()
    }

    #[test]
    fn egress_fixture_and_parity_modes_are_offline() {
        for policy in [
            EgressPolicy::fixture("tenant-a", "identity_user", digest()),
            EgressPolicy::parity("tenant-a", "identity_user", digest()),
        ] {
            let decision = policy.decide(
                "https://provider.example.test/users",
                &context(),
                &lease(),
                &1_500,
            );
            assert_eq!(decision.kind, EgressDecisionKind::Denied);
            assert_eq!(decision.reason, Some(EgressPolicyError::OfflineMode));
        }
    }

    #[test]
    fn egress_live_mode_requires_declared_origin_request_intent_and_lease() {
        let policy = EgressPolicy::live(
            "tenant-a",
            "identity_user",
            digest(),
            ["https://provider.example.test"],
        )
        .unwrap();
        let decision = policy.decide(
            "https://provider.example.test/users",
            &context(),
            &lease(),
            &1_500,
        );
        assert_eq!(decision.kind, EgressDecisionKind::Allowed);
        assert_eq!(
            decision.origin.as_deref(),
            Some("https://provider.example.test")
        );

        let other_host = policy.decide(
            "https://evil.example.test/users",
            &context(),
            &lease(),
            &1_500,
        );
        assert_eq!(other_host.kind, EgressDecisionKind::Denied);
        assert_eq!(other_host.reason, Some(EgressPolicyError::HostNotAllowed));

        let mut wrong_intent = context();
        wrong_intent.request_intent_digest = "c".repeat(64);
        assert_eq!(
            policy
                .decide(
                    "https://provider.example.test/users",
                    &wrong_intent,
                    &lease(),
                    &1_500
                )
                .reason,
            Some(EgressPolicyError::ContextMismatch)
        );

        assert_eq!(
            policy
                .decide(
                    "https://provider.example.test/users",
                    &context(),
                    &lease(),
                    &2_000
                )
                .reason,
            Some(EgressPolicyError::Lease(CredentialLeaseError::Expired))
        );
    }

    #[test]
    fn egress_rejects_open_redirects_to_unapproved_hosts() {
        let policy = EgressPolicy::live(
            "tenant-a",
            "identity_user",
            digest(),
            ["https://provider.example.test"],
        )
        .unwrap();
        let decision = policy.decide(
            "https://redirect.example.test/final",
            &context(),
            &lease(),
            &1_500,
        );
        assert_eq!(decision.kind, EgressDecisionKind::Denied);
        assert_eq!(decision.reason, Some(EgressPolicyError::HostNotAllowed));
    }
}
