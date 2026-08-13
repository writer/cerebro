use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{DecisionId, TenantId};

/// Provider surface on which a third-party application is installed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VendorUsePlatform {
    /// A GitHub App installation on an organization or repository set.
    GitHub,
    /// A Slack app installation on an Enterprise Grid organization or workspace.
    Slack,
}

/// Provider lifecycle point represented by one observation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VendorUseObservationKind {
    /// A provider request that has not yet granted the application access.
    InstallationRequest,
    /// A currently installed application with provider access.
    ActiveInstallation,
}

/// Normalized decision imported from the authoritative vendor-review system.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VendorReviewDecision {
    /// The review has not reached a terminal decision.
    Pending,
    /// The reviewed use is approved within its recorded scope.
    Approved,
    /// The reviewed use was rejected.
    Rejected,
}

/// Ordered provider permission access used to reject privilege escalation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderPermissionAccess {
    /// Read-only access to the named provider capability.
    Read,
    /// Mutation access to the named provider capability.
    Write,
    /// Provider-administrative access to the named capability.
    Admin,
}

/// One normalized provider permission and its maximum access level.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderPermission {
    /// Exact provider permission name; aliases and wildcards are not interpreted.
    pub name: String,
    /// Requested or approved access level.
    pub access: ProviderPermissionAccess,
}

/// Scoped, time-bounded vendor-use approval imported by a trusted adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VendorUseApproval {
    /// Cerebro tenant whose policy domain issued and consumes the approval.
    pub tenant_id: TenantId,
    /// Stable identifier of the authoritative approval decision.
    pub decision_id: DecisionId,
    /// Canonical vendor URN, independent of the vendor's display name.
    pub vendor_urn: String,
    /// Stable reference to the authoritative security review.
    pub security_review_ref: String,
    /// Current decision imported from the vendor-review system.
    pub review_decision: VendorReviewDecision,
    /// Provider surface covered by the approval.
    pub platform: VendorUsePlatform,
    /// Stable provider application identifier covered by the approval.
    pub application_id: String,
    /// Exact organization, enterprise, or workspace identifier.
    pub provider_tenant_id: String,
    /// Concrete operator use case reviewed for this installation.
    pub use_case: String,
    /// Exact resource URNs the application may access.
    pub permitted_resource_urns: Vec<String>,
    /// Maximum provider permissions approved for the application.
    pub permitted_permissions: Vec<ProviderPermission>,
    /// Inclusive Unix-millisecond beginning of the approval window.
    pub issued_at_unix_ms: u64,
    /// Exclusive Unix-millisecond end of the approval window.
    pub expires_at_unix_ms: u64,
    /// Inclusive Unix-millisecond revocation time, when withdrawn early.
    pub revoked_at_unix_ms: Option<u64>,
    /// Time the importing adapter observed the authoritative review state.
    pub source_observed_at_unix_ms: u64,
}

/// Current provider observation of an installed or requested application.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VendorUseObservation {
    /// Cerebro tenant containing the observed provider installation.
    pub tenant_id: TenantId,
    /// Provider surface on which the application was observed.
    pub platform: VendorUsePlatform,
    /// Whether access is requested or already active.
    pub kind: VendorUseObservationKind,
    /// Stable provider application identifier, never a display name.
    pub application_id: String,
    /// Exact provider organization, enterprise, or workspace identifier.
    pub provider_tenant_id: String,
    /// Concrete use case asserted by the request or installation record.
    pub use_case: String,
    /// Exact resource URNs currently requested or reachable.
    pub resource_urns: Vec<String>,
    /// Provider permissions currently requested or granted.
    pub permissions: Vec<ProviderPermission>,
    /// Stable revision or event reference from the authoritative provider.
    pub source_revision: String,
    /// Time the provider state was authoritatively observed.
    pub source_observed_at_unix_ms: u64,
}

/// Freshness requirements applied to both provider and approval evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VendorUsePolicy {
    /// Maximum accepted age of the provider installation observation.
    pub max_observation_age_ms: u64,
    /// Maximum accepted age of the imported vendor-review snapshot.
    pub max_approval_evidence_age_ms: u64,
}

/// Material vendor-use state exposed to operators and mission policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VendorUseState {
    /// Current provider state exactly matches a fresh active approval.
    ActiveCompliant,
    /// An installation request exactly matches a fresh active approval.
    RequestedApproved,
    /// An active provider installation has no matching approval.
    ActiveUnapproved,
    /// A provider installation request has no matching approval.
    RequestedUnapproved,
    /// A review exists but has not reached approval.
    PendingReview,
    /// The authoritative review rejected the requested use.
    ReviewRejected,
    /// The matching approval has not entered its validity window.
    ApprovalNotYetValid,
    /// The matching approval reached its exclusive expiry.
    ApprovalExpired,
    /// The matching approval was explicitly revoked.
    ApprovalRevoked,
    /// The imported approval evidence is too old to authorize use.
    ApprovalEvidenceStale,
    /// The provider observation is too old to establish current state.
    ObservationEvidenceStale,
    /// Current use exceeds or disagrees with the approved binding.
    ScopeDrift,
    /// The supplied policy, approval, or observation is malformed.
    InvalidEvidence,
}

/// Deterministic reason current vendor use cannot be considered compliant.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VendorUseDenial {
    /// Freshness policy contains a zero maximum age or evaluation time.
    InvalidPolicy,
    /// Provider observation is incomplete, duplicated, or temporally invalid.
    InvalidObservation,
    /// No approval was supplied for the request or active installation.
    NoApproval,
    /// Approval is incomplete, duplicated, or temporally invalid.
    InvalidApproval,
    /// Observation and approval belong to different Cerebro tenants.
    TenantMismatch,
    /// Approval covers a different provider surface.
    PlatformMismatch,
    /// Approval covers a different provider application identifier.
    ApplicationMismatch,
    /// Approval covers a different provider organization or workspace.
    ProviderTenantMismatch,
    /// Approval covers a different concrete use case.
    UseCaseMismatch,
    /// Provider state was observed too long ago.
    ObservationStale,
    /// Vendor-review state is still pending.
    ReviewPending,
    /// Vendor-review state rejected the requested use.
    ReviewRejected,
    /// Evaluation precedes the approval's inclusive start time.
    ApprovalNotYetValid,
    /// Evaluation is at or after the approval's exclusive expiry.
    ApprovalExpired,
    /// Evaluation is at or after the approval's revocation time.
    ApprovalRevoked,
    /// Vendor-review evidence was observed too long ago.
    ApprovalEvidenceStale,
    /// At least one observed resource is outside the approved exact set.
    ResourceNotApproved,
    /// At least one observed permission is absent from the approval.
    PermissionNotApproved,
    /// At least one observed permission exceeds its approved access level.
    PermissionAccessExceeded,
}

/// Result of evaluating current provider use against one exact approval.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum VendorUseDecision {
    /// Every identity, scope, permission, time, and freshness binding matched.
    Authorized {
        /// Authoritative decision that approved the exact use.
        decision_id: DecisionId,
        /// Material current state suitable for operator projection.
        state: VendorUseState,
    },
    /// At least one required binding failed closed.
    Denied {
        /// Material current state suitable for operator projection.
        state: VendorUseState,
        /// First deterministic reason the evaluation failed.
        reason: VendorUseDenial,
    },
}

/// Evaluates one current provider observation against one vendor-use approval.
///
/// The evaluator performs no provider access, persistence, normalization, or
/// remediation. Trusted adapters must map provider and vendor-review records
/// into these contracts and establish their provenance before evaluation.
pub fn evaluate_vendor_use(
    observation: &VendorUseObservation,
    approval: Option<&VendorUseApproval>,
    policy: VendorUsePolicy,
    evaluated_at_unix_ms: u64,
) -> VendorUseDecision {
    if evaluated_at_unix_ms == 0
        || policy.max_observation_age_ms == 0
        || policy.max_approval_evidence_age_ms == 0
    {
        return denied(
            VendorUseState::InvalidEvidence,
            VendorUseDenial::InvalidPolicy,
        );
    }
    if !valid_observation(observation, evaluated_at_unix_ms) {
        return denied(
            VendorUseState::InvalidEvidence,
            VendorUseDenial::InvalidObservation,
        );
    }
    if evidence_is_stale(
        observation.source_observed_at_unix_ms,
        evaluated_at_unix_ms,
        policy.max_observation_age_ms,
    ) {
        return denied(
            VendorUseState::ObservationEvidenceStale,
            VendorUseDenial::ObservationStale,
        );
    }

    let Some(approval) = approval else {
        let state = match observation.kind {
            VendorUseObservationKind::InstallationRequest => VendorUseState::RequestedUnapproved,
            VendorUseObservationKind::ActiveInstallation => VendorUseState::ActiveUnapproved,
        };
        return denied(state, VendorUseDenial::NoApproval);
    };
    if !valid_approval(approval, evaluated_at_unix_ms) {
        return denied(
            VendorUseState::InvalidEvidence,
            VendorUseDenial::InvalidApproval,
        );
    }
    if observation.tenant_id != approval.tenant_id {
        return scope_drift(VendorUseDenial::TenantMismatch);
    }
    if observation.platform != approval.platform {
        return scope_drift(VendorUseDenial::PlatformMismatch);
    }
    if observation.application_id != approval.application_id {
        return scope_drift(VendorUseDenial::ApplicationMismatch);
    }
    if observation.provider_tenant_id != approval.provider_tenant_id {
        return scope_drift(VendorUseDenial::ProviderTenantMismatch);
    }
    if observation.use_case != approval.use_case {
        return scope_drift(VendorUseDenial::UseCaseMismatch);
    }
    if evidence_is_stale(
        approval.source_observed_at_unix_ms,
        evaluated_at_unix_ms,
        policy.max_approval_evidence_age_ms,
    ) {
        return denied(
            VendorUseState::ApprovalEvidenceStale,
            VendorUseDenial::ApprovalEvidenceStale,
        );
    }
    match approval.review_decision {
        VendorReviewDecision::Pending => {
            return denied(
                VendorUseState::PendingReview,
                VendorUseDenial::ReviewPending,
            );
        }
        VendorReviewDecision::Rejected => {
            return denied(
                VendorUseState::ReviewRejected,
                VendorUseDenial::ReviewRejected,
            );
        }
        VendorReviewDecision::Approved => {}
    }
    if evaluated_at_unix_ms < approval.issued_at_unix_ms {
        return denied(
            VendorUseState::ApprovalNotYetValid,
            VendorUseDenial::ApprovalNotYetValid,
        );
    }
    if evaluated_at_unix_ms >= approval.expires_at_unix_ms {
        return denied(
            VendorUseState::ApprovalExpired,
            VendorUseDenial::ApprovalExpired,
        );
    }
    if approval
        .revoked_at_unix_ms
        .is_some_and(|revoked| evaluated_at_unix_ms >= revoked)
    {
        return denied(
            VendorUseState::ApprovalRevoked,
            VendorUseDenial::ApprovalRevoked,
        );
    }
    if observation.resource_urns.iter().any(|resource| {
        !approval
            .permitted_resource_urns
            .iter()
            .any(|permitted| permitted == resource)
    }) {
        return scope_drift(VendorUseDenial::ResourceNotApproved);
    }
    for requested in &observation.permissions {
        let Some(permitted) = approval
            .permitted_permissions
            .iter()
            .find(|permission| permission.name == requested.name)
        else {
            return scope_drift(VendorUseDenial::PermissionNotApproved);
        };
        if requested.access > permitted.access {
            return scope_drift(VendorUseDenial::PermissionAccessExceeded);
        }
    }

    let state = match observation.kind {
        VendorUseObservationKind::InstallationRequest => VendorUseState::RequestedApproved,
        VendorUseObservationKind::ActiveInstallation => VendorUseState::ActiveCompliant,
    };
    VendorUseDecision::Authorized {
        decision_id: approval.decision_id.clone(),
        state,
    }
}

fn denied(state: VendorUseState, reason: VendorUseDenial) -> VendorUseDecision {
    VendorUseDecision::Denied { state, reason }
}

fn scope_drift(reason: VendorUseDenial) -> VendorUseDecision {
    denied(VendorUseState::ScopeDrift, reason)
}

fn evidence_is_stale(observed_at: u64, evaluated_at: u64, max_age: u64) -> bool {
    evaluated_at.saturating_sub(observed_at) > max_age
}

fn valid_observation(observation: &VendorUseObservation, evaluated_at: u64) -> bool {
    valid_value(&observation.application_id)
        && valid_value(&observation.provider_tenant_id)
        && valid_value(&observation.use_case)
        && valid_value(&observation.source_revision)
        && observation.source_observed_at_unix_ms > 0
        && observation.source_observed_at_unix_ms <= evaluated_at
        && valid_values(&observation.resource_urns)
        && valid_permissions(&observation.permissions)
}

fn valid_approval(approval: &VendorUseApproval, evaluated_at: u64) -> bool {
    valid_value(&approval.vendor_urn)
        && valid_value(&approval.security_review_ref)
        && valid_value(&approval.application_id)
        && valid_value(&approval.provider_tenant_id)
        && valid_value(&approval.use_case)
        && approval.issued_at_unix_ms < approval.expires_at_unix_ms
        && approval
            .revoked_at_unix_ms
            .is_none_or(|revoked| revoked >= approval.issued_at_unix_ms)
        && approval.source_observed_at_unix_ms > 0
        && approval.source_observed_at_unix_ms <= evaluated_at
        && valid_values(&approval.permitted_resource_urns)
        && valid_permissions(&approval.permitted_permissions)
}

fn valid_values(values: &[String]) -> bool {
    !values.is_empty()
        && values.iter().all(|value| valid_value(value))
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn valid_permissions(permissions: &[ProviderPermission]) -> bool {
    !permissions.is_empty()
        && permissions
            .iter()
            .all(|permission| valid_value(&permission.name))
        && permissions
            .iter()
            .map(|permission| &permission.name)
            .collect::<BTreeSet<_>>()
            .len()
            == permissions.len()
}

fn valid_value(value: &str) -> bool {
    !value.trim().is_empty()
        && value.trim() == value
        && value.len() <= 1_024
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 10_000;

    fn permission(name: &str, access: ProviderPermissionAccess) -> ProviderPermission {
        ProviderPermission {
            name: name.into(),
            access,
        }
    }

    fn observation() -> VendorUseObservation {
        VendorUseObservation {
            tenant_id: TenantId::parse("tenant-1").unwrap(),
            platform: VendorUsePlatform::GitHub,
            kind: VendorUseObservationKind::ActiveInstallation,
            application_id: "github-app-123".into(),
            provider_tenant_id: "github-org-456".into(),
            use_case: "ci-performance-evaluation".into(),
            resource_urns: vec!["urn:github:repo:writer/cerebro".into()],
            permissions: vec![
                permission("contents", ProviderPermissionAccess::Read),
                permission("checks", ProviderPermissionAccess::Write),
            ],
            source_revision: "github-audit-event-789".into(),
            source_observed_at_unix_ms: NOW - 10,
        }
    }

    fn approval() -> VendorUseApproval {
        VendorUseApproval {
            tenant_id: TenantId::parse("tenant-1").unwrap(),
            decision_id: DecisionId::parse("decision-1").unwrap(),
            vendor_urn: "urn:vendor:example-ci".into(),
            security_review_ref: "vanta-review-123".into(),
            review_decision: VendorReviewDecision::Approved,
            platform: VendorUsePlatform::GitHub,
            application_id: "github-app-123".into(),
            provider_tenant_id: "github-org-456".into(),
            use_case: "ci-performance-evaluation".into(),
            permitted_resource_urns: vec![
                "urn:github:repo:writer/cerebro".into(),
                "urn:github:repo:writer/other".into(),
            ],
            permitted_permissions: vec![
                permission("contents", ProviderPermissionAccess::Read),
                permission("checks", ProviderPermissionAccess::Write),
            ],
            issued_at_unix_ms: NOW - 1_000,
            expires_at_unix_ms: NOW + 1_000,
            revoked_at_unix_ms: None,
            source_observed_at_unix_ms: NOW - 10,
        }
    }

    fn policy() -> VendorUsePolicy {
        VendorUsePolicy {
            max_observation_age_ms: 100,
            max_approval_evidence_age_ms: 100,
        }
    }

    #[test]
    fn authorizes_exact_fresh_scoped_use() {
        assert_eq!(
            evaluate_vendor_use(&observation(), Some(&approval()), policy(), NOW),
            VendorUseDecision::Authorized {
                decision_id: DecisionId::parse("decision-1").unwrap(),
                state: VendorUseState::ActiveCompliant,
            }
        );
    }

    #[test]
    fn active_installation_without_approval_is_unapproved() {
        assert_eq!(
            evaluate_vendor_use(&observation(), None, policy(), NOW),
            denied(
                VendorUseState::ActiveUnapproved,
                VendorUseDenial::NoApproval,
            )
        );
    }

    #[test]
    fn installation_request_without_approval_is_not_reported_as_active() {
        let mut request = observation();
        request.kind = VendorUseObservationKind::InstallationRequest;
        assert_eq!(
            evaluate_vendor_use(&request, None, policy(), NOW),
            denied(
                VendorUseState::RequestedUnapproved,
                VendorUseDenial::NoApproval,
            )
        );
    }

    #[test]
    fn approved_installation_request_is_not_reported_as_active() {
        let mut request = observation();
        request.kind = VendorUseObservationKind::InstallationRequest;
        assert_eq!(
            evaluate_vendor_use(&request, Some(&approval()), policy(), NOW),
            VendorUseDecision::Authorized {
                decision_id: DecisionId::parse("decision-1").unwrap(),
                state: VendorUseState::RequestedApproved,
            }
        );
    }

    #[test]
    fn pending_and_rejected_reviews_fail_closed() {
        let mut pending = approval();
        pending.review_decision = VendorReviewDecision::Pending;
        assert_eq!(
            evaluate_vendor_use(&observation(), Some(&pending), policy(), NOW),
            denied(
                VendorUseState::PendingReview,
                VendorUseDenial::ReviewPending
            )
        );

        pending.review_decision = VendorReviewDecision::Rejected;
        assert_eq!(
            evaluate_vendor_use(&observation(), Some(&pending), policy(), NOW),
            denied(
                VendorUseState::ReviewRejected,
                VendorUseDenial::ReviewRejected,
            )
        );
    }

    #[test]
    fn stale_provider_or_approval_evidence_fails_closed() {
        let mut stale_observation = observation();
        stale_observation.source_observed_at_unix_ms = NOW - 101;
        assert_eq!(
            evaluate_vendor_use(&stale_observation, Some(&approval()), policy(), NOW),
            denied(
                VendorUseState::ObservationEvidenceStale,
                VendorUseDenial::ObservationStale,
            )
        );

        let mut stale_approval = approval();
        stale_approval.source_observed_at_unix_ms = NOW - 101;
        assert_eq!(
            evaluate_vendor_use(&observation(), Some(&stale_approval), policy(), NOW),
            denied(
                VendorUseState::ApprovalEvidenceStale,
                VendorUseDenial::ApprovalEvidenceStale,
            )
        );

        stale_approval.review_decision = VendorReviewDecision::Pending;
        assert_eq!(
            evaluate_vendor_use(&observation(), Some(&stale_approval), policy(), NOW),
            denied(
                VendorUseState::ApprovalEvidenceStale,
                VendorUseDenial::ApprovalEvidenceStale,
            )
        );
    }

    #[test]
    fn expiry_and_revocation_are_distinct_states() {
        let mut expired = approval();
        expired.expires_at_unix_ms = NOW;
        assert_eq!(
            evaluate_vendor_use(&observation(), Some(&expired), policy(), NOW),
            denied(
                VendorUseState::ApprovalExpired,
                VendorUseDenial::ApprovalExpired,
            )
        );

        let mut revoked = approval();
        revoked.revoked_at_unix_ms = Some(NOW);
        assert_eq!(
            evaluate_vendor_use(&observation(), Some(&revoked), policy(), NOW),
            denied(
                VendorUseState::ApprovalRevoked,
                VendorUseDenial::ApprovalRevoked,
            )
        );
    }

    #[test]
    fn resource_expansion_is_scope_drift() {
        let mut expanded = observation();
        expanded
            .resource_urns
            .push("urn:github:repo:writer/private".into());
        assert_eq!(
            evaluate_vendor_use(&expanded, Some(&approval()), policy(), NOW),
            scope_drift(VendorUseDenial::ResourceNotApproved)
        );
    }

    #[test]
    fn missing_or_escalated_permission_is_scope_drift() {
        let mut missing = observation();
        missing
            .permissions
            .push(permission("administration", ProviderPermissionAccess::Read));
        assert_eq!(
            evaluate_vendor_use(&missing, Some(&approval()), policy(), NOW),
            scope_drift(VendorUseDenial::PermissionNotApproved)
        );

        let mut escalated = observation();
        escalated.permissions[0].access = ProviderPermissionAccess::Write;
        assert_eq!(
            evaluate_vendor_use(&escalated, Some(&approval()), policy(), NOW),
            scope_drift(VendorUseDenial::PermissionAccessExceeded)
        );
    }

    #[test]
    fn application_tenant_and_use_case_bindings_are_exact() {
        let mut mismatched = observation();
        mismatched.application_id = "github-app-other".into();
        assert_eq!(
            evaluate_vendor_use(&mismatched, Some(&approval()), policy(), NOW),
            scope_drift(VendorUseDenial::ApplicationMismatch)
        );

        let mut mismatched = observation();
        mismatched.provider_tenant_id = "github-org-other".into();
        assert_eq!(
            evaluate_vendor_use(&mismatched, Some(&approval()), policy(), NOW),
            scope_drift(VendorUseDenial::ProviderTenantMismatch)
        );

        let mut mismatched = observation();
        mismatched.use_case = "production-ci".into();
        assert_eq!(
            evaluate_vendor_use(&mismatched, Some(&approval()), policy(), NOW),
            scope_drift(VendorUseDenial::UseCaseMismatch)
        );
    }

    #[test]
    fn malformed_or_future_evidence_is_invalid() {
        let mut duplicated = observation();
        duplicated
            .resource_urns
            .push(duplicated.resource_urns[0].clone());
        assert_eq!(
            evaluate_vendor_use(&duplicated, Some(&approval()), policy(), NOW),
            denied(
                VendorUseState::InvalidEvidence,
                VendorUseDenial::InvalidObservation,
            )
        );

        let mut future = approval();
        future.source_observed_at_unix_ms = NOW + 1;
        assert_eq!(
            evaluate_vendor_use(&observation(), Some(&future), policy(), NOW),
            denied(
                VendorUseState::InvalidEvidence,
                VendorUseDenial::InvalidApproval,
            )
        );
    }
}
