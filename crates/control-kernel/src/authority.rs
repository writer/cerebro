use serde::{Deserialize, Serialize};

use crate::{ActorId, DecisionId, GrantId, TenantId, VerificationId};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Time-bounded authority for one actor to perform named actions on scoped resources.
///
/// A grant is data, not proof of authorization by itself. Call [`Self::authorize`]
/// with the exact tenant, actor, action, resource, and observation time before use.
pub struct CapabilityGrant {
    /// Tenant whose policy domain issued and consumes the grant.
    pub tenant_id: TenantId,
    /// Stable identifier copied into successful authorization decisions.
    pub grant_id: GrantId,
    /// Only actor permitted to exercise the grant.
    pub actor_id: ActorId,
    /// Exact action names permitted by the grant; wildcards are not interpreted.
    pub actions: Vec<String>,
    /// Resource URN prefixes delimiting the grant's target scope.
    pub resource_urn_prefixes: Vec<String>,
    /// Inclusive Unix-millisecond start of the authorization window.
    pub issued_at_unix_ms: u64,
    /// Exclusive Unix-millisecond end of the authorization window.
    pub expires_at_unix_ms: u64,
    /// Inclusive revocation time, when the grant was withdrawn early.
    pub revoked_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Exact attempted use of a [`CapabilityGrant`].
pub struct AuthorizationRequest {
    /// Tenant containing the target operation.
    pub tenant_id: TenantId,
    /// Actor that will execute the operation.
    pub actor_id: ActorId,
    /// Exact capability or action name being requested.
    pub action: String,
    /// Canonical resource URN that the action would affect.
    pub resource_urn: String,
    /// Unix-millisecond decision time used for validity and revocation checks.
    pub observed_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
/// Result of matching an authorization request against one capability grant.
pub enum AuthorizationDecision {
    /// Every tenant, actor, action, resource, and time binding matched.
    Allowed {
        /// Grant that authorized the exact request.
        grant_id: GrantId,
    },
    /// At least one required binding failed closed.
    Denied {
        /// First deterministic reason the request was rejected.
        reason: AuthorizationDenial,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Fail-closed reason a capability grant cannot authorize a request.
pub enum AuthorizationDenial {
    /// The grant has invalid time bounds, empty scope, or malformed values.
    InvalidGrant,
    /// Request and grant belong to different tenants.
    TenantMismatch,
    /// Requesting actor is not the actor named by the grant.
    ActorMismatch,
    /// Request time precedes the grant's inclusive start.
    NotYetValid,
    /// Request time is at or after the grant's exclusive expiry.
    Expired,
    /// Request time is at or after the recorded revocation time.
    Revoked,
    /// The exact requested action is absent from the grant.
    ActionNotGranted,
    /// The resource URN does not begin with any granted prefix.
    ResourceNotGranted,
}

impl CapabilityGrant {
    /// Evaluates every grant binding against an exact request.
    ///
    /// Checks have a deterministic order and return the first denial. Resource
    /// matching is literal prefix matching; callers must issue delimiters that
    /// prevent sibling-resource ambiguity. An allowed result identifies the grant
    /// but does not execute the action or prove its eventual effect.
    pub fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationDecision {
        let denial = if !self.is_well_formed() {
            Some(AuthorizationDenial::InvalidGrant)
        } else if self.tenant_id != request.tenant_id {
            Some(AuthorizationDenial::TenantMismatch)
        } else if self.actor_id != request.actor_id {
            Some(AuthorizationDenial::ActorMismatch)
        } else if request.observed_at_unix_ms < self.issued_at_unix_ms {
            Some(AuthorizationDenial::NotYetValid)
        } else if request.observed_at_unix_ms >= self.expires_at_unix_ms {
            Some(AuthorizationDenial::Expired)
        } else if self
            .revoked_at_unix_ms
            .is_some_and(|revoked| request.observed_at_unix_ms >= revoked)
        {
            Some(AuthorizationDenial::Revoked)
        } else if !self.actions.iter().any(|action| action == &request.action) {
            Some(AuthorizationDenial::ActionNotGranted)
        } else if !self
            .resource_urn_prefixes
            .iter()
            .any(|prefix| request.resource_urn.starts_with(prefix))
        {
            Some(AuthorizationDenial::ResourceNotGranted)
        } else {
            None
        };

        match denial {
            Some(reason) => AuthorizationDecision::Denied { reason },
            None => AuthorizationDecision::Allowed {
                grant_id: self.grant_id.clone(),
            },
        }
    }

    fn is_well_formed(&self) -> bool {
        self.issued_at_unix_ms < self.expires_at_unix_ms
            && !self.actions.is_empty()
            && !self.resource_urn_prefixes.is_empty()
            && self.actions.iter().all(|value| valid_value(value))
            && self
                .resource_urn_prefixes
                .iter()
                .all(|value| valid_value(value))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Durable approval or rejection bound to the digest of an exact proposal.
pub struct DecisionReceipt {
    /// Stable identifier for the approval-system decision.
    pub decision_id: DecisionId,
    /// Digest of the complete proposal presented to the decision maker.
    pub proposal_digest: String,
    /// Whether the decision maker approved the proposal.
    pub approved: bool,
    /// Canonical human, service, or policy actor that made the decision.
    pub decided_by: ActorId,
    /// Non-zero Unix-millisecond time at which the decision was recorded.
    pub decided_at_unix_ms: u64,
}

impl DecisionReceipt {
    /// Returns whether this receipt approves the exact expected proposal digest.
    ///
    /// This check deliberately says nothing about whether `decided_by` had approval
    /// authority; the adapter importing the receipt must establish that provenance.
    pub fn authorizes(&self, expected_proposal_digest: &str) -> bool {
        self.approved
            && valid_value(&self.proposal_digest)
            && self.proposal_digest == expected_proposal_digest
            && self.decided_at_unix_ms > 0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Independent post-effect observation used to verify an external state change.
pub struct VerificationReceipt {
    /// Stable identifier for this verification observation.
    pub verification_id: VerificationId,
    /// Actor that performed the effect being evaluated.
    pub executor_actor_id: ActorId,
    /// Different actor that made the post-effect observation.
    pub verifier_actor_id: ActorId,
    /// Authoritative source revision observed before execution.
    pub previous_source_revision: String,
    /// Authoritative source revision observed after execution.
    pub observed_source_revision: String,
    /// Whether the verifier found the intended effect in the new source state.
    pub effective: bool,
    /// Non-empty authoritative evidence records supporting the conclusion.
    pub evidence_urns: Vec<String>,
    /// Non-zero Unix-millisecond time of the independent observation.
    pub verified_at_unix_ms: u64,
}

impl VerificationReceipt {
    /// Returns whether the receipt independently confirms an effective state change.
    ///
    /// Confirmation requires different executor and verifier identities, a changed
    /// authoritative source revision, an affirmative effect result, evidence URNs,
    /// and a non-zero verification time. It does not validate provider signatures;
    /// importing adapters remain responsible for receipt authenticity.
    pub fn independently_confirms_effect(&self) -> bool {
        self.executor_actor_id != self.verifier_actor_id
            && valid_value(&self.previous_source_revision)
            && valid_value(&self.observed_source_revision)
            && self.previous_source_revision != self.observed_source_revision
            && self.effective
            && !self.evidence_urns.is_empty()
            && self.evidence_urns.iter().all(|urn| valid_value(urn))
            && self.verified_at_unix_ms > 0
    }
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

    fn grant() -> CapabilityGrant {
        CapabilityGrant {
            tenant_id: TenantId::parse("tenant-1").unwrap(),
            grant_id: GrantId::parse("grant-1").unwrap(),
            actor_id: ActorId::parse("worker-1").unwrap(),
            actions: vec!["identity.disable".into()],
            resource_urn_prefixes: vec!["urn:identity:".into()],
            issued_at_unix_ms: 100,
            expires_at_unix_ms: 200,
            revoked_at_unix_ms: None,
        }
    }

    fn request() -> AuthorizationRequest {
        AuthorizationRequest {
            tenant_id: TenantId::parse("tenant-1").unwrap(),
            actor_id: ActorId::parse("worker-1").unwrap(),
            action: "identity.disable".into(),
            resource_urn: "urn:identity:123".into(),
            observed_at_unix_ms: 150,
        }
    }

    #[test]
    fn grants_bind_tenant_actor_action_resource_and_time() {
        assert!(matches!(
            grant().authorize(&request()),
            AuthorizationDecision::Allowed { .. }
        ));

        let mut wrong_tenant = request();
        wrong_tenant.tenant_id = TenantId::parse("tenant-2").unwrap();
        assert_eq!(
            grant().authorize(&wrong_tenant),
            AuthorizationDecision::Denied {
                reason: AuthorizationDenial::TenantMismatch
            }
        );

        let mut expired = request();
        expired.observed_at_unix_ms = 200;
        assert_eq!(
            grant().authorize(&expired),
            AuthorizationDecision::Denied {
                reason: AuthorizationDenial::Expired
            }
        );
    }

    #[test]
    fn grants_fail_closed_for_every_binding() {
        let mut invalid = grant();
        invalid.actions.clear();
        assert_eq!(
            invalid.authorize(&request()),
            AuthorizationDecision::Denied {
                reason: AuthorizationDenial::InvalidGrant
            }
        );

        let mut wrong_actor = request();
        wrong_actor.actor_id = ActorId::parse("worker-2").unwrap();
        assert_eq!(
            grant().authorize(&wrong_actor),
            AuthorizationDecision::Denied {
                reason: AuthorizationDenial::ActorMismatch
            }
        );
        let mut early = request();
        early.observed_at_unix_ms = 99;
        assert_eq!(
            grant().authorize(&early),
            AuthorizationDecision::Denied {
                reason: AuthorizationDenial::NotYetValid
            }
        );
        let mut revoked = grant();
        revoked.revoked_at_unix_ms = Some(150);
        assert_eq!(
            revoked.authorize(&request()),
            AuthorizationDecision::Denied {
                reason: AuthorizationDenial::Revoked
            }
        );
        let mut wrong_action = request();
        wrong_action.action = "identity.delete".into();
        assert_eq!(
            grant().authorize(&wrong_action),
            AuthorizationDecision::Denied {
                reason: AuthorizationDenial::ActionNotGranted
            }
        );
        let mut wrong_resource = request();
        wrong_resource.resource_urn = "urn:database:1".into();
        assert_eq!(
            grant().authorize(&wrong_resource),
            AuthorizationDecision::Denied {
                reason: AuthorizationDenial::ResourceNotGranted
            }
        );
    }

    #[test]
    fn decisions_bind_the_exact_proposal() {
        let receipt = DecisionReceipt {
            decision_id: DecisionId::parse("decision-1").unwrap(),
            proposal_digest: "sha256:approved".into(),
            approved: true,
            decided_by: ActorId::parse("policy-engine").unwrap(),
            decided_at_unix_ms: 10,
        };
        assert!(receipt.authorizes("sha256:approved"));
        assert!(!receipt.authorizes("sha256:changed"));
    }

    #[test]
    fn verification_requires_a_new_source_revision_and_independent_actor() {
        let mut receipt = VerificationReceipt {
            verification_id: VerificationId::parse("verification-1").unwrap(),
            executor_actor_id: ActorId::parse("worker-1").unwrap(),
            verifier_actor_id: ActorId::parse("observer-1").unwrap(),
            previous_source_revision: "revision-1".into(),
            observed_source_revision: "revision-2".into(),
            effective: true,
            evidence_urns: vec!["urn:evidence:1".into()],
            verified_at_unix_ms: 20,
        };
        assert!(receipt.independently_confirms_effect());
        receipt.verifier_actor_id = receipt.executor_actor_id.clone();
        assert!(!receipt.independently_confirms_effect());
    }
}
