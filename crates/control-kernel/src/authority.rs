use serde::{Deserialize, Serialize};

use crate::{ActorId, DecisionId, GrantId, TenantId, VerificationId};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CapabilityGrant {
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
    pub actor_id: ActorId,
    pub actions: Vec<String>,
    pub resource_urn_prefixes: Vec<String>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub revoked_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthorizationRequest {
    pub tenant_id: TenantId,
    pub actor_id: ActorId,
    pub action: String,
    pub resource_urn: String,
    pub observed_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum AuthorizationDecision {
    Allowed { grant_id: GrantId },
    Denied { reason: AuthorizationDenial },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationDenial {
    InvalidGrant,
    TenantMismatch,
    ActorMismatch,
    NotYetValid,
    Expired,
    Revoked,
    ActionNotGranted,
    ResourceNotGranted,
}

impl CapabilityGrant {
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
pub struct DecisionReceipt {
    pub decision_id: DecisionId,
    pub proposal_digest: String,
    pub approved: bool,
    pub decided_by: ActorId,
    pub decided_at_unix_ms: u64,
}

impl DecisionReceipt {
    pub fn authorizes(&self, expected_proposal_digest: &str) -> bool {
        self.approved
            && valid_value(&self.proposal_digest)
            && self.proposal_digest == expected_proposal_digest
            && self.decided_at_unix_ms > 0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerificationReceipt {
    pub verification_id: VerificationId,
    pub executor_actor_id: ActorId,
    pub verifier_actor_id: ActorId,
    pub previous_source_revision: String,
    pub observed_source_revision: String,
    pub effective: bool,
    pub evidence_urns: Vec<String>,
    pub verified_at_unix_ms: u64,
}

impl VerificationReceipt {
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
