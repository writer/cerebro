use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{ActionProposal, ActorId, ContentDigest, GraphRevision, OpaqueId, SdkError, TenantId};

const FINDING_VALIDATION_DIGEST_SCHEMA: &str = "cerebro.finding-validation.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingValidationDecision {
    Confirmed,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FindingValidationReceipt {
    pub tenant_id: TenantId,
    pub finding_id: OpaqueId,
    pub finding_revision_digest: ContentDigest,
    pub graph_revision: GraphRevision,
    pub policy_id: String,
    pub policy_definition_digest: ContentDigest,
    pub decision: FindingValidationDecision,
    pub evidence_digests: Vec<ContentDigest>,
    pub validated_by: ActorId,
    pub validated_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub receipt_digest: ContentDigest,
}

impl FindingValidationReceipt {
    pub fn computed_digest(&self) -> Result<ContentDigest, SdkError> {
        #[derive(Serialize)]
        struct DigestMaterial<'a> {
            schema: &'static str,
            tenant_id: &'a TenantId,
            finding_id: &'a OpaqueId,
            finding_revision_digest: &'a ContentDigest,
            graph_revision: &'a GraphRevision,
            policy_id: &'a str,
            policy_definition_digest: &'a ContentDigest,
            decision: FindingValidationDecision,
            evidence_digests: &'a [ContentDigest],
            validated_by: &'a ActorId,
            validated_at_unix_ms: u64,
            expires_at_unix_ms: u64,
        }

        serde_json::to_vec(&DigestMaterial {
            schema: FINDING_VALIDATION_DIGEST_SCHEMA,
            tenant_id: &self.tenant_id,
            finding_id: &self.finding_id,
            finding_revision_digest: &self.finding_revision_digest,
            graph_revision: &self.graph_revision,
            policy_id: &self.policy_id,
            policy_definition_digest: &self.policy_definition_digest,
            decision: self.decision,
            evidence_digests: &self.evidence_digests,
            validated_by: &self.validated_by,
            validated_at_unix_ms: self.validated_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
        })
        .map(ContentDigest::of_bytes)
        .map_err(|error| {
            SdkError::Backend(format!(
                "finding validation receipt serialization failed: {error}"
            ))
        })
    }

    pub fn bind_computed_digest(&mut self) -> Result<(), SdkError> {
        self.receipt_digest = self.computed_digest()?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), SdkError> {
        if self.evidence_digests.is_empty() || self.evidence_digests.len() > 100 {
            return Err(SdkError::OutOfRange("finding validation evidence count"));
        }
        if self.policy_id.is_empty()
            || self.policy_id.len() > 255
            || !self
                .policy_id
                .bytes()
                .enumerate()
                .all(|(index, byte)| match byte {
                    b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => true,
                    b'.' | b'_' | b'-' => index != 0,
                    _ => false,
                })
        {
            return Err(SdkError::Invalid("finding validation policy id"));
        }
        let evidence = self
            .evidence_digests
            .iter()
            .map(ContentDigest::as_str)
            .collect::<Vec<_>>();
        if evidence.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(SdkError::Invalid("finding validation evidence ordering"));
        }
        if self.validated_at_unix_ms == 0 || self.expires_at_unix_ms <= self.validated_at_unix_ms {
            return Err(SdkError::OutOfRange("finding validation validity"));
        }
        if self.receipt_digest != self.computed_digest()? {
            return Err(SdkError::Invalid("finding validation receipt digest"));
        }
        Ok(())
    }

    pub fn authorizes_action(
        &self,
        proposal: &ActionProposal,
        committed_at_unix_ms: u64,
    ) -> Result<(), SdkError> {
        self.validate()?;
        if self.decision != FindingValidationDecision::Confirmed {
            return Err(SdkError::Conflict(
                "the finding validation decision is not confirmed".to_owned(),
            ));
        }
        if self.tenant_id != proposal.tenant_id
            || self.finding_id != proposal.finding_id
            || self.finding_revision_digest != proposal.finding_revision_digest
            || self.graph_revision != proposal.graph_revision
            || self.receipt_digest != proposal.finding_validation_receipt_digest
        {
            return Err(SdkError::Conflict(
                "the finding validation receipt does not bind this Action proposal".to_owned(),
            ));
        }
        if self.validated_by == proposal.proposed_by {
            return Err(SdkError::Conflict(
                "the Action proposer cannot validate the finding".to_owned(),
            ));
        }
        if self.validated_at_unix_ms > proposal.proposed_at_unix_ms
            || committed_at_unix_ms < proposal.proposed_at_unix_ms
            || committed_at_unix_ms >= self.expires_at_unix_ms
        {
            return Err(SdkError::Conflict(
                "the finding validation receipt is not current at Action commit time".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredFindingValidationReceipt {
    tenant_id: String,
    finding_id: String,
    finding_revision_digest: String,
    graph_revision: u64,
    policy_id: String,
    policy_definition_digest: String,
    decision: FindingValidationDecision,
    evidence_digests: Vec<String>,
    validated_by: String,
    validated_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    receipt_digest: String,
}

impl TryFrom<StoredFindingValidationReceipt> for FindingValidationReceipt {
    type Error = SdkError;

    fn try_from(stored: StoredFindingValidationReceipt) -> Result<Self, Self::Error> {
        let receipt = Self {
            tenant_id: TenantId::parse(stored.tenant_id)
                .map_err(|_| SdkError::Invalid("finding validation tenant id"))?,
            finding_id: OpaqueId::parse(stored.finding_id)?,
            finding_revision_digest: ContentDigest::parse(stored.finding_revision_digest)?,
            graph_revision: GraphRevision::new(stored.graph_revision)?,
            policy_id: stored.policy_id,
            policy_definition_digest: ContentDigest::parse(stored.policy_definition_digest)?,
            decision: stored.decision,
            evidence_digests: stored
                .evidence_digests
                .into_iter()
                .map(ContentDigest::parse)
                .collect::<Result<_, _>>()?,
            validated_by: ActorId::parse(stored.validated_by)
                .map_err(|_| SdkError::Invalid("finding validator actor id"))?,
            validated_at_unix_ms: stored.validated_at_unix_ms,
            expires_at_unix_ms: stored.expires_at_unix_ms,
            receipt_digest: ContentDigest::parse(stored.receipt_digest)?,
        };
        receipt.validate()?;
        Ok(receipt)
    }
}

impl<'de> Deserialize<'de> for FindingValidationReceipt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        StoredFindingValidationReceipt::deserialize(deserializer)?
            .try_into()
            .map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{ActionEffect, ActionOperationId};

    fn receipt() -> FindingValidationReceipt {
        let mut receipt = FindingValidationReceipt {
            tenant_id: TenantId::parse("tenant:one").unwrap(),
            finding_id: OpaqueId::parse("finding:one").unwrap(),
            finding_revision_digest: ContentDigest::of_bytes("finding"),
            graph_revision: GraphRevision::new(4).unwrap(),
            policy_id: "policy-one".to_owned(),
            policy_definition_digest: ContentDigest::of_bytes("policy"),
            decision: FindingValidationDecision::Confirmed,
            evidence_digests: vec![
                ContentDigest::of_bytes("evidence-one"),
                ContentDigest::of_bytes("evidence-two"),
            ],
            validated_by: ActorId::parse("validator:one").unwrap(),
            validated_at_unix_ms: 10,
            expires_at_unix_ms: 30,
            receipt_digest: ContentDigest::of_bytes("placeholder"),
        };
        receipt.bind_computed_digest().unwrap();
        receipt
    }

    fn proposal(receipt: &FindingValidationReceipt) -> ActionProposal {
        let target = OpaqueId::parse("target:one").unwrap();
        let mut proposal = ActionProposal {
            operation_id: ActionOperationId::parse("operation:one").unwrap(),
            tenant_id: receipt.tenant_id.clone(),
            finding_id: receipt.finding_id.clone(),
            finding_revision_digest: receipt.finding_revision_digest.clone(),
            finding_validation_receipt_digest: receipt.receipt_digest.clone(),
            graph_revision: receipt.graph_revision,
            action_kind: "endpoint.cerebro.revoke_device".to_owned(),
            action_definition_digest: ContentDigest::of_bytes("definition"),
            target_id: target.clone(),
            expected_effects: vec![ActionEffect {
                target_id: target,
                effect_kind: "deny_device_access".to_owned(),
                expected_state_digest: ContentDigest::of_bytes("expected"),
            }],
            rollback_ref: OpaqueId::parse("rollback:one").unwrap(),
            idempotency_key: OpaqueId::parse("idempotency:one").unwrap(),
            simulation_digest: ContentDigest::of_bytes("simulation"),
            verification_plan_digest: ContentDigest::of_bytes("verification"),
            proposed_by: ActorId::parse("proposer:one").unwrap(),
            proposed_at_unix_ms: 20,
            proposal_expires_at_unix_ms: 40,
            proposal_digest: ContentDigest::of_bytes("placeholder"),
        };
        proposal.bind_computed_digest().unwrap();
        proposal
    }

    #[test]
    fn confirmed_receipt_binds_action_and_rejects_spoofed_authority() {
        let receipt = receipt();
        let authorized_proposal = proposal(&receipt);
        receipt.authorizes_action(&authorized_proposal, 20).unwrap();

        let mut rejected = receipt.clone();
        rejected.decision = FindingValidationDecision::Rejected;
        rejected.bind_computed_digest().unwrap();
        let rejected_proposal = proposal(&rejected);
        assert!(rejected.authorizes_action(&rejected_proposal, 20).is_err());

        let mut stale = receipt.clone();
        stale.expires_at_unix_ms = 20;
        stale.bind_computed_digest().unwrap();
        let stale_proposal = proposal(&stale);
        assert!(stale.authorizes_action(&stale_proposal, 20).is_err());

        let mut self_validated = proposal(&receipt);
        self_validated.proposed_by = receipt.validated_by.clone();
        self_validated.bind_computed_digest().unwrap();
        assert!(receipt.authorizes_action(&self_validated, 20).is_err());

        let mut wrong_graph = proposal(&receipt);
        wrong_graph.graph_revision = GraphRevision::new(5).unwrap();
        wrong_graph.bind_computed_digest().unwrap();
        assert!(receipt.authorizes_action(&wrong_graph, 20).is_err());
    }

    #[test]
    fn receipt_requires_canonical_evidence_and_digest() {
        let receipt = receipt();
        let value = serde_json::to_value(&receipt).unwrap();
        assert_eq!(
            serde_json::from_value::<FindingValidationReceipt>(value.clone()).unwrap(),
            receipt
        );

        let mut unordered = receipt.clone();
        unordered.evidence_digests.reverse();
        unordered.bind_computed_digest().unwrap();
        assert!(unordered.validate().is_err());

        let mut tampered = value;
        tampered["expires_at_unix_ms"] = serde_json::json!(31);
        assert!(serde_json::from_value::<FindingValidationReceipt>(tampered).is_err());

        let unique = receipt.evidence_digests.iter().collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), receipt.evidence_digests.len());
    }
}
