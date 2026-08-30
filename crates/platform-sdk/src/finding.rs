//! Content-addressed validation receipts that gate action proposals from findings.
//!
//! A receipt binds one finding revision, graph revision, policy definition,
//! ordered evidence set, validator, decision, and validity window. Validation is
//! deterministic and transport-safe, but policy evaluation, evidence admission,
//! actor authorization, and durable receipt storage happen outside this module.

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{ActionProposal, ActorId, ContentDigest, GraphRevision, OpaqueId, SdkError, TenantId};

// Domain-separate this receipt from other JSON values hashed with SHA-256.
const FINDING_VALIDATION_DIGEST_SCHEMA: &str = "cerebro.finding-validation.v1";

/// Binary outcome assigned by the finding-validation authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingValidationDecision {
    /// Evidence and policy established the finding as confirmed.
    Confirmed,
    /// Evidence or policy rejected the finding.
    Rejected,
}

/// Self-validating receipt for one policy decision over one finding revision.
///
/// Evidence digests are a canonical set encoded as a strictly increasing vector
/// of one to 100 values. Current receipts require a non-empty policy ID when
/// authorizing an action. Historical receipts that predate Rust policy binding
/// remain deserializable with an empty policy ID but are intentionally barred
/// from action authorization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FindingValidationReceipt {
    /// Tenant whose finding, graph revision, and policy were evaluated.
    pub tenant_id: TenantId,
    /// Stable identity of the validated finding.
    pub finding_id: OpaqueId,
    /// Digest of the exact finding revision that was evaluated.
    pub finding_revision_digest: ContentDigest,
    /// Non-zero graph revision used during validation.
    pub graph_revision: GraphRevision,
    /// Stable policy identity, omitted on the wire only for historical receipts.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub policy_id: String,
    /// Digest of the exact policy definition applied.
    pub policy_definition_digest: ContentDigest,
    /// Confirmed or rejected validation outcome.
    pub decision: FindingValidationDecision,
    /// Strictly sorted, duplicate-free evidence content digests.
    pub evidence_digests: Vec<ContentDigest>,
    /// Actor that issued the validation decision.
    pub validated_by: ActorId,
    /// Non-zero Unix-millisecond validation time.
    pub validated_at_unix_ms: u64,
    /// Exclusive Unix-millisecond expiration time.
    pub expires_at_unix_ms: u64,
    /// SHA-256 digest of the schema-tagged receipt material.
    pub receipt_digest: ContentDigest,
}

impl FindingValidationReceipt {
    /// Computes the schema-tagged digest for the receipt's semantic fields.
    ///
    /// The stored [`Self::receipt_digest`] is excluded to avoid recursive
    /// content addressing. A non-empty policy ID selects the current material;
    /// an empty ID selects the historical layout that omitted the field. Vector
    /// order is preserved, so callers should validate canonical evidence order
    /// before treating the digest as an authoritative receipt identity.
    ///
    /// This method serializes fields as supplied and does not otherwise validate
    /// the receipt.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Backend`] if JSON serialization fails.
    pub fn computed_digest(&self) -> Result<ContentDigest, SdkError> {
        if self.policy_id.is_empty() {
            return self.computed_legacy_digest();
        }

        // A dedicated struct freezes field order and prevents receipt_digest
        // from accidentally entering its own hash material.
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

    /// Computes the digest layout used before receipts carried a policy ID.
    ///
    /// The schema tag remains the same for wire compatibility; omission of the
    /// `policy_id` field is what distinguishes the historical digest material.
    fn computed_legacy_digest(&self) -> Result<ContentDigest, SdkError> {
        #[derive(Serialize)]
        struct DigestMaterial<'a> {
            schema: &'static str,
            tenant_id: &'a TenantId,
            finding_id: &'a OpaqueId,
            finding_revision_digest: &'a ContentDigest,
            graph_revision: &'a GraphRevision,
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
                "legacy finding validation receipt serialization failed: {error}"
            ))
        })
    }

    /// Replaces the stored digest with [`Self::computed_digest`].
    ///
    /// This helper does not call [`Self::validate`]. A caller can therefore bind
    /// a digest to malformed or non-canonical fields and must validate before
    /// persisting or using the receipt for authority.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Backend`] if digest serialization fails.
    pub fn bind_computed_digest(&mut self) -> Result<(), SdkError> {
        self.receipt_digest = self.computed_digest()?;
        Ok(())
    }

    /// Validates canonical shape, validity interval, and receipt digest.
    ///
    /// Current policy IDs are at most 255 bytes, begin with an ASCII
    /// alphanumeric character, and then contain only ASCII alphanumerics, `.`,
    /// `_`, or `-`. An empty policy ID is accepted only for historical read
    /// compatibility. Evidence must contain one to 100 strictly increasing
    /// digests, which simultaneously enforces deterministic order and uniqueness.
    ///
    /// This check does not evaluate policy, authenticate the validator, load the
    /// finding or graph revision, verify evidence availability, or prove tenant
    /// ownership of referenced objects.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::OutOfRange`] for invalid evidence count or validity
    /// interval, [`SdkError::Invalid`] for malformed policy identity,
    /// non-canonical evidence order, or a mismatched receipt digest, and
    /// [`SdkError::Backend`] if digest serialization fails.
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.evidence_digests.is_empty() || self.evidence_digests.len() > 100 {
            return Err(SdkError::OutOfRange("finding validation evidence count"));
        }
        if !self.policy_id.is_empty()
            && (self.policy_id.len() > 255
                || !self
                    .policy_id
                    .bytes()
                    .enumerate()
                    .all(|(index, byte)| match byte {
                        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => true,
                        b'.' | b'_' | b'-' => index != 0,
                        _ => false,
                    }))
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

    /// Checks whether this receipt authorizes one proposal at commit time.
    ///
    /// Authorization requires a valid current-format receipt with a confirmed
    /// decision; exact tenant, finding identity and revision, graph revision,
    /// and receipt-digest binding; separation between validator and proposer;
    /// validation no later than proposal time; commit no earlier than proposal
    /// time; and commit strictly before receipt expiration.
    ///
    /// This method validates the receipt but does not call
    /// [`ActionProposal::validate`], recompute the proposal digest, authorize the
    /// actors, or execute the action. The action-admission boundary must perform
    /// those independent checks before accepting this result as authority.
    ///
    /// # Errors
    ///
    /// Returns receipt validation errors, or [`SdkError::Conflict`] for a legacy
    /// receipt, rejected decision, binding mismatch, self-validation, or invalid
    /// proposal/commit timing.
    pub fn authorizes_action(
        &self,
        proposal: &ActionProposal,
        committed_at_unix_ms: u64,
    ) -> Result<(), SdkError> {
        self.validate()?;
        if self.policy_id.is_empty() {
            return Err(SdkError::Conflict(
                "the finding validation receipt predates Rust policy binding".to_owned(),
            ));
        }
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

        // Receipt identity binds the policy material indirectly; explicit actor
        // separation prevents the proposal author from self-validating the gate.
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

/// Strict wire representation decoded before typed validation.
///
/// Unknown fields are rejected to prevent silently unsigned extensions from
/// entering a receipt. `policy_id` alone is optional for historical payloads;
/// every other field must be present.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredFindingValidationReceipt {
    tenant_id: String,
    finding_id: String,
    finding_revision_digest: String,
    graph_revision: u64,
    #[serde(default)]
    policy_id: Option<String>,
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

    /// Parses typed identities and validates the complete stored receipt.
    ///
    /// A missing historical policy ID is normalized to the empty-string sentinel
    /// used by legacy digest computation and serialization compatibility.
    fn try_from(stored: StoredFindingValidationReceipt) -> Result<Self, Self::Error> {
        let receipt = Self {
            tenant_id: TenantId::parse(stored.tenant_id)
                .map_err(|_| SdkError::Invalid("finding validation tenant id"))?,
            finding_id: OpaqueId::parse(stored.finding_id)?,
            finding_revision_digest: ContentDigest::parse(stored.finding_revision_digest)?,
            graph_revision: GraphRevision::new(stored.graph_revision)?,
            policy_id: stored.policy_id.unwrap_or_default(),
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
    /// Decodes only strict, typed, digest-valid receipt payloads.
    ///
    /// Deserialization is intentionally routed through the stored form so public
    /// consumers cannot obtain an unchecked receipt from untrusted JSON.
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

    #[test]
    fn historical_receipt_without_policy_id_remains_readable_but_cannot_authorize_actions() {
        let mut historical = receipt();
        historical.policy_id.clear();
        historical.bind_computed_digest().unwrap();
        let value = serde_json::to_value(&historical).unwrap();

        assert!(value.get("policy_id").is_none());
        let decoded = serde_json::from_value::<FindingValidationReceipt>(value).unwrap();
        assert_eq!(decoded, historical);
        assert!(decoded.authorizes_action(&proposal(&decoded), 20).is_err());
    }
}
