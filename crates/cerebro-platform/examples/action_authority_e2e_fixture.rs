use std::{
    error::Error,
    time::{SystemTime, UNIX_EPOCH},
};

use cerebro_action_catalog::lookup;
use cerebro_platform_sdk::{
    ActionEffect, ActionOperationId, ActionProposal, ActorId, ContentDigest,
    FindingValidationDecision, FindingValidationReceipt, GraphRevision, OpaqueId, TenantId,
};
use serde::Serialize;

const TENANT_ID: &str = "tenant-demo";
const VALIDATOR_ID: &str = "validator:rust-e2e";
const PROPOSER_ID: &str = "proposer:rust-e2e";
const APPROVER_ID: &str = "approver:rust-e2e";
const WORKER_ID: &str = "rust-e2e-user";
const OPERATION_ID: &str = "operation:rust-action-e2e";

#[derive(Serialize)]
struct Fixture {
    finding_validation: FindingValidationReceipt,
    proposal: ActionProposal,
    approver_id: &'static str,
    worker_id: &'static str,
    operation_id: &'static str,
    decision_id: &'static str,
    claim_expires_at_unix_ms: u64,
}

fn main() -> Result<(), Box<dyn Error>> {
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let expires_at = now
        .checked_add(10 * 60 * 1_000)
        .ok_or("fixture expiration overflow")?;
    let policy = cerebro_policy_catalog::definitions()
        .first()
        .ok_or("generated policy catalog is empty")?;
    let definition = lookup("identity.okta.suspend_user")?;

    let mut finding_validation = FindingValidationReceipt {
        tenant_id: TenantId::parse(TENANT_ID)?,
        finding_id: OpaqueId::parse("finding:rust-action-e2e")?,
        finding_revision_digest: ContentDigest::of_bytes("rust-action-e2e-finding-revision"),
        graph_revision: GraphRevision::new(1)?,
        policy_id: policy.id.to_owned(),
        policy_definition_digest: ContentDigest::parse(policy.definition_digest)?,
        decision: FindingValidationDecision::Confirmed,
        evidence_digests: vec![ContentDigest::of_bytes("rust-action-e2e-evidence")],
        validated_by: ActorId::parse(VALIDATOR_ID)?,
        validated_at_unix_ms: now,
        expires_at_unix_ms: expires_at,
        receipt_digest: ContentDigest::of_bytes("unbound"),
    };
    finding_validation.bind_computed_digest()?;

    let target_id = OpaqueId::parse("okta-user:rust-e2e")?;
    let mut proposal = ActionProposal {
        operation_id: ActionOperationId::parse(OPERATION_ID)?,
        tenant_id: finding_validation.tenant_id.clone(),
        finding_id: finding_validation.finding_id.clone(),
        finding_revision_digest: finding_validation.finding_revision_digest.clone(),
        finding_validation_receipt_digest: finding_validation.receipt_digest.clone(),
        graph_revision: finding_validation.graph_revision,
        action_kind: definition.id.to_owned(),
        action_definition_digest: ContentDigest::parse(definition.definition_digest)?,
        target_id: target_id.clone(),
        expected_effects: vec![ActionEffect {
            target_id,
            effect_kind: definition.effect.to_owned(),
            expected_state_digest: ContentDigest::of_bytes("suspended"),
        }],
        rollback_ref: OpaqueId::parse("rollback:rust-action-e2e")?,
        idempotency_key: OpaqueId::parse("idempotency:rust-action-e2e")?,
        simulation_digest: ContentDigest::of_bytes("rust-action-e2e-simulation"),
        verification_plan_digest: ContentDigest::of_bytes("rust-action-e2e-verification"),
        proposed_by: ActorId::parse(PROPOSER_ID)?,
        proposed_at_unix_ms: now,
        proposal_expires_at_unix_ms: expires_at,
        proposal_digest: ContentDigest::of_bytes("unbound"),
    };
    proposal.bind_computed_digest()?;

    println!(
        "{}",
        serde_json::to_string(&Fixture {
            finding_validation,
            proposal,
            approver_id: APPROVER_ID,
            worker_id: WORKER_ID,
            operation_id: OPERATION_ID,
            decision_id: "decision:rust-action-e2e",
            claim_expires_at_unix_ms: expires_at,
        })?
    );
    Ok(())
}
