use std::collections::{BTreeMap, BTreeSet};

use cerebro_platform_engine::{
    ActionCommand, RevisionSnapshot, SimulationTopology, SnapshotKey, SnapshotValue,
    assertion_definition_digest, build_recovery_report, compile_assertion, diff_snapshots,
    evaluate_assertion, event_matches, incident_manifest_digest, package_incident_snapshot,
    plan_query, simulate_topology, transition_action,
};
use cerebro_platform_sdk::{
    ActionEffect, ActionOperation, ActionOperationId, ActionProposal, ActionState,
    AssertionCondition, AssertionDefinition, AssertionDefinitionId, AssertionState, ContentDigest,
    EntityId, EvaluationTrigger, EvidenceQuality, FactQuery, GraphDiffRequest, GraphRevision,
    IncidentSnapshotId, IncidentSnapshotManifest, OpaqueId, PlatformEvent, PlatformEventKind,
    ProposedChange, QueryNode, QueryResult, RecoveryCheck, RecoveryState, ResourceBudget,
    RevisionSelector, SimulationId, SimulationRequest, SubscriptionEventFilter, TenantId,
    VerificationState,
};

fn tenant() -> TenantId {
    TenantId::parse("tenant-a").expect("valid tenant")
}

fn revision(value: u64) -> GraphRevision {
    GraphRevision::new(value).expect("valid revision")
}

fn digest(value: &str) -> ContentDigest {
    ContentDigest::of_bytes(value)
}

fn query(limit: usize) -> FactQuery {
    FactQuery::new(
        vec![QueryNode {
            variable: "repository".to_owned(),
            kinds: vec!["repository".to_owned()],
            keys: vec!["repository:one".to_owned()],
        }],
        Vec::new(),
        Vec::new(),
        limit,
    )
    .expect("valid query")
}

#[test]
fn typed_assertions_compile_and_evaluate_without_transport_state() {
    let mut definition = AssertionDefinition {
        assertion_id: AssertionDefinitionId::parse("assertion-definition:one")
            .expect("valid assertion"),
        tenant_id: tenant(),
        name: "Repository exists".to_owned(),
        query: query(10),
        condition: AssertionCondition::AtLeastOneMatch,
        triggers: vec![EvaluationTrigger::GraphChange],
        evidence_max_age_seconds: 300,
        enabled: true,
        definition_digest: digest("placeholder"),
    };
    definition.definition_digest =
        assertion_definition_digest(&definition).expect("definition digest");
    let compiled = compile_assertion(definition).expect("compiled assertion");
    let result = QueryResult {
        tenant_id: tenant(),
        graph_revision: 3,
        matches: Vec::new(),
        truncated: false,
    };
    let quality = EvidenceQuality::new(100, 100, 100, 100, 100, false).expect("valid quality");
    let evaluation =
        evaluate_assertion(&compiled, &result, &quality, 10).expect("assertion evaluation");
    assert_eq!(evaluation.state, AssertionState::Violated);
    assert_eq!(evaluation.reason_codes, vec!["condition_not_met"]);
}

#[test]
fn temporal_diff_is_stable_bounded_and_cursor_bound() {
    let entity = EntityId::parse("repository:one").expect("valid entity");
    let before = RevisionSnapshot {
        tenant_id: tenant(),
        revision: revision(1),
        values: BTreeMap::from([(
            SnapshotKey::Entity(entity.clone()),
            SnapshotValue {
                digest: digest("before"),
                observed_at_unix_millis: 1,
            },
        )]),
    };
    let after = RevisionSnapshot {
        tenant_id: tenant(),
        revision: revision(2),
        values: BTreeMap::from([(
            SnapshotKey::Entity(entity),
            SnapshotValue {
                digest: digest("after"),
                observed_at_unix_millis: 2,
            },
        )]),
    };
    let request = GraphDiffRequest {
        tenant_id: tenant(),
        from_revision: revision(1),
        to_revision: RevisionSelector::Exact(revision(2)),
        limit: 1,
        cursor: None,
    };
    let result = diff_snapshots(&request, &before, &after).expect("graph diff");
    assert_eq!(result.changes.len(), 1);
    assert!(!result.truncated);
}

#[test]
fn subscriptions_match_every_declared_dimension() {
    let filter = SubscriptionEventFilter {
        event_kinds: vec![PlatformEventKind::GraphChanged],
        entity_kinds: Vec::new(),
        entity_ids: vec![EntityId::parse("repository:one").expect("valid entity")],
        assertion_ids: Vec::new(),
    };
    let event = PlatformEvent {
        cursor: cerebro_platform_sdk::DurableCursor::new(1),
        tenant_id: tenant(),
        kind: PlatformEventKind::GraphChanged,
        graph_revision: Some(revision(1)),
        entity_kind: None,
        entity_id: Some(EntityId::parse("repository:one").expect("valid entity")),
        assertion_id: None,
        occurred_at_unix_millis: 1,
        payload_digest: digest("event"),
    };
    assert!(event_matches(&filter, &event));
}

#[test]
fn adaptive_plans_respect_tenant_budgets() {
    let budget =
        ResourceBudget::new(100, 6, 2_000, 8, 100, 10_000, 1_024, 100).expect("valid budget");
    let plan = plan_query(&query(10), &budget).expect("query plan");
    assert_eq!(
        plan.strategy,
        cerebro_platform_engine::QueryStrategy::StableKeyLookup
    );
    assert_eq!(plan.max_rows, 10);
}

#[test]
fn action_transitions_are_optimistic_and_fail_closed() {
    let proposal = ActionProposal {
        operation_id: ActionOperationId::parse("operation:one").expect("valid operation"),
        tenant_id: tenant(),
        graph_revision: revision(1),
        action_kind: "revoke_access".to_owned(),
        target_id: OpaqueId::parse("grant:one").expect("valid target"),
        expected_effects: vec![ActionEffect {
            target_id: OpaqueId::parse("grant:one").expect("valid target"),
            effect_kind: "access_removed".to_owned(),
            expected_state_digest: digest("expected"),
        }],
        rollback_ref: OpaqueId::parse("rollback:one").expect("valid rollback"),
        idempotency_key: OpaqueId::parse("idempotency:one").expect("valid key"),
        simulation_digest: digest("simulation"),
        proposal_digest: digest("proposal"),
    };
    let operation = ActionOperation {
        proposal,
        state: ActionState::Proposed,
        version: 1,
        claimed_by: None,
        external_receipt_ref: None,
        observed_effect_digest: None,
        verification_state: VerificationState::Pending,
    };
    let simulated =
        transition_action(&operation, 1, ActionCommand::RecordSimulation).expect("transition");
    assert_eq!(simulated.state, ActionState::Simulated);
    assert_eq!(simulated.version, 2);
    assert!(transition_action(&operation, 0, ActionCommand::RecordSimulation).is_err());
}

#[test]
fn recovery_reports_fail_on_any_failed_proof() {
    let report = build_recovery_report(
        tenant(),
        10,
        revision(3),
        revision(3),
        vec![RecoveryCheck {
            name: "ledger replay".to_owned(),
            state: RecoveryState::Failed,
            expected_digest: Some(digest("expected")),
            observed_digest: Some(digest("observed")),
            reason_code: Some("digest_mismatch".to_owned()),
        }],
    )
    .expect("recovery report");
    assert_eq!(report.state, RecoveryState::Failed);
}

#[test]
fn counterfactual_simulation_does_not_mutate_the_input_topology() {
    let entity = EntityId::parse("repository:one").expect("valid entity");
    let topology = SimulationTopology {
        tenant_id: tenant(),
        entities: BTreeSet::from([entity.clone()]),
        relationships: BTreeSet::new(),
    };
    let request = SimulationRequest {
        simulation_id: SimulationId::parse("simulation:one").expect("valid simulation"),
        tenant_id: tenant(),
        base_revision: revision(1),
        changes: vec![ProposedChange::RemoveEntity {
            entity_id: entity.clone(),
        }],
        assertions: Vec::new(),
        max_affected_entities: 10,
    };
    let result = simulate_topology(&request, &topology, Vec::new()).expect("simulation");
    assert_eq!(result.affected_entities, vec![entity.clone()]);
    assert!(topology.entities.contains(&entity));
}

#[test]
fn incident_packages_bind_manifest_payload_and_signature() {
    let mut manifest = IncidentSnapshotManifest {
        snapshot_id: IncidentSnapshotId::parse("snapshot:one").expect("valid snapshot"),
        tenant_id: tenant(),
        graph_revision: revision(1),
        created_at_unix_millis: 10,
        entity_ids: vec![EntityId::parse("repository:one").expect("valid entity")],
        source_receipt_digests: vec![digest("source-receipt")],
        policy_digests: vec![digest("policy")],
        mission_ids: Vec::new(),
        verification_receipt_digests: Vec::new(),
        manifest_digest: digest("placeholder"),
    };
    manifest.manifest_digest = incident_manifest_digest(&manifest).expect("manifest digest");
    let snapshot =
        package_incident_snapshot(manifest, b"canonical".to_vec(), vec![1]).expect("snapshot");
    assert_eq!(snapshot.payload_digest, digest("canonical"));
}
