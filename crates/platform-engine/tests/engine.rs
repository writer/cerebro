use std::collections::{BTreeMap, BTreeSet};

use cerebro_platform_engine::{
    ActionCommand, RevisionSnapshot, SimulationTopology, SnapshotKey, SnapshotValue,
    assemble_provenance, assertion_definition_digest, build_recovery_report, compile_assertion,
    diff_snapshots, evaluate_assertion, event_matches, incident_manifest_digest, materialize_view,
    package_incident_snapshot, plan_query, simulate_topology, transition_action,
    validate_plugin_execution,
};
use cerebro_platform_sdk::{
    ActionEffect, ActionOperation, ActionOperationId, ActionProposal, ActionState,
    AnalysisPluginManifest, AssertionCondition, AssertionDefinition, AssertionDefinitionId,
    AssertionState, ContentDigest, EntityId, EntityKind, EvaluationTrigger, EvidenceAuthority,
    EvidenceQuality, EvidenceReference, FactQuery, GraphDiffRequest, GraphRevision,
    IncidentSnapshotId, IncidentSnapshotManifest, MaterializedViewDefinition, OpaqueId,
    PlatformEvent, PlatformEventKind, PluginCapability, PluginId, PluginLimits, ProposedChange,
    QueryEdge, QueryNode, QueryResult, RecoveryCheck, RecoveryState, RelationKind, ResourceBudget,
    ResourceUsage, RevisionSelector, SimulationId, SimulationRequest, SourceRuntimeId,
    SubscriptionEventFilter, TenantId, VerificationState, ViewId,
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
    let waiting =
        transition_action(&simulated, 2, ActionCommand::RequestApproval).expect("transition");
    let claimed = transition_action(
        &waiting,
        3,
        ActionCommand::Claim {
            worker_id: OpaqueId::parse("worker:one").expect("valid worker"),
        },
    )
    .expect("transition");
    let executing =
        transition_action(&claimed, 4, ActionCommand::StartExecution).expect("transition");
    let completed = transition_action(
        &executing,
        5,
        ActionCommand::Complete {
            external_receipt_ref: OpaqueId::parse("receipt:one").expect("valid receipt"),
            observed_effect_digest: digest("observed"),
        },
    )
    .expect("transition");
    let verified = transition_action(&completed, 6, ActionCommand::Verify).expect("transition");
    assert_eq!(verified.state, ActionState::Verified);
    assert_eq!(verified.verification_state, VerificationState::Verified);
    assert_eq!(verified.version, 7);
    assert!(transition_action(&verified, 7, ActionCommand::StartExecution).is_err());

    let uncertain =
        transition_action(&executing, 5, ActionCommand::MarkOutcomeUnknown).expect("transition");
    let reconciled = transition_action(
        &uncertain,
        6,
        ActionCommand::Reconcile {
            observed_effect_digest: digest("reconciled"),
        },
    )
    .expect("transition");
    assert_eq!(reconciled.state, ActionState::Reconciled);

    let failed = transition_action(&simulated, 2, ActionCommand::Fail).expect("transition");
    let rolled_back = transition_action(&failed, 3, ActionCommand::RollBack).expect("transition");
    assert_eq!(rolled_back.state, ActionState::RolledBack);
    assert_eq!(rolled_back.verification_state, VerificationState::Stale);
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

#[test]
fn assertion_definition_digest_binds_the_assertion_identity() {
    let definition = AssertionDefinition {
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
    let changed_id = AssertionDefinition {
        assertion_id: AssertionDefinitionId::parse("assertion-definition:two")
            .expect("valid assertion"),
        ..definition.clone()
    };
    assert_ne!(
        assertion_definition_digest(&definition).expect("digest"),
        assertion_definition_digest(&changed_id).expect("digest")
    );
}

#[test]
fn temporal_pagination_reconstructs_the_complete_ordered_diff() {
    let before = RevisionSnapshot {
        tenant_id: tenant(),
        revision: revision(1),
        values: BTreeMap::new(),
    };
    let values = (0..31)
        .map(|index| {
            (
                SnapshotKey::Entity(
                    EntityId::parse(format!("repository:{index:02}")).expect("valid entity"),
                ),
                SnapshotValue {
                    digest: digest(&format!("value-{index}")),
                    observed_at_unix_millis: i64::from(index),
                },
            )
        })
        .collect();
    let after = RevisionSnapshot {
        tenant_id: tenant(),
        revision: revision(2),
        values,
    };
    let mut cursor = None;
    let mut changes = Vec::new();
    let mut complete_digest = None;
    loop {
        let page = diff_snapshots(
            &GraphDiffRequest {
                tenant_id: tenant(),
                from_revision: revision(1),
                to_revision: RevisionSelector::Exact(revision(2)),
                limit: 7,
                cursor,
            },
            &before,
            &after,
        )
        .expect("graph diff page");
        if let Some(expected) = &complete_digest {
            assert_eq!(expected, &page.digest);
        } else {
            complete_digest = Some(page.digest.clone());
        }
        changes.extend(page.changes);
        if !page.truncated {
            break;
        }
        cursor = page.next_cursor;
    }
    assert_eq!(changes.len(), 31);
    assert!(
        changes
            .windows(2)
            .all(|pair| pair[0].entity_id < pair[1].entity_id)
    );
}

#[test]
fn simulation_failure_is_atomic_for_multi_change_requests() {
    let entity = EntityId::parse("repository:one").expect("valid entity");
    let topology = SimulationTopology {
        tenant_id: tenant(),
        entities: BTreeSet::from([entity.clone()]),
        relationships: BTreeSet::new(),
    };
    let request = SimulationRequest {
        simulation_id: SimulationId::parse("simulation:failure").expect("valid simulation"),
        tenant_id: tenant(),
        base_revision: revision(1),
        changes: vec![
            ProposedChange::RemoveEntity {
                entity_id: entity.clone(),
            },
            ProposedChange::RemoveEntity {
                entity_id: EntityId::parse("repository:missing").expect("valid entity"),
            },
        ],
        assertions: Vec::new(),
        max_affected_entities: 10,
    };
    assert!(simulate_topology(&request, &topology, Vec::new()).is_err());
    assert_eq!(topology.entities, BTreeSet::from([entity]));
}

#[test]
fn materialized_results_bind_the_view_definition() {
    let result = QueryResult {
        tenant_id: tenant(),
        graph_revision: 3,
        matches: Vec::new(),
        truncated: false,
    };
    let definition = MaterializedViewDefinition {
        view_id: ViewId::parse("view:one").expect("valid view"),
        tenant_id: tenant(),
        name: "Repositories".to_owned(),
        query: query(10),
        max_rows: 10,
        definition_digest: digest("definition-one"),
    };
    let changed = MaterializedViewDefinition {
        view_id: ViewId::parse("view:two").expect("valid view"),
        definition_digest: digest("definition-two"),
        ..definition.clone()
    };
    assert_ne!(
        materialize_view(&definition, &result, 10)
            .expect("materialized view")
            .result_digest,
        materialize_view(&changed, &result, 10)
            .expect("materialized view")
            .result_digest
    );
}

#[test]
fn plugin_execution_obeys_manifest_limits_below_tenant_limits() {
    let manifest = AnalysisPluginManifest {
        plugin_id: PluginId::parse("plugin:one").expect("valid plugin"),
        abi_version: "v1".to_owned(),
        artifact_digest: digest("plugin"),
        capabilities: vec![PluginCapability::AssertionEvaluation],
        limits: PluginLimits {
            memory_bytes: 512,
            execution_millis: 50,
            input_bytes: 1_024,
            output_bytes: 1_024,
        },
        zero_imports_required: true,
        deterministic_output_required: true,
    };
    let budget =
        ResourceBudget::new(100, 6, 2_000, 8, 100, 10_000, 1_024, 100).expect("valid budget");
    let usage = ResourceUsage {
        query_results: 0,
        query_depth: 0,
        query_millis: 0,
        concurrent_queries: 0,
        subscription_batch: 0,
        snapshot_entities: 0,
        plugin_memory_bytes: 513,
        plugin_millis: 50,
    };
    assert!(validate_plugin_execution(&manifest, &budget, &usage).is_err());
    let valid_usage = ResourceUsage {
        plugin_memory_bytes: 512,
        ..usage
    };
    assert!(validate_plugin_execution(&manifest, &budget, &valid_usage).is_ok());
    let oversized_manifest = AnalysisPluginManifest {
        limits: PluginLimits {
            memory_bytes: 2_048,
            ..manifest.limits.clone()
        },
        ..manifest
    };
    assert!(validate_plugin_execution(&oversized_manifest, &budget, &valid_usage).is_err());
}

#[test]
fn recovery_digest_is_independent_of_check_input_order() {
    let checks = vec![
        RecoveryCheck {
            name: "projection".to_owned(),
            state: RecoveryState::Passed,
            expected_digest: Some(digest("projection")),
            observed_digest: Some(digest("projection")),
            reason_code: None,
        },
        RecoveryCheck {
            name: "ledger".to_owned(),
            state: RecoveryState::Passed,
            expected_digest: Some(digest("ledger")),
            observed_digest: Some(digest("ledger")),
            reason_code: None,
        },
    ];
    let mut reversed = checks.clone();
    reversed.reverse();
    let first =
        build_recovery_report(tenant(), 10, revision(3), revision(3), checks).expect("report");
    let second =
        build_recovery_report(tenant(), 10, revision(3), revision(3), reversed).expect("report");
    assert_eq!(first.report_digest, second.report_digest);
}

#[test]
fn provenance_is_sorted_bound_to_one_target_and_digest_stable() {
    let evidence = |id: &str| EvidenceReference {
        evidence_id: OpaqueId::parse(id).expect("valid evidence"),
        source_runtime_id: SourceRuntimeId::parse("runtime:one").expect("valid runtime"),
        event_id: OpaqueId::parse(format!("event:{id}")).expect("valid event"),
        observed_at_unix_millis: 10,
        authority: EvidenceAuthority::Authoritative,
        content_digest: digest(id),
    };
    let quality = EvidenceQuality::new(100, 100, 100, 100, 100, false).expect("quality");
    let explanation = assemble_provenance(
        tenant(),
        revision(2),
        Some(EntityId::parse("repository:one").expect("valid entity")),
        None,
        vec![evidence("two"), evidence("one")],
        quality.clone(),
    )
    .expect("provenance");
    assert_eq!(explanation.evidence[0].evidence_id.as_str(), "one");
    assert_eq!(explanation.evidence[1].evidence_id.as_str(), "two");
    assert!(
        assemble_provenance(
            tenant(),
            revision(2),
            None,
            None,
            vec![evidence("one")],
            quality,
        )
        .is_err()
    );
}

#[test]
fn simulation_adds_and_removes_relationships_with_endpoint_checks() {
    let left = EntityId::parse("repository:left").expect("valid entity");
    let right = EntityId::parse("repository:right").expect("valid entity");
    let relationship = cerebro_platform_engine::SimulationRelationship {
        from_entity_id: left.clone(),
        relation: RelationKind::DependsOn,
        to_entity_id: right.clone(),
    };
    let empty = SimulationTopology {
        tenant_id: tenant(),
        entities: BTreeSet::from([left.clone(), right.clone()]),
        relationships: BTreeSet::new(),
    };
    let add = SimulationRequest {
        simulation_id: SimulationId::parse("simulation:add").expect("valid simulation"),
        tenant_id: tenant(),
        base_revision: revision(1),
        changes: vec![ProposedChange::AddRelationship {
            from_entity_id: left.clone(),
            relation: RelationKind::DependsOn,
            to_entity_id: right.clone(),
        }],
        assertions: Vec::new(),
        max_affected_entities: 2,
    };
    assert_eq!(
        simulate_topology(&add, &empty, Vec::new())
            .expect("simulation")
            .affected_entities,
        vec![left.clone(), right.clone()]
    );

    let connected = SimulationTopology {
        relationships: BTreeSet::from([relationship]),
        ..empty.clone()
    };
    let remove = SimulationRequest {
        simulation_id: SimulationId::parse("simulation:remove").expect("valid simulation"),
        changes: vec![ProposedChange::RemoveRelationship {
            from_entity_id: left,
            relation: RelationKind::DependsOn,
            to_entity_id: right,
        }],
        ..add
    };
    assert!(simulate_topology(&remove, &connected, Vec::new()).is_ok());
    assert!(simulate_topology(&remove, &empty, Vec::new()).is_err());
}

#[test]
fn subscription_filters_fail_each_nonmatching_dimension() {
    let event = PlatformEvent {
        cursor: cerebro_platform_sdk::DurableCursor::new(1),
        tenant_id: tenant(),
        kind: PlatformEventKind::GraphChanged,
        graph_revision: Some(revision(1)),
        entity_kind: Some(EntityKind::Repository),
        entity_id: Some(EntityId::parse("repository:one").expect("valid entity")),
        assertion_id: Some(
            AssertionDefinitionId::parse("assertion-definition:one").expect("valid assertion"),
        ),
        occurred_at_unix_millis: 1,
        payload_digest: digest("event"),
    };
    let base = SubscriptionEventFilter {
        event_kinds: vec![PlatformEventKind::GraphChanged],
        entity_kinds: vec![EntityKind::Repository],
        entity_ids: vec![EntityId::parse("repository:one").expect("valid entity")],
        assertion_ids: vec![
            AssertionDefinitionId::parse("assertion-definition:one").expect("valid assertion"),
        ],
    };
    assert!(event_matches(&base, &event));
    assert!(!event_matches(
        &SubscriptionEventFilter {
            event_kinds: vec![PlatformEventKind::ActionChanged],
            ..base.clone()
        },
        &event
    ));
    assert!(!event_matches(
        &SubscriptionEventFilter {
            entity_kinds: vec![EntityKind::Person],
            ..base.clone()
        },
        &event
    ));
    assert!(!event_matches(
        &SubscriptionEventFilter {
            entity_ids: vec![EntityId::parse("repository:two").expect("valid entity")],
            ..base.clone()
        },
        &event
    ));
    assert!(!event_matches(
        &SubscriptionEventFilter {
            assertion_ids: vec![
                AssertionDefinitionId::parse("assertion-definition:two").expect("valid assertion"),
            ],
            ..base
        },
        &event
    ));
}

#[test]
fn query_planner_selects_bounded_scan_and_traversal_and_rejects_budget_overflow() {
    let budget =
        ResourceBudget::new(100, 6, 2_000, 8, 100, 10_000, 1_024, 100).expect("valid budget");
    let scan = FactQuery::new(
        vec![QueryNode {
            variable: "repository".to_owned(),
            kinds: vec!["repository".to_owned()],
            keys: Vec::new(),
        }],
        Vec::new(),
        Vec::new(),
        10,
    )
    .expect("query");
    assert_eq!(
        plan_query(&scan, &budget).expect("plan").strategy,
        cerebro_platform_engine::QueryStrategy::BoundedProjectionScan
    );
    let traversal = FactQuery::new(
        vec![
            QueryNode {
                variable: "repository".to_owned(),
                kinds: vec!["repository".to_owned()],
                keys: Vec::new(),
            },
            QueryNode {
                variable: "service".to_owned(),
                kinds: vec!["service".to_owned()],
                keys: Vec::new(),
            },
        ],
        vec![QueryEdge {
            variable: "dependency".to_owned(),
            from_variable: "repository".to_owned(),
            relation: "depends_on".to_owned(),
            to_variable: "service".to_owned(),
        }],
        Vec::new(),
        10,
    )
    .expect("query");
    assert_eq!(
        plan_query(&traversal, &budget).expect("plan").strategy,
        cerebro_platform_engine::QueryStrategy::BoundedTraversal
    );
    assert!(plan_query(&query(101), &budget).is_err());
}

#[test]
fn assertion_evaluation_is_indeterminate_for_truncation_conflict_and_disabled_policy() {
    let mut definition = AssertionDefinition {
        assertion_id: AssertionDefinitionId::parse("assertion-definition:indeterminate")
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
    let compiled = compile_assertion(definition.clone()).expect("compiled");
    let result = QueryResult {
        tenant_id: tenant(),
        graph_revision: 2,
        matches: Vec::new(),
        truncated: true,
    };
    let quality = EvidenceQuality::new(100, 100, 100, 100, 100, false).expect("quality");
    assert_eq!(
        evaluate_assertion(&compiled, &result, &quality, 10)
            .expect("evaluation")
            .state,
        AssertionState::Indeterminate
    );
    let conflict = EvidenceQuality::new(100, 100, 100, 100, 100, true).expect("quality");
    assert_eq!(
        evaluate_assertion(
            &compiled,
            &QueryResult {
                truncated: false,
                ..result.clone()
            },
            &conflict,
            10,
        )
        .expect("evaluation")
        .state,
        AssertionState::Indeterminate
    );
    definition.enabled = false;
    definition.definition_digest =
        assertion_definition_digest(&definition).expect("definition digest");
    let disabled = compile_assertion(definition).expect("compiled");
    assert_eq!(
        evaluate_assertion(
            &disabled,
            &QueryResult {
                truncated: false,
                ..result
            },
            &quality,
            10,
        )
        .expect("evaluation")
        .state,
        AssertionState::Indeterminate
    );
}
