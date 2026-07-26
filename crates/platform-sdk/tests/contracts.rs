use cerebro_platform_sdk::{
    ActionEffect, ActionOperationId, ActionProposal, AnalysisPluginManifest, AssertionCondition,
    AssertionDefinition, AssertionDefinitionId, BudgetError, ContentDigest, EntityId,
    EvaluationTrigger, EvidenceAuthority, EvidenceQuality, EvidenceReference, FactQuery,
    GraphChange, GraphChangeKind, GraphDiffRequest, GraphRevision, IncidentSnapshot,
    IncidentSnapshotId, IncidentSnapshotManifest, MaterializedViewDefinition, OpaqueId,
    PlatformEventKind, PluginCapability, PluginId, PluginLimits, ProposedChange,
    ProvenanceExplanation, QueryNode, ResourceBudget, ResourceUsage, RevisionSelector, SdkError,
    SimulationId, SimulationRequest, SourceRuntimeId, SubscriptionDefinition,
    SubscriptionEventFilter, SubscriptionId, TenantId, ViewId,
};

fn tenant() -> TenantId {
    TenantId::parse("tenant-a").expect("valid tenant")
}

fn digest(value: &str) -> ContentDigest {
    ContentDigest::of_bytes(value)
}

fn budget() -> ResourceBudget {
    ResourceBudget::new(500, 6, 2_000, 8, 100, 10_000, 64 * 1024 * 1024, 1_000)
        .expect("valid budget")
}

fn query(limit: usize) -> FactQuery {
    FactQuery::new(
        vec![QueryNode {
            variable: "repository".to_owned(),
            kinds: vec!["repository".to_owned()],
            keys: Vec::new(),
        }],
        Vec::new(),
        Vec::new(),
        limit,
    )
    .expect("valid query")
}

#[test]
fn resource_budgets_reject_zero_limits_and_excess_usage() {
    assert_eq!(
        ResourceBudget::new(0, 6, 2_000, 8, 100, 10_000, 64 * 1024 * 1024, 1_000),
        Err(BudgetError::Zero("max query results"))
    );

    let usage = ResourceUsage {
        query_results: 501,
        query_depth: 6,
        query_millis: 2_000,
        concurrent_queries: 8,
        subscription_batch: 100,
        snapshot_entities: 10_000,
        plugin_memory_bytes: 64 * 1024 * 1024,
        plugin_millis: 1_000,
    };
    assert_eq!(
        usage.validate(&budget()),
        Err(BudgetError::UsageExceedsLimit("query results"))
    );
    assert_eq!(
        ResourceBudget::new(501, 6, 2_000, 8, 100, 10_000, 64 * 1024 * 1024, 1_000),
        Err(BudgetError::ExceedsMaximum("max query results"))
    );
    assert_eq!(
        ResourceBudget::new(500, 7, 2_000, 8, 100, 10_000, 64 * 1024 * 1024, 1_000),
        Err(BudgetError::ExceedsMaximum("max query depth"))
    );
}

#[test]
fn graph_diffs_require_a_forward_bounded_window() {
    let revision = GraphRevision::new(10).expect("valid revision");
    let request = GraphDiffRequest {
        tenant_id: tenant(),
        from_revision: revision,
        to_revision: RevisionSelector::Exact(revision),
        limit: 500,
        cursor: None,
    };
    assert!(request.validate().is_err());

    let valid = GraphDiffRequest {
        to_revision: RevisionSelector::Exact(GraphRevision::new(11).expect("valid revision")),
        ..request
    };
    assert!(valid.validate().is_ok());
}

#[test]
fn graph_changes_require_one_target_and_kind_specific_digests() {
    let change = GraphChange {
        kind: GraphChangeKind::EntityAdded,
        entity_id: Some(EntityId::parse("repository:one").expect("valid entity")),
        assertion_id: None,
        before_digest: None,
        after_digest: Some(digest("after")),
        observed_at_unix_millis: 1,
    };
    assert!(change.validate().is_ok());

    let invalid = GraphChange {
        after_digest: None,
        ..change
    };
    assert!(invalid.validate().is_err());
}

#[test]
fn evidence_quality_is_bounded_and_conservative() {
    let quality = EvidenceQuality::new(90, 80, 70, 60, 50, false).expect("valid quality");
    assert_eq!(quality.minimum_score(), 50);
    assert!(EvidenceQuality::new(101, 80, 70, 60, 50, false).is_err());
}

#[test]
fn assertion_conditions_have_explicit_match_semantics() {
    assert!(AssertionCondition::NoMatches.evaluate(0));
    assert!(!AssertionCondition::NoMatches.evaluate(1));
    assert!(AssertionCondition::AtLeastOneMatch.evaluate(1));
    assert!(AssertionCondition::MatchCountAtMost(2).evaluate(2));
    assert!(AssertionCondition::MatchCountAtLeast(2).evaluate(3));
}

#[test]
fn simulations_are_read_only_and_bounded() {
    let request = SimulationRequest {
        simulation_id: SimulationId::parse("simulation:one").expect("valid simulation"),
        tenant_id: tenant(),
        base_revision: GraphRevision::new(1).expect("valid revision"),
        changes: vec![ProposedChange::RemoveEntity {
            entity_id: EntityId::parse("repository:one").expect("valid entity"),
        }],
        assertions: vec![
            AssertionDefinitionId::parse("assertion-definition:one")
                .expect("valid assertion definition"),
        ],
        max_affected_entities: 10_000,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn subscriptions_require_a_filter_and_bounded_batches() {
    let empty_filter = SubscriptionEventFilter {
        event_kinds: Vec::new(),
        entity_kinds: Vec::new(),
        entity_ids: Vec::new(),
        assertion_ids: Vec::new(),
    };
    let subscription = SubscriptionDefinition {
        subscription_id: SubscriptionId::parse("subscription:one").expect("valid subscription"),
        tenant_id: tenant(),
        filter: empty_filter,
        batch_limit: 100,
        definition_digest: digest("subscription"),
    };
    assert!(subscription.validate().is_err());

    let duplicate = SubscriptionDefinition {
        filter: SubscriptionEventFilter {
            event_kinds: vec![
                PlatformEventKind::GraphChanged,
                PlatformEventKind::GraphChanged,
            ],
            entity_kinds: Vec::new(),
            entity_ids: Vec::new(),
            assertion_ids: Vec::new(),
        },
        ..subscription
    };
    assert!(duplicate.validate().is_err());
}

#[test]
fn first_party_plugins_require_deterministic_zero_import_execution() {
    let manifest = AnalysisPluginManifest {
        plugin_id: PluginId::parse("plugin:one").expect("valid plugin"),
        abi_version: "v1".to_owned(),
        artifact_digest: digest("plugin"),
        capabilities: vec![PluginCapability::AssertionEvaluation],
        limits: PluginLimits {
            memory_bytes: 64 * 1024 * 1024,
            execution_millis: 1_000,
            input_bytes: 1024,
            output_bytes: 1024,
        },
        zero_imports_required: true,
        deterministic_output_required: true,
    };
    assert!(manifest.validate().is_ok());

    let unsafe_manifest = AnalysisPluginManifest {
        zero_imports_required: false,
        ..manifest
    };
    assert!(unsafe_manifest.validate().is_err());
}

#[test]
fn opaque_ids_reject_display_labels() {
    assert!(OpaqueId::parse("mission:one").is_ok());
    assert!(OpaqueId::parse("Mission One").is_err());
}

#[test]
fn action_proposals_reject_duplicate_or_untyped_effects() {
    let effect = ActionEffect {
        target_id: OpaqueId::parse("grant:one").expect("valid target"),
        effect_kind: "access_removed".to_owned(),
        expected_state_digest: digest("expected"),
    };
    let proposal = ActionProposal {
        operation_id: ActionOperationId::parse("operation:one").expect("valid operation"),
        tenant_id: tenant(),
        graph_revision: GraphRevision::new(1).expect("valid revision"),
        action_kind: "revoke_access".to_owned(),
        target_id: OpaqueId::parse("grant:one").expect("valid target"),
        expected_effects: vec![effect.clone(), effect],
        rollback_ref: OpaqueId::parse("rollback:one").expect("valid rollback"),
        idempotency_key: OpaqueId::parse("idempotency:one").expect("valid key"),
        simulation_digest: digest("simulation"),
        proposal_digest: digest("proposal"),
    };
    assert!(proposal.validate().is_err());

    let invalid_kind = ActionProposal {
        expected_effects: vec![ActionEffect {
            target_id: OpaqueId::parse("grant:one").expect("valid target"),
            effect_kind: "Access removed".to_owned(),
            expected_state_digest: digest("expected"),
        }],
        ..proposal
    };
    assert!(invalid_kind.validate().is_err());
}

#[test]
fn sdk_errors_preserve_specific_operator_messages() {
    let cases = [
        (SdkError::Empty("value"), "value is required"),
        (SdkError::Invalid("value"), "value is invalid"),
        (SdkError::TooLong("value"), "value exceeds its size limit"),
        (
            SdkError::OutOfRange("value"),
            "value is outside its allowed range",
        ),
        (
            SdkError::Conflict("revision".to_owned()),
            "platform conflict: revision",
        ),
        (
            SdkError::NotFound("entity".to_owned()),
            "platform value not found: entity",
        ),
        (
            SdkError::CapabilityUnavailable("diff".to_owned()),
            "platform capability unavailable: diff",
        ),
        (
            SdkError::Backend("postgres".to_owned()),
            "platform backend failed: postgres",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
    }
}

#[test]
fn assertion_definitions_validate_names_triggers_freshness_and_conditions() {
    let definition = AssertionDefinition {
        assertion_id: AssertionDefinitionId::parse("assertion-definition:one")
            .expect("valid assertion definition"),
        tenant_id: tenant(),
        name: "Repository ownership remains explicit".to_owned(),
        query: query(25),
        condition: AssertionCondition::NoMatches,
        triggers: vec![EvaluationTrigger::GraphChange],
        evidence_max_age_seconds: 300,
        enabled: true,
        definition_digest: digest("assertion"),
    };
    assert!(definition.validate().is_ok());

    let mut invalid = definition.clone();
    invalid.name = " padded ".to_owned();
    assert_eq!(invalid.validate(), Err(SdkError::Invalid("assertion name")));
    invalid.name = "x".repeat(257);
    assert_eq!(invalid.validate(), Err(SdkError::TooLong("assertion name")));
    invalid.name = "valid".to_owned();
    invalid.triggers.clear();
    assert_eq!(
        invalid.validate(),
        Err(SdkError::Empty("assertion triggers"))
    );
    invalid.triggers.push(EvaluationTrigger::Manual);
    invalid.evidence_max_age_seconds = 0;
    assert_eq!(
        invalid.validate(),
        Err(SdkError::OutOfRange("assertion evidence max age"))
    );
    invalid.evidence_max_age_seconds = 1;
    invalid.condition = AssertionCondition::MatchCountAtLeast(0);
    assert_eq!(
        invalid.validate(),
        Err(SdkError::OutOfRange("assertion minimum match count"))
    );
}

#[test]
fn incident_snapshots_require_receipts_payload_integrity_and_signatures() {
    let manifest = IncidentSnapshotManifest {
        snapshot_id: IncidentSnapshotId::parse("incident-snapshot:one").expect("valid snapshot"),
        tenant_id: tenant(),
        graph_revision: GraphRevision::new(1).expect("valid revision"),
        created_at_unix_millis: 1,
        entity_ids: vec![EntityId::parse("repository:one").expect("valid entity")],
        source_receipt_digests: vec![digest("source receipt")],
        policy_digests: vec![digest("policy")],
        mission_ids: vec![OpaqueId::parse("mission:one").expect("valid mission")],
        verification_receipt_digests: vec![digest("verification receipt")],
        manifest_digest: digest("manifest"),
    };
    let payload = b"canonical incident snapshot".to_vec();
    let snapshot = IncidentSnapshot {
        manifest: manifest.clone(),
        payload_digest: ContentDigest::of_bytes(&payload),
        canonical_payload: payload,
        signature: vec![1, 2, 3],
    };
    assert!(snapshot.validate().is_ok());

    let mut invalid_manifest = manifest;
    invalid_manifest.entity_ids.clear();
    assert_eq!(
        invalid_manifest.validate(),
        Err(SdkError::OutOfRange("incident snapshot entity count"))
    );
    invalid_manifest
        .entity_ids
        .push(EntityId::parse("repository:one").expect("valid entity"));
    invalid_manifest.source_receipt_digests.clear();
    assert_eq!(
        invalid_manifest.validate(),
        Err(SdkError::Empty("incident snapshot source receipts"))
    );

    let mut invalid = snapshot.clone();
    invalid.canonical_payload.clear();
    assert_eq!(
        invalid.validate(),
        Err(SdkError::Empty("incident snapshot payload"))
    );
    invalid = snapshot.clone();
    invalid.payload_digest = digest("wrong");
    assert_eq!(
        invalid.validate(),
        Err(SdkError::Invalid("incident snapshot payload digest"))
    );
    invalid = snapshot;
    invalid.signature.clear();
    assert_eq!(
        invalid.validate(),
        Err(SdkError::Empty("incident snapshot signature"))
    );
}

#[test]
fn materialized_views_cannot_escape_query_or_platform_bounds() {
    let view = MaterializedViewDefinition {
        view_id: ViewId::parse("view:one").expect("valid view"),
        tenant_id: tenant(),
        name: "High-risk repositories".to_owned(),
        query: query(100),
        max_rows: 100,
        definition_digest: digest("view"),
    };
    assert!(view.validate().is_ok());

    let mut invalid = view.clone();
    invalid.name = String::new();
    assert_eq!(
        invalid.validate(),
        Err(SdkError::Invalid("materialized view name"))
    );
    invalid.name = "x".repeat(257);
    assert_eq!(
        invalid.validate(),
        Err(SdkError::TooLong("materialized view name"))
    );
    invalid.name = "valid".to_owned();
    invalid.max_rows = 101;
    assert_eq!(
        invalid.validate(),
        Err(SdkError::OutOfRange("materialized view max rows"))
    );
}

#[test]
fn provenance_requires_one_target_and_at_least_one_evidence_reference() {
    let explanation = ProvenanceExplanation {
        tenant_id: tenant(),
        graph_revision: GraphRevision::new(1).expect("valid revision"),
        entity_id: Some(EntityId::parse("repository:one").expect("valid entity")),
        assertion_id: None,
        evidence: vec![EvidenceReference {
            evidence_id: OpaqueId::parse("evidence:one").expect("valid evidence"),
            source_runtime_id: SourceRuntimeId::parse("github-prod").expect("valid runtime"),
            event_id: OpaqueId::parse("event:one").expect("valid event"),
            observed_at_unix_millis: 1,
            authority: EvidenceAuthority::Authoritative,
            content_digest: digest("evidence"),
        }],
        quality: EvidenceQuality::new(100, 100, 100, 100, 100, false).expect("valid quality"),
        explanation_digest: digest("explanation"),
    };
    assert!(explanation.validate().is_ok());

    let mut invalid = explanation.clone();
    invalid.entity_id = None;
    assert_eq!(
        invalid.validate(),
        Err(SdkError::Invalid("provenance target"))
    );
    invalid = explanation;
    invalid.evidence.clear();
    assert_eq!(
        invalid.validate(),
        Err(SdkError::Empty("provenance evidence"))
    );
}
