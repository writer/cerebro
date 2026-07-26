use cerebro_platform_sdk::{
    AnalysisPluginManifest, AssertionCondition, AssertionDefinitionId, BudgetError, ContentDigest,
    EntityId, EvidenceQuality, GraphChange, GraphChangeKind, GraphDiffRequest, GraphRevision,
    OpaqueId, PluginCapability, PluginId, PluginLimits, ProposedChange, ResourceBudget,
    ResourceUsage, RevisionSelector, SimulationId, SimulationRequest, SubscriptionDefinition,
    SubscriptionEventFilter, SubscriptionId, TenantId,
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
