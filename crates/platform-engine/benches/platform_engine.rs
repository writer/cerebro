use std::collections::BTreeSet;
use std::hint::black_box;
use std::time::{Duration, Instant};

use cerebro_platform_engine::{
    RevisionSnapshot, SimulationRelationship, SimulationTopology, SnapshotKey, SnapshotValue,
    assertion_definition_digest, compile_assertion, diff_snapshots, evaluate_assertion,
    simulate_topology,
};
use cerebro_platform_sdk::{
    AssertionCondition, AssertionDefinition, AssertionDefinitionId, ContentDigest, EntityId,
    EvaluationTrigger, EvidenceQuality, FactQuery, GraphDiffRequest, GraphRevision, ProposedChange,
    QueryNode, QueryResult, RelationKind, RevisionSelector, SimulationId, SimulationRequest,
    TenantId,
};

fn main() {
    let (request, before, after) = diff_fixture();
    report("diff_500_changes", 200, || {
        black_box(diff_snapshots(&request, &before, &after).expect("benchmark diff"));
    });

    let (compiled, query_result, quality) = assertion_fixture();
    report("evaluate_assertion", 10_000, || {
        black_box(
            evaluate_assertion(&compiled, &query_result, &quality, 10)
                .expect("benchmark assertion"),
        );
    });

    let (simulation_request, topology) = simulation_fixture();
    report("simulate_100_relationship_removals", 200, || {
        black_box(
            simulate_topology(&simulation_request, &topology, Vec::new())
                .expect("benchmark simulation"),
        );
    });
}

fn report(name: &str, iterations: u32, operation: impl Fn()) {
    for _ in 0..10 {
        operation();
    }
    let started = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    let elapsed = started.elapsed() / iterations;
    println!("{name}: {} ns/op", nanos(elapsed));
}

fn nanos(duration: Duration) -> u128 {
    duration.as_nanos()
}

fn tenant() -> TenantId {
    TenantId::parse("tenant-a").expect("valid tenant")
}

fn revision(value: u64) -> GraphRevision {
    GraphRevision::new(value).expect("valid revision")
}

fn digest(value: impl AsRef<[u8]>) -> ContentDigest {
    ContentDigest::of_bytes(value)
}

fn diff_fixture() -> (GraphDiffRequest, RevisionSnapshot, RevisionSnapshot) {
    let before_values = (0..500)
        .map(|index| {
            (
                SnapshotKey::Entity(
                    EntityId::parse(format!("repository:{index:03}")).expect("valid entity"),
                ),
                SnapshotValue {
                    digest: digest(format!("before-{index}")),
                    observed_at_unix_millis: 1,
                },
            )
        })
        .collect();
    let after_values = (0..500)
        .map(|index| {
            (
                SnapshotKey::Entity(
                    EntityId::parse(format!("repository:{index:03}")).expect("valid entity"),
                ),
                SnapshotValue {
                    digest: digest(format!("after-{index}")),
                    observed_at_unix_millis: 2,
                },
            )
        })
        .collect();
    (
        GraphDiffRequest {
            tenant_id: tenant(),
            from_revision: revision(1),
            to_revision: RevisionSelector::Exact(revision(2)),
            limit: 500,
            cursor: None,
        },
        RevisionSnapshot {
            tenant_id: tenant(),
            revision: revision(1),
            values: before_values,
        },
        RevisionSnapshot {
            tenant_id: tenant(),
            revision: revision(2),
            values: after_values,
        },
    )
}

fn assertion_fixture() -> (
    cerebro_platform_engine::CompiledAssertion,
    QueryResult,
    EvidenceQuality,
) {
    let query = FactQuery::new(
        vec![QueryNode {
            variable: "repository".to_owned(),
            kinds: vec!["repository".to_owned()],
            keys: vec!["repository:one".to_owned()],
        }],
        Vec::new(),
        Vec::new(),
        10,
    )
    .expect("valid query");
    let mut definition = AssertionDefinition {
        assertion_id: AssertionDefinitionId::parse("assertion-definition:one")
            .expect("valid assertion"),
        tenant_id: tenant(),
        name: "Repository exists".to_owned(),
        query,
        condition: AssertionCondition::AtLeastOneMatch,
        triggers: vec![EvaluationTrigger::GraphChange],
        evidence_max_age_seconds: 300,
        enabled: true,
        definition_digest: digest("placeholder"),
    };
    definition.definition_digest =
        assertion_definition_digest(&definition).expect("definition digest");
    (
        compile_assertion(definition).expect("compiled assertion"),
        QueryResult {
            tenant_id: tenant(),
            graph_revision: 2,
            matches: Vec::new(),
            truncated: false,
        },
        EvidenceQuality::new(100, 100, 100, 100, 100, false).expect("valid quality"),
    )
}

fn simulation_fixture() -> (SimulationRequest, SimulationTopology) {
    let entities = (0..101)
        .map(|index| EntityId::parse(format!("repository:{index:03}")).expect("valid entity"))
        .collect::<BTreeSet<_>>();
    let relationships = (0..100)
        .map(|index| SimulationRelationship {
            from_entity_id: EntityId::parse(format!("repository:{index:03}"))
                .expect("valid entity"),
            relation: RelationKind::DependsOn,
            to_entity_id: EntityId::parse(format!("repository:{:03}", index + 1))
                .expect("valid entity"),
        })
        .collect::<BTreeSet<_>>();
    let changes = relationships
        .iter()
        .map(|relationship| ProposedChange::RemoveRelationship {
            from_entity_id: relationship.from_entity_id.clone(),
            relation: relationship.relation,
            to_entity_id: relationship.to_entity_id.clone(),
        })
        .collect();
    (
        SimulationRequest {
            simulation_id: SimulationId::parse("simulation:benchmark").expect("valid simulation"),
            tenant_id: tenant(),
            base_revision: revision(1),
            changes,
            assertions: Vec::new(),
            max_affected_entities: 101,
        },
        SimulationTopology {
            tenant_id: tenant(),
            entities,
            relationships,
        },
    )
}
