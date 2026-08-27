use cerebro_organizational_model::{Entity, EntityKind, RelationKind, RelationshipAssertion};

use super::*;

#[test]
fn missing_assertion_entity_is_rejected_before_any_write() {
    let tenant = TenantId::parse("tenant-a").unwrap();
    let runtime = SourceRuntimeId::parse("okta-prod").unwrap();
    let collection = CompleteCollection::new(
        tenant.clone(),
        runtime.clone(),
        CollectionId::parse("collection-missing-entity").unwrap(),
        "okta.users",
        10,
    )
    .unwrap();
    let provider = ProviderIdentity::new(
        tenant.clone(),
        runtime,
        ProviderKind::parse("okta.user").unwrap(),
        "00u-missing",
        "Provider Person",
    )
    .unwrap()
    .into_entity();
    let repository = Entity::canonical(
        tenant,
        EntityId::parse("repository:missing").unwrap(),
        EntityKind::Repository,
        "Repository",
    )
    .unwrap();
    let provenance = AssertionProvenance::direct(
        vec![
            ObservationRef::new(
                collection.receipt(),
                ObservationId::parse("observation-missing-entity").unwrap(),
                "okta.user:00u-missing",
            )
            .unwrap(),
        ],
        "okta-identity-mapper",
        "v1",
    )
    .unwrap();
    let relationship = RelationshipAssertion::new(
        &provider,
        RelationKind::CanAccess,
        &repository,
        provenance,
        10,
    )
    .unwrap();
    let mut builder = collection.begin_delta();
    builder
        .add_assertion(GraphAssertion::Relationship(relationship))
        .unwrap();

    let mut graph = OrganizationalGraph::new();
    assert_eq!(
        graph.apply(builder.build()),
        Err(GraphError::MissingEntity(provider.id().clone()))
    );
    assert_eq!(
        graph.graph_revision(&TenantId::parse("tenant-a").unwrap()),
        0
    );
    assert!(
        graph
            .entities(&TenantId::parse("tenant-a").unwrap())
            .is_empty()
    );
    assert!(
        graph
            .assertions(&TenantId::parse("tenant-a").unwrap())
            .is_empty()
    );
}

#[test]
fn retraction_from_another_runtime_is_rejected_without_removal() {
    let first = identity_delta(
        "00u-retract",
        "person-retract",
        IdentityBindingState::Confirmed,
        None,
    );
    let assertion_id = first.assertions()[0].id().clone();
    let tenant = TenantId::parse("tenant-a").unwrap();
    let mut graph = OrganizationalGraph::new();
    graph.apply(first).unwrap();
    let revision = graph.graph_revision(&tenant);

    let collection = CompleteCollection::new(
        tenant.clone(),
        SourceRuntimeId::parse("github-prod").unwrap(),
        CollectionId::parse("github-retract").unwrap(),
        "github.users",
        10,
    )
    .unwrap();
    let mut builder = collection.begin_delta();
    builder
        .retract_missing(assertion_id.clone(), "provider no longer reports it")
        .unwrap();

    assert_eq!(
        graph.apply(builder.build()),
        Err(GraphError::RetractionSourceMismatch(assertion_id))
    );
    assert_eq!(graph.graph_revision(&tenant), revision);
    assert_eq!(graph.assertions(&tenant).len(), 1);
}

#[test]
fn failed_delta_does_not_partially_change_graph() {
    let mut graph = OrganizationalGraph::new();
    graph
        .apply(identity_delta(
            "00u1",
            "person-1",
            IdentityBindingState::Confirmed,
            None,
        ))
        .unwrap();
    let revision = graph.graph_revision(&TenantId::parse("tenant-a").unwrap());
    let _ = graph.apply(identity_delta(
        "00u1",
        "person-2",
        IdentityBindingState::Confirmed,
        None,
    ));
    assert_eq!(
        graph.graph_revision(&TenantId::parse("tenant-a").unwrap()),
        revision
    );
    assert_eq!(
        graph.entities(&TenantId::parse("tenant-a").unwrap()).len(),
        2,
        "a rejected delta cannot insert its new canonical identity"
    );
}
