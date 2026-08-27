use cerebro_organizational_model::{Entity, EntityKind};

use super::*;

#[test]
fn entity_conflict_is_rejected_without_partial_mutation() {
    let tenant = TenantId::parse("tenant-a").unwrap();
    let runtime = SourceRuntimeId::parse("okta-prod").unwrap();
    let provider = ProviderIdentity::new(
        tenant.clone(),
        runtime.clone(),
        ProviderKind::parse("okta.user").unwrap(),
        "00u-conflict",
        "Provider Person",
    )
    .unwrap()
    .into_entity();
    let conflicting = Entity::canonical(
        tenant.clone(),
        provider.id().clone(),
        EntityKind::Identity,
        "Canonical collision",
    )
    .unwrap();

    let mut graph = OrganizationalGraph::new();
    let mut first = CompleteCollection::new(
        tenant.clone(),
        runtime.clone(),
        CollectionId::parse("collection-conflict-first").unwrap(),
        "okta.users",
        10,
    )
    .unwrap()
    .begin_delta();
    first.add_entity(provider.clone()).unwrap();
    graph.apply(first.build()).unwrap();
    let revision = graph.graph_revision(&tenant);

    let mut second = CompleteCollection::new(
        tenant.clone(),
        runtime,
        CollectionId::parse("collection-conflict-second").unwrap(),
        "okta.users",
        10,
    )
    .unwrap()
    .begin_delta();
    second.add_entity(conflicting).unwrap();

    assert_eq!(
        graph.apply(second.build()),
        Err(GraphError::EntityConflict(provider.id().clone()))
    );
    assert_eq!(graph.graph_revision(&tenant), revision);
    assert_eq!(graph.entities(&tenant), vec![provider]);
    assert!(graph.assertions(&tenant).is_empty());
}

#[test]
fn stable_entity_identity_allows_source_data_refresh() {
    let tenant = TenantId::parse("tenant-a").unwrap();
    let runtime = SourceRuntimeId::parse("okta-prod").unwrap();
    let entity = ProviderIdentity::new(
        tenant.clone(),
        runtime.clone(),
        ProviderKind::parse("okta.user").unwrap(),
        "00u-refresh",
        "Old label",
    )
    .unwrap()
    .into_entity();
    let refreshed = ProviderIdentity::new(
        tenant.clone(),
        runtime.clone(),
        ProviderKind::parse("okta.user").unwrap(),
        "00u-refresh",
        "New label",
    )
    .unwrap()
    .into_entity()
    .with_property("department", "Security")
    .unwrap();
    let mut graph = OrganizationalGraph::new();
    for (collection_id, value) in [
        ("collection-refresh-1", entity),
        ("collection-refresh-2", refreshed.clone()),
    ] {
        let collection = CompleteCollection::new(
            tenant.clone(),
            runtime.clone(),
            CollectionId::parse(collection_id).unwrap(),
            "okta.users",
            10,
        )
        .unwrap();
        let mut builder = collection.begin_delta();
        builder.add_entity(value).unwrap();
        graph.apply(builder.build()).unwrap();
    }
    assert_eq!(graph.entity(&tenant, refreshed.id()).unwrap(), refreshed);
}
