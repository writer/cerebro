use cerebro_organizational_graph::{GraphRead, OrganizationalGraph};
use cerebro_organizational_model::TenantId;

use crate::{GraphMapper, asana_users_graph_batch};

use super::users_test_support as support;

#[test]
fn asana_users_graph_projection_is_idempotent_and_tenant_scoped() {
    let first = support::decoded_page("tenant-a", "", 1, support::USERS_PAGE_1);
    let first_batch = asana_users_graph_batch(
        support::collection_receipt("tenant-a", "asana-users-page-1"),
        &first,
    )
    .unwrap();
    assert_eq!(first_batch.records.len(), 2);
    assert_eq!(first_batch.next_cursor.as_deref(), Some("cursor-page-2"));

    let mapper = support::mapper();
    let first_delta = mapper.map(&first_batch).unwrap();
    assert_eq!(first_delta.entities().len(), 2);
    let first_entity_id = first_delta
        .entities()
        .iter()
        .find(|entity| {
            entity
                .properties()
                .get("user_id")
                .is_some_and(|id| id == "user-1")
        })
        .unwrap()
        .id()
        .clone();
    let mut graph = OrganizationalGraph::new();
    let first_write = graph.apply(first_delta).unwrap();
    assert_eq!(first_write.entities_upserted, 2);
    let tenant_a = TenantId::parse("tenant-a").unwrap();
    let first_read = graph.entity(&tenant_a, &first_entity_id).unwrap();
    assert_eq!(
        first_read.kind(),
        &cerebro_organizational_model::EntityKind::Identity
    );
    assert_eq!(first_read.properties()["user_id"], "user-1");
    assert_eq!(first_read.properties()["email"], "user.one@example.test");

    let second = support::decoded_page("tenant-a", "cursor-page-2", 2, support::USERS_PAGE_2);
    let second_batch = asana_users_graph_batch(
        support::collection_receipt("tenant-a", "asana-users-page-2"),
        &second,
    )
    .unwrap();
    assert!(second_batch.next_cursor.is_none());
    let second_delta = mapper.map(&second_batch).unwrap();
    graph.apply(second_delta).unwrap();
    let entities = graph.entities(&tenant_a);
    assert_eq!(entities.len(), 3, "replayed user-2 must remain idempotent");
    assert_eq!(
        entities
            .iter()
            .filter(|entity| entity
                .properties()
                .get("user_id")
                .is_some_and(|id| id == "user-2"))
            .count(),
        1
    );

    let tenant_b_output = support::decoded_page("tenant-b", "", 1, support::USERS_PAGE_1);
    assert_ne!(
        first.result.as_ref().unwrap().records[0].event_id,
        tenant_b_output.result.as_ref().unwrap().records[0].event_id
    );
    let tenant_b_batch = asana_users_graph_batch(
        support::collection_receipt("tenant-b", "asana-users-tenant-b-page-1"),
        &tenant_b_output,
    )
    .unwrap();
    graph.apply(mapper.map(&tenant_b_batch).unwrap()).unwrap();
    assert_eq!(
        graph.entities(&TenantId::parse("tenant-b").unwrap()).len(),
        2
    );
    assert_eq!(graph.entities(&tenant_a).len(), 3);
}
