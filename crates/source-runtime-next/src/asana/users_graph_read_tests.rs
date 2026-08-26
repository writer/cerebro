use std::{collections::HashMap, path::Path};

use cerebro_organizational_graph::{GraphRead, OrganizationalGraph};
use cerebro_organizational_model::{
    CollectionId, CollectionReceipt, ObservationId, SourceRuntimeId, TenantId,
};
use cerebro_source_catalog::SourceCatalog;
use sha2::{Digest, Sha256};

use crate::{
    CatalogGraphMapper, GraphMapper, PageAppendReceipt, PageEventInput, PageProjectionReceipt,
    PagePublication, PagePublicationError, PagePublicationInput, PagePublicationState,
    PublishClaim, asana_users_graph_batch,
};

use super::{AsanaError, users_test_support as support};

fn collection_receipt(tenant_id: &str, collection_id: &str) -> CollectionReceipt {
    CollectionReceipt::incremental(
        TenantId::parse(tenant_id).unwrap(),
        SourceRuntimeId::parse("asana-users-runtime").unwrap(),
        CollectionId::parse(collection_id).unwrap(),
        "asana.users",
        support::OBSERVED_AT_MILLIS,
    )
    .unwrap()
}

fn mapper() -> CatalogGraphMapper {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let catalog = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )
    .unwrap();
    CatalogGraphMapper::new(catalog.get("asana").unwrap().clone(), "asana-users-v1").unwrap()
}

fn decoded_page(
    tenant_id: &str,
    cursor: &str,
    page_number: u32,
    body: &[u8],
) -> crate::source_execution::SourceWorkerDecodeOutputV2 {
    let plan = support::plan();
    let metadata = support::metadata();
    let context = support::context(tenant_id, cursor, page_number);
    let execution = support::plan_page(&plan, &context, &metadata).unwrap();
    support::decode_page(
        &plan,
        &context,
        &metadata,
        &execution,
        200,
        body,
        HashMap::new(),
    )
    .unwrap()
}

#[test]
fn asana_users_graph_projection_is_idempotent_and_tenant_scoped() {
    let first = decoded_page("tenant-a", "", 1, support::USERS_PAGE_1);
    let first_batch =
        asana_users_graph_batch(collection_receipt("tenant-a", "asana-users-page-1"), &first)
            .unwrap();
    assert_eq!(first_batch.records.len(), 2);
    assert_eq!(first_batch.next_cursor.as_deref(), Some("cursor-page-2"));

    let mapper = mapper();
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

    let second = decoded_page("tenant-a", "cursor-page-2", 2, support::USERS_PAGE_2);
    let second_batch = asana_users_graph_batch(
        collection_receipt("tenant-a", "asana-users-page-2"),
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

    let tenant_b_output = decoded_page("tenant-b", "", 1, support::USERS_PAGE_1);
    assert_ne!(
        first.result.as_ref().unwrap().records[0].event_id,
        tenant_b_output.result.as_ref().unwrap().records[0].event_id
    );
    let tenant_b_batch = asana_users_graph_batch(
        collection_receipt("tenant-b", "asana-users-tenant-b-page-1"),
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

#[test]
fn asana_users_graph_input_rejects_tenant_and_result_tampering() {
    let output = decoded_page("tenant-a", "", 1, support::USERS_PAGE_1);
    assert_eq!(
        asana_users_graph_batch(
            collection_receipt("tenant-b", "asana-users-wrong-tenant"),
            &output,
        ),
        Err(AsanaError::EventContractRejection)
    );
    let wrong_scope = CollectionReceipt::incremental(
        TenantId::parse("tenant-a").unwrap(),
        SourceRuntimeId::parse("asana-users-runtime").unwrap(),
        CollectionId::parse("asana-users-wrong-scope").unwrap(),
        "asana.projects",
        support::OBSERVED_AT_MILLIS,
    )
    .unwrap();
    assert_eq!(
        asana_users_graph_batch(wrong_scope, &output),
        Err(AsanaError::EventContractRejection)
    );

    let mut tampered = output;
    tampered.result.as_mut().unwrap().records[0]
        .attributes
        .insert("user_id".to_owned(), "other-user".to_owned());
    reseal_result(&mut tampered);
    assert_eq!(
        asana_users_graph_batch(
            collection_receipt("tenant-a", "asana-users-tampered"),
            &tampered,
        ),
        Err(AsanaError::EventContractRejection)
    );

    let mut credential_shaped = decoded_page("tenant-a", "", 1, support::USERS_PAGE_1);
    let record = &mut credential_shaped.result.as_mut().unwrap().records[0];
    let mut payload: serde_json::Value = serde_json::from_slice(&record.payload_json).unwrap();
    payload["profile"] = serde_json::json!({"access_token": "secret-sentinel"});
    record.payload_json = serde_json::to_vec(&payload).unwrap();
    reseal_result(&mut credential_shaped);
    assert_eq!(
        asana_users_graph_batch(
            collection_receipt("tenant-a", "asana-users-credential-shaped"),
            &credential_shaped,
        ),
        Err(AsanaError::CredentialMaterial)
    );
}

fn reseal_result(output: &mut crate::source_execution::SourceWorkerDecodeOutputV2) {
    let recomputed_digest = crate::source_execution::canonical_result_digest(
        output.receipt.as_ref().unwrap(),
        &output.result.as_ref().unwrap().next_cursor,
        &output.result.as_ref().unwrap().records,
    )
    .unwrap();
    output.result.as_mut().unwrap().result_digest_sha256 = recomputed_digest;
}

#[test]
fn asana_users_restart_preserves_append_projection_checkpoint_order() {
    let output = decoded_page("tenant-a", "", 1, support::USERS_PAGE_1);
    let result = output.result.as_ref().unwrap();
    let safe_receipt = output.receipt.as_ref().unwrap();
    let batch = asana_users_graph_batch(
        collection_receipt("tenant-a", "asana-users-restart-page"),
        &output,
    )
    .unwrap();

    // This in-memory epoch is only a state-machine fixture. It is not a
    // persisted authority record or production promotion receipt.
    let mut publication = PagePublication::prepare(
        PagePublicationInput {
            logical_page_id: result.logical_page_id.clone(),
            tenant_id: TenantId::parse("tenant-a").unwrap(),
            source_runtime_id: SourceRuntimeId::parse("asana-users-runtime").unwrap(),
            source_id: "asana".to_owned(),
            family_id: "users".to_owned(),
            lease_generation: result.lease_generation,
            authority_epoch: 1,
            request_intent_sha256: safe_receipt.request_intent_digest.clone(),
            input_progress_sha256: sha256(""),
            target_progress_sha256: sha256(&result.next_cursor),
            result_sha256: result.result_digest_sha256.clone(),
        },
        result
            .records
            .iter()
            .map(|record| PageEventInput {
                event_id: ObservationId::parse(&record.event_id).unwrap(),
                envelope_sha256: sha256(&record.payload_json),
            })
            .collect(),
    )
    .unwrap();
    let first_claim = PublishClaim::new("asana-worker-a", 1).unwrap();
    publication.begin_publishing(first_claim.clone()).unwrap();
    assert!(publication.commit(&first_claim).is_err());
    assert!(
        publication
            .record_projection(
                &first_claim,
                PageProjectionReceipt {
                    delta_sha256: sha256("uncommitted"),
                    graph_revision: 1,
                },
            )
            .is_err()
    );

    let first_append = append_receipt(&publication, 0, 100);
    publication
        .record_append(&first_claim, first_append.clone())
        .unwrap();
    let persisted = serde_json::to_value(&publication).unwrap();
    let mut recovered = PagePublication::restore_snapshot(persisted).unwrap();
    let successor = PublishClaim::new("asana-worker-b", 2).unwrap();
    recovered
        .transfer_claim(&first_claim, successor.clone())
        .unwrap();
    let second_append = append_receipt(&recovered, 1, 101);
    assert_eq!(
        recovered.record_append(&first_claim, second_append.clone()),
        Err(PagePublicationError::StaleClaim)
    );
    recovered.record_append(&successor, first_append).unwrap();
    recovered.record_append(&successor, second_append).unwrap();
    assert_eq!(recovered.state(), PagePublicationState::Published);

    let delta = mapper().map(&batch).unwrap();
    let mut graph = OrganizationalGraph::new();
    let write = graph.apply(delta).unwrap();
    assert!(recovered.commit(&successor).is_err());
    recovered
        .record_projection(
            &successor,
            PageProjectionReceipt {
                delta_sha256: write.delta_digest,
                graph_revision: write.graph_revision,
            },
        )
        .unwrap();
    recovered.commit(&successor).unwrap();
    assert_eq!(recovered.state(), PagePublicationState::Committed);
    let durable_cursor = batch.next_cursor;
    assert_eq!(durable_cursor.as_deref(), Some("cursor-page-2"));
    assert_eq!(
        graph.entities(&TenantId::parse("tenant-a").unwrap()).len(),
        2
    );
}

fn append_receipt(
    publication: &PagePublication,
    ordinal: usize,
    stream_sequence: u64,
) -> PageAppendReceipt {
    let event = &publication.events()[ordinal];
    PageAppendReceipt {
        ordinal: event.ordinal(),
        event_id: event.event_id().clone(),
        message_id: event.message_id().to_owned(),
        stream: "CEREBRO_EVENTS".to_owned(),
        stream_sequence,
    }
}

fn sha256(value: impl AsRef<[u8]>) -> String {
    let digest = Sha256::digest(value.as_ref());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
