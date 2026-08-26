use cerebro_organizational_graph::{GraphRead, OrganizationalGraph};
use cerebro_organizational_model::{ObservationId, SourceRuntimeId, TenantId};
use sha2::{Digest, Sha256};

use crate::{
    GraphMapper, PageAppendReceipt, PageEventInput, PageProjectionReceipt, PagePublication,
    PagePublicationError, PagePublicationInput, PagePublicationState, PublishClaim,
    asana_users_graph_batch,
};

use super::users_test_support as support;

#[test]
fn asana_users_restart_preserves_append_projection_checkpoint_order() {
    let output = support::decoded_page("tenant-a", "", 1, support::USERS_PAGE_1);
    let result = output.result.as_ref().unwrap();
    let safe_receipt = output.receipt.as_ref().unwrap();
    let batch = asana_users_graph_batch(
        support::collection_receipt("tenant-a", "asana-users-restart-page"),
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

    let delta = support::mapper().map(&batch).unwrap();
    let mut graph = OrganizationalGraph::new();
    let write = graph.apply(delta).unwrap();
    assert!(recovered.commit(&successor).is_err());
    recovered
        .record_projection(
            &successor,
            PageProjectionReceipt {
                delta_sha256: write
                    .delta_digest
                    .strip_prefix("sha256:")
                    .expect("graph delta digest prefix")
                    .to_owned(),
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
