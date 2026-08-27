use cerebro_organizational_graph::OrganizationalGraph;
use cerebro_organizational_model::{SourceRuntimeId, TenantId};
use cerebro_source_catalog::CompiledSource;
use sha2::{Digest, Sha256};

use crate::{
    CatalogGraphMapper, CollectedBatch, CommittedSourceEvent, CommittedSourceInput, GraphMapper,
    GraphSink, PageAppendReceipt, PageEventInput, PageProjectionReceipt, PagePublication,
    PagePublicationError, PagePublicationInput, PagePublicationState, PublishClaim,
};

fn digest<I, B>(parts: I) -> String
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    let mut hasher = Sha256::new();
    for part in parts {
        let part = part.as_ref();
        hasher.update(part.len().to_be_bytes());
        hasher.update(part);
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(super) fn committed_events(
    batch: &CollectedBatch,
    tenant_id: &TenantId,
    runtime_id: &SourceRuntimeId,
) -> Vec<CommittedSourceEvent> {
    let observed_at = batch.scope.receipt().observed_at_unix_ms();
    batch
        .records
        .iter()
        .map(|record| {
            CommittedSourceEvent::from_input(CommittedSourceInput {
                tenant_id: tenant_id.clone(),
                source_runtime_id: runtime_id.clone(),
                observation_id: record.observation_id.clone(),
                source_id: "google_gemini".to_owned(),
                family_id: "model_catalog".to_owned(),
                event_kind: "google_gemini.model_catalog".to_owned(),
                schema_ref: "google_gemini/model_catalog/v1".to_owned(),
                observed_at_unix_ms: observed_at,
                attributes: record.fields.clone(),
                payload: record.payload.clone(),
            })
            .unwrap()
        })
        .collect()
}

pub(super) async fn record_append_receipts_and_project_after_restart(
    source: &CompiledSource,
    tenant_id: &TenantId,
    runtime_id: &SourceRuntimeId,
    committed: Vec<CommittedSourceEvent>,
) -> (OrganizationalGraph, PagePublication) {
    let event_inputs = committed
        .iter()
        .map(|event| PageEventInput {
            event_id: event.observation_id().clone(),
            envelope_sha256: event.record_digest(),
        })
        .collect::<Vec<_>>();
    let result_digest = digest(committed.iter().map(CommittedSourceEvent::record_digest));
    let mut publication = PagePublication::prepare(
        PagePublicationInput {
            logical_page_id: "gemini-model-catalog-page".to_owned(),
            tenant_id: tenant_id.clone(),
            source_runtime_id: runtime_id.clone(),
            source_id: "google_gemini".to_owned(),
            family_id: "model_catalog".to_owned(),
            lease_generation: 1,
            authority_epoch: 1,
            request_intent_sha256: digest([b"GET /v1beta/models".as_slice()]),
            input_progress_sha256: digest([b"initial".as_slice()]),
            target_progress_sha256: digest([b"terminal".as_slice()]),
            result_sha256: result_digest,
        },
        event_inputs,
    )
    .unwrap();
    let first_claim = PublishClaim::new("worker-a", 1).unwrap();
    publication.begin_publishing(first_claim.clone()).unwrap();
    let first_intent = publication.events()[0].clone();
    publication
        .record_append(
            &first_claim,
            PageAppendReceipt {
                ordinal: first_intent.ordinal(),
                event_id: first_intent.event_id().clone(),
                message_id: first_intent.message_id().to_owned(),
                stream: "source-events".to_owned(),
                stream_sequence: 41,
            },
        )
        .unwrap();

    let snapshot = serde_json::to_value(&publication).unwrap();
    let mut publication = PagePublication::restore_snapshot(snapshot).unwrap();
    let successor = PublishClaim::new("worker-b", 2).unwrap();
    publication
        .transfer_claim(&first_claim, successor.clone())
        .unwrap();
    let second_intent = publication.events()[1].clone();
    let second_receipt = PageAppendReceipt {
        ordinal: second_intent.ordinal(),
        event_id: second_intent.event_id().clone(),
        message_id: second_intent.message_id().to_owned(),
        stream: "source-events".to_owned(),
        stream_sequence: 42,
    };
    assert_eq!(
        publication.record_append(&first_claim, second_receipt.clone()),
        Err(PagePublicationError::StaleClaim)
    );
    publication
        .record_append(&successor, second_receipt)
        .unwrap();
    assert_eq!(publication.state(), PagePublicationState::Published);

    let mapper = CatalogGraphMapper::new(source.clone(), "google-gemini-model-catalog-v1").unwrap();
    let mut graph = OrganizationalGraph::new();
    let mut projection_digests = Vec::new();
    let mut graph_revision = 0;
    for event in committed {
        let provider_id = event.payload()["name"].as_str().unwrap().to_owned();
        let event_batch = event
            .into_batch("google_gemini.model_catalog".to_owned(), provider_id)
            .unwrap();
        let delta = mapper.map(&event_batch).unwrap();
        let receipt = GraphSink::apply(&mut graph, &event_batch, delta)
            .await
            .unwrap();
        projection_digests.push(receipt.delta_digest);
        graph_revision = receipt.graph_revision;
    }
    publication
        .record_projection(
            &successor,
            PageProjectionReceipt {
                delta_sha256: digest(projection_digests),
                graph_revision,
            },
        )
        .unwrap();
    publication.commit(&successor).unwrap();
    (graph, publication)
}
