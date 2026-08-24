use std::collections::HashMap;

use serde_json::Value;

use crate::source_execution::{
    SourceExecutionDispatcher, SourceExecutionError, SourceExecutionLifecycleEnvelopeV2,
    SourceExecutionLifecycleRequestV1, SourceExecutionSelectionRequestV1,
    SourceWorkerDecodeEnvelopeV2, SourceWorkerDecodeRequestV1, SourceWorkerExecutionContextV1,
    SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1, SourceWorkerRuntimeMetadataV2,
    seal_page_program_v2,
};

use super::{ASANA_SOURCE_EXECUTION_ADAPTERS, AsanaFamily, DEFAULT_BASE_URL};

const OBSERVED_AT_MILLIS: i64 = 1_780_272_000_000;

fn context(cursor: &str, page: u32) -> SourceWorkerExecutionContextV1 {
    SourceWorkerExecutionContextV1 {
        tenant_id: "tenant".to_owned(),
        runtime_id: "asana-runtime".to_owned(),
        logical_page_id: format!("source-page-v2:asana-{page}"),
        prior_cursor: cursor.to_owned(),
        runtime_generation: 7,
        lease_generation: 11,
        observed_at_unix_millis: OBSERVED_AT_MILLIS,
    }
}

fn metadata(family: AsanaFamily) -> SourceWorkerRuntimeMetadataV2 {
    SourceWorkerRuntimeMetadataV2 {
        public_config: HashMap::from([
            ("family".to_owned(), family.as_str().to_owned()),
            ("workspace_gid".to_owned(), "workspace-1".to_owned()),
            ("page_size".to_owned(), "2".to_owned()),
        ]),
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    }
}

#[test]
fn closed_dispatcher_compiles_every_asana_family() {
    let dispatcher = SourceExecutionDispatcher;
    assert_eq!(
        ASANA_SOURCE_EXECUTION_ADAPTERS.len(),
        AsanaFamily::ALL.len()
    );
    for adapter in &ASANA_SOURCE_EXECUTION_ADAPTERS {
        let family = adapter.family();
        let plan = dispatcher
            .compile_plan(&SourceExecutionSelectionRequestV1 {
                source_id: "asana".to_owned(),
                family_id: family.as_str().to_owned(),
            })
            .unwrap();
        assert_eq!(plan, adapter.compiled_plan().unwrap());
        assert_eq!(plan.provider_kernel, family.event_kind());
        assert_eq!(plan.origin, DEFAULT_BASE_URL);
        assert_eq!(plan.record_selector, "$.data[*]");
        assert_eq!(plan.id_field, "gid");
        assert_eq!(plan.event_kind, family.event_kind());
        assert_eq!(plan.schema_ref, family.schema_ref());
    }
    assert_eq!(
        dispatcher.compile_plan(&SourceExecutionSelectionRequestV1 {
            source_id: "asana".to_owned(),
            family_id: "tasks".to_owned(),
        }),
        Err(SourceExecutionError::UnknownAdapter)
    );
}

#[test]
fn plans_all_families_without_credentials_and_requires_workspace_scope() {
    let dispatcher = SourceExecutionDispatcher;
    for adapter in &ASANA_SOURCE_EXECUTION_ADAPTERS {
        let family = adapter.family();
        let plan = adapter.compiled_plan().unwrap();
        let execution = dispatcher
            .dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(plan),
                    context: Some(context("", 1)),
                }),
                metadata: Some(metadata(family)),
            })
            .unwrap();
        assert_eq!(execution.credential_operation, "source.bearer");
        assert_eq!(execution.allowed_origin, DEFAULT_BASE_URL);
        assert!(execution.body.is_empty());
        assert!(execution.declared_headers.is_empty());
        let request = execution.request.unwrap();
        assert_eq!(request.method, "GET");
        assert!(request.url.starts_with(DEFAULT_BASE_URL));
        assert!(request.url.contains("limit=2"));
        assert!(!request.url.contains("token"));
        match family {
            AsanaFamily::Users | AsanaFamily::Projects => {
                assert!(request.url.contains("workspace=workspace-1"));
            }
            AsanaFamily::AuditEvents => {
                assert!(
                    request
                        .url
                        .contains("/workspaces/workspace-1/audit_log_events?")
                );
            }
        }
    }

    let adapter = &ASANA_SOURCE_EXECUTION_ADAPTERS[0];
    let mut missing = metadata(adapter.family());
    missing.public_config.remove("workspace_gid");
    assert_eq!(
        dispatcher.dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(adapter.compiled_plan().unwrap()),
                context: Some(context("", 1)),
            }),
            metadata: Some(missing),
        }),
        Err(SourceExecutionError::MissingConfiguration)
    );
}

#[test]
fn users_page_decodes_and_seals_a_restartable_cursor() {
    let dispatcher = SourceExecutionDispatcher;
    let family = AsanaFamily::Users;
    let plan = dispatcher
        .compile_plan(&SourceExecutionSelectionRequestV1 {
            source_id: "asana".to_owned(),
            family_id: family.as_str().to_owned(),
        })
        .unwrap();
    let context = context("", 1);
    let metadata = metadata(family);
    let execution = dispatcher
        .dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(plan.clone()),
                context: Some(context.clone()),
            }),
            metadata: Some(metadata.clone()),
        })
        .unwrap();
    let request = execution.request.as_ref().unwrap();
    let output = dispatcher
        .dispatch_decode_v2(&SourceWorkerDecodeEnvelopeV2 {
            request: Some(SourceWorkerDecodeRequestV1 {
                plan: Some(plan.clone()),
                status_code: 200,
                response_body: br#"{"data":[{"gid":"user-1","name":"User One","email":"user@example.test"}],"next_page":{"offset":"cursor-2"}}"#.to_vec(),
                logical_page_id: context.logical_page_id.clone(),
                request_intent_digest: request.request_intent_digest.clone(),
                receipt: None,
                context: Some(context.clone()),
            }),
            metadata: Some(metadata.clone()),
            response_headers: HashMap::new(),
            response_headers_sha256: String::new(),
            execution_intent_digest_sha256: execution.execution_intent_digest_sha256.clone(),
        })
        .unwrap();
    let result = output.result.as_ref().unwrap();
    assert_eq!(result.next_cursor, "cursor-2");
    assert_eq!(result.records.len(), 1);
    let record = &result.records[0];
    assert_eq!(record.provider_id, "user-1");
    assert_eq!(record.attributes["tenant_id"], "tenant");
    assert_eq!(record.attributes["user_id"], "user-1");
    let payload: Value = serde_json::from_slice(&record.payload_json).unwrap();
    assert_eq!(payload["gid"], "user-1");
    assert!(!record.event_id.contains("tenant"));

    let decision = seal_page_program_v2(&SourceExecutionLifecycleEnvelopeV2 {
        request: Some(SourceExecutionLifecycleRequestV1 {
            plan: Some(plan),
            context: Some(context),
            receipt: output.receipt,
            result: output.result,
            current_lease_generation: 11,
        }),
        metadata: Some(metadata),
    })
    .unwrap();
    assert_eq!(decision.checkpoint_cursor, "cursor-2");
    assert_eq!(decision.admitted_records.len(), 1);
}
