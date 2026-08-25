use std::collections::HashMap;

use crate::source_execution::{
    SourceExecutionAdapter, SourceExecutionDispatcher, SourceExecutionSelectionRequestV1,
    SourceWorkerDecodeEnvelopeV2, SourceWorkerDecodeRequestV1, SourceWorkerExecutionContextV1,
    SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1, SourceWorkerRuntimeMetadataV2,
    SourceWorkerSafeReceiptV1, response_digest,
};

use super::{DEEPSEEK_SOURCE_EXECUTION_ADAPTERS, DeepSeekSourceExecutionAdapter};
use crate::deepseek::DeepSeekFamily;

const OBSERVED_AT_MILLIS: i64 = 1_780_272_000_000;

fn context(tenant: &str) -> SourceWorkerExecutionContextV1 {
    SourceWorkerExecutionContextV1 {
        tenant_id: tenant.to_owned(),
        runtime_id: "deepseek-runtime".to_owned(),
        logical_page_id: "source-page-v2:deepseek-1".to_owned(),
        prior_cursor: String::new(),
        runtime_generation: 7,
        lease_generation: 11,
        observed_at_unix_millis: OBSERVED_AT_MILLIS,
    }
}

fn metadata(family: DeepSeekFamily) -> SourceWorkerRuntimeMetadataV2 {
    SourceWorkerRuntimeMetadataV2 {
        public_config: HashMap::from([("family".to_owned(), family.as_str().to_owned())]),
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    }
}

fn adapter(family: DeepSeekFamily) -> &'static DeepSeekSourceExecutionAdapter {
    DEEPSEEK_SOURCE_EXECUTION_ADAPTERS
        .iter()
        .find(|adapter| adapter.family_id() == family.as_str())
        .expect("DeepSeek adapter")
}

#[test]
fn shared_dispatcher_compiles_both_deepseek_families() {
    assert_eq!(DEEPSEEK_SOURCE_EXECUTION_ADAPTERS.len(), 2);
    for family in DeepSeekFamily::ALL {
        let plan = adapter(family).compiled_plan();
        assert_eq!(plan.source_id, "deepseek");
        assert_eq!(plan.family_id, family.as_str());
        assert_eq!(plan.origin, "https://api.deepseek.com");
        assert_eq!(plan.path, family.path());
        assert_eq!(
            SourceExecutionDispatcher
                .compile_plan(&SourceExecutionSelectionRequestV1 {
                    source_id: "deepseek".to_owned(),
                    family_id: family.as_str().to_owned(),
                })
                .unwrap(),
            plan
        );
    }
}

#[test]
fn both_families_plan_origin_restricted_credential_free_requests() {
    for family in DeepSeekFamily::ALL {
        let adapter = adapter(family);
        let execution = adapter
            .plan_v2(&SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(adapter.compiled_plan()),
                    context: Some(context("tenant-a")),
                }),
                metadata: Some(metadata(family)),
            })
            .unwrap();
        assert_eq!(execution.allowed_origin, "https://api.deepseek.com");
        assert_eq!(execution.credential_operation, "source.bearer");
        assert!(execution.body.is_empty());
        assert!(execution.declared_headers.is_empty());
        let request = execution.request.unwrap();
        assert_eq!(
            request.url,
            format!("https://api.deepseek.com{}", family.path())
        );
        assert!(!request.url.contains("token"));
    }
}

#[test]
fn model_decode_is_tenant_scoped_terminal_and_deterministic() {
    let family = DeepSeekFamily::ModelCatalog;
    let adapter = adapter(family);
    let plan = adapter.compiled_plan();
    let context = context("tenant-a");
    let metadata = metadata(family);
    let execution = adapter
        .plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(plan.clone()),
                context: Some(context.clone()),
            }),
            metadata: Some(metadata.clone()),
        })
        .unwrap();
    let planned = execution.request.as_ref().unwrap();
    let body = br#"{"data":[{"id":"deepseek-chat","updated_at":"2026-06-01T00:00:00Z"}]}"#;
    let receipt = SourceWorkerSafeReceiptV1 {
        plan_digest_sha256: plan.plan_digest_sha256.clone(),
        logical_page_id: context.logical_page_id.clone(),
        request_intent_digest: planned.request_intent_digest.clone(),
        runtime_generation: context.runtime_generation,
        lease_generation: context.lease_generation,
        credential_operation: execution.credential_operation.clone(),
        status_code: 200,
        response_bytes: body.len() as u64,
        response_sha256: response_digest(body),
        tenant_id: context.tenant_id.clone(),
        runtime_id: context.runtime_id.clone(),
        observed_at_unix_millis: context.observed_at_unix_millis,
    };
    let result = adapter
        .decode_v2(&SourceWorkerDecodeEnvelopeV2 {
            request: Some(SourceWorkerDecodeRequestV1 {
                plan: Some(plan),
                status_code: 200,
                response_body: body.to_vec(),
                logical_page_id: context.logical_page_id.clone(),
                request_intent_digest: planned.request_intent_digest.clone(),
                receipt: Some(receipt),
                context: Some(context.clone()),
            }),
            metadata: Some(metadata),
            response_headers: HashMap::new(),
            response_headers_sha256: String::new(),
            execution_intent_digest_sha256: execution.execution_intent_digest_sha256,
        })
        .unwrap();
    assert!(result.next_cursor.is_empty());
    assert_eq!(result.records.len(), 1);
    let record = &result.records[0];
    assert_eq!(record.provider_id, "deepseek-chat");
    assert_eq!(record.attributes["tenant_id"], "tenant-a");
    adapter.validate_record_identity(&context, record).unwrap();
    assert!(
        !record
            .payload_json
            .windows(5)
            .any(|value| value == b"token")
    );
}

#[test]
fn prior_cursor_and_untrusted_tenant_fail_closed() {
    let family = DeepSeekFamily::ModelCatalog;
    let adapter = adapter(family);
    let mut invalid = context("tenant-a");
    invalid.prior_cursor = "not-admitted".to_owned();
    assert!(
        adapter
            .plan_v2(&SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(adapter.compiled_plan()),
                    context: Some(invalid),
                }),
                metadata: Some(metadata(family)),
            })
            .is_err()
    );
}
