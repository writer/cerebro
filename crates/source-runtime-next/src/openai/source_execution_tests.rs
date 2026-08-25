use std::collections::HashMap;

use crate::source_execution::{
    SourceExecutionAdapter, SourceExecutionDispatcher, SourceExecutionSelectionRequestV1,
    SourceWorkerDecodeEnvelopeV2, SourceWorkerDecodeRequestV1, SourceWorkerExecutionContextV1,
    SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1, SourceWorkerRuntimeMetadataV2,
    SourceWorkerSafeReceiptV1, response_digest,
};

use super::{OPENAI_SOURCE_EXECUTION_ADAPTERS, OpenAiSourceExecutionAdapter};
use crate::openai::{OpenAiFamily, family::ORIGIN};

const OBSERVED_AT_MILLIS: i64 = 1_780_272_000_000;

fn context(cursor: &str) -> SourceWorkerExecutionContextV1 {
    SourceWorkerExecutionContextV1 {
        tenant_id: "tenant".to_owned(),
        runtime_id: "openai-runtime".to_owned(),
        logical_page_id: "source-page-v2:openai-1".to_owned(),
        prior_cursor: cursor.to_owned(),
        runtime_generation: 7,
        lease_generation: 11,
        observed_at_unix_millis: OBSERVED_AT_MILLIS,
    }
}

fn metadata(family: OpenAiFamily) -> SourceWorkerRuntimeMetadataV2 {
    let mut public_config = HashMap::from([
        ("family".to_owned(), family.id().to_owned()),
        ("per_page".to_owned(), "2".to_owned()),
    ]);
    for parameter in family.spec().path_parameters {
        public_config.insert((*parameter).to_owned(), format!("{parameter}-1"));
    }
    SourceWorkerRuntimeMetadataV2 {
        public_config,
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    }
}

fn adapter(family: OpenAiFamily) -> &'static OpenAiSourceExecutionAdapter {
    OPENAI_SOURCE_EXECUTION_ADAPTERS
        .iter()
        .find(|adapter| adapter.family_id() == family.id())
        .expect("OpenAI adapter")
}

#[test]
fn shared_dispatcher_compiles_every_openai_family() {
    assert_eq!(OPENAI_SOURCE_EXECUTION_ADAPTERS.len(), 39);
    for family in OpenAiFamily::all() {
        let plan = adapter(family).compiled_plan();
        assert_eq!(plan.source_id, "openai");
        assert_eq!(plan.family_id, family.id());
        assert_eq!(plan.provider_kernel, family.id());
        assert_eq!(plan.origin, ORIGIN);
        assert_eq!(plan.event_kind, family.event_kind());
        assert_eq!(plan.schema_ref, family.schema_ref());
        assert_eq!(
            SourceExecutionDispatcher
                .compile_plan(&SourceExecutionSelectionRequestV1 {
                    source_id: "openai".to_owned(),
                    family_id: family.id().to_owned(),
                })
                .unwrap_or_else(|error| panic!("{} compile: {error}", family.id())),
            plan
        );
    }
}

#[test]
fn every_family_plans_one_origin_restricted_credential_free_request() {
    for family in OpenAiFamily::all() {
        let execution = adapter(family)
            .plan_v2(&SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(adapter(family).compiled_plan()),
                    context: Some(context("")),
                }),
                metadata: Some(metadata(family)),
            })
            .unwrap_or_else(|error| panic!("{} plan: {error}", family.id()));
        assert_eq!(execution.allowed_origin, ORIGIN);
        assert_eq!(
            execution.credential_operation,
            "openai.admin_api_key_bearer"
        );
        assert!(execution.body.is_empty());
        assert!(execution.declared_headers.is_empty());
        let request = execution.request.expect("planned request");
        let url = reqwest::Url::parse(&request.url).expect("planned URL");
        assert_eq!(url.origin().ascii_serialization(), ORIGIN);
        assert!(url.username().is_empty());
        assert!(url.password().is_none());
        assert!(url.query_pairs().all(|(key, _)| !matches!(
            key.as_ref(),
            "api_key" | "api_token" | "access_token" | "token"
        )));
    }
}

#[test]
fn user_decode_preserves_cursor_and_tenant_scoped_identity() {
    let family = OpenAiFamily::parse("user").unwrap();
    let adapter = adapter(family);
    let plan = adapter.compiled_plan();
    let context = context("");
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
    let body = br#"{"data":[{"id":"user_1","email":"person@example.test","role":"owner","added_at":1711471533}],"has_more":true,"last_id":"user_1"}"#;
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
            metadata: Some(metadata.clone()),
            response_headers: HashMap::new(),
            response_headers_sha256: String::new(),
            execution_intent_digest_sha256: execution.execution_intent_digest_sha256,
        })
        .unwrap();
    assert_eq!(result.next_cursor, "user_1");
    assert_eq!(result.records.len(), 1);
    let record = &result.records[0];
    assert_eq!(record.provider_id, "user_1");
    assert_eq!(record.attributes["user_id"], "user_1");
    adapter
        .validate_record_identity_v2(&context, record, &metadata)
        .unwrap();
}
