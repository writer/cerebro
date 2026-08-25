use std::collections::HashMap;

use crate::source_execution::{
    SourceExecutionAdapter, SourceExecutionDispatcher, SourceExecutionError,
    SourceExecutionSelectionRequestV1, SourceWorkerDecodeEnvelopeV2, SourceWorkerDecodeRequestV1,
    SourceWorkerExecutionContextV1, SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1,
    SourceWorkerRuntimeMetadataV2, SourceWorkerSafeReceiptV1, response_digest,
};

use super::{
    PORTABLE_AI_SOURCE_EXECUTION_ADAPTERS, adapter::PortableAiSourceExecutionAdapter,
    catalog::SOURCES,
};

const OBSERVED_AT_MILLIS: i64 = 1_780_272_000_000;

fn adapter(source: &str, family: &str) -> &'static PortableAiSourceExecutionAdapter {
    PORTABLE_AI_SOURCE_EXECUTION_ADAPTERS
        .iter()
        .find(|adapter| adapter.source_id() == source && adapter.family_id() == family)
        .expect("portable AI adapter")
}

fn context(cursor: &str) -> SourceWorkerExecutionContextV1 {
    SourceWorkerExecutionContextV1 {
        tenant_id: "tenant".to_owned(),
        runtime_id: "portable-ai-runtime".to_owned(),
        logical_page_id: "source-page-v2:portable-ai-1".to_owned(),
        prior_cursor: cursor.to_owned(),
        runtime_generation: 7,
        lease_generation: 11,
        observed_at_unix_millis: OBSERVED_AT_MILLIS,
    }
}

fn metadata(source: &str, family: &str) -> SourceWorkerRuntimeMetadataV2 {
    let mut public_config = HashMap::from([("family".to_owned(), family.to_owned())]);
    match source {
        "azure_openai" => {
            public_config.insert("subscription_id".to_owned(), "sub-1".to_owned());
            public_config.insert("resource_group".to_owned(), "rg-ai".to_owned());
            public_config.insert("account_name".to_owned(), "acct-openai".to_owned());
            public_config.insert("location".to_owned(), "westus".to_owned());
        }
        "google_vertex_ai" => {
            public_config.insert("project_id".to_owned(), "project-1".to_owned());
            public_config.insert("location".to_owned(), "us-central1".to_owned());
        }
        "huggingface" => {
            public_config.insert("organization".to_owned(), "writer".to_owned());
        }
        _ => {}
    }
    SourceWorkerRuntimeMetadataV2 {
        public_config,
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    }
}

fn execution(
    adapter: &PortableAiSourceExecutionAdapter,
    context: SourceWorkerExecutionContextV1,
    metadata: SourceWorkerRuntimeMetadataV2,
) -> crate::source_execution::SourceWorkerHttpExecutionV2 {
    adapter
        .plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(adapter.compiled_plan()),
                context: Some(context),
            }),
            metadata: Some(metadata),
        })
        .expect("portable AI execution")
}

#[test]
fn embedded_catalog_compiles_all_eight_sources_and_thirty_six_families() {
    assert_eq!(SOURCES.len(), 8);
    assert_eq!(PORTABLE_AI_SOURCE_EXECUTION_ADAPTERS.len(), 36);
    for adapter in PORTABLE_AI_SOURCE_EXECUTION_ADAPTERS.iter() {
        let plan = adapter.compiled_plan();
        assert_eq!(plan.source_id, adapter.source_id());
        assert_eq!(plan.family_id, adapter.family_id());
        assert_eq!(plan.provider_kernel, adapter.provider_kernel());
        assert!(!plan.required_attributes.is_empty());
        assert!(!plan.required_payload_fields.is_empty());
        assert_eq!(
            SourceExecutionDispatcher
                .compile_plan(&SourceExecutionSelectionRequestV1 {
                    source_id: plan.source_id.clone(),
                    family_id: plan.family_id.clone(),
                })
                .expect("dispatcher plan"),
            plan
        );
    }
}

#[test]
fn every_family_plans_an_origin_restricted_request_without_credentials() {
    for adapter in PORTABLE_AI_SOURCE_EXECUTION_ADAPTERS.iter() {
        let execution = execution(
            adapter,
            context(""),
            metadata(adapter.source_id(), adapter.family_id()),
        );
        let request = execution.request.expect("request");
        let origin = reqwest::Url::parse(&execution.allowed_origin).expect("origin");
        let url = reqwest::Url::parse(&request.url).expect("request URL");
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), origin.host_str());
        assert!(url.username().is_empty());
        assert!(url.password().is_none());
        assert!(request.url.find("${config.").is_none());
        assert!(execution.body.is_empty());
        assert!(execution.declared_headers.is_empty());
        assert!(url.query_pairs().all(|(key, _)| !matches!(
            key.as_ref(),
            "api_key" | "apikey" | "access_token" | "client_secret" | "token"
        )));
        let expected_operation = if adapter.source_id() == "google_gemini" {
            "google.api_key_header"
        } else {
            "source.bearer"
        };
        assert_eq!(execution.credential_operation, expected_operation);
    }
}

#[test]
fn provider_specific_public_request_contracts_are_preserved() {
    let azure = execution(
        adapter("azure_openai", "deployments"),
        context(""),
        metadata("azure_openai", "deployments"),
    );
    let azure_url = reqwest::Url::parse(&azure.request.unwrap().url).unwrap();
    assert_eq!(azure_url.host_str(), Some("management.azure.com"));
    assert_eq!(
        azure_url
            .query_pairs()
            .find(|(key, _)| key == "api-version")
            .map(|(_, value)| value.into_owned()),
        Some("2024-10-01".to_owned())
    );

    let vertex = execution(
        adapter("google_vertex_ai", "models"),
        context(""),
        metadata("google_vertex_ai", "models"),
    );
    assert_eq!(
        reqwest::Url::parse(&vertex.request.unwrap().url)
            .unwrap()
            .host_str(),
        Some("us-central1-aiplatform.googleapis.com")
    );

    let huggingface = execution(
        adapter("huggingface", "repositories"),
        context(""),
        metadata("huggingface", "repositories"),
    );
    let huggingface_url = reqwest::Url::parse(&huggingface.request.unwrap().url).unwrap();
    let query = huggingface_url.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(
        query.get("author").map(|value| value.as_ref()),
        Some("writer")
    );
    assert_eq!(query.get("limit").map(|value| value.as_ref()), Some("100"));
}

#[test]
fn continuation_urls_cannot_escape_the_provider_origin() {
    let error = adapter("azure_openai", "deployments")
        .plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(adapter("azure_openai", "deployments").compiled_plan()),
                context: Some(context("https://attacker.example/next")),
            }),
            metadata: Some(metadata("azure_openai", "deployments")),
        })
        .unwrap_err();
    assert_eq!(error, SourceExecutionError::EgressDenied);
}

#[test]
fn gemini_decode_emits_tenant_scoped_records_and_a_valid_cursor() {
    let adapter = adapter("google_gemini", "model_catalog");
    let plan = adapter.compiled_plan();
    let context = context("");
    let metadata = metadata("google_gemini", "model_catalog");
    let execution = execution(adapter, context.clone(), metadata.clone());
    let planned = execution.request.as_ref().unwrap();
    let body = br#"{"models":[{"name":"models/gemini-2.5-pro","displayName":"Gemini 2.5 Pro"}],"nextPageToken":"page-2"}"#;
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
    assert_eq!(result.next_cursor, "page-2");
    assert_eq!(result.records.len(), 1);
    let record = &result.records[0];
    assert_eq!(record.provider_id, "models/gemini-2.5-pro");
    assert_eq!(record.attributes["tenant_id"], "tenant");
    assert_eq!(
        record.attributes["resource_urn"],
        "urn:cerebro:tenant:google_gemini_model_catalog:models%2Fgemini-2.5-pro"
    );
    adapter
        .validate_record_identity_v2(&context, record, &metadata)
        .unwrap();
}

#[test]
fn provider_payloads_cannot_supply_tenant_or_credential_material() {
    let adapter = adapter("google_gemini", "model_catalog");
    for body in [
        br#"{"models":[{"name":"model-1","tenant_id":"other"}]}"#.as_slice(),
        br#"{"models":[{"name":"model-1","apiKey":"secret"}]}"#.as_slice(),
    ] {
        let error = super::normalize::normalize_records(
            adapter.source,
            adapter.family,
            "tenant",
            body,
            OBSERVED_AT_MILLIS,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            SourceExecutionError::TenantMismatch | SourceExecutionError::InvalidProviderRecord
        ));
    }
}
