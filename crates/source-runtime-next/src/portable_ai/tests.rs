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
        "aws_bedrock" => {
            public_config.insert("region".to_owned(), "us-east-1".to_owned());
            public_config.insert("service".to_owned(), "bedrock".to_owned());
        }
        "azure_openai" => {
            public_config.insert("subscription_id".to_owned(), "sub-1".to_owned());
            public_config.insert("resource_group".to_owned(), "rg-ai".to_owned());
            public_config.insert("account_name".to_owned(), "acct-openai".to_owned());
            public_config.insert("location".to_owned(), "westus".to_owned());
        }
        "cloudflare_workers_ai" => {
            public_config.insert("account_id".to_owned(), "account-1".to_owned());
            public_config.insert("gateway_id".to_owned(), "gateway-1".to_owned());
        }
        "elevenlabs" => {
            public_config.insert(
                "service_account_user_id".to_owned(),
                "service-user-1".to_owned(),
            );
        }
        "fireworks_ai" => {
            public_config.insert("account_id".to_owned(), "account-1".to_owned());
        }
        "google_vertex_ai" => {
            public_config.insert("project_id".to_owned(), "project-1".to_owned());
            public_config.insert("location".to_owned(), "us-central1".to_owned());
        }
        "huggingface" => {
            public_config.insert("organization".to_owned(), "writer".to_owned());
        }
        "ibm_watsonx_ai" => {
            public_config.insert("project_id".to_owned(), "project-1".to_owned());
            public_config.insert("region".to_owned(), "us-south".to_owned());
        }
        "langchain" => {
            public_config.insert(
                "base_url".to_owned(),
                "https://api.smith.langchain.com".to_owned(),
            );
            public_config.insert("organization_id".to_owned(), "org-1".to_owned());
            public_config.insert("workspace_id".to_owned(), "workspace-1".to_owned());
        }
        "langfuse" => {
            public_config.insert(
                "base_url".to_owned(),
                "https://cloud.langfuse.com".to_owned(),
            );
            public_config.insert("project_id".to_owned(), "project-1".to_owned());
            if family == "metric" {
                public_config.insert(
                    "metrics_query".to_owned(),
                    r#"{"view":"observations","dimensions":[{"field":"name"}],"metrics":[{"measure":"count","aggregation":"count"}],"fromTimestamp":"2026-08-01T00:00:00Z","toTimestamp":"2026-08-02T00:00:00Z"}"#.to_owned(),
                );
            }
        }
        "microsoft_foundry" => {
            public_config.insert(
                "endpoint".to_owned(),
                "project.services.ai.azure.com".to_owned(),
            );
            public_config.insert("project_name".to_owned(), "project-1".to_owned());
        }
        "qdrant_cloud" => {
            public_config.insert("account_id".to_owned(), "account-1".to_owned());
        }
        "writer" => {
            public_config.insert("base_url".to_owned(), "https://api.writer.com".to_owned());
            if matches!(family, "application_graph" | "application_job") {
                public_config.insert("application_id".to_owned(), "application-1".to_owned());
            }
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
fn embedded_catalog_compiles_all_twenty_five_sources_and_131_families() {
    assert_eq!(SOURCES.len(), 25);
    assert_eq!(PORTABLE_AI_SOURCE_EXECUTION_ADAPTERS.len(), 131);
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
        assert!(!request.url.contains("${config."));
        if request.method == "GET" {
            assert!(execution.body.is_empty());
        }
        assert!(url.query_pairs().all(|(key, _)| !matches!(
            key.as_ref(),
            "api_key" | "apikey" | "access_token" | "client_secret" | "token"
        )));
        let expected_operation = match adapter.source_id() {
            "google_gemini" => "google.api_key_header",
            "elevenlabs" => "elevenlabs.xi_api_key",
            "langchain" => "langsmith.x_api_key",
            "langfuse" => "langfuse.basic",
            "microsoft_foundry" => "microsoft_foundry.api_key",
            "pinecone" => "pinecone.api_key",
            "qdrant_cloud" => "qdrant.api_key",
            "aws_bedrock" => "aws.sigv4",
            _ => "source.bearer",
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
fn langchain_post_headers_body_auth_and_offset_are_deterministic() {
    let run_adapter = adapter("langchain", "run");
    let run_metadata = metadata("langchain", "run");
    let first = execution(run_adapter, context(""), run_metadata.clone());
    assert_eq!(first.credential_operation, "langsmith.x_api_key");
    assert_eq!(
        first
            .declared_headers
            .get("x-organization-id")
            .map(String::as_str),
        Some("org-1")
    );
    assert_eq!(
        first
            .declared_headers
            .get("x-tenant-id")
            .map(String::as_str),
        Some("workspace-1")
    );
    let first_body: serde_json::Value = serde_json::from_slice(&first.body).unwrap();
    assert_eq!(first_body["limit"], 100);
    assert!(first_body.get("cursor").is_none());

    let second = execution(run_adapter, context("cursor-2"), run_metadata.clone());
    let second_body: serde_json::Value = serde_json::from_slice(&second.body).unwrap();
    assert_eq!(second_body["cursor"], "cursor-2");
    let mut bearer_metadata = run_metadata;
    bearer_metadata
        .public_config
        .insert("auth_model".to_owned(), "bearer_token".to_owned());
    assert_eq!(
        execution(run_adapter, context(""), bearer_metadata).credential_operation,
        "source.bearer"
    );

    let project_adapter = adapter("langchain", "project");
    let project = execution(
        project_adapter,
        context(""),
        metadata("langchain", "project"),
    );
    let project_url = reqwest::Url::parse(&project.request.unwrap().url).unwrap();
    let query = project_url.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(query.get("offset").map(|value| value.as_ref()), Some("0"));
    assert_eq!(query.get("limit").map(|value| value.as_ref()), Some("100"));
    let records = (0..100)
        .map(|index| serde_json::json!({"id": format!("project-{index}")}))
        .collect::<Vec<_>>();
    let body = serde_json::to_vec(&records).unwrap();
    assert_eq!(
        project_adapter
            .next_cursor(
                &body,
                &HashMap::new(),
                "https://api.smith.langchain.com",
                "",
            )
            .unwrap(),
        "100"
    );
}

#[test]
fn provider_specific_origins_and_safe_headers_remain_closed() {
    let foundry = execution(
        adapter("microsoft_foundry", "agents"),
        context(""),
        metadata("microsoft_foundry", "agents"),
    );
    assert_eq!(
        foundry.allowed_origin,
        "https://project.services.ai.azure.com/api/projects/project-1"
    );
    assert!(
        foundry
            .request
            .unwrap()
            .url
            .starts_with("https://project.services.ai.azure.com/api/projects/project-1/agents?")
    );

    let pinecone = execution(
        adapter("pinecone", "indexes"),
        context(""),
        metadata("pinecone", "indexes"),
    );
    assert_eq!(
        pinecone
            .declared_headers
            .get("x-pinecone-api-version")
            .map(String::as_str),
        Some("2025-10")
    );
    assert_eq!(pinecone.credential_operation, "pinecone.api_key");

    assert_eq!(
        adapter("stability_ai", "account")
            .compiled_plan()
            .record_selector,
        "$"
    );
}

#[test]
fn writer_path_context_supplies_stable_identity_without_trusting_provider_tenant_data() {
    let graph_adapter = adapter("writer", "application_graph");
    let runtime_metadata = metadata("writer", "application_graph");
    let records = super::normalize::normalize_records(
        graph_adapter.source,
        graph_adapter.family,
        "tenant",
        br#"{"graph_ids":["graph-1","graph-2"]}"#,
        OBSERVED_AT_MILLIS,
        &runtime_metadata.public_config,
    )
    .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].provider_id, "application-1");
    assert_eq!(records[0].attributes["application_id"], "application-1");
    let payload: serde_json::Value = serde_json::from_slice(&records[0].payload_json).unwrap();
    assert_eq!(payload["application_id"], "application-1");
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
            &HashMap::new(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            SourceExecutionError::TenantMismatch | SourceExecutionError::InvalidProviderRecord
        ));
    }
}

#[test]
fn aws_bedrock_and_langfuse_preserve_provider_specific_request_contracts() {
    let aws = execution(
        adapter("aws_bedrock", "foundation_models"),
        context(""),
        metadata("aws_bedrock", "foundation_models"),
    );
    assert_eq!(aws.credential_operation, "aws.sigv4");
    assert_eq!(
        aws.request.unwrap().url,
        "https://bedrock.us-east-1.amazonaws.com/foundation-models"
    );

    let member = execution(
        adapter("langfuse", "project_member"),
        context(""),
        metadata("langfuse", "project_member"),
    );
    assert_eq!(member.credential_operation, "langfuse.basic");
    assert_eq!(
        member.request.unwrap().url,
        "https://cloud.langfuse.com/api/public/projects/project-1/memberships"
    );
}

#[test]
fn langfuse_page_cursor_is_bounded_and_preserves_public_filters() {
    let adapter = adapter("langfuse", "trace");
    let runtime_metadata = metadata("langfuse", "trace");
    let first = execution(adapter, context(""), runtime_metadata.clone());
    let first_url = reqwest::Url::parse(&first.request.unwrap().url).unwrap();
    assert_eq!(
        first_url
            .query_pairs()
            .find(|(key, _)| key == "page")
            .map(|(_, value)| value.into_owned()),
        Some("1".to_owned())
    );
    assert_eq!(
        adapter
            .next_cursor(
                br#"{"meta":{"page":1,"totalPages":2}}"#,
                &HashMap::new(),
                "https://cloud.langfuse.com",
                "",
            )
            .unwrap(),
        "2"
    );
    let second = execution(adapter, context("2"), runtime_metadata);
    let second_url = reqwest::Url::parse(&second.request.unwrap().url).unwrap();
    assert_eq!(
        second_url
            .query_pairs()
            .find(|(key, _)| key == "page")
            .map(|(_, value)| value.into_owned()),
        Some("2".to_owned())
    );
    assert_eq!(
        adapter
            .plan_v2(&SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(adapter.compiled_plan()),
                    context: Some(context("10000001")),
                }),
                metadata: Some(metadata("langfuse", "trace")),
            })
            .unwrap_err(),
        SourceExecutionError::InvalidCursor
    );
}

#[test]
fn langfuse_metric_query_fails_closed_before_request_planning() {
    let adapter = adapter("langfuse", "metric");
    let mut metadata = metadata("langfuse", "metric");
    metadata.public_config.insert(
        "metrics_query".to_owned(),
        r#"{"view":"unknown"}"#.to_owned(),
    );
    assert_eq!(
        adapter
            .plan_v2(&SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(adapter.compiled_plan()),
                    context: Some(context("")),
                }),
                metadata: Some(metadata),
            })
            .unwrap_err(),
        SourceExecutionError::MissingConfiguration
    );
}

#[test]
fn langfuse_alternative_identity_and_public_project_context_normalize_deterministically() {
    let adapter = adapter("langfuse", "project_member");
    let metadata = metadata("langfuse", "project_member");
    let records = super::normalize::normalize_records(
        adapter.source,
        adapter.family,
        "tenant",
        br#"{"memberships":[{"email":"operator@example.com","status":"active"}]}"#,
        OBSERVED_AT_MILLIS,
        &metadata.public_config,
    )
    .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].provider_id, "operator@example.com");
    assert_eq!(records[0].attributes["project_id"], "project-1");
    assert_eq!(records[0].attributes["tenant_id"], "tenant");
}
