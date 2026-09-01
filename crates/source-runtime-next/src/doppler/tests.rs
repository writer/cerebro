use std::collections::HashMap;

use prost::Message;
use serde_json::{Value, json};

use crate::source_execution::{
    SourceExecutionDispatcher, SourceExecutionError, SourceExecutionPlanV1,
    SourceExecutionSelectionRequestV1, SourceWorkerDecodeEnvelopeV2, SourceWorkerDecodeOutputV2,
    SourceWorkerDecodeRequestV1, SourceWorkerExecutionContextV1, SourceWorkerHttpExecutionV2,
    SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1, SourceWorkerRuntimeMetadataV2,
};

use super::{
    family::DopplerFamily, origin::DEFAULT_BASE_URL, request::PAGE_SIZE,
    source_execution::DOPPLER_SOURCE_EXECUTION_ADAPTERS, types::DopplerKernel,
};

const OBSERVED_AT_MILLIS: i64 = 1_788_134_400_000;

fn context(tenant: &str, cursor: &str, page: u32) -> SourceWorkerExecutionContextV1 {
    SourceWorkerExecutionContextV1 {
        tenant_id: tenant.to_owned(),
        runtime_id: "doppler-runtime".to_owned(),
        logical_page_id: format!("source-page-v2:doppler-{page}"),
        prior_cursor: cursor.to_owned(),
        runtime_generation: 7,
        lease_generation: 11,
        observed_at_unix_millis: OBSERVED_AT_MILLIS,
    }
}

fn metadata(family: &str) -> SourceWorkerRuntimeMetadataV2 {
    SourceWorkerRuntimeMetadataV2 {
        public_config: HashMap::from([("family".to_owned(), family.to_owned())]),
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    }
}

fn plan(dispatcher: SourceExecutionDispatcher, family: &str) -> SourceExecutionPlanV1 {
    dispatcher
        .compile_plan(&SourceExecutionSelectionRequestV1 {
            source_id: "doppler".to_owned(),
            family_id: family.to_owned(),
        })
        .unwrap()
}

fn plan_page(
    dispatcher: SourceExecutionDispatcher,
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    metadata: &SourceWorkerRuntimeMetadataV2,
) -> Result<SourceWorkerHttpExecutionV2, SourceExecutionError> {
    dispatcher.dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
        request: Some(SourceWorkerPlanRequestV1 {
            plan: Some(plan.clone()),
            context: Some(context.clone()),
        }),
        metadata: Some(metadata.clone()),
    })
}

fn decode_page(
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    metadata: &SourceWorkerRuntimeMetadataV2,
    execution: &SourceWorkerHttpExecutionV2,
    status_code: u32,
    body: &[u8],
    response_headers: HashMap<String, String>,
) -> Result<SourceWorkerDecodeOutputV2, SourceExecutionError> {
    let planned = execution.request.as_ref().unwrap();
    SourceExecutionDispatcher.dispatch_decode_v2(&SourceWorkerDecodeEnvelopeV2 {
        request: Some(SourceWorkerDecodeRequestV1 {
            plan: Some(plan.clone()),
            status_code,
            response_body: body.to_vec(),
            logical_page_id: context.logical_page_id.clone(),
            request_intent_digest: planned.request_intent_digest.clone(),
            receipt: None,
            context: Some(context.clone()),
        }),
        metadata: Some(metadata.clone()),
        response_headers,
        response_headers_sha256: String::new(),
        execution_intent_digest_sha256: execution.execution_intent_digest_sha256.clone(),
    })
}

#[test]
fn closed_dispatcher_registers_exactly_the_three_doppler_families() {
    let dispatcher = SourceExecutionDispatcher;
    assert_eq!(
        DOPPLER_SOURCE_EXECUTION_ADAPTERS.len(),
        DopplerFamily::ALL.len()
    );
    for adapter in &DOPPLER_SOURCE_EXECUTION_ADAPTERS {
        let family = adapter.family();
        let compiled = plan(dispatcher, family.as_str());
        assert_eq!(compiled, adapter.compiled_plan());
        assert_eq!(compiled.source_id, "doppler");
        assert_eq!(compiled.family_id, family.as_str());
        assert_eq!(compiled.provider_kernel, family.event_kind());
        assert_eq!(compiled.origin, DEFAULT_BASE_URL);
        assert_eq!(compiled.method, "GET");
        assert_eq!(compiled.path, family.path());
        assert_eq!(compiled.record_selector, "$.data[*]");
        assert_eq!(compiled.id_field, "id");
        assert_eq!(compiled.max_response_bytes, 8 << 20);
    }
    for family in ["", "future"] {
        assert_eq!(
            dispatcher.compile_plan(&SourceExecutionSelectionRequestV1 {
                source_id: "doppler".to_owned(),
                family_id: family.to_owned(),
            }),
            Err(SourceExecutionError::UnknownAdapter)
        );
    }
}

#[test]
fn planning_is_origin_restricted_bearer_and_credential_free() {
    let dispatcher = SourceExecutionDispatcher;
    for family in DopplerFamily::ALL {
        let plan = plan(dispatcher, family.as_str());
        let context = context("tenant-a", "", 1);
        let metadata = metadata(family.as_str());
        let execution = plan_page(dispatcher, &plan, &context, &metadata).unwrap();
        assert_eq!(execution.allowed_origin, DEFAULT_BASE_URL);
        assert_eq!(execution.credential_operation, "source.bearer");
        assert!(execution.body.is_empty());
        assert!(execution.declared_headers.is_empty());
        let request = execution.request.unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.accept, "application/json");
        assert_eq!(request.max_response_bytes, 8 << 20);
        assert_eq!(
            request.url,
            format!(
                "{}{path}?limit={PAGE_SIZE}",
                DEFAULT_BASE_URL,
                path = family.path()
            )
        );
        assert!(!request.url.contains("token"));

        let kernel = DopplerKernel::new(None, "tenant-a", family, OBSERVED_AT_MILLIS).unwrap();
        let provider_request = kernel.plan(None).unwrap();
        assert_eq!(provider_request.authorization_header(), "Authorization");
        assert_eq!(provider_request.authorization_scheme(), "Bearer");
        assert!(!provider_request.contains_credentials());
        assert!(!provider_request.allows_redirects());
    }

    let plan = plan(dispatcher, "secrets");
    for base_url in [
        "http://api.doppler.com",
        "https://user@api.doppler.com",
        "https://api.doppler.com/other",
        "https://127.0.0.1",
        "https://localhost",
    ] {
        let mut metadata = metadata("secrets");
        metadata
            .public_config
            .insert("base_url".to_owned(), base_url.to_owned());
        assert_eq!(
            plan_page(dispatcher, &plan, &context("tenant-a", "", 1), &metadata),
            Err(SourceExecutionError::MissingConfiguration),
            "{base_url}"
        );
    }
}

#[test]
fn all_families_decode_to_the_exact_catalog_event_contract() {
    let dispatcher = SourceExecutionDispatcher;
    let fixtures = [
        (
            DopplerFamily::Secrets,
            json!({"data":[{
                "id":"secret-1","name":"DATABASE_URL","status":"active","type":"env_var",
                "project":{"id":"project-1"},"updated_at":"2026-08-31T00:00:00Z"
            }]}),
        ),
        (
            DopplerFamily::Projects,
            json!({"data":[{
                "id":"project-1","name":"Backend","type":"project",
                "updated_at":"2026-08-31T00:00:00Z"
            }]}),
        ),
        (
            DopplerFamily::AuditEvents,
            json!({"data":[{
                "id":"event-1","event_type":"secret.read",
                "actor":{"id":"user-1","email":"operator@example.test","name":"Operator"},
                "target":{"id":"secret-1","name":"DATABASE_URL","type":"secret"},
                "created_at":"2026-08-31T00:00:00Z"
            }]}),
        ),
    ];
    for (family, fixture) in fixtures {
        let plan = plan(dispatcher, family.as_str());
        let context = context("tenant-a", "", 1);
        let metadata = metadata(family.as_str());
        let execution = plan_page(dispatcher, &plan, &context, &metadata).unwrap();
        let body = serde_json::to_vec(&fixture).unwrap();
        let output = decode_page(
            &plan,
            &context,
            &metadata,
            &execution,
            200,
            &body,
            HashMap::new(),
        )
        .unwrap();
        assert_eq!(
            output.receipt.as_ref().unwrap().credential_operation,
            "source.bearer"
        );
        let result = output.result.unwrap();
        assert_eq!(result.tenant_id, "tenant-a");
        assert_eq!(result.records.len(), 1);
        let record = &result.records[0];
        assert_eq!(record.attributes["tenant_id"], "tenant-a");
        assert_eq!(record.attributes["source_event_id"], record.provider_id);
        assert!(
            family.required_attributes().iter().all(|attribute| record
                .attributes
                .get(*attribute)
                .is_some_and(|value| !value.is_empty())),
            "{}",
            family.as_str()
        );
        assert!(record.event_id.starts_with("doppler-tenant-a-"));
        let payload: Value = serde_json::from_slice(&record.payload_json).unwrap();
        assert_eq!(payload["id"], fixture["data"][0]["id"]);
        if family == DopplerFamily::Secrets {
            assert_eq!(record.attributes["project_id"], "project-1");
        }
        if family == DopplerFamily::Projects {
            assert_eq!(
                record.attributes["resource_urn"],
                "urn:cerebro:tenant-a:doppler_projects:project-1"
            );
        }
        if family == DopplerFamily::AuditEvents {
            assert_eq!(record.attributes["actor_id"], "user-1");
            assert_eq!(record.attributes["resource_id"], "secret-1");
        }
    }
}

#[test]
fn cursor_round_trips_and_terminal_pages_stop() {
    let dispatcher = SourceExecutionDispatcher;
    let plan = plan(dispatcher, "projects");
    let metadata = metadata("projects");
    let first_context = context("tenant-a", "", 1);
    let first_execution = plan_page(dispatcher, &plan, &first_context, &metadata).unwrap();
    let first = decode_page(
        &plan,
        &first_context,
        &metadata,
        &first_execution,
        200,
        br#"{"data":[{"id":"project-1","name":"One"}],"next_cursor":"opaque /?=cursor"}"#,
        HashMap::new(),
    )
    .unwrap();
    assert_eq!(first.result.unwrap().next_cursor, "opaque /?=cursor");

    let second_context = context("tenant-a", "opaque /?=cursor", 2);
    let second_execution = plan_page(dispatcher, &plan, &second_context, &metadata).unwrap();
    let url = reqwest::Url::parse(&second_execution.request.as_ref().unwrap().url).unwrap();
    let query = url.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(
        query.get("cursor").map(|value| value.as_ref()),
        Some("opaque /?=cursor")
    );
    assert_eq!(query.get("limit").map(|value| value.as_ref()), Some("100"));
    let terminal = decode_page(
        &plan,
        &second_context,
        &metadata,
        &second_execution,
        200,
        br#"{"data":[]}"#,
        HashMap::new(),
    )
    .unwrap();
    assert!(terminal.result.unwrap().next_cursor.is_empty());

    assert_eq!(
        decode_page(
            &plan,
            &second_context,
            &metadata,
            &second_execution,
            200,
            br#"{"data":[],"next_cursor":"opaque /?=cursor"}"#,
            HashMap::new(),
        ),
        Err(SourceExecutionError::InvalidCursor)
    );
    assert_eq!(
        plan_page(
            dispatcher,
            &plan,
            &context("tenant-a", "bad\ncursor", 3),
            &metadata,
        ),
        Err(SourceExecutionError::InvalidCursor)
    );
}

#[test]
fn response_and_record_bounds_fail_closed() {
    let dispatcher = SourceExecutionDispatcher;
    let plan = plan(dispatcher, "projects");
    let context = context("tenant-a", "", 1);
    let metadata = metadata("projects");
    let execution = plan_page(dispatcher, &plan, &context, &metadata).unwrap();
    assert_eq!(
        decode_page(
            &plan,
            &context,
            &metadata,
            &execution,
            200,
            &vec![b' '; (8 << 20) + 1],
            HashMap::new(),
        ),
        Err(SourceExecutionError::ResponseTooLarge)
    );
    let records = (0..=PAGE_SIZE)
        .map(|index| json!({"id":format!("project-{index}"),"name":"Project"}))
        .collect::<Vec<_>>();
    let body = serde_json::to_vec(&json!({"data":records})).unwrap();
    assert_eq!(
        decode_page(
            &plan,
            &context,
            &metadata,
            &execution,
            200,
            &body,
            HashMap::new(),
        ),
        Err(SourceExecutionError::ResultTooLarge)
    );
}

#[test]
fn tenant_identity_is_host_owned_and_duplicate_conflicts_are_rejected() {
    let dispatcher = SourceExecutionDispatcher;
    let plan = plan(dispatcher, "projects");
    let metadata = metadata("projects");
    let context_a = context("tenant-a", "", 1);
    let execution_a = plan_page(dispatcher, &plan, &context_a, &metadata).unwrap();
    assert_eq!(
        decode_page(
            &plan,
            &context_a,
            &metadata,
            &execution_a,
            200,
            br#"{"data":[{"id":"project-1","name":"One","tenant_id":"tenant-b"}]}"#,
            HashMap::new(),
        ),
        Err(SourceExecutionError::TenantMismatch)
    );
    assert_eq!(
        decode_page(
            &plan,
            &context_a,
            &metadata,
            &execution_a,
            200,
            br#"{"data":[{"id":"project-1","name":"One"},{"id":"project-1","name":"Two"}]}"#,
            HashMap::new(),
        ),
        Err(SourceExecutionError::DuplicateConflict)
    );
    let exact_duplicate = decode_page(
        &plan,
        &context_a,
        &metadata,
        &execution_a,
        200,
        br#"{"data":[{"id":"project-1","name":"One"},{"id":"project-1","name":"One"}]}"#,
        HashMap::new(),
    )
    .unwrap();
    let first_event_id = exact_duplicate.result.unwrap().records.remove(0).event_id;

    let context_b = context("tenant-b", "", 1);
    let execution_b = plan_page(dispatcher, &plan, &context_b, &metadata).unwrap();
    let tenant_b = decode_page(
        &plan,
        &context_b,
        &metadata,
        &execution_b,
        200,
        br#"{"data":[{"id":"project-1","name":"One"}]}"#,
        HashMap::new(),
    )
    .unwrap();
    assert_ne!(first_event_id, tenant_b.result.unwrap().records[0].event_id);
}

#[test]
fn provider_failures_are_typed_before_response_parsing() {
    let dispatcher = SourceExecutionDispatcher;
    let plan = plan(dispatcher, "audit_events");
    let context = context("tenant-a", "", 1);
    let metadata = metadata("audit_events");
    let execution = plan_page(dispatcher, &plan, &context, &metadata).unwrap();
    for (status, expected) in [
        (401, SourceExecutionError::AuthenticationRejected),
        (403, SourceExecutionError::RequiredProviderScopeMissing),
        (408, SourceExecutionError::ProviderTimeout),
        (429, SourceExecutionError::ProviderRateLimit),
        (503, SourceExecutionError::UnexpectedProviderStatus),
        (418, SourceExecutionError::UnexpectedProviderStatus),
    ] {
        let headers = if status == 429 {
            HashMap::from([("retry-after".to_owned(), "30".to_owned())])
        } else {
            HashMap::new()
        };
        assert_eq!(
            decode_page(
                &plan,
                &context,
                &metadata,
                &execution,
                status,
                b"provider body must not enter the error",
                headers,
            ),
            Err(expected),
            "{status}"
        );
    }
}

#[test]
fn credential_and_secret_values_never_cross_the_kernel_output() {
    let dispatcher = SourceExecutionDispatcher;
    let plan = plan(dispatcher, "secrets");
    let context = context("tenant-a", "", 1);
    let runtime_metadata = metadata("secrets");
    let execution = plan_page(dispatcher, &plan, &context, &runtime_metadata).unwrap();
    let output = decode_page(
        &plan,
        &context,
        &runtime_metadata,
        &execution,
        200,
        br#"{"data":[{"id":"secret-1","name":"DATABASE_URL","value":"credential-value-needle","token":"provider-token-needle","nested":{"password":"password-needle"}}]}"#,
        HashMap::new(),
    )
    .unwrap();
    let encoded = output.encode_to_vec();
    for needle in [
        b"credential-value-needle".as_slice(),
        b"provider-token-needle".as_slice(),
        b"password-needle".as_slice(),
    ] {
        assert!(!encoded.windows(needle.len()).any(|window| window == needle));
    }

    let mut unsafe_metadata = metadata("secrets");
    unsafe_metadata
        .public_config
        .insert("token".to_owned(), "host-credential-needle".to_owned());
    assert_eq!(
        plan_page(dispatcher, &plan, &context, &unsafe_metadata),
        Err(SourceExecutionError::InvalidExecutionContext)
    );
}

#[test]
fn malformed_or_incomplete_provider_records_fail_closed() {
    let dispatcher = SourceExecutionDispatcher;
    for (family, body, expected) in [
        (
            "projects",
            b"not-json".as_slice(),
            SourceExecutionError::MalformedResponse,
        ),
        (
            "projects",
            br#"{"items":[]}"#.as_slice(),
            SourceExecutionError::MalformedResponse,
        ),
        (
            "projects",
            br#"{"data":[{"name":"missing id"}]}"#.as_slice(),
            SourceExecutionError::MissingStableIdentity,
        ),
        (
            "secrets",
            br#"{"data":[{"id":"secret-1"}]}"#.as_slice(),
            SourceExecutionError::EventContractRejected,
        ),
        (
            "audit_events",
            br#"{"data":[{"id":"event-1","event_type":"read"}]}"#.as_slice(),
            SourceExecutionError::EventContractRejected,
        ),
    ] {
        let plan = plan(dispatcher, family);
        let context = context("tenant-a", "", 1);
        let metadata = metadata(family);
        let execution = plan_page(dispatcher, &plan, &context, &metadata).unwrap();
        assert_eq!(
            decode_page(
                &plan,
                &context,
                &metadata,
                &execution,
                200,
                body,
                HashMap::new(),
            ),
            Err(expected),
            "{family}"
        );
    }
}
