use std::collections::HashMap;

use serde_json::Value;

use crate::source_execution::{
    SourceExecutionAdapter, SourceExecutionError, SourceExecutionLifecycleEnvelopeV2,
    SourceExecutionLifecycleRequestV1, SourceExecutionPlanV1, SourceWorkerDecodeEnvelopeV2,
    SourceWorkerDecodeRequestV1, SourceWorkerExecutionContextV1, SourceWorkerHttpExecutionV2,
    SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1, SourceWorkerRuntimeMetadataV2,
    SourceWorkerSafeReceiptV1, response_digest, seal_page_program_v2, tenant_scoped_event_id,
};

use super::source_execution::{
    AMPLITUDE_SOURCE_EXECUTION_ADAPTERS, AmplitudeSourceExecutionAdapter,
};

const OBSERVED_AT_MILLIS: i64 = 1_780_272_000_000;
const USERS_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/amplitude/testdata/read_users.json"
));
const GROUPS_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/amplitude/testdata/read_groups.json"
));

fn adapter(family: &str) -> &'static AmplitudeSourceExecutionAdapter {
    AMPLITUDE_SOURCE_EXECUTION_ADAPTERS
        .iter()
        .find(|adapter| adapter.family_id() == family)
        .unwrap()
}

fn context(cursor: &str, page: u32) -> SourceWorkerExecutionContextV1 {
    SourceWorkerExecutionContextV1 {
        tenant_id: "tenant-1".to_owned(),
        runtime_id: "amplitude-runtime".to_owned(),
        logical_page_id: format!("source-page-v2:amplitude-{page}"),
        prior_cursor: cursor.to_owned(),
        runtime_generation: 7,
        lease_generation: 11,
        observed_at_unix_millis: OBSERVED_AT_MILLIS,
    }
}

fn metadata(family: &str) -> SourceWorkerRuntimeMetadataV2 {
    SourceWorkerRuntimeMetadataV2 {
        public_config: HashMap::from([
            ("family".to_owned(), family.to_owned()),
            ("per_page".to_owned(), "100".to_owned()),
        ]),
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    }
}

fn plan_page(
    adapter: &AmplitudeSourceExecutionAdapter,
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    metadata: &SourceWorkerRuntimeMetadataV2,
) -> SourceWorkerHttpExecutionV2 {
    adapter
        .plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(plan.clone()),
                context: Some(context.clone()),
            }),
            metadata: Some(metadata.clone()),
        })
        .unwrap()
}

fn receipt(
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    execution: &SourceWorkerHttpExecutionV2,
    status_code: u32,
    body: &[u8],
) -> SourceWorkerSafeReceiptV1 {
    let request = execution.request.as_ref().unwrap();
    SourceWorkerSafeReceiptV1 {
        plan_digest_sha256: plan.plan_digest_sha256.clone(),
        logical_page_id: context.logical_page_id.clone(),
        request_intent_digest: request.request_intent_digest.clone(),
        runtime_generation: context.runtime_generation,
        lease_generation: context.lease_generation,
        credential_operation: execution.credential_operation.clone(),
        status_code,
        response_bytes: body.len() as u64,
        response_sha256: response_digest(body),
        tenant_id: context.tenant_id.clone(),
        runtime_id: context.runtime_id.clone(),
        observed_at_unix_millis: context.observed_at_unix_millis,
    }
}

fn decode_page(
    adapter: &AmplitudeSourceExecutionAdapter,
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    metadata: &SourceWorkerRuntimeMetadataV2,
    execution: &SourceWorkerHttpExecutionV2,
    status_code: u32,
    body: &[u8],
) -> Result<crate::source_execution::SourceWorkerDecodeResultV1, SourceExecutionError> {
    let safe_receipt = receipt(plan, context, execution, status_code, body);
    adapter.decode_v2(&SourceWorkerDecodeEnvelopeV2 {
        request: Some(SourceWorkerDecodeRequestV1 {
            plan: Some(plan.clone()),
            status_code,
            response_body: body.to_vec(),
            logical_page_id: context.logical_page_id.clone(),
            request_intent_digest: execution
                .request
                .as_ref()
                .unwrap()
                .request_intent_digest
                .clone(),
            receipt: Some(safe_receipt),
            context: Some(context.clone()),
        }),
        metadata: Some(metadata.clone()),
        response_headers: HashMap::new(),
        response_headers_sha256: String::new(),
        execution_intent_digest_sha256: execution.execution_intent_digest_sha256.clone(),
    })
}

#[test]
fn amplitude_plans_both_scim_families_without_credentials() {
    for (family, path, kind, schema) in [
        (
            "users",
            "/scim/1/Users",
            "amplitude.users",
            "amplitude/users/v1",
        ),
        (
            "groups",
            "/scim/1/Groups",
            "amplitude.groups",
            "amplitude/groups/v1",
        ),
    ] {
        let adapter = adapter(family);
        let plan = adapter.compiled_plan();
        assert_eq!(plan.plan_id, format!("source-plan-v1:amplitude:{family}"));
        assert_eq!(plan.source_id, "amplitude");
        assert_eq!(plan.family_id, family);
        assert_eq!(plan.provider_kernel, kind);
        assert_eq!(plan.origin, "https://core.amplitude.com");
        assert_eq!(plan.path, path);
        assert_eq!(plan.record_selector, "$.Resources[*]");
        assert_eq!(plan.id_field, "id");
        assert_eq!(plan.event_kind, kind);
        assert_eq!(plan.schema_ref, schema);

        let context = context("101", 2);
        let metadata = metadata(family);
        let execution = plan_page(adapter, &plan, &context, &metadata);
        assert_eq!(execution.credential_operation, "source.bearer");
        assert_eq!(execution.allowed_origin, "https://core.amplitude.com");
        assert!(execution.body.is_empty());
        assert!(execution.declared_headers.is_empty());
        let request = execution.request.unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(
            request.url,
            format!("https://core.amplitude.com{path}?startIndex=101&itemsPerPage=100")
        );
        assert!(!request.url.to_ascii_lowercase().contains("authorization"));
        assert!(!request.url.to_ascii_lowercase().contains("bearer"));
        assert!(!request.url.to_ascii_lowercase().contains("token"));
    }
}

#[test]
fn amplitude_decodes_fixtures_with_tenant_scoped_identity_and_seals() {
    for (family, body, provider_id) in [
        ("users", USERS_FIXTURE, "datamonster@example.com"),
        ("groups", GROUPS_FIXTURE, "632"),
    ] {
        let adapter = adapter(family);
        let plan = adapter.compiled_plan();
        let context = context("", 1);
        let metadata = metadata(family);
        let execution = plan_page(adapter, &plan, &context, &metadata);
        let safe_receipt = receipt(&plan, &context, &execution, 200, body);
        let result =
            decode_page(adapter, &plan, &context, &metadata, &execution, 200, body).unwrap();
        assert!(result.next_cursor.is_empty());
        assert_eq!(result.records.len(), 1);
        let record = &result.records[0];
        assert_eq!(record.provider_id, provider_id);
        assert_eq!(
            record.event_id,
            tenant_scoped_event_id("amplitude", family, "tenant-1", provider_id).unwrap()
        );
        assert_eq!(record.attributes["tenant_id"], "tenant-1");
        assert_eq!(record.attributes["source_event_id"], provider_id);
        assert_eq!(record.attributes["family"], family);
        let payload: Value = serde_json::from_slice(&record.payload_json).unwrap();
        assert_eq!(payload["id"], provider_id);
        adapter.validate_record_identity(&context, record).unwrap();

        let decision = seal_page_program_v2(&SourceExecutionLifecycleEnvelopeV2 {
            request: Some(SourceExecutionLifecycleRequestV1 {
                plan: Some(plan),
                context: Some(context),
                receipt: Some(safe_receipt),
                result: Some(result),
                current_lease_generation: 11,
            }),
            metadata: Some(metadata),
        })
        .unwrap();
        assert_eq!(decision.admitted_records.len(), 1);
        assert!(decision.checkpoint_cursor.is_empty());
    }
}

#[test]
fn amplitude_pagination_and_typed_provider_failures_fail_closed() {
    let adapter = adapter("users");
    let plan = adapter.compiled_plan();
    let execution_context = context("", 1);
    let metadata = metadata("users");
    let execution = plan_page(adapter, &plan, &execution_context, &metadata);
    let mut page: Value = serde_json::from_slice(USERS_FIXTURE).unwrap();
    page["totalResults"] = Value::from(200);
    let body = serde_json::to_vec(&page).unwrap();
    let result = decode_page(
        adapter,
        &plan,
        &execution_context,
        &metadata,
        &execution,
        200,
        &body,
    )
    .unwrap();
    assert_eq!(result.next_cursor, "101");

    for (status, expected) in [
        (401, SourceExecutionError::AuthenticationRejected),
        (403, SourceExecutionError::RequiredProviderScopeMissing),
        (429, SourceExecutionError::ProviderRateLimit),
        (503, SourceExecutionError::UnexpectedProviderStatus),
    ] {
        assert_eq!(
            decode_page(
                adapter,
                &plan,
                &execution_context,
                &metadata,
                &execution,
                status,
                b"{}",
            ),
            Err(expected)
        );
    }

    let bad_context = context("0", 2);
    assert_eq!(
        adapter.plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(plan.clone()),
                context: Some(bad_context),
            }),
            metadata: Some(metadata.clone()),
        }),
        Err(SourceExecutionError::InvalidCursor)
    );

    let mut wrong_family = metadata;
    wrong_family
        .public_config
        .insert("family".to_owned(), "groups".to_owned());
    assert_eq!(
        adapter.plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(plan),
                context: Some(execution_context),
            }),
            metadata: Some(wrong_family),
        }),
        Err(SourceExecutionError::MissingConfiguration)
    );
}

#[test]
fn amplitude_rejects_duplicate_conflicts_and_scrubs_untrusted_scope_and_credentials() {
    let adapter = adapter("users");
    let plan = adapter.compiled_plan();
    let context = context("", 1);
    let metadata = metadata("users");
    let execution = plan_page(adapter, &plan, &context, &metadata);
    let mut page: Value = serde_json::from_slice(USERS_FIXTURE).unwrap();
    let resource = page["Resources"][0].as_object_mut().unwrap();
    resource.insert("tenant_id".to_owned(), Value::from("foreign-tenant"));
    resource.insert(
        "access_token".to_owned(),
        Value::from("credential-material"),
    );
    resource.insert(
        "nested".to_owned(),
        serde_json::json!({"client_secret": "credential-material"}),
    );
    let body = serde_json::to_vec(&page).unwrap();
    let result = decode_page(adapter, &plan, &context, &metadata, &execution, 200, &body).unwrap();
    let record = &result.records[0];
    assert_eq!(record.attributes["tenant_id"], "tenant-1");
    let payload: Value = serde_json::from_slice(&record.payload_json).unwrap();
    assert!(payload.get("tenant_id").is_none());
    assert!(payload.get("access_token").is_none());
    assert!(payload["nested"].get("client_secret").is_none());
    assert!(!String::from_utf8_lossy(&record.payload_json).contains("credential-material"));

    let first = page["Resources"][0].clone();
    let mut duplicate = first.clone();
    duplicate["displayName"] = Value::from("Conflicting display name");
    page["Resources"] = Value::Array(vec![first, duplicate]);
    page["itemsPerPage"] = Value::from(2);
    page["totalResults"] = Value::from(2);
    let conflicting_body = serde_json::to_vec(&page).unwrap();
    assert_eq!(
        decode_page(
            adapter,
            &plan,
            &context,
            &metadata,
            &execution,
            200,
            &conflicting_body,
        ),
        Err(SourceExecutionError::DuplicateConflict)
    );
}
