use std::{collections::HashMap, fs, path::PathBuf};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::source_execution::{
    SourceExecutionAdapter, SourceExecutionError, SourceExecutionLifecycleEnvelopeV2,
    SourceExecutionLifecycleRequestV1, SourceExecutionPlanV1, SourceWorkerDecodeEnvelopeV2,
    SourceWorkerDecodeRequestV1, SourceWorkerDecodeResultV1, SourceWorkerExecutionContextV1,
    SourceWorkerHttpExecutionV2, SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1,
    SourceWorkerRuntimeMetadataV2, SourceWorkerSafeReceiptV1, response_digest,
    seal_page_program_v2,
};

use super::{
    AcunetixFamily,
    source_execution::{
        ACUNETIX_SOURCE_EXECUTION_ADAPTERS, AcunetixSourceExecutionAdapter, CREDENTIAL_OPERATION,
    },
};

const OBSERVED_AT_MILLIS: i64 = 1_780_272_000_000;
const ORIGIN: &str = "https://scanner.example.test/api/v1";

#[derive(Deserialize)]
struct GoOracleEvent {
    payload: Value,
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn family_adapter(family: AcunetixFamily) -> &'static AcunetixSourceExecutionAdapter {
    ACUNETIX_SOURCE_EXECUTION_ADAPTERS
        .iter()
        .find(|adapter| adapter.family_id() == family.as_str())
        .unwrap()
}

fn fixture(family: AcunetixFamily) -> Value {
    let bytes = fs::read(root().join(format!(
        "sources/acunetix/testdata/read_{}.json",
        family.as_str()
    )))
    .unwrap();
    serde_json::from_slice::<Vec<GoOracleEvent>>(&bytes)
        .unwrap()
        .pop()
        .unwrap()
        .payload
}

fn response(family: AcunetixFamily, records: Vec<Value>, cursor: Option<&str>) -> Vec<u8> {
    let mut response = json!({family.response_key(): records});
    if let Some(cursor) = cursor {
        response["pagination"] = json!({"next_cursor": cursor});
    }
    serde_json::to_vec(&response).unwrap()
}

fn context(cursor: &str, page: u32) -> SourceWorkerExecutionContextV1 {
    SourceWorkerExecutionContextV1 {
        tenant_id: "tenant".to_owned(),
        runtime_id: "acunetix-runtime".to_owned(),
        logical_page_id: format!("source-page-v2:acunetix-{page}"),
        prior_cursor: cursor.to_owned(),
        runtime_generation: 7,
        lease_generation: 11,
        observed_at_unix_millis: OBSERVED_AT_MILLIS,
    }
}

fn family_metadata(family: AcunetixFamily) -> SourceWorkerRuntimeMetadataV2 {
    SourceWorkerRuntimeMetadataV2 {
        public_config: HashMap::from([
            ("family".to_owned(), family.as_str().to_owned()),
            ("base_url".to_owned(), ORIGIN.to_owned()),
        ]),
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    }
}

fn plan_page(
    adapter: &AcunetixSourceExecutionAdapter,
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

fn plan_error(
    adapter: &AcunetixSourceExecutionAdapter,
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    metadata: &SourceWorkerRuntimeMetadataV2,
) -> SourceExecutionError {
    adapter
        .plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(plan.clone()),
                context: Some(context.clone()),
            }),
            metadata: Some(metadata.clone()),
        })
        .unwrap_err()
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
    adapter: &AcunetixSourceExecutionAdapter,
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    metadata: &SourceWorkerRuntimeMetadataV2,
    status_code: u32,
    body: &[u8],
    response_headers: HashMap<String, String>,
) -> Result<SourceWorkerDecodeResultV1, SourceExecutionError> {
    let execution = plan_page(adapter, plan, context, metadata);
    let safe_receipt = receipt(plan, context, &execution, status_code, body);
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
        response_headers,
        response_headers_sha256: String::new(),
        execution_intent_digest_sha256: execution.execution_intent_digest_sha256.clone(),
    })
}

#[test]
fn acunetix_plans_all_five_families_without_credentials() {
    for family in AcunetixFamily::ALL {
        let adapter = family_adapter(family);
        let plan = adapter.compiled_plan();
        assert_eq!(plan.source_id, "acunetix");
        assert_eq!(plan.family_id, family.as_str());
        assert_eq!(plan.provider_kernel, family.event_kind());
        assert_eq!(plan.origin, "https://{host}/api/v1");
        assert_eq!(plan.path, format!("/api/v1{}", family.path()));
        assert_eq!(
            plan.record_selector,
            format!("$.{}[*]", family.response_key())
        );
        assert_eq!(plan.id_field, family.id_field());
        assert_eq!(plan.event_kind, family.event_kind());
        assert_eq!(plan.schema_ref, family.schema_ref());
        assert_eq!(plan.max_response_bytes, 8 << 20);

        for (cursor, page, expected_query) in [("", 1, "l=100"), ("page-2", 2, "l=100&c=page-2")] {
            let context = context(cursor, page);
            let metadata = family_metadata(family);
            let execution = plan_page(adapter, &plan, &context, &metadata);
            assert_eq!(execution.credential_operation, CREDENTIAL_OPERATION);
            assert_eq!(execution.credential_operation, "acunetix.x_auth");
            assert_eq!(execution.allowed_origin, ORIGIN);
            assert!(execution.body.is_empty());
            assert!(execution.declared_headers.is_empty());
            let request = execution.request.unwrap();
            assert_eq!(request.method, "GET");
            assert_eq!(request.accept, "application/json");
            assert_eq!(request.max_response_bytes, 8 << 20);
            assert_eq!(
                request.url,
                format!("{ORIGIN}{}?{expected_query}", family.path())
            );
            for secret_marker in [
                "authorization",
                "bearer",
                "token",
                "secret",
                "x-auth",
                "x_auth",
            ] {
                assert!(!request.url.to_ascii_lowercase().contains(secret_marker));
            }
        }
    }
}

#[test]
fn acunetix_decodes_every_fixture_with_exact_contract_and_seals() {
    for family in AcunetixFamily::ALL {
        let adapter = family_adapter(family);
        let plan = adapter.compiled_plan();
        let context = context("", 1);
        let metadata = family_metadata(family);
        let execution = plan_page(adapter, &plan, &context, &metadata);
        let body = response(family, vec![fixture(family)], None);
        let safe_receipt = receipt(&plan, &context, &execution, 200, &body);
        let result = decode_page(
            adapter,
            &plan,
            &context,
            &metadata,
            200,
            &body,
            HashMap::new(),
        )
        .unwrap();
        assert!(result.next_cursor.is_empty());
        assert_eq!(result.records.len(), 1);
        let record = &result.records[0];
        assert_eq!(record.attributes["tenant_id"], "tenant");
        assert_eq!(record.attributes["source_event_id"], record.provider_id);
        assert_eq!(record.attributes["source_system"], "acunetix");
        assert_eq!(record.attributes["schema"], family.as_str());
        assert!(record.event_id.starts_with("acunetix-tenant-"));
        for attribute in &plan.required_attributes {
            assert!(
                record
                    .attributes
                    .get(attribute)
                    .is_some_and(|value| !value.is_empty()),
                "{family:?} missing required attribute {attribute}"
            );
        }
        let payload: Value = serde_json::from_slice(&record.payload_json).unwrap();
        for field in &plan.required_payload_fields {
            assert!(
                payload.get(field).is_some_and(|value| !value.is_null()),
                "{family:?} missing required payload field {field}"
            );
        }
        adapter
            .validate_record_identity_v2(&context, record, &metadata)
            .unwrap();
        assert_eq!(
            adapter.validate_record_identity(&context, record),
            Err(SourceExecutionError::MissingConfiguration)
        );

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
fn acunetix_pagination_and_provider_failures_are_typed() {
    let family = AcunetixFamily::Targets;
    let adapter = family_adapter(family);
    let plan = adapter.compiled_plan();
    let metadata = family_metadata(family);
    let first_context = context("", 1);
    let body = response(family, vec![fixture(family)], Some("page-2"));
    let result = decode_page(
        adapter,
        &plan,
        &first_context,
        &metadata,
        200,
        &body,
        HashMap::new(),
    )
    .unwrap();
    assert_eq!(result.next_cursor, "page-2");

    let second_context = context("page-2", 2);
    let terminal = decode_page(
        adapter,
        &plan,
        &second_context,
        &metadata,
        200,
        &response(family, Vec::new(), None),
        HashMap::new(),
    )
    .unwrap();
    assert!(terminal.records.is_empty());
    assert!(terminal.next_cursor.is_empty());

    let family = AcunetixFamily::Vulnerabilities;
    let adapter = family_adapter(family);
    let plan = adapter.compiled_plan();
    let metadata = family_metadata(family);
    for (status, expected) in [
        (401, SourceExecutionError::AuthenticationRejected),
        (403, SourceExecutionError::RequiredProviderScopeMissing),
        (404, SourceExecutionError::UnexpectedProviderStatus),
        (503, SourceExecutionError::UnexpectedProviderStatus),
    ] {
        assert_eq!(
            decode_page(
                adapter,
                &plan,
                &first_context,
                &metadata,
                status,
                b"{}",
                HashMap::new(),
            ),
            Err(expected)
        );
    }
    assert_eq!(
        decode_page(
            adapter,
            &plan,
            &first_context,
            &metadata,
            429,
            b"{}",
            HashMap::from([("retry-after".to_owned(), "60".to_owned())]),
        ),
        Err(SourceExecutionError::ProviderRateLimit)
    );
}

#[test]
fn acunetix_rejects_bad_scope_cursor_config_duplicates_and_secret_material() {
    let family = AcunetixFamily::Targets;
    let adapter = family_adapter(family);
    let plan = adapter.compiled_plan();
    let metadata = family_metadata(family);
    assert_eq!(
        plan_error(adapter, &plan, &context("../escape", 2), &metadata),
        SourceExecutionError::InvalidCursor
    );

    let mut wrong_family = metadata.clone();
    wrong_family
        .public_config
        .insert("family".to_owned(), "scans".to_owned());
    assert_eq!(
        plan_error(adapter, &plan, &context("", 1), &wrong_family),
        SourceExecutionError::MissingConfiguration
    );

    let mut missing_base_url = metadata.clone();
    missing_base_url.public_config.remove("base_url");
    assert_eq!(
        plan_error(adapter, &plan, &context("", 1), &missing_base_url),
        SourceExecutionError::MissingConfiguration
    );

    let mut bad_base_url = metadata.clone();
    bad_base_url.public_config.insert(
        "base_url".to_owned(),
        "http://scanner.example.test/api/v1".to_owned(),
    );
    assert_eq!(
        plan_error(adapter, &plan, &context("", 1), &bad_base_url),
        SourceExecutionError::MissingConfiguration
    );

    let execution_context = context("", 1);
    let original = fixture(family);
    let duplicate_body = response(family, vec![original.clone(), original.clone()], None);
    let result = decode_page(
        adapter,
        &plan,
        &execution_context,
        &metadata,
        200,
        &duplicate_body,
        HashMap::new(),
    )
    .unwrap();
    assert_eq!(result.records.len(), 1);

    let mut conflicting = original.clone();
    conflicting["address"] = Value::from("https://different.example.test");
    let conflicting_body = response(family, vec![original.clone(), conflicting], None);
    assert_eq!(
        decode_page(
            adapter,
            &plan,
            &execution_context,
            &metadata,
            200,
            &conflicting_body,
            HashMap::new(),
        ),
        Err(SourceExecutionError::DuplicateConflict)
    );

    for credential_key in ["x_auth", "X-Auth", "api_key", "token"] {
        let mut secret = original.clone();
        secret["nested"] = json!({credential_key: "credential-material"});
        let secret_body = response(family, vec![secret], None);
        let error = decode_page(
            adapter,
            &plan,
            &execution_context,
            &metadata,
            200,
            &secret_body,
            HashMap::new(),
        )
        .unwrap_err();
        assert_eq!(error, SourceExecutionError::InvalidProviderRecord);
        assert!(!format!("{error:?}").contains("credential-material"));
    }

    let mut untrusted_scope = original;
    untrusted_scope["nested"] = json!({"tenant_id": "untrusted-tenant"});
    let untrusted_scope_body = response(family, vec![untrusted_scope], None);
    assert_eq!(
        decode_page(
            adapter,
            &plan,
            &execution_context,
            &metadata,
            200,
            &untrusted_scope_body,
            HashMap::new(),
        ),
        Err(SourceExecutionError::TenantMismatch)
    );
}

#[test]
fn acunetix_adapter_set_closes_exactly_the_catalog_families() {
    assert_eq!(ACUNETIX_SOURCE_EXECUTION_ADAPTERS.len(), 5);
    assert_eq!(
        ACUNETIX_SOURCE_EXECUTION_ADAPTERS.len(),
        AcunetixFamily::ALL.len()
    );
    for (adapter, family) in ACUNETIX_SOURCE_EXECUTION_ADAPTERS
        .iter()
        .zip(AcunetixFamily::ALL)
    {
        let compiled = adapter.compiled_plan();
        assert_eq!(compiled.source_id, "acunetix");
        assert_eq!(compiled.family_id, family.as_str());
        assert_eq!(compiled.provider_kernel, family.event_kind());
        assert_eq!(
            (
                adapter.source_id(),
                adapter.family_id(),
                adapter.provider_kernel()
            ),
            ("acunetix", family.as_str(), family.event_kind())
        );
        assert_eq!(
            compiled.plan_id,
            format!("source-plan-v1:acunetix:{}", family.as_str())
        );
    }
}
