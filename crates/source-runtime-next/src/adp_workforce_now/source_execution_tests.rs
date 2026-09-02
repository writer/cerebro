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
    AdpFamily,
    source_execution::{ADP_WORKFORCE_NOW_SOURCE_EXECUTION_ADAPTERS, AdpSourceExecutionAdapter},
};

const OBSERVED_AT_MILLIS: i64 = 1_780_272_000_000;
const ORIGIN: &str = "https://api.adp.com";

#[derive(Deserialize)]
struct GoOracleEvent {
    payload: Value,
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn family_adapter(family: AdpFamily) -> &'static AdpSourceExecutionAdapter {
    ADP_WORKFORCE_NOW_SOURCE_EXECUTION_ADAPTERS
        .iter()
        .find(|adapter| adapter.family_id() == family.as_str())
        .unwrap()
}

/// The Go oracle payload carries the normalized `schema_ref`, `source_id`,
/// `tenant_id`, and (for events) `actor` fields that the kernel adds itself;
/// strip them back to the raw provider record shape.
fn fixture(family: AdpFamily) -> Value {
    let bytes = fs::read(root().join(format!(
        "sources/adp_workforce_now/testdata/read_{}.json",
        family.as_str()
    )))
    .unwrap();
    let mut payload = serde_json::from_slice::<Vec<GoOracleEvent>>(&bytes)
        .unwrap()
        .pop()
        .unwrap()
        .payload;
    let values = payload.as_object_mut().unwrap();
    for key in ["schema_ref", "source_id", "tenant_id"] {
        values.remove(key);
    }
    if family == AdpFamily::EventNotifications {
        values.remove("actor");
    }
    payload
}

fn response(family: AdpFamily, records: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec(&json!({family.response_key(): records})).unwrap()
}

fn context(cursor: &str, page: u32) -> SourceWorkerExecutionContextV1 {
    SourceWorkerExecutionContextV1 {
        tenant_id: "tenant".to_owned(),
        runtime_id: "adp-workforce-now-runtime".to_owned(),
        logical_page_id: format!("source-page-v2:adp-workforce-now-{page}"),
        prior_cursor: cursor.to_owned(),
        runtime_generation: 7,
        lease_generation: 11,
        observed_at_unix_millis: OBSERVED_AT_MILLIS,
    }
}

fn family_metadata(family: AdpFamily) -> SourceWorkerRuntimeMetadataV2 {
    SourceWorkerRuntimeMetadataV2 {
        public_config: HashMap::from([("family".to_owned(), family.as_str().to_owned())]),
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    }
}

fn plan_page(
    adapter: &AdpSourceExecutionAdapter,
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
    adapter: &AdpSourceExecutionAdapter,
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
    adapter: &AdpSourceExecutionAdapter,
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
fn adp_workforce_now_plans_both_families_without_credentials() {
    for (family, cursor, page, expected_url) in [
        (
            AdpFamily::EventNotifications,
            "",
            1,
            "https://api.adp.com/core/v1/event-notification-messages",
        ),
        (
            AdpFamily::Users,
            "",
            1,
            "https://api.adp.com/hr/v2/workers?%24top=100&%24skip=0",
        ),
        (
            AdpFamily::Users,
            "100",
            2,
            "https://api.adp.com/hr/v2/workers?%24top=100&%24skip=100",
        ),
    ] {
        let adapter = family_adapter(family);
        let plan = adapter.compiled_plan();
        assert_eq!(plan.source_id, "adp_workforce_now");
        assert_eq!(plan.family_id, family.as_str());
        assert_eq!(plan.provider_kernel, family.event_kind());
        assert_eq!(plan.origin, ORIGIN);
        assert_eq!(plan.path, family.path());
        assert_eq!(plan.id_field, family.id_field());
        assert_eq!(plan.event_kind, family.event_kind());
        assert_eq!(plan.schema_ref, family.schema_ref());
        assert_eq!(plan.max_response_bytes, 8 << 20);

        let context = context(cursor, page);
        let metadata = family_metadata(family);
        let execution = plan_page(adapter, &plan, &context, &metadata);
        assert_eq!(execution.credential_operation, "source.bearer");
        assert_eq!(execution.allowed_origin, ORIGIN);
        assert!(execution.body.is_empty());
        assert!(execution.declared_headers.is_empty());
        let request = execution.request.unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.accept, "application/json");
        assert_eq!(request.url, expected_url);
        for secret_marker in ["authorization", "bearer", "token", "secret"] {
            assert!(!request.url.to_ascii_lowercase().contains(secret_marker));
        }
    }
}

#[test]
fn adp_workforce_now_decodes_both_families_with_exact_contract_and_seals() {
    for family in AdpFamily::ALL {
        let adapter = family_adapter(family);
        let plan = adapter.compiled_plan();
        let context = context("", 1);
        let metadata = family_metadata(family);
        let execution = plan_page(adapter, &plan, &context, &metadata);
        let body = response(family, vec![fixture(family)]);
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
        assert_eq!(record.attributes["resource_id"], "G3GMA28TB2SVJ2TF");
        assert!(record.event_id.starts_with("adp-workforce-now-tenant-"));
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
fn adp_workforce_now_pagination_and_provider_failures_are_typed() {
    let family = AdpFamily::Users;
    let adapter = family_adapter(family);
    let plan = adapter.compiled_plan();
    let context = context("", 1);
    let metadata = family_metadata(family);
    let full_page = (1..=100)
        .map(|number| {
            json!({
                "associateOID": format!("worker-{number}"),
                "person": {"legalName": {"formattedName": format!("Worker {number}")}},
                "workerDates": {"originalHireDate": "2026-07-01"}
            })
        })
        .collect();
    let result = decode_page(
        adapter,
        &plan,
        &context,
        &metadata,
        200,
        &response(family, full_page),
        HashMap::new(),
    )
    .unwrap();
    assert_eq!(result.records.len(), 100);
    assert_eq!(result.next_cursor, "100");

    let family = AdpFamily::EventNotifications;
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
                &context,
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
            &context,
            &metadata,
            429,
            b"{}",
            HashMap::from([("retry-after".to_owned(), "60".to_owned())]),
        ),
        Err(SourceExecutionError::ProviderRateLimit)
    );
}

#[test]
fn adp_workforce_now_rejects_bad_scope_cursor_duplicates_and_secret_material() {
    let family = AdpFamily::Users;
    let adapter = family_adapter(family);
    let plan = adapter.compiled_plan();
    let metadata = family_metadata(family);
    for cursor in ["next", "-1", "10000001"] {
        assert_eq!(
            plan_error(adapter, &plan, &context(cursor, 2), &metadata),
            SourceExecutionError::InvalidCursor
        );
    }
    let events = family_adapter(AdpFamily::EventNotifications);
    assert_eq!(
        plan_error(
            events,
            &events.compiled_plan(),
            &context("100", 2),
            &family_metadata(AdpFamily::EventNotifications),
        ),
        SourceExecutionError::InvalidCursor
    );

    let mut wrong_family = metadata.clone();
    wrong_family
        .public_config
        .insert("family".to_owned(), "event_notifications".to_owned());
    assert_eq!(
        plan_error(adapter, &plan, &context("", 1), &wrong_family),
        SourceExecutionError::MissingConfiguration
    );
    let mut foreign_origin = metadata.clone();
    foreign_origin
        .public_config
        .insert("base_url".to_owned(), "https://other.adp.com".to_owned());
    assert_eq!(
        plan_error(adapter, &plan, &context("", 1), &foreign_origin),
        SourceExecutionError::MissingConfiguration
    );

    let execution_context = context("", 1);
    let original = fixture(family);
    let duplicate_body = response(family, vec![original.clone(), original.clone()]);
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
    conflicting["workerID"] = json!({"idValue": "different"});
    let conflicting_body = response(family, vec![original.clone(), conflicting]);
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

    let mut secret = original.clone();
    secret["nested"] = json!({"client_secret": "credential-material"});
    let secret_body = response(family, vec![secret]);
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

    let mut untrusted_scope = original;
    untrusted_scope["nested"] = json!({"tenant_id": "untrusted-tenant"});
    let untrusted_scope_body = response(family, vec![untrusted_scope]);
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
fn adapter_set_covers_exactly_the_adp_workforce_now_families() {
    assert_eq!(
        ADP_WORKFORCE_NOW_SOURCE_EXECUTION_ADAPTERS.len(),
        AdpFamily::ALL.len()
    );
    for (adapter, family) in ADP_WORKFORCE_NOW_SOURCE_EXECUTION_ADAPTERS
        .iter()
        .zip(AdpFamily::ALL)
    {
        let compiled = adapter.compiled_plan();
        assert_eq!(compiled.source_id, "adp_workforce_now");
        assert_eq!(compiled.family_id, family.as_str());
        assert_eq!(compiled.provider_kernel, family.event_kind());
        assert_eq!(
            (
                adapter.source_id(),
                adapter.family_id(),
                adapter.provider_kernel()
            ),
            ("adp_workforce_now", family.as_str(), family.event_kind())
        );
    }
}
