use std::collections::HashMap;

use serde_json::{Value, json};

use crate::source_execution::{
    SourceExecutionAdapter, SourceExecutionDispatcher, SourceExecutionError,
    SourceExecutionLifecycleEnvelopeV2, SourceExecutionLifecycleRequestV1, SourceExecutionPlanV1,
    SourceExecutionSelectionRequestV1, SourceWorkerDecodeEnvelopeV2, SourceWorkerDecodeRequestV1,
    SourceWorkerDecodeResultV1, SourceWorkerExecutionContextV1, SourceWorkerHttpExecutionV2,
    SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1, SourceWorkerRuntimeMetadataV2,
    SourceWorkerSafeReceiptV1, response_digest, seal_page_program_v2,
};

use super::{
    AbuseIpDbFamily,
    source_execution::{
        ABUSEIPDB_SOURCE_EXECUTION_ADAPTERS, AbuseIpDbSourceExecutionAdapter, CREDENTIAL_OPERATION,
    },
};

const OBSERVED_AT_MILLIS: i64 = 1_780_272_000_000;
const ORIGIN: &str = "https://api.abuseipdb.com/api/v2";

fn family_adapter(family: AbuseIpDbFamily) -> &'static AbuseIpDbSourceExecutionAdapter {
    ABUSEIPDB_SOURCE_EXECUTION_ADAPTERS
        .iter()
        .find(|adapter| adapter.family_id() == family.as_str())
        .unwrap()
}

fn raw(family: AbuseIpDbFamily) -> Value {
    match family {
        AbuseIpDbFamily::Reports => json!({
            "reportedAt": "2026-06-01T00:00:00Z",
            "reporterId": 43121,
            "comment": "SSH login attempts",
            "categories": [18, 22],
            "reporterCountryCode": "US"
        }),
        AbuseIpDbFamily::IpAddresses => json!({
            "ipAddress": "192.0.2.10",
            "abuseConfidenceScore": 100,
            "countryCode": "US",
            "lastReportedAt": "2026-06-01T00:00:00Z"
        }),
    }
}

fn response(family: AbuseIpDbFamily, records: Vec<Value>, last_page: Option<u64>) -> Vec<u8> {
    let body = match family {
        AbuseIpDbFamily::Reports => json!({
            "data": {
                "results": records,
                "page": 1,
                "perPage": 100,
                "lastPage": last_page.unwrap_or(1)
            }
        }),
        AbuseIpDbFamily::IpAddresses => json!({"data": records}),
    };
    serde_json::to_vec(&body).unwrap()
}

fn context(cursor: &str, page: u32) -> SourceWorkerExecutionContextV1 {
    SourceWorkerExecutionContextV1 {
        tenant_id: "tenant".to_owned(),
        runtime_id: "abuseipdb-runtime".to_owned(),
        logical_page_id: format!("source-page-v2:abuseipdb-{page}"),
        prior_cursor: cursor.to_owned(),
        runtime_generation: 7,
        lease_generation: 11,
        observed_at_unix_millis: OBSERVED_AT_MILLIS,
    }
}

/// The host forwards every declared AbuseIPDB selector regardless of family;
/// the bridge must read only the selectors that belong to the selected family.
fn family_metadata(family: AbuseIpDbFamily) -> SourceWorkerRuntimeMetadataV2 {
    SourceWorkerRuntimeMetadataV2 {
        public_config: HashMap::from([
            ("family".to_owned(), family.as_str().to_owned()),
            ("ip_address".to_owned(), "192.0.2.10".to_owned()),
            ("max_age_in_days".to_owned(), "30".to_owned()),
            ("confidence_minimum".to_owned(), "90".to_owned()),
            ("ip_version".to_owned(), "4".to_owned()),
        ]),
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    }
}

fn plan_page(
    adapter: &AbuseIpDbSourceExecutionAdapter,
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
    adapter: &AbuseIpDbSourceExecutionAdapter,
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
    adapter: &AbuseIpDbSourceExecutionAdapter,
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
fn abuseipdb_plans_both_families_without_credentials() {
    for (family, cursor, page, expected_url) in [
        (
            AbuseIpDbFamily::Reports,
            "2",
            2,
            "https://api.abuseipdb.com/api/v2/reports?ipAddress=192.0.2.10&maxAgeInDays=30&perPage=100&page=2",
        ),
        (
            AbuseIpDbFamily::IpAddresses,
            "",
            1,
            "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&ipVersion=4&limit=10000",
        ),
    ] {
        let adapter = family_adapter(family);
        let plan = adapter.compiled_plan();
        assert_eq!(plan.source_id, "abuseipdb");
        assert_eq!(plan.family_id, family.as_str());
        assert_eq!(plan.provider_kernel, family.event_kind());
        assert_eq!(plan.origin, ORIGIN);
        assert_eq!(plan.path, format!("/api/v2{}", family.path()));
        assert_eq!(plan.event_kind, family.event_kind());
        assert_eq!(plan.schema_ref, family.schema_ref());
        assert_eq!(plan.max_response_bytes, 8 << 20);

        let context = context(cursor, page);
        let metadata = family_metadata(family);
        let execution = plan_page(adapter, &plan, &context, &metadata);
        assert_eq!(execution.credential_operation, CREDENTIAL_OPERATION);
        assert_eq!(execution.credential_operation, "abuseipdb.key");
        assert_eq!(execution.allowed_origin, ORIGIN);
        assert!(execution.body.is_empty());
        assert!(execution.declared_headers.is_empty());
        let request = execution.request.unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.accept, "application/json");
        assert_eq!(request.url, expected_url);
        for secret_marker in ["authorization", "bearer", "token", "secret", "key="] {
            assert!(!request.url.to_ascii_lowercase().contains(secret_marker));
        }
    }
}

#[test]
fn abuseipdb_decodes_both_families_with_exact_contract_and_seals() {
    for family in AbuseIpDbFamily::ALL {
        let adapter = family_adapter(family);
        let plan = adapter.compiled_plan();
        let context = context("", 1);
        let metadata = family_metadata(family);
        let execution = plan_page(adapter, &plan, &context, &metadata);
        let body = response(family, vec![raw(family)], None);
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
        assert_eq!(record.attributes["resource_id"], "192.0.2.10");
        assert!(record.event_id.starts_with("abuseipdb-tenant-"));
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
fn abuseipdb_pagination_and_provider_failures_are_typed() {
    let family = AbuseIpDbFamily::Reports;
    let adapter = family_adapter(family);
    let plan = adapter.compiled_plan();
    let context = context("", 1);
    let metadata = family_metadata(family);
    let body = response(family, vec![raw(family)], Some(2));
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
    assert_eq!(result.next_cursor, "2");

    let family = AbuseIpDbFamily::IpAddresses;
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
fn abuseipdb_rejects_bad_scope_cursor_filters_duplicates_and_secret_material() {
    let family = AbuseIpDbFamily::Reports;
    let adapter = family_adapter(family);
    let plan = adapter.compiled_plan();
    let metadata = family_metadata(family);
    assert_eq!(
        plan_error(adapter, &plan, &context("0", 2), &metadata),
        SourceExecutionError::InvalidCursor
    );
    assert_eq!(
        plan_error(
            family_adapter(AbuseIpDbFamily::IpAddresses),
            &family_adapter(AbuseIpDbFamily::IpAddresses).compiled_plan(),
            &context("2", 2),
            &family_metadata(AbuseIpDbFamily::IpAddresses),
        ),
        SourceExecutionError::InvalidCursor
    );

    let mut missing_ip = metadata.clone();
    missing_ip.public_config.remove("ip_address");
    assert_eq!(
        plan_error(adapter, &plan, &context("", 1), &missing_ip),
        SourceExecutionError::MissingConfiguration
    );
    let mut bad_age = metadata.clone();
    bad_age
        .public_config
        .insert("max_age_in_days".to_owned(), "soon".to_owned());
    assert_eq!(
        plan_error(adapter, &plan, &context("", 1), &bad_age),
        SourceExecutionError::MissingConfiguration
    );
    let mut wrong_family = metadata.clone();
    wrong_family
        .public_config
        .insert("family".to_owned(), "ip_addresses".to_owned());
    assert_eq!(
        plan_error(adapter, &plan, &context("", 1), &wrong_family),
        SourceExecutionError::MissingConfiguration
    );

    let execution_context = context("", 1);
    let original = raw(family);
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
    conflicting["comment"] = Value::from("different");
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

    let mut secret = original.clone();
    secret["nested"] = json!({"api_key": "credential-material"});
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

    let mut foreign_ip = raw(family);
    foreign_ip["ipAddress"] = Value::from("198.51.100.7");
    let foreign_ip_body = response(family, vec![foreign_ip], None);
    assert_eq!(
        decode_page(
            adapter,
            &plan,
            &execution_context,
            &metadata,
            200,
            &foreign_ip_body,
            HashMap::new(),
        ),
        Err(SourceExecutionError::InvalidProviderRecord)
    );
}

#[test]
fn closed_dispatcher_registers_exactly_the_abuseipdb_families() {
    let dispatcher = SourceExecutionDispatcher;
    assert_eq!(ABUSEIPDB_SOURCE_EXECUTION_ADAPTERS.len(), 2);
    assert_eq!(
        ABUSEIPDB_SOURCE_EXECUTION_ADAPTERS.len(),
        AbuseIpDbFamily::ALL.len()
    );
    for adapter in &ABUSEIPDB_SOURCE_EXECUTION_ADAPTERS {
        let compiled = dispatcher
            .compile_plan(&SourceExecutionSelectionRequestV1 {
                source_id: "abuseipdb".to_owned(),
                family_id: adapter.family_id().to_owned(),
            })
            .unwrap();
        assert_eq!(compiled, adapter.compiled_plan());
        assert_eq!(compiled.source_id, "abuseipdb");
        assert_eq!(compiled.family_id, adapter.family_id());
        assert_eq!(compiled.provider_kernel, adapter.provider_kernel());
        let registered = dispatcher.adapter_for(&compiled).unwrap();
        assert_eq!(
            (
                registered.source_id(),
                registered.family_id(),
                registered.provider_kernel()
            ),
            (
                adapter.source_id(),
                adapter.family_id(),
                adapter.provider_kernel()
            )
        );
    }
    for family in ["", "future"] {
        assert_eq!(
            dispatcher.compile_plan(&SourceExecutionSelectionRequestV1 {
                source_id: "abuseipdb".to_owned(),
                family_id: family.to_owned(),
            }),
            Err(SourceExecutionError::UnknownAdapter)
        );
    }
}
