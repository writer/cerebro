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
use crate::source_execution::{SourceExecutionDispatcher, SourceExecutionSelectionRequestV1};

use super::{
    AhaFamily,
    source_execution::{AHA_SOURCE_EXECUTION_ADAPTERS, AhaSourceExecutionAdapter},
};

const OBSERVED_AT_MILLIS: i64 = 1_780_272_000_000;

#[derive(Deserialize)]
struct GoOracleEvent {
    payload: Value,
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn adapter(family: AhaFamily) -> &'static AhaSourceExecutionAdapter {
    AHA_SOURCE_EXECUTION_ADAPTERS
        .iter()
        .find(|adapter| adapter.family_id() == family.as_str())
        .unwrap()
}

fn fixture(family: AhaFamily) -> Value {
    let bytes = fs::read(root().join(format!(
        "sources/aha/testdata/read_{}.json",
        family.as_str()
    )))
    .unwrap();
    serde_json::from_slice::<Vec<GoOracleEvent>>(&bytes)
        .unwrap()
        .pop()
        .unwrap()
        .payload
}

fn response(family: AhaFamily, records: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec(&json!({family.response_key(): records})).unwrap()
}

fn context(cursor: &str, page: u32) -> SourceWorkerExecutionContextV1 {
    SourceWorkerExecutionContextV1 {
        tenant_id: "tenant".to_owned(),
        runtime_id: "aha-runtime".to_owned(),
        logical_page_id: format!("source-page-v2:aha-{page}"),
        prior_cursor: cursor.to_owned(),
        runtime_generation: 7,
        lease_generation: 11,
        observed_at_unix_millis: OBSERVED_AT_MILLIS,
    }
}

fn metadata(family: AhaFamily) -> SourceWorkerRuntimeMetadataV2 {
    SourceWorkerRuntimeMetadataV2 {
        public_config: HashMap::from([
            ("family".to_owned(), family.as_str().to_owned()),
            ("base_url".to_owned(), "https://example.aha.io".to_owned()),
            ("product_id".to_owned(), "product-1".to_owned()),
        ]),
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    }
}

fn plan_page(
    adapter: &AhaSourceExecutionAdapter,
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
    adapter: &AhaSourceExecutionAdapter,
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
fn aha_plans_all_five_families_without_credentials() {
    for family in AhaFamily::ALL {
        let adapter = adapter(family);
        let plan = adapter.compiled_plan();
        assert_eq!(plan.source_id, "aha");
        assert_eq!(plan.family_id, family.as_str());
        assert_eq!(plan.provider_kernel, family.event_kind());
        assert_eq!(plan.origin, "https://{account}.aha.io");
        assert_eq!(
            plan.path,
            format!("/api/v1{}", family.path(Some("{product_id}")).unwrap())
        );
        assert_eq!(plan.id_field, family.id_field());
        assert_eq!(plan.event_kind, family.event_kind());
        assert_eq!(plan.schema_ref, family.schema_ref());

        let context = context("", 1);
        let metadata = metadata(family);
        let execution = plan_page(adapter, &plan, &context, &metadata);
        assert_eq!(execution.credential_operation, "source.bearer");
        assert_eq!(execution.allowed_origin, "https://example.aha.io");
        assert!(execution.body.is_empty());
        assert!(execution.declared_headers.is_empty());
        let request = execution.request.unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.accept, "application/json");
        let suffix = family.path(Some("product-1")).unwrap();
        let expected_url = format!("https://example.aha.io/api/v1{suffix}?per_page=100&page=1");
        assert_eq!(request.url, expected_url);
        for secret_marker in ["authorization", "bearer", "token", "secret"] {
            assert!(!request.url.to_ascii_lowercase().contains(secret_marker));
        }
    }
}

#[test]
fn aha_decodes_every_fixture_with_exact_contract_and_seals() {
    for family in AhaFamily::ALL {
        let adapter = adapter(family);
        let plan = adapter.compiled_plan();
        let context = context("", 1);
        let metadata = metadata(family);
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
        .unwrap_or_else(|error| panic!("{family:?}: {error:?}"));
        assert!(result.next_cursor.is_empty());
        assert_eq!(result.records.len(), 1);
        let record = &result.records[0];
        assert_eq!(record.attributes["tenant_id"], "tenant");
        assert_eq!(record.attributes["source_event_id"], record.provider_id);
        assert!(record.event_id.starts_with("aha-tenant-"));
        for attribute in &plan.required_attributes {
            assert!(
                record
                    .attributes
                    .get(attribute)
                    .is_some_and(|value| !value.is_empty())
            );
        }
        let payload: Value = serde_json::from_slice(&record.payload_json).unwrap();
        for field in &plan.required_payload_fields {
            assert!(payload.get(field).is_some_and(|value| !value.is_null()));
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
fn aha_pagination_and_provider_failures_are_typed() {
    let paged_family = AhaFamily::Features;
    let paged_adapter = adapter(paged_family);
    let paged_plan = paged_adapter.compiled_plan();
    let paged_context = context("", 1);
    let paged_metadata = metadata(paged_family);
    let template = fixture(paged_family);
    let body = response(
        paged_family,
        (1..=100)
            .map(|number| {
                let mut record = template.clone();
                record["id"] = Value::String(format!("feature-{number}"));
                record["name"] = Value::String(format!("Feature {number}"));
                record
            })
            .collect(),
    );
    let result = decode_page(
        paged_adapter,
        &paged_plan,
        &paged_context,
        &paged_metadata,
        200,
        &body,
        HashMap::new(),
    )
    .unwrap();
    assert_eq!(result.next_cursor, "2");

    let family = AhaFamily::Users;
    let adapter = adapter(family);
    let plan = adapter.compiled_plan();
    let context = context("", 1);
    let metadata = metadata(family);
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
fn aha_rejects_bad_scope_cursor_duplicates_and_secret_material() {
    let family = AhaFamily::Products;
    let adapter = adapter(family);
    let plan = adapter.compiled_plan();
    let metadata = metadata(family);
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

    let release_adapter = AHA_SOURCE_EXECUTION_ADAPTERS
        .iter()
        .find(|candidate| candidate.family_id() == AhaFamily::Releases.as_str())
        .unwrap();
    let release_plan = release_adapter.compiled_plan();
    let mut missing_product = metadata.clone();
    missing_product
        .public_config
        .insert("family".to_owned(), "releases".to_owned());
    missing_product.public_config.remove("product_id");
    assert_eq!(
        release_adapter.plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(release_plan),
                context: Some(context("", 1)),
            }),
            metadata: Some(missing_product),
        }),
        Err(SourceExecutionError::MissingConfiguration)
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
    conflicting["updated_at"] = Value::from("2026-06-03T00:00:00Z");
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

    let mut secret = original;
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

    let mut untrusted_scope = fixture(family);
    untrusted_scope["nested"] = json!({"runtime_id": "untrusted-runtime"});
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

    let mut wrong_family = metadata;
    wrong_family
        .public_config
        .insert("family".to_owned(), "users".to_owned());
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
fn closed_dispatcher_registers_exactly_the_aha_families() {
    let dispatcher = SourceExecutionDispatcher;
    assert_eq!(AHA_SOURCE_EXECUTION_ADAPTERS.len(), 5);
    for adapter in &AHA_SOURCE_EXECUTION_ADAPTERS {
        let compiled = dispatcher
            .compile_plan(&SourceExecutionSelectionRequestV1 {
                source_id: "aha".to_owned(),
                family_id: adapter.family_id().to_owned(),
            })
            .unwrap();
        assert_eq!(compiled, adapter.compiled_plan());
        assert_eq!(compiled.source_id, "aha");
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
                source_id: "aha".to_owned(),
                family_id: family.to_owned(),
            }),
            Err(SourceExecutionError::UnknownAdapter)
        );
    }
}
