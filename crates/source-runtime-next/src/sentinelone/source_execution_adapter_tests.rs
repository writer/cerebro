use prost::Message;
use serde_json::Value;

use crate::source_execution::{SourceWorkerSafeReceiptV1, response_digest};

use super::*;

const AGENT_PAGE: &[u8] = include_bytes!("fixtures/agent_page.json");
const GO_PARITY: &str = include_str!("fixtures/agent_go_parity.json");

fn context(cursor: &str) -> SourceWorkerExecutionContextV1 {
    SourceWorkerExecutionContextV1 {
        tenant_id: "sentinelone.example.test".to_owned(),
        runtime_id: "sentinelone-agent-runtime".to_owned(),
        logical_page_id: "agent-page-1".to_owned(),
        prior_cursor: cursor.to_owned(),
        runtime_generation: 7,
        lease_generation: 11,
        observed_at_unix_millis: 1_776_906_123_456,
    }
}

fn exact_plan() -> SourceExecutionPlanV1 {
    let mut plan = SourceExecutionPlanV1 {
        plan_id: PLAN_ID.to_owned(),
        source_id: SOURCE_ID.to_owned(),
        family_id: FAMILY_ID.to_owned(),
        provider_kernel: PROVIDER_KERNEL.to_owned(),
        method: METHOD.to_owned(),
        origin: "https://sentinelone.example.test".to_owned(),
        path: PATH.to_owned(),
        record_selector: RECORD_SELECTOR.to_owned(),
        id_field: ID_FIELD.to_owned(),
        singleton_fallback_id: String::new(),
        max_response_bytes: MAX_RESPONSE_BYTES,
        event_kind: EVENT_KIND.to_owned(),
        schema_ref: SCHEMA_REF.to_owned(),
        required_attributes: vec!["family".to_owned()],
        required_payload_fields: vec!["id".to_owned()],
        plan_digest_sha256: String::new(),
    };
    plan.plan_digest_sha256 = canonical_plan_digest(&plan);
    plan
}

fn receipt(
    body: &[u8],
    execution: &SourceWorkerExecutionContextV1,
    intent: &str,
    status: u32,
) -> SourceWorkerSafeReceiptV1 {
    SourceWorkerSafeReceiptV1 {
        plan_digest_sha256: exact_plan().plan_digest_sha256,
        logical_page_id: execution.logical_page_id.clone(),
        request_intent_digest: intent.to_owned(),
        runtime_generation: execution.runtime_generation,
        lease_generation: execution.lease_generation,
        credential_operation: "sentinelone-api-token-read".to_owned(),
        status_code: status,
        response_bytes: body.len() as u64,
        response_sha256: response_digest(body),
        tenant_id: execution.tenant_id.clone(),
        runtime_id: execution.runtime_id.clone(),
        observed_at_unix_millis: execution.observed_at_unix_millis,
    }
}

fn decode_request(
    body: &[u8],
    execution: SourceWorkerExecutionContextV1,
) -> SourceWorkerDecodeRequestV1 {
    let plan = exact_plan();
    let intent = plan_agent_request(&SourceWorkerPlanRequestV1 {
        plan: Some(plan.clone()),
        context: Some(execution.clone()),
    })
    .unwrap()
    .request_intent_digest;
    SourceWorkerDecodeRequestV1 {
        plan: Some(plan),
        status_code: 200,
        response_body: body.to_vec(),
        logical_page_id: execution.logical_page_id.clone(),
        request_intent_digest: intent.clone(),
        receipt: Some(receipt(body, &execution, &intent, 200)),
        context: Some(execution.clone()),
    }
}

#[test]
fn plans_deterministic_agent_request_without_credentials() {
    let output = plan_agent_request(&SourceWorkerPlanRequestV1 {
        plan: Some(exact_plan()),
        context: Some(context("cursor-A-1")),
    })
    .unwrap();
    assert_eq!(output.method, "GET");
    assert_eq!(
        output.url,
        "https://sentinelone.example.test/web/api/v2.1/agents?limit=200&cursor=cursor-A-1"
    );
    assert_eq!(output.request_intent_digest.len(), 64);
    let first_page = plan_agent_request(&SourceWorkerPlanRequestV1 {
        plan: Some(exact_plan()),
        context: Some(context("")),
    })
    .unwrap();
    assert_ne!(
        output.request_intent_digest,
        first_page.request_intent_digest
    );
    let encoded = output.encode_to_vec();
    for secret_shape in [
        b"ApiToken".as_slice(),
        b"Bearer",
        b"Authorization",
        b"token-value",
    ] {
        assert!(
            !encoded
                .windows(secret_shape.len())
                .any(|window| window == secret_shape)
        );
    }
}

#[test]
fn normalizes_checked_in_agent_fixture_with_go_semantic_parity() {
    let result = decode_agent_response(&decode_request(AGENT_PAGE, context(""))).unwrap();
    assert_eq!(result.next_cursor, "cursor-A-2");
    assert_eq!(result.records.len(), 1, "exact duplicates collapse");
    let record = &result.records[0];
    assert_eq!(record.provider_id, "A-1");
    assert_eq!(
        record.event_id,
        "sentinelone-agent-sentinelone.example.test-A-1"
    );
    assert_eq!(record.occurred_at_unix_millis, 1_776_906_000_000);
    let expected: Value = serde_json::from_str(GO_PARITY).unwrap();
    let attributes = serde_json::to_value(&record.attributes).unwrap();
    assert_eq!(attributes, expected["attributes"]);
    let mut payload: Value = serde_json::from_slice(&record.payload_json).unwrap();
    let raw = payload.as_object_mut().unwrap().remove("raw").unwrap();
    assert_eq!(payload, expected["payload"]);
    assert!(raw.get("tenantId").is_none());
}

#[test]
fn trusted_context_owns_tenant_identity() {
    let result = decode_agent_response(&decode_request(AGENT_PAGE, context(""))).unwrap();
    let record = &result.records[0];
    assert_eq!(record.attributes["tenant_host"], "sentinelone.example.test");
    let payload: Value = serde_json::from_slice(&record.payload_json).unwrap();
    assert_eq!(payload["tenant_host"], "sentinelone.example.test");
    assert_ne!(payload["tenant_host"], "provider-controlled-tenant");
    assert_eq!(result.tenant_id, "sentinelone.example.test");
    assert_eq!(result.runtime_id, "sentinelone-agent-runtime");
    assert_eq!(result.runtime_generation, 7);
    assert_eq!(result.lease_generation, 11);
}

#[test]
fn decode_is_deterministic_for_the_same_receipt() {
    let request = decode_request(AGENT_PAGE, context(""));
    let first = decode_agent_response(&request).unwrap();
    let second = decode_agent_response(&request).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.result_digest_sha256.len(), 64);
    assert!(
        first
            .result_digest_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
}

#[test]
fn adapter_rejects_an_event_identity_outside_trusted_tenant_scope() {
    let result = decode_agent_response(&decode_request(AGENT_PAGE, context(""))).unwrap();
    let mut record = result.records[0].clone();
    record.event_id = "sentinelone-agent-other-tenant-A-1".to_owned();
    assert_eq!(
        SentinelOneAgentSourceExecutionAdapter.validate_record_identity(&context(""), &record),
        Err(SourceExecutionError::TenantMismatch)
    );
}

#[test]
fn conflicting_duplicate_agent_identity_fails_closed() {
    let mut body: Value = serde_json::from_slice(AGENT_PAGE).unwrap();
    body["data"][1]["computerName"] = Value::String("different-host".to_owned());
    let body = serde_json::to_vec(&body).unwrap();
    assert_eq!(
        decode_agent_response(&decode_request(&body, context(""))).unwrap_err(),
        SourceExecutionError::DuplicateConflict
    );
}

#[test]
fn cursor_receipt_tenant_status_and_timestamp_fail_closed() {
    let invalid_cursor = plan_agent_request(&SourceWorkerPlanRequestV1 {
        plan: Some(exact_plan()),
        context: Some(context("bad\ncursor")),
    });
    assert_eq!(
        invalid_cursor.unwrap_err(),
        SourceExecutionError::InvalidCursor
    );

    let mut mismatched = decode_request(AGENT_PAGE, context(""));
    mismatched.context.as_mut().unwrap().lease_generation += 1;
    assert_eq!(
        decode_agent_response(&mismatched).unwrap_err(),
        SourceExecutionError::StaleGeneration
    );

    let mut unsafe_tenant = context("");
    unsafe_tenant.tenant_id = "tenant/other".to_owned();
    assert_eq!(
        plan_agent_request(&SourceWorkerPlanRequestV1 {
            plan: Some(exact_plan()),
            context: Some(unsafe_tenant),
        })
        .unwrap_err(),
        SourceExecutionError::InvalidExecutionContext
    );

    for (status, expected) in [
        (401, SourceExecutionError::AuthenticationRejected),
        (403, SourceExecutionError::RequiredProviderScopeMissing),
        (429, SourceExecutionError::ProviderRateLimit),
        (503, SourceExecutionError::UnexpectedProviderStatus),
    ] {
        let mut request = decode_request(AGENT_PAGE, context(""));
        request.status_code = status;
        request.receipt.as_mut().unwrap().status_code = status;
        assert_eq!(decode_agent_response(&request).unwrap_err(), expected);
    }

    let missing_time = br#"{"data":[{"id":"A-2"}]}"#;
    let fallback = decode_agent_response(&decode_request(missing_time, context(""))).unwrap();
    assert_eq!(
        fallback.records[0].occurred_at_unix_millis,
        context("").observed_at_unix_millis
    );

    let malformed = br#"{"data":"not-an-array"}"#;
    assert_eq!(
        decode_agent_response(&decode_request(malformed, context(""))).unwrap_err(),
        SourceExecutionError::MalformedResponse
    );
}
