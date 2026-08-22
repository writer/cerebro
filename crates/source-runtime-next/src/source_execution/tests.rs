use prost::Message;

use super::{
    canonical_plan_digest,
    contract::{
        AUTHORIZATION_POLICY_FALLBACK_ID, AUTHORIZATION_POLICY_FAMILY, AUTHORIZATION_POLICY_KERNEL,
        AUTHORIZATION_POLICY_KIND, AUTHORIZATION_POLICY_PATH, AUTHORIZATION_POLICY_SCHEMA,
        AZURE_SOURCE_ID, MAX_CURSOR_BYTES, MAX_RESPONSE_BYTES,
    },
    decode,
    error::SourceExecutionError,
    plan, response_digest, tenant_scoped_event_id, validate_and_deduplicate_records,
    validate_cursor, validate_http_request,
    wire::{
        SourceExecutionPlanV1, SourceWorkerDecodeRequestV1, SourceWorkerDecodeResultV1,
        SourceWorkerExecutionContextV1, SourceWorkerHttpRequestV1, SourceWorkerPlanRequestV1,
        SourceWorkerRecordV1, SourceWorkerSafeReceiptV1,
    },
};

const GO_LIVE_TEST_RESPONSE: &[u8] = br#"{
    "id":"authorizationPolicy",
    "allowEmailVerifiedUsersToJoinOrganization":false,
    "allowInvitesFrom":"adminsAndGuestInviters",
    "allowedToSignUpEmailBasedSubscriptions":false,
    "allowedToUseSSPR":true,
    "blockMsolPowerShell":true,
    "defaultUserRolePermissions":{
        "allowedToCreateApps":false,
        "allowedToCreateSecurityGroups":false,
        "allowedToReadBitlockerKeysForOwnedDevice":true,
        "permissionGrantPoliciesAssigned":["ManagePermissionGrantsForSelf.microsoft-user-default-low"]
    }
}"#;

fn exact_plan() -> SourceExecutionPlanV1 {
    let mut plan = SourceExecutionPlanV1 {
        plan_id: "source-plan-v1:azure:authorization_policy".to_owned(),
        source_id: AZURE_SOURCE_ID.to_owned(),
        family_id: AUTHORIZATION_POLICY_FAMILY.to_owned(),
        provider_kernel: AUTHORIZATION_POLICY_KERNEL.to_owned(),
        method: "GET".to_owned(),
        origin: "https://graph.microsoft.com".to_owned(),
        path: AUTHORIZATION_POLICY_PATH.to_owned(),
        record_selector: "$".to_owned(),
        id_field: "id".to_owned(),
        singleton_fallback_id: AUTHORIZATION_POLICY_FALLBACK_ID.to_owned(),
        max_response_bytes: MAX_RESPONSE_BYTES,
        event_kind: AUTHORIZATION_POLICY_KIND.to_owned(),
        schema_ref: AUTHORIZATION_POLICY_SCHEMA.to_owned(),
        required_attributes: vec![
            "family".to_owned(),
            "resource_id".to_owned(),
            "resource_name".to_owned(),
            "resource_provider".to_owned(),
            "resource_type".to_owned(),
        ],
        required_payload_fields: vec!["id".to_owned()],
        plan_digest_sha256: String::new(),
    };
    plan.plan_digest_sha256 = canonical_plan_digest(&plan);
    plan
}

fn exact_context(tenant_id: &str) -> SourceWorkerExecutionContextV1 {
    SourceWorkerExecutionContextV1 {
        tenant_id: tenant_id.to_owned(),
        runtime_id: "runtime-1".to_owned(),
        logical_page_id: "page-sha256".to_owned(),
        prior_cursor: String::new(),
        runtime_generation: 7,
        lease_generation: 11,
        observed_at_unix_millis: 1_782_000_123_456,
    }
}

fn planned_request(context: &SourceWorkerExecutionContextV1) -> SourceWorkerHttpRequestV1 {
    let output = plan(
        &SourceWorkerPlanRequestV1 {
            plan: Some(exact_plan()),
            context: Some(context.clone()),
        }
        .encode_to_vec(),
    )
    .unwrap();
    SourceWorkerHttpRequestV1::decode(output.as_slice()).unwrap()
}

fn exact_receipt(
    body: &[u8],
    status_code: u32,
    context: &SourceWorkerExecutionContextV1,
    intent: &str,
) -> SourceWorkerSafeReceiptV1 {
    SourceWorkerSafeReceiptV1 {
        plan_digest_sha256: exact_plan().plan_digest_sha256,
        logical_page_id: context.logical_page_id.clone(),
        request_intent_digest: intent.to_owned(),
        runtime_generation: context.runtime_generation,
        lease_generation: context.lease_generation,
        credential_operation: "lease-operation-1".to_owned(),
        status_code,
        response_bytes: body.len() as u64,
        response_sha256: response_digest(body),
        tenant_id: context.tenant_id.clone(),
        runtime_id: context.runtime_id.clone(),
        observed_at_unix_millis: context.observed_at_unix_millis,
    }
}

fn exact_decode_request(context: &SourceWorkerExecutionContextV1) -> SourceWorkerDecodeRequestV1 {
    let intent = planned_request(context).request_intent_digest;
    SourceWorkerDecodeRequestV1 {
        plan: Some(exact_plan()),
        status_code: 200,
        response_body: GO_LIVE_TEST_RESPONSE.to_vec(),
        logical_page_id: context.logical_page_id.clone(),
        request_intent_digest: intent.clone(),
        receipt: Some(exact_receipt(GO_LIVE_TEST_RESPONSE, 200, context, &intent)),
        context: Some(context.clone()),
    }
}

#[test]
fn decodes_the_go_generated_canonical_plan_wire() {
    let hex = include_str!(
        "../../../../proto/cerebro/v1/testdata/azure_authorization_policy_plan_v1.hex"
    )
    .trim();
    let wire = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("canonical plan fixture is not lowercase hex"),
            };
            digit(pair[0]) << 4 | digit(pair[1])
        })
        .collect::<Vec<_>>();
    assert_eq!(
        SourceExecutionPlanV1::decode(wire.as_slice()).unwrap(),
        exact_plan()
    );
}

#[test]
fn plans_exact_credential_free_request_bound_to_context() {
    let context = exact_context("tenant-a");
    let request = planned_request(&context);
    assert_eq!(request.method, "GET");
    assert_eq!(
        request.url,
        "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
    );
    assert_eq!(request.accept, "application/json");
    assert_eq!(request.max_response_bytes, MAX_RESPONSE_BYTES);
    assert_eq!(request.request_intent_digest.len(), 64);
    assert!(
        !request
            .encode_to_vec()
            .windows(6)
            .any(|window| window == b"Bearer")
    );

    let other_tenant = planned_request(&exact_context("tenant-b"));
    assert_ne!(
        request.request_intent_digest,
        other_tenant.request_intent_digest
    );
}

#[test]
fn shared_boundary_rejects_origin_escape_even_with_a_recomputed_intent() {
    let context = exact_context("tenant-a");
    let plan = exact_plan();
    let mut request = planned_request(&context);
    request.url = "https://example.com/v1.0/policies/authorizationPolicy".to_owned();
    request.request_intent_digest =
        super::canonical_request_intent_digest(&plan, &context, &request);
    assert_eq!(
        validate_http_request(&plan, &context, &request),
        Err(SourceExecutionError::EgressDenied)
    );
}

#[test]
fn decodes_go_response_with_tenant_identity_fence_and_host_time() {
    let context = exact_context("tenant-a");
    let output = decode(&exact_decode_request(&context).encode_to_vec()).unwrap();
    let result = SourceWorkerDecodeResultV1::decode(output.as_slice()).unwrap();
    assert_eq!(result.plan_digest_sha256, exact_plan().plan_digest_sha256);
    assert_eq!(result.logical_page_id, context.logical_page_id);
    assert_eq!(result.next_cursor, "");
    assert_eq!(result.tenant_id, "tenant-a");
    assert_eq!(result.runtime_id, context.runtime_id);
    assert_eq!(result.runtime_generation, 7);
    assert_eq!(result.lease_generation, 11);
    assert_eq!(
        result.observed_at_unix_millis,
        context.observed_at_unix_millis
    );
    assert_eq!(result.records.len(), 1);
    let record = &result.records[0];
    assert_eq!(record.provider_id, "authorizationPolicy");
    assert_eq!(
        record.occurred_at_unix_millis,
        context.observed_at_unix_millis
    );
    assert_eq!(
        record.event_id,
        "azure-authorization-policy-authorizationPolicy"
    );
    assert_eq!(
        record.attributes.get("resource_id").map(String::as_str),
        Some("authorizationPolicy")
    );
    assert_eq!(
        record
            .attributes
            .get("default_user_can_read_bitlocker")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(result.result_digest_sha256.len(), 64);
}

#[test]
fn tenant_scope_is_bound_even_when_the_go_event_id_is_stable() {
    let first = decode(&exact_decode_request(&exact_context("tenant-a")).encode_to_vec()).unwrap();
    let second = decode(&exact_decode_request(&exact_context("tenant-b")).encode_to_vec()).unwrap();
    let first = SourceWorkerDecodeResultV1::decode(first.as_slice()).unwrap();
    let second = SourceWorkerDecodeResultV1::decode(second.as_slice()).unwrap();
    assert_eq!(first.records[0].event_id, second.records[0].event_id);
    assert_ne!(first.tenant_id, second.tenant_id);
    assert_ne!(first.request_intent_digest, second.request_intent_digest);
    assert_ne!(first.result_digest_sha256, second.result_digest_sha256);
}

#[test]
fn collapses_exact_duplicates_and_rejects_conflicting_duplicates() {
    let record = SourceWorkerRecordV1 {
        provider_id: "provider-1".to_owned(),
        attributes: [("kind".to_owned(), "account".to_owned())]
            .into_iter()
            .collect(),
        payload_json: br#"{"id":"provider-1"}"#.to_vec(),
        event_id: tenant_scoped_event_id("twilio", "accounts", "tenant-a", "provider-1").unwrap(),
        occurred_at_unix_millis: 1_782_000_123_456,
    };
    assert_eq!(
        validate_and_deduplicate_records(vec![record.clone(), record.clone()])
            .unwrap()
            .len(),
        1
    );
    let mut conflict = record.clone();
    conflict.payload_json = br#"{"id":"provider-1","status":"closed"}"#.to_vec();
    assert_eq!(
        validate_and_deduplicate_records(vec![record, conflict]),
        Err(SourceExecutionError::DuplicateConflict)
    );
}

#[test]
fn rejects_invalid_cursor_tampered_plan_and_unsafe_response() {
    assert_eq!(
        validate_cursor(&"a".repeat(MAX_CURSOR_BYTES + 1)),
        Err(SourceExecutionError::InvalidCursor)
    );
    assert_eq!(
        validate_cursor("cursor\nother-origin"),
        Err(SourceExecutionError::InvalidCursor)
    );

    let context = exact_context("tenant-a");
    let mut tampered = exact_plan();
    tampered.path = "/v1.0/users".to_owned();
    assert_eq!(
        plan(
            &SourceWorkerPlanRequestV1 {
                plan: Some(tampered),
                context: Some(context.clone()),
            }
            .encode_to_vec()
        ),
        Err(SourceExecutionError::InvalidPlan)
    );

    let mut unsupported = exact_decode_request(&context);
    unsupported.status_code = 500;
    unsupported.receipt.as_mut().unwrap().status_code = 500;
    assert_eq!(
        decode(&unsupported.encode_to_vec()),
        Err(SourceExecutionError::UnexpectedProviderStatus)
    );
    let mut oversize = exact_decode_request(&context);
    oversize.response_body = vec![b' '; (MAX_RESPONSE_BYTES + 1) as usize];
    assert_eq!(
        decode(&oversize.encode_to_vec()),
        Err(SourceExecutionError::ResponseTooLarge)
    );
}

#[test]
fn closed_dispatcher_rejects_unknown_adapter_tuples() {
    let dispatcher = super::SourceExecutionDispatcher;
    let mut unknown = exact_plan();
    unknown.provider_kernel = "azure.users".to_owned();
    unknown.plan_digest_sha256 = canonical_plan_digest(&unknown);
    assert!(matches!(
        dispatcher.adapter_for(&unknown),
        Err(SourceExecutionError::UnknownAdapter)
    ));
}

#[test]
fn rejects_tenant_generation_timestamp_and_intent_mismatches() {
    let context = exact_context("tenant-a");
    let mut tenant = exact_decode_request(&context);
    tenant.receipt.as_mut().unwrap().tenant_id = "tenant-b".to_owned();
    assert_eq!(
        decode(&tenant.encode_to_vec()),
        Err(SourceExecutionError::TenantMismatch)
    );

    let mut generation = exact_decode_request(&context);
    generation.receipt.as_mut().unwrap().lease_generation += 1;
    assert_eq!(
        decode(&generation.encode_to_vec()),
        Err(SourceExecutionError::StaleGeneration)
    );

    let mut timestamp = exact_decode_request(&context);
    timestamp.receipt.as_mut().unwrap().observed_at_unix_millis += 1;
    assert_eq!(
        decode(&timestamp.encode_to_vec()),
        Err(SourceExecutionError::MissingExecutionIdentity)
    );

    let mut intent = exact_decode_request(&context);
    intent.request_intent_digest = "b".repeat(64);
    intent.receipt.as_mut().unwrap().request_intent_digest = "b".repeat(64);
    assert_eq!(
        decode(&intent.encode_to_vec()),
        Err(SourceExecutionError::InvalidDigest)
    );
}

#[test]
fn failure_taxonomy_is_stable_bounded_and_actionable() {
    let errors = [
        SourceExecutionError::Protobuf,
        SourceExecutionError::UnknownAdapter,
        SourceExecutionError::MissingConfiguration,
        SourceExecutionError::MissingCredentialReference,
        SourceExecutionError::CredentialUnavailable,
        SourceExecutionError::AuthenticationRejected,
        SourceExecutionError::RequiredProviderScopeMissing,
        SourceExecutionError::EgressDenied,
        SourceExecutionError::ConnectionFailure,
        SourceExecutionError::ProviderTimeout,
        SourceExecutionError::ProviderRateLimit,
        SourceExecutionError::UnexpectedProviderStatus,
        SourceExecutionError::InvalidPlan,
        SourceExecutionError::InvalidExecutionContext,
        SourceExecutionError::InvalidCursor,
        SourceExecutionError::ResponseTooLarge,
        SourceExecutionError::ResultTooLarge,
        SourceExecutionError::MissingExecutionIdentity,
        SourceExecutionError::TenantMismatch,
        SourceExecutionError::StaleGeneration,
        SourceExecutionError::InvalidDigest,
        SourceExecutionError::MalformedResponse,
        SourceExecutionError::InvalidProviderRecord,
        SourceExecutionError::MissingStableIdentity,
        SourceExecutionError::DuplicateConflict,
        SourceExecutionError::EventContractRejected,
        SourceExecutionError::AppendFailed,
        SourceExecutionError::ProjectionFailed,
        SourceExecutionError::LeaseLost,
        SourceExecutionError::StaleAuthority,
        SourceExecutionError::InternalRuntime,
    ];
    for error in errors {
        let message = error.to_string();
        assert!(error.code().starts_with("source_worker."));
        assert!(!error.operator_action().is_empty());
        assert!(message.len() <= 160);
        assert!(!message.contains('\n'));
    }
}
