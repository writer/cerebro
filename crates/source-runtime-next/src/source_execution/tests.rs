use std::collections::HashMap;

use prost::Message;

use super::{
    canonical_http_execution_digest, canonical_plan_digest, canonical_response_headers_digest,
    contract::{
        AUTHORIZATION_POLICY_FALLBACK_ID, AUTHORIZATION_POLICY_FAMILY, AUTHORIZATION_POLICY_KERNEL,
        AUTHORIZATION_POLICY_KIND, AUTHORIZATION_POLICY_PATH, AUTHORIZATION_POLICY_SCHEMA,
        AZURE_SOURCE_ID, MAX_CURSOR_BYTES, MAX_RESPONSE_BYTES, MAX_SAFE_HEADER_BYTES,
        MAX_SAFE_HEADER_ENTRIES,
    },
    decode, decode_v2,
    error::SourceExecutionError,
    plan, plan_v2, response_digest, tenant_scoped_event_id, validate_and_deduplicate_records,
    validate_cursor, validate_declared_headers, validate_http_execution, validate_http_request,
    validate_public_config, validate_response_headers, validate_runtime_metadata,
    wire::{
        SourceExecutionPlanV1, SourceExecutionSelectionRequestV1, SourceWorkerDecodeEnvelopeV2,
        SourceWorkerDecodeOutputV2, SourceWorkerDecodeRequestV1, SourceWorkerDecodeResultV1,
        SourceWorkerExecutionContextV1, SourceWorkerHttpExecutionV2, SourceWorkerHttpRequestV1,
        SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1, SourceWorkerRecordV1,
        SourceWorkerRuntimeMetadataV2, SourceWorkerSafeReceiptV1,
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

fn sentinelone_plan() -> SourceExecutionPlanV1 {
    crate::sentinelone::SentinelOneAgentSourceExecutionAdapter.compiled_plan()
}

fn sentinelone_context(cursor: &str) -> SourceWorkerExecutionContextV1 {
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

fn twilio_plan() -> SourceExecutionPlanV1 {
    super::SourceExecutionDispatcher
        .compile_plan(&SourceExecutionSelectionRequestV1 {
            source_id: "twilio".to_owned(),
            family_id: "accounts".to_owned(),
        })
        .unwrap()
}

fn twilio_context(cursor: &str) -> SourceWorkerExecutionContextV1 {
    SourceWorkerExecutionContextV1 {
        tenant_id: "trusted-tenant".to_owned(),
        runtime_id: "twilio-accounts-runtime".to_owned(),
        logical_page_id: "accounts-page-1".to_owned(),
        prior_cursor: cursor.to_owned(),
        runtime_generation: 7,
        lease_generation: 11,
        observed_at_unix_millis: 1_780_372_800_000,
    }
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
fn v2_wire_round_trips_validated_public_metadata_without_credentials() {
    let metadata = SourceWorkerRuntimeMetadataV2 {
        public_config: HashMap::from([(
            "insights_origin".to_owned(),
            "https://api.jumpcloud.com/insights/directory/v1".to_owned(),
        )]),
        prior_terminal_watermark_unix_millis: 1_782_000_000_000,
        prior_checkpoint: "audit-terminal-1".to_owned(),
    };
    validate_runtime_metadata(&metadata).unwrap();
    let wire = metadata.encode_to_vec();
    assert_eq!(
        SourceWorkerRuntimeMetadataV2::decode(wire.as_slice()).unwrap(),
        metadata
    );
    assert!(!wire.windows(10).any(|value| value == b"credential"));

    let mut unsafe_metadata = metadata;
    unsafe_metadata
        .public_config
        .insert("api_token".to_owned(), "redacted".to_owned());
    assert_eq!(
        validate_runtime_metadata(&unsafe_metadata),
        Err(SourceExecutionError::InvalidExecutionContext)
    );
}

#[test]
fn v2_header_contract_rejects_credentials_and_bounds_metadata() {
    assert!(
        validate_declared_headers(&HashMap::from([(
            "content-type".to_owned(),
            "application/json".to_owned(),
        )]))
        .is_ok()
    );
    for name in ["authorization", "x-api-key"] {
        assert_eq!(
            validate_declared_headers(&HashMap::from([(name.to_owned(), "secret".to_owned())])),
            Err(SourceExecutionError::InvalidExecutionContext)
        );
    }

    let too_many = (0..=MAX_SAFE_HEADER_ENTRIES)
        .map(|index| (format!("x-next-{index}"), "value".to_owned()))
        .collect();
    assert_eq!(
        validate_response_headers(&too_many),
        Err(SourceExecutionError::ResultTooLarge)
    );
    let oversized = HashMap::from([(
        "x-search_after".to_owned(),
        "x".repeat(MAX_SAFE_HEADER_BYTES + 1),
    )]);
    assert_eq!(
        validate_response_headers(&oversized),
        Err(SourceExecutionError::InvalidExecutionContext)
    );
    let aggregate = (0..5)
        .map(|index| (format!("x-next-{index}"), "x".repeat(4090)))
        .collect();
    assert_eq!(
        validate_response_headers(&aggregate),
        Err(SourceExecutionError::ResultTooLarge)
    );

    let first = HashMap::from([
        ("x-result-count".to_owned(), "2".to_owned()),
        ("x-limit".to_owned(), "2".to_owned()),
        ("x-search_after".to_owned(), "cursor".to_owned()),
        ("retry-after".to_owned(), "30".to_owned()),
    ]);
    let second = HashMap::from([
        ("retry-after".to_owned(), "30".to_owned()),
        ("x-search_after".to_owned(), "cursor".to_owned()),
        ("x-limit".to_owned(), "2".to_owned()),
        ("x-result-count".to_owned(), "2".to_owned()),
    ]);
    assert_eq!(
        canonical_response_headers_digest(&first).unwrap(),
        canonical_response_headers_digest(&second).unwrap()
    );
}

#[test]
fn generic_x_api_key_operation_is_closed_and_digest_bound() {
    let plan = exact_plan();
    let context = exact_context("tenant-a");
    let metadata = SourceWorkerRuntimeMetadataV2::default();
    let mut execution = SourceWorkerHttpExecutionV2 {
        request: Some(planned_request(&context)),
        body: Vec::new(),
        declared_headers: HashMap::new(),
        execution_intent_digest_sha256: String::new(),
        credential_operation: "source.x_api_key".to_owned(),
        allowed_origin: plan.origin.clone(),
    };
    execution.execution_intent_digest_sha256 =
        canonical_http_execution_digest(&plan, &context, &metadata, &execution);
    assert!(validate_http_execution(&plan, &context, &execution, &metadata).is_ok());

    execution.credential_operation = "source.api_key".to_owned();
    execution.execution_intent_digest_sha256 =
        canonical_http_execution_digest(&plan, &context, &metadata, &execution);
    assert_eq!(
        validate_http_execution(&plan, &context, &execution, &metadata),
        Err(SourceExecutionError::InvalidPlan)
    );
}

#[test]
fn rust_constructs_and_validates_v2_receipt_evidence() {
    let context = exact_context("tenant-a");
    let metadata = SourceWorkerRuntimeMetadataV2::default();
    let planned = plan_v2(
        &SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(exact_plan()),
                context: Some(context.clone()),
            }),
            metadata: Some(metadata.clone()),
        }
        .encode_to_vec(),
    )
    .unwrap();
    let planned = SourceWorkerHttpExecutionV2::decode(planned.as_slice()).unwrap();
    let request = planned.request.as_ref().unwrap();
    let output = decode_v2(
        &SourceWorkerDecodeEnvelopeV2 {
            request: Some(SourceWorkerDecodeRequestV1 {
                plan: Some(exact_plan()),
                status_code: 200,
                response_body: GO_LIVE_TEST_RESPONSE.to_vec(),
                logical_page_id: context.logical_page_id.clone(),
                request_intent_digest: request.request_intent_digest.clone(),
                receipt: None,
                context: Some(context.clone()),
            }),
            metadata: Some(metadata),
            response_headers: HashMap::from([("x-result-count".to_owned(), "1".to_owned())]),
            response_headers_sha256: String::new(),
            execution_intent_digest_sha256: planned.execution_intent_digest_sha256,
        }
        .encode_to_vec(),
    )
    .unwrap();
    let output = SourceWorkerDecodeOutputV2::decode(output.as_slice()).unwrap();
    let receipt = output.receipt.unwrap();
    assert_eq!(receipt.credential_operation, "source.bearer");
    assert_eq!(receipt.response_bytes, GO_LIVE_TEST_RESPONSE.len() as u64);
    assert_eq!(
        receipt.response_sha256,
        response_digest(GO_LIVE_TEST_RESPONSE)
    );
    assert_eq!(output.result.unwrap().tenant_id, context.tenant_id);
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
fn public_config_allows_one_bounded_metrics_query_but_rejects_total_overflow() {
    let within_limit = HashMap::from([("metrics_query".to_owned(), "x".repeat(8 * 1024))]);
    assert_eq!(validate_public_config(&within_limit), Ok(()));
    let over_limit = HashMap::from([("metrics_query".to_owned(), "x".repeat(16 * 1024 + 1))]);
    assert_eq!(
        validate_public_config(&over_limit),
        Err(SourceExecutionError::InvalidExecutionContext)
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
fn closed_dispatcher_registers_and_executes_the_exact_sentinelone_agent_plan() {
    let dispatcher = super::SourceExecutionDispatcher;
    let plan = sentinelone_plan();
    let adapter = dispatcher.adapter_for(&plan).unwrap();
    assert_eq!(adapter.source_id(), "sentinelone");
    assert_eq!(adapter.family_id(), "agent");
    assert_eq!(adapter.provider_kernel(), "sentinelone.agent");

    let paged_context = sentinelone_context("cursor-A-1");
    let planned = dispatcher
        .dispatch_plan(&SourceWorkerPlanRequestV1 {
            plan: Some(plan.clone()),
            context: Some(paged_context),
        })
        .unwrap();
    assert_eq!(
        planned.url,
        "https://sentinelone.invalid/web/api/v2.1/agents?limit=200&cursor=cursor-A-1"
    );

    let context = sentinelone_context("");
    let planned = dispatcher
        .dispatch_plan(&SourceWorkerPlanRequestV1 {
            plan: Some(plan.clone()),
            context: Some(context.clone()),
        })
        .unwrap();
    let body = include_bytes!("../sentinelone/fixtures/agent_page.json");
    let receipt = SourceWorkerSafeReceiptV1 {
        plan_digest_sha256: plan.plan_digest_sha256.clone(),
        logical_page_id: context.logical_page_id.clone(),
        request_intent_digest: planned.request_intent_digest.clone(),
        runtime_generation: context.runtime_generation,
        lease_generation: context.lease_generation,
        credential_operation: "sentinelone-api-token-read".to_owned(),
        status_code: 200,
        response_bytes: body.len() as u64,
        response_sha256: response_digest(body),
        tenant_id: context.tenant_id.clone(),
        runtime_id: context.runtime_id.clone(),
        observed_at_unix_millis: context.observed_at_unix_millis,
    };
    let decoded = dispatcher
        .dispatch_decode(&SourceWorkerDecodeRequestV1 {
            plan: Some(plan),
            status_code: 200,
            response_body: body.to_vec(),
            logical_page_id: context.logical_page_id.clone(),
            request_intent_digest: planned.request_intent_digest,
            receipt: Some(receipt),
            context: Some(context),
        })
        .unwrap();
    assert_eq!(decoded.next_cursor, "cursor-A-2");
    assert_eq!(decoded.records.len(), 1);
    assert_eq!(
        decoded.records[0].event_id,
        "sentinelone-agent-sentinelone.example.test-A-1"
    );
}

#[test]
fn closed_dispatcher_registers_and_executes_the_exact_twilio_accounts_plan() {
    let dispatcher = super::SourceExecutionDispatcher;
    let plan = twilio_plan();
    let adapter = dispatcher.adapter_for(&plan).unwrap();
    assert_eq!(adapter.source_id(), "twilio");
    assert_eq!(adapter.family_id(), "accounts");
    assert_eq!(adapter.provider_kernel(), "twilio.accounts");

    let context = twilio_context("accounts-page-1");
    let execution = dispatcher
        .dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(plan.clone()),
                context: Some(context.clone()),
            }),
            metadata: Some(SourceWorkerRuntimeMetadataV2 {
                public_config: HashMap::new(),
                prior_terminal_watermark_unix_millis: 0,
                prior_checkpoint: String::new(),
            }),
        })
        .unwrap();
    assert_eq!(execution.credential_operation, "twilio.basic");
    assert_eq!(execution.allowed_origin, "https://api.twilio.com");
    let planned = execution.request.unwrap();
    assert_eq!(
        planned.url,
        "https://api.twilio.com/2010-04-01/Accounts.json?limit=100&cursor=accounts-page-1"
    );

    assert_eq!(
        dispatcher.dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(plan.clone()),
                context: Some(context.clone()),
            }),
            metadata: Some(SourceWorkerRuntimeMetadataV2 {
                public_config: HashMap::from([(
                    "base_url".to_owned(),
                    "https://twilio.example.test".to_owned(),
                )]),
                prior_terminal_watermark_unix_millis: 0,
                prior_checkpoint: String::new(),
            }),
        }),
        Err(SourceExecutionError::InvalidPlan)
    );

    let body = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sources/twilio/testdata/source_worker_accounts_page.json"
    ));
    let receipt = SourceWorkerSafeReceiptV1 {
        plan_digest_sha256: plan.plan_digest_sha256.clone(),
        logical_page_id: context.logical_page_id.clone(),
        request_intent_digest: planned.request_intent_digest.clone(),
        runtime_generation: context.runtime_generation,
        lease_generation: context.lease_generation,
        credential_operation: "twilio.basic".to_owned(),
        status_code: 200,
        response_bytes: body.len() as u64,
        response_sha256: response_digest(body),
        tenant_id: context.tenant_id.clone(),
        runtime_id: context.runtime_id.clone(),
        observed_at_unix_millis: context.observed_at_unix_millis,
    };
    let decoded = dispatcher
        .dispatch_decode(&SourceWorkerDecodeRequestV1 {
            plan: Some(plan),
            status_code: 200,
            response_body: body.to_vec(),
            logical_page_id: context.logical_page_id.clone(),
            request_intent_digest: planned.request_intent_digest,
            receipt: Some(receipt),
            context: Some(context),
        })
        .unwrap();
    assert_eq!(decoded.next_cursor, "accounts-page-2");
    assert_eq!(decoded.records.len(), 1);
    assert_eq!(
        decoded.records[0].event_id,
        "twilio-trusted-tenant-a92380b4993d-accounts-record-1"
    );
}

#[test]
fn closed_dispatcher_registers_the_exact_twilio_audit_events_plan() {
    let dispatcher = super::SourceExecutionDispatcher;
    let plan = dispatcher
        .compile_plan(&SourceExecutionSelectionRequestV1 {
            source_id: "twilio".to_owned(),
            family_id: "audit_events".to_owned(),
        })
        .unwrap();
    assert_eq!(plan.source_id, "twilio");
    assert_eq!(plan.family_id, "audit_events");
    assert_eq!(plan.provider_kernel, "twilio.audit_events");
    assert_eq!(plan.origin, "https://api.twilio.com");
    assert_eq!(plan.path, "/v1/Events");
    assert_eq!(plan.event_kind, "twilio.audit_events");
    assert_eq!(plan.schema_ref, "twilio/audit_events/v1");
    assert_eq!(
        dispatcher.adapter_for(&plan).unwrap().family_id(),
        "audit_events"
    );
    let keys = dispatcher
        .compile_plan(&SourceExecutionSelectionRequestV1 {
            source_id: "twilio".to_owned(),
            family_id: "keys".to_owned(),
        })
        .unwrap();
    assert_eq!(keys.provider_kernel, "twilio.keys");
    assert_eq!(keys.path, "/2010-04-01/Accounts/{account_sid}/Keys.json");
}

#[test]
fn closed_dispatcher_registers_only_the_ready_google_workspace_plans() {
    let dispatcher = super::SourceExecutionDispatcher;
    for (family, kernel, path, kind, schema) in [
        (
            "user",
            "google_workspace.user",
            "/admin/directory/v1/users",
            "google_workspace.user",
            "google_workspace/user/v1",
        ),
        (
            "group",
            "google_workspace.group",
            "/admin/directory/v1/groups",
            "google_workspace.group",
            "google_workspace/group/v1",
        ),
    ] {
        let plan = dispatcher
            .compile_plan(&SourceExecutionSelectionRequestV1 {
                source_id: "google_workspace".to_owned(),
                family_id: family.to_owned(),
            })
            .unwrap();
        assert_eq!(plan.provider_kernel, kernel);
        assert_eq!(plan.origin, "https://admin.googleapis.com");
        assert_eq!(plan.path, path);
        assert_eq!(plan.event_kind, kind);
        assert_eq!(plan.schema_ref, schema);
        assert_eq!(dispatcher.adapter_for(&plan).unwrap().family_id(), family);
    }

    for family in ["audit", "group_member", "role_assignment", "future-family"] {
        assert_eq!(
            dispatcher.compile_plan(&SourceExecutionSelectionRequestV1 {
                source_id: "google_workspace".to_owned(),
                family_id: family.to_owned(),
            }),
            Err(SourceExecutionError::UnknownAdapter)
        );
    }
}

#[test]
fn twilio_keys_require_and_bind_public_account_scope_in_v2() {
    let dispatcher = super::SourceExecutionDispatcher;
    let plan = dispatcher
        .compile_plan(&SourceExecutionSelectionRequestV1 {
            source_id: "twilio".to_owned(),
            family_id: "keys".to_owned(),
        })
        .unwrap();
    let context = SourceWorkerExecutionContextV1 {
        tenant_id: "trusted-tenant".to_owned(),
        runtime_id: "twilio-keys-runtime".to_owned(),
        logical_page_id: "keys-page-1".to_owned(),
        prior_cursor: "keys-page-1".to_owned(),
        runtime_generation: 7,
        lease_generation: 11,
        observed_at_unix_millis: 1_780_372_800_000,
    };
    let metadata = SourceWorkerRuntimeMetadataV2 {
        public_config: HashMap::from([("account_sid".to_owned(), "AC123".to_owned())]),
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    };
    assert_eq!(
        dispatcher.dispatch_plan(&SourceWorkerPlanRequestV1 {
            plan: Some(plan.clone()),
            context: Some(context.clone()),
        }),
        Err(SourceExecutionError::InvalidPlan)
    );
    assert_eq!(
        dispatcher.dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(plan.clone()),
                context: Some(context.clone()),
            }),
            metadata: Some(SourceWorkerRuntimeMetadataV2::default()),
        }),
        Err(SourceExecutionError::InvalidPlan)
    );
    let execution = dispatcher
        .dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(plan.clone()),
                context: Some(context.clone()),
            }),
            metadata: Some(metadata.clone()),
        })
        .unwrap();
    assert_eq!(execution.credential_operation, "twilio.basic");
    let planned = execution.request.unwrap();
    assert_eq!(
        planned.url,
        "https://api.twilio.com/2010-04-01/Accounts/AC123/Keys.json?limit=100&cursor=keys-page-1"
    );
    let body = br#"{
        "keys":[{
            "id":"key-1",
            "name":"Key One",
            "created_at":"2026-06-01T00:00:00Z"
        }],
        "next_cursor":"keys-page-2"
    }"#;
    let decode_request = SourceWorkerDecodeRequestV1 {
        plan: Some(plan),
        status_code: 200,
        response_body: body.to_vec(),
        logical_page_id: context.logical_page_id.clone(),
        request_intent_digest: planned.request_intent_digest,
        receipt: None,
        context: Some(context),
    };
    let mut changed_scope = metadata.clone();
    changed_scope
        .public_config
        .insert("account_sid".to_owned(), "AC999".to_owned());
    assert_eq!(
        dispatcher.dispatch_decode_v2(&SourceWorkerDecodeEnvelopeV2 {
            request: Some(decode_request.clone()),
            metadata: Some(changed_scope),
            response_headers: HashMap::new(),
            response_headers_sha256: String::new(),
            execution_intent_digest_sha256: execution.execution_intent_digest_sha256.clone(),
        }),
        Err(SourceExecutionError::InvalidDigest)
    );
    let output = dispatcher
        .dispatch_decode_v2(&SourceWorkerDecodeEnvelopeV2 {
            request: Some(decode_request),
            metadata: Some(metadata),
            response_headers: HashMap::new(),
            response_headers_sha256: String::new(),
            execution_intent_digest_sha256: execution.execution_intent_digest_sha256,
        })
        .unwrap();
    let result = output.result.unwrap();
    assert_eq!(result.next_cursor, "keys-page-2");
    assert_eq!(result.records.len(), 1);
    assert_eq!(result.records[0].attributes["secret_id"], "key-1");
    assert_eq!(result.records[0].attributes["secret_name"], "Key One");
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
