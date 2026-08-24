use std::collections::HashMap;

use prost::Message;
use serde_json::Value;

use crate::source_execution::{
    SourceWorkerRuntimeMetadataV2, SourceWorkerSafeReceiptV1, response_digest,
};

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
    SentinelOneAgentSourceExecutionAdapter.compiled_plan()
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
        "https://sentinelone.invalid/web/api/v2.1/agents?limit=200&cursor=cursor-A-1"
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
fn metadata_aware_dispatch_uses_dynamic_origin_closed_auth_and_restart_boundary() {
    let dispatcher = crate::source_execution::SourceExecutionDispatcher;
    let plan = dispatcher
        .compile_plan(
            &crate::source_execution::SourceExecutionSelectionRequestV1 {
                source_id: SOURCE_ID.to_owned(),
                family_id: FAMILY_ID.to_owned(),
            },
        )
        .unwrap();
    let execution_context = context("cursor-A-1");
    let metadata = SourceWorkerRuntimeMetadataV2 {
        public_config: HashMap::from([
            (
                "base_url".to_owned(),
                "https://sentinelone.example.test/".to_owned(),
            ),
            ("per_page".to_owned(), "200".to_owned()),
            ("site_id".to_owned(), "site-1".to_owned()),
        ]),
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    };
    let planned = dispatcher
        .dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(plan.clone()),
                context: Some(execution_context.clone()),
            }),
            metadata: Some(metadata.clone()),
        })
        .unwrap();
    assert_eq!(planned.allowed_origin, "https://sentinelone.example.test");
    assert_eq!(planned.credential_operation, CREDENTIAL_OPERATION);
    assert_eq!(
        planned.request.as_ref().unwrap().url,
        "https://sentinelone.example.test/web/api/v2.1/agents?limit=200&cursor=cursor-A-1&siteIds=site-1"
    );
    assert!(planned.body.is_empty());
    assert!(planned.declared_headers.is_empty());

    let first_context = context("");
    let first = dispatcher
        .dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(plan.clone()),
                context: Some(first_context.clone()),
            }),
            metadata: Some(metadata.clone()),
        })
        .unwrap();
    let first_request = first.request.as_ref().unwrap();
    let decoded = dispatcher
        .dispatch_decode_v2(&SourceWorkerDecodeEnvelopeV2 {
            request: Some(SourceWorkerDecodeRequestV1 {
                plan: Some(plan.clone()),
                status_code: 200,
                response_body: AGENT_PAGE.to_vec(),
                logical_page_id: first_context.logical_page_id.clone(),
                request_intent_digest: first_request.request_intent_digest.clone(),
                receipt: None,
                context: Some(first_context),
            }),
            metadata: Some(metadata),
            response_headers: HashMap::new(),
            execution_intent_digest_sha256: first.execution_intent_digest_sha256,
            response_headers_sha256: String::new(),
        })
        .unwrap();
    let result = decoded.result.unwrap();
    assert_eq!(result.next_cursor, "cursor-A-2");
    assert_eq!(
        durable_checkpoint_cursor(&plan, &result).as_deref(),
        Some("cursor-A-2")
    );
    let mut terminal = result;
    terminal.next_cursor.clear();
    assert_eq!(
        durable_checkpoint_cursor(&plan, &terminal).as_deref(),
        Some("A-1")
    );
}

#[test]
fn metadata_aware_dispatch_requires_a_safe_public_origin() {
    let plan = SentinelOneAgentSourceExecutionAdapter.compiled_plan();
    for config in [
        HashMap::new(),
        HashMap::from([(
            "base_url".to_owned(),
            "http://sentinelone.example.test".to_owned(),
        )]),
    ] {
        let result = SentinelOneAgentSourceExecutionAdapter.plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(plan.clone()),
                context: Some(context("")),
            }),
            metadata: Some(SourceWorkerRuntimeMetadataV2 {
                public_config: config,
                prior_terminal_watermark_unix_millis: 0,
                prior_checkpoint: String::new(),
            }),
        });
        assert!(matches!(
            result,
            Err(SourceExecutionError::MissingConfiguration | SourceExecutionError::InvalidPlan)
        ));
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

#[test]
fn closed_dispatcher_executes_promoted_direct_families_with_go_identity_and_shape() {
    struct Case {
        family: &'static str,
        path: &'static str,
        provider_id: &'static str,
        body: Value,
        identity_attribute: &'static str,
        expected_attributes: Vec<(&'static str, &'static str)>,
        expected_payload: Vec<(&'static str, Value)>,
    }

    let cases = vec![
        Case {
            family: "activity",
            path: "/web/api/v2.1/activities",
            provider_id: "activity-fixture-1",
            body: serde_json::json!({"data": [{
                "id": "activity-fixture-1",
                "activityType": 27,
                "primaryDescription": "User user@example.test logged into the management console",
                "agentId": "agent-fixture-1",
                "siteId": "site-fixture-1",
                "groupId": "group-fixture-1",
                "createdAt": "2026-04-23T00:30:00Z",
                "tenantId": "provider-controlled-tenant"
            }], "pagination": {}}),
            identity_attribute: "activity_id",
            expected_attributes: vec![
                ("activity_type", "27"),
                ("agent_id", "agent-fixture-1"),
                ("site_id", "site-fixture-1"),
                ("group_id", "group-fixture-1"),
            ],
            expected_payload: vec![
                ("activity_type", Value::from(27)),
                ("agent_id", Value::from("agent-fixture-1")),
                ("site_id", Value::from("site-fixture-1")),
            ],
        },
        Case {
            family: "exclusion",
            path: "/web/api/v2.1/exclusions",
            provider_id: "exclusion-fixture-1",
            body: serde_json::json!({"data": [{
                "id": "exclusion-fixture-1",
                "type": "path",
                "mode": "suppress_alerts",
                "osType": "macos",
                "scope": "site",
                "scopeName": "Production",
                "value": "/Applications/Approved.app",
                "notRecommended": "NONE",
                "includeChildren": "true",
                "updatedAt": "2026-04-22T00:00:00Z"
            }], "pagination": {}}),
            identity_attribute: "exclusion_id",
            expected_attributes: vec![
                ("exclusion_type", "path"),
                ("mode", "suppress_alerts"),
                ("scope", "site"),
                ("scope_name", "Production"),
                ("not_recommended", "false"),
                ("include_children", "true"),
            ],
            expected_payload: vec![
                ("type", Value::from("path")),
                ("scope", Value::from("site")),
                ("include_children", Value::from(true)),
            ],
        },
        Case {
            family: "group",
            path: "/web/api/v2.1/groups",
            provider_id: "group-fixture-1",
            body: serde_json::json!({"data": [{
                "id": "group-fixture-1",
                "name": "Default Group",
                "type": "static",
                "isDefault": true,
                "siteId": "site-fixture-1",
                "totalAgents": 1,
                "registrationToken": "provider-secret-shape",
                "updatedAt": "2026-04-22T00:00:00Z"
            }], "pagination": {}}),
            identity_attribute: "group_id",
            expected_attributes: vec![
                ("group_name", "Default Group"),
                ("type", "static"),
                ("site_id", "site-fixture-1"),
                ("is_default", "true"),
                ("total_agents", "1"),
            ],
            expected_payload: vec![
                ("name", Value::from("Default Group")),
                ("is_default", Value::from(true)),
                ("total_agents", Value::from(1)),
                ("has_registration_token", Value::from(true)),
            ],
        },
        Case {
            family: "site",
            path: "/web/api/v2.1/sites",
            provider_id: "site-fixture-1",
            body: serde_json::json!({"data": [{
                "id": "site-fixture-1",
                "name": "Production",
                "state": "active",
                "siteType": "Paid",
                "isDefault": true,
                "updatedAt": "2026-04-22T00:00:00Z"
            }], "pagination": {}}),
            identity_attribute: "site_id",
            expected_attributes: vec![
                ("site_name", "Production"),
                ("state", "active"),
                ("site_type", "Paid"),
                ("is_default", "true"),
            ],
            expected_payload: vec![
                ("name", Value::from("Production")),
                ("state", Value::from("active")),
                ("site_type", Value::from("Paid")),
                ("is_default", Value::from(true)),
            ],
        },
        Case {
            family: "threat",
            path: "/web/api/v2.1/threats",
            provider_id: "threat-fixture-1",
            body: serde_json::json!({"data": [{
                "id": "threat-fixture-1",
                "threatInfo": {
                    "analystVerdict": "true_positive",
                    "classification": "Malware",
                    "classificationSource": "Engine",
                    "confidenceLevel": "malicious",
                    "incidentStatus": "unresolved",
                    "mitigationStatus": "not_mitigated",
                    "identifiedAt": "2026-04-23T01:00:00Z",
                    "sha256": "feedfacecafebeef"
                },
                "agentDetectionInfo": {
                    "agentIpV4": "203.0.113.20",
                    "agentIpV6": "2001:db8::20",
                    "externalIp": "198.51.100.20",
                    "agentUuid": "agent-uuid-1",
                    "siteId": "site-fixture-1",
                    "groupId": "group-fixture-1"
                },
                "agentRealtimeInfo": {
                    "agentId": "agent-fixture-1",
                    "agentComputerName": "host-fixture-1",
                    "agentIsActive": true,
                    "agentInfected": true,
                    "activeThreats": 1
                },
                "indicators": [{
                    "category": "Malware",
                    "tactics": [{"name": "Execution"}]
                }],
                "tenantId": "provider-controlled-tenant"
            }], "pagination": {}}),
            identity_attribute: "threat_id",
            expected_attributes: vec![
                ("classification", "Malware"),
                ("classification_norm", "malware"),
                ("analyst_verdict_norm", "true_positive"),
                ("incident_status_norm", "unresolved"),
                ("mitigation_status_norm", "not_mitigated"),
                ("agent_id", "agent-fixture-1"),
                ("hostname", "host-fixture-1"),
                ("ip", "203.0.113.20"),
                ("ip_addresses", "203.0.113.20,2001:db8::20,198.51.100.20"),
                ("mitre_tactics", "Execution"),
            ],
            expected_payload: vec![],
        },
    ];

    let dispatcher = crate::source_execution::SourceExecutionDispatcher;
    for case in cases {
        let plan = dispatcher
            .compile_plan(
                &crate::source_execution::SourceExecutionSelectionRequestV1 {
                    source_id: SOURCE_ID.to_owned(),
                    family_id: case.family.to_owned(),
                },
            )
            .unwrap();
        assert_eq!(plan.path, case.path);
        assert_eq!(plan.event_kind, format!("sentinelone.{}", case.family));
        assert_eq!(plan.schema_ref, format!("sentinelone/{}/v1", case.family));

        let execution_context = SourceWorkerExecutionContextV1 {
            tenant_id: "sentinelone.example.test".to_owned(),
            runtime_id: format!("sentinelone-{}-runtime", case.family),
            logical_page_id: format!("{}-page-1", case.family),
            prior_cursor: String::new(),
            runtime_generation: 7,
            lease_generation: 11,
            observed_at_unix_millis: 1_776_906_123_456,
        };
        let metadata = SourceWorkerRuntimeMetadataV2 {
            public_config: HashMap::from([
                (
                    "base_url".to_owned(),
                    "https://sentinelone.example.test/".to_owned(),
                ),
                ("per_page".to_owned(), "200".to_owned()),
            ]),
            prior_terminal_watermark_unix_millis: 0,
            prior_checkpoint: String::new(),
        };
        let planned = dispatcher
            .dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(plan.clone()),
                    context: Some(execution_context.clone()),
                }),
                metadata: Some(metadata.clone()),
            })
            .unwrap();
        assert_eq!(planned.credential_operation, CREDENTIAL_OPERATION);
        assert!(planned.request.as_ref().unwrap().url.starts_with(&format!(
            "https://sentinelone.example.test{}?limit=200",
            case.path
        )));
        assert!(planned.declared_headers.is_empty());
        assert!(planned.body.is_empty());

        let body = serde_json::to_vec(&case.body).unwrap();
        let decoded = dispatcher
            .dispatch_decode_v2(&SourceWorkerDecodeEnvelopeV2 {
                request: Some(SourceWorkerDecodeRequestV1 {
                    plan: Some(plan.clone()),
                    status_code: 200,
                    response_body: body,
                    logical_page_id: execution_context.logical_page_id.clone(),
                    request_intent_digest: planned
                        .request
                        .as_ref()
                        .unwrap()
                        .request_intent_digest
                        .clone(),
                    receipt: None,
                    context: Some(execution_context.clone()),
                }),
                metadata: Some(metadata),
                response_headers: HashMap::new(),
                execution_intent_digest_sha256: planned.execution_intent_digest_sha256,
                response_headers_sha256: String::new(),
            })
            .unwrap();
        let result = decoded.result.unwrap();
        assert_eq!(result.records.len(), 1);
        let record = &result.records[0];
        assert_eq!(record.provider_id, case.provider_id);
        assert_eq!(
            record.event_id,
            format!(
                "sentinelone-{}-sentinelone.example.test-{}",
                case.family, case.provider_id
            )
        );
        assert_eq!(record.attributes["family"], case.family);
        assert_eq!(record.attributes["tenant_host"], "sentinelone.example.test");
        assert_eq!(record.attributes[case.identity_attribute], case.provider_id);
        for (name, expected) in case.expected_attributes {
            assert_eq!(
                record.attributes[name], expected,
                "{}.{}",
                case.family, name
            );
        }
        let payload: Value = serde_json::from_slice(&record.payload_json).unwrap();
        assert_eq!(payload["id"], case.provider_id);
        assert_eq!(payload["tenant_host"], "sentinelone.example.test");
        assert!(payload["raw"].get("tenantId").is_none());
        assert!(payload["raw"].get("registrationToken").is_none());
        assert!(
            !record
                .payload_json
                .windows(b"provider-secret-shape".len())
                .any(|window| window == b"provider-secret-shape")
        );
        for (name, expected) in case.expected_payload {
            assert_eq!(payload[name], expected, "{}.{}", case.family, name);
        }
        assert_eq!(
            durable_checkpoint_cursor(&plan, &result).as_deref(),
            Some(case.provider_id)
        );
    }
}

#[test]
fn threat_runtime_preserves_go_event_shape_and_strips_nested_secret_fields() {
    let dispatcher = crate::source_execution::SourceExecutionDispatcher;
    let adapter = SENTINELONE_DIRECT_SOURCE_EXECUTION_ADAPTERS
        .iter()
        .find(|adapter| adapter.family_id() == "threat")
        .unwrap();
    let plan = adapter.compiled_plan();
    let execution_context = context("");
    let metadata = SourceWorkerRuntimeMetadataV2 {
        public_config: HashMap::from([
            (
                "base_url".to_owned(),
                "https://sentinelone.example.test".to_owned(),
            ),
            ("site_id".to_owned(), "site-fixture-1".to_owned()),
            ("since".to_owned(), "2026-04-01T00:00:00Z".to_owned()),
            ("until".to_owned(), "2026-04-30T00:00:00Z".to_owned()),
        ]),
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    };
    let planned = adapter
        .plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(plan.clone()),
                context: Some(execution_context.clone()),
            }),
            metadata: Some(metadata.clone()),
        })
        .unwrap();
    let url = &planned.request.as_ref().unwrap().url;
    for expected in [
        "siteIds=site-fixture-1",
        "createdAt__gte=2026-04-01T00%3A00%3A00Z",
        "createdAt__lte=2026-04-30T00%3A00%3A00Z",
    ] {
        assert!(url.contains(expected), "missing {expected} in {url}");
    }
    let body = serde_json::to_vec(&serde_json::json!({
        "data": [{
            "id": "threat-fixture-1",
            "threatInfo": {
                "analystVerdict": "true_positive",
                "classification": "Malware",
                "classificationSource": "Engine",
                "confidenceLevel": "malicious",
                "incidentStatus": "unresolved",
                "mitigationStatus": "not_mitigated",
                "identifiedAt": "2026-04-23T01:00:00Z",
                "sha256": "feedfacecafebeef"
            },
            "agentDetectionInfo": {
                "agentIpV4": "203.0.113.20",
                "agentIpV6": "2001:db8::20",
                "externalIp": "198.51.100.20",
                "agentUuid": "agent-uuid-1",
                "siteId": "site-fixture-1",
                "groupId": "group-fixture-1"
            },
            "agentRealtimeInfo": {
                "agentId": "agent-fixture-1",
                "agentComputerName": "host-fixture-1",
                "agentIsActive": true,
                "agentInfected": true,
                "activeThreats": 1
            },
            "indicators": [{
                "category": "Malware",
                "description": "Observed execution",
                "tactics": [{
                    "name": "Execution",
                    "techniques": [
                        {"name": "Native API"},
                        {"name": "Native API"}
                    ]
                }]
            }],
            "mitigationStatus": [{
                "action": "kill",
                "status": "success",
                "reportId": "report-1"
            }],
            "whiteningOptions": ["path"],
            "nested": {"apiToken": "provider-secret-shape"},
            "tenantId": "provider-controlled-tenant"
        }],
        "pagination": {"nextCursor": "cursor-2"}
    }))
    .unwrap();
    let decoded = dispatcher
        .dispatch_decode_v2(&SourceWorkerDecodeEnvelopeV2 {
            request: Some(SourceWorkerDecodeRequestV1 {
                plan: Some(plan.clone()),
                status_code: 200,
                response_body: body,
                logical_page_id: execution_context.logical_page_id.clone(),
                request_intent_digest: planned
                    .request
                    .as_ref()
                    .unwrap()
                    .request_intent_digest
                    .clone(),
                receipt: None,
                context: Some(execution_context),
            }),
            metadata: Some(metadata),
            response_headers: HashMap::new(),
            execution_intent_digest_sha256: planned.execution_intent_digest_sha256,
            response_headers_sha256: String::new(),
        })
        .unwrap()
        .result
        .unwrap();
    assert_eq!(decoded.next_cursor, "cursor-2");
    assert_eq!(decoded.records.len(), 1);
    let record = &decoded.records[0];
    assert_eq!(record.occurred_at_unix_millis, 1_776_906_000_000);
    assert_eq!(record.attributes["mitre_tactics"], "Execution");
    assert_eq!(record.attributes["mitre_techniques"], "Native API");
    let payload: Value = serde_json::from_slice(&record.payload_json).unwrap();
    assert_eq!(payload["tenant_host"], "sentinelone.example.test");
    assert_eq!(payload["threat_info"]["classification"], "Malware");
    assert_eq!(payload["agent_realtime"]["is_decommissioned"], false);
    assert_eq!(payload["indicators"]["mitre_techniques"][0], "Native API");
    assert_eq!(payload["mitigation_actions"][0]["action"], "kill");
    assert_eq!(payload["whitening_options"][0], "path");
    assert!(payload["raw"].get("tenantId").is_none());
    assert!(payload["raw"]["nested"].get("apiToken").is_none());
    assert!(
        !record
            .payload_json
            .windows(b"provider-secret-shape".len())
            .any(|window| window == b"provider-secret-shape")
    );
}

#[test]
fn activity_runtime_binds_public_filters_without_credential_material() {
    let adapter = SENTINELONE_DIRECT_SOURCE_EXECUTION_ADAPTERS
        .iter()
        .find(|adapter| adapter.family_id() == "activity")
        .unwrap();
    let plan = adapter.compiled_plan();
    let metadata = SourceWorkerRuntimeMetadataV2 {
        public_config: HashMap::from([
            (
                "base_url".to_owned(),
                "https://sentinelone.example.test".to_owned(),
            ),
            ("site_id".to_owned(), "site-1".to_owned()),
            ("group_id".to_owned(), "group-1".to_owned()),
            ("since".to_owned(), "2026-01-01T00:00:00Z".to_owned()),
            ("until".to_owned(), "2026-02-01T00:00:00Z".to_owned()),
            ("activity_type".to_owned(), "27".to_owned()),
        ]),
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    };
    let planned = adapter
        .plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(plan),
                context: Some(context("")),
            }),
            metadata: Some(metadata),
        })
        .unwrap();
    let url = planned.request.unwrap().url;
    for expected in [
        "siteIds=site-1",
        "groupIds=group-1",
        "createdAt__gte=2026-01-01T00%3A00%3A00Z",
        "createdAt__lte=2026-02-01T00%3A00%3A00Z",
        "activityTypes=27",
    ] {
        assert!(url.contains(expected), "missing {expected} in {url}");
    }
    assert!(!url.contains("token"));
}
