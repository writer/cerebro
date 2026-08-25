use std::collections::HashMap;

use serde_json::Value;

use crate::source_execution::{
    SourceExecutionDispatcher, SourceExecutionError, SourceExecutionLifecycleEnvelopeV2,
    SourceExecutionLifecycleRequestV1, SourceExecutionPlanV1, SourceExecutionSelectionRequestV1,
    SourceWorkerDecodeEnvelopeV2, SourceWorkerDecodeOutputV2, SourceWorkerDecodeRequestV1,
    SourceWorkerExecutionContextV1, SourceWorkerHttpExecutionV2, SourceWorkerPlanEnvelopeV2,
    SourceWorkerPlanRequestV1, SourceWorkerRuntimeMetadataV2, seal_page_program_v2,
};

use super::{DEFAULT_BASE_URL, PAGERDUTY_SOURCE_EXECUTION_ADAPTERS};

const OBSERVED_AT_MILLIS: i64 = 1_780_272_000_000;

fn context(cursor: &str, page: u32) -> SourceWorkerExecutionContextV1 {
    SourceWorkerExecutionContextV1 {
        tenant_id: "tenant".to_owned(),
        runtime_id: "pagerduty-runtime".to_owned(),
        logical_page_id: format!("source-page-v2:pagerduty-{page}"),
        prior_cursor: cursor.to_owned(),
        runtime_generation: 7,
        lease_generation: 11,
        observed_at_unix_millis: OBSERVED_AT_MILLIS,
    }
}

fn metadata() -> SourceWorkerRuntimeMetadataV2 {
    SourceWorkerRuntimeMetadataV2 {
        public_config: HashMap::from([
            ("family".to_owned(), "user".to_owned()),
            ("per_page".to_owned(), "2".to_owned()),
        ]),
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    }
}

fn plan(dispatcher: SourceExecutionDispatcher) -> SourceExecutionPlanV1 {
    dispatcher
        .compile_plan(&SourceExecutionSelectionRequestV1 {
            source_id: "pagerduty".to_owned(),
            family_id: "user".to_owned(),
        })
        .unwrap()
}

fn plan_page(
    dispatcher: SourceExecutionDispatcher,
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    metadata: &SourceWorkerRuntimeMetadataV2,
) -> SourceWorkerHttpExecutionV2 {
    dispatcher
        .dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(plan.clone()),
                context: Some(context.clone()),
            }),
            metadata: Some(metadata.clone()),
        })
        .unwrap()
}

fn decode_page(
    dispatcher: SourceExecutionDispatcher,
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    metadata: &SourceWorkerRuntimeMetadataV2,
    execution: &SourceWorkerHttpExecutionV2,
    status_code: u32,
    body: &[u8],
) -> Result<SourceWorkerDecodeOutputV2, SourceExecutionError> {
    let planned = execution.request.as_ref().unwrap();
    dispatcher.dispatch_decode_v2(&SourceWorkerDecodeEnvelopeV2 {
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
        response_headers: HashMap::new(),
        response_headers_sha256: String::new(),
        execution_intent_digest_sha256: execution.execution_intent_digest_sha256.clone(),
    })
}

#[test]
fn closed_dispatcher_registers_every_portable_pagerduty_family() {
    let dispatcher = SourceExecutionDispatcher;
    let plan = plan(dispatcher);
    assert_eq!(plan.plan_id, "source-plan-v1:pagerduty:user");
    assert_eq!(plan.provider_kernel, "pagerduty.user");
    assert_eq!(plan.origin, DEFAULT_BASE_URL);
    assert_eq!(plan.path, "/users");
    assert_eq!(plan.record_selector, "$.users[*]");
    assert_eq!(plan.event_kind, "pagerduty.user");
    assert_eq!(plan.schema_ref, "pagerduty/user/v1");

    for adapter in &PAGERDUTY_SOURCE_EXECUTION_ADAPTERS {
        let family = adapter.family();
        assert_eq!(
            dispatcher
                .compile_plan(&SourceExecutionSelectionRequestV1 {
                    source_id: "pagerduty".to_owned(),
                    family_id: family.as_str().to_owned(),
                })
                .unwrap(),
            adapter.compiled_plan(),
            "{}",
            family.as_str()
        );
    }

    for family in ["", "future"] {
        assert_eq!(
            dispatcher.compile_plan(&SourceExecutionSelectionRequestV1 {
                source_id: "pagerduty".to_owned(),
                family_id: family.to_owned(),
            }),
            Err(SourceExecutionError::UnknownAdapter),
            "{family}"
        );
    }
}

#[test]
fn provider_local_catalog_compiles_and_plans_every_pagerduty_family() {
    let execution_context = context("", 1);
    assert_eq!(
        PAGERDUTY_SOURCE_EXECUTION_ADAPTERS.len(),
        crate::pagerduty::PagerDutyFamily::ALL.len()
    );

    for adapter in &PAGERDUTY_SOURCE_EXECUTION_ADAPTERS {
        let family = adapter.family();
        let plan = adapter.compiled_plan();
        assert_eq!(plan.source_id, "pagerduty");
        assert_eq!(plan.family_id, family.as_str());
        assert_eq!(plan.provider_kernel, family.event_kind());
        assert_eq!(plan.path, family.path_template());
        assert_eq!(
            plan.record_selector,
            format!("$.{}[*]", family.response_key())
        );
        assert_eq!(plan.event_kind, family.event_kind());
        assert_eq!(plan.schema_ref, family.schema_ref());
        assert!(
            plan.required_attributes
                .contains(&family.identity_attribute().to_owned())
        );

        let mut metadata = SourceWorkerRuntimeMetadataV2 {
            public_config: HashMap::from([
                ("family".to_owned(), family.as_str().to_owned()),
                ("per_page".to_owned(), "2".to_owned()),
            ]),
            prior_terminal_watermark_unix_millis: 0,
            prior_checkpoint: String::new(),
        };
        if family == crate::pagerduty::PagerDutyFamily::Integration {
            metadata
                .public_config
                .insert("service_ids".to_owned(), "PS1, PS2".to_owned());
            assert!(plan.required_attributes.contains(&"service_id".to_owned()));
        }
        let execution = crate::source_execution::SourceExecutionAdapter::plan_v2(
            adapter,
            &SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(plan.clone()),
                    context: Some(execution_context.clone()),
                }),
                metadata: Some(metadata),
            },
        )
        .unwrap();
        assert_eq!(execution.credential_operation, "pagerduty.token");
        assert_eq!(execution.allowed_origin, DEFAULT_BASE_URL);
        let request = execution.request.unwrap();
        assert_eq!(request.method, "GET");
        assert!(request.url.starts_with(DEFAULT_BASE_URL));
        assert!(request.url.ends_with("limit=2"));
        if family == crate::pagerduty::PagerDutyFamily::Integration {
            assert!(request.url.contains("/services/PS1/integrations?"));
        }
    }
}

#[test]
fn integration_adapter_requires_bounded_service_scope() {
    let adapter = PAGERDUTY_SOURCE_EXECUTION_ADAPTERS
        .iter()
        .find(|adapter| adapter.family() == crate::pagerduty::PagerDutyFamily::Integration)
        .unwrap();
    let plan = adapter.compiled_plan();
    let metadata = SourceWorkerRuntimeMetadataV2 {
        public_config: HashMap::from([
            ("family".to_owned(), "integration".to_owned()),
            ("per_page".to_owned(), "2".to_owned()),
        ]),
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    };
    assert_eq!(
        crate::source_execution::SourceExecutionAdapter::plan_v2(
            adapter,
            &SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(plan),
                    context: Some(context("", 1)),
                }),
                metadata: Some(metadata),
            },
        ),
        Err(SourceExecutionError::MissingConfiguration)
    );
}

#[test]
fn plan_and_decode_are_credential_free_and_go_compatible() {
    let dispatcher = SourceExecutionDispatcher;
    let plan = plan(dispatcher);
    let context = context("", 1);
    let metadata = metadata();
    let execution = plan_page(dispatcher, &plan, &context, &metadata);
    assert_eq!(execution.credential_operation, "pagerduty.token");
    assert_eq!(execution.allowed_origin, DEFAULT_BASE_URL);
    assert!(execution.body.is_empty());
    assert!(execution.declared_headers.is_empty());
    let request = execution.request.as_ref().unwrap();
    assert_eq!(request.method, "GET");
    assert_eq!(request.url, "https://api.pagerduty.com/users?limit=2");
    assert!(!request.url.contains("token"));

    let output = decode_page(
        dispatcher,
        &plan,
        &context,
        &metadata,
        &execution,
        200,
        br#"{"users":[{"id":"PU1","name":"Alice","email":"alice@example.test"}],"limit":2,"offset":0,"more":false}"#,
    )
    .unwrap();
    assert_eq!(
        output.receipt.as_ref().unwrap().credential_operation,
        "pagerduty.token"
    );
    let result = output.result.as_ref().unwrap();
    assert!(result.next_cursor.is_empty());
    assert_eq!(result.records.len(), 1);
    let record = &result.records[0];
    assert_eq!(record.provider_id, "PU1");
    assert_eq!(record.attributes["user_id"], "PU1");
    assert_eq!(record.attributes["source_provider"], "pagerduty");
    assert!(record.event_id.starts_with("pagerduty-tenant-"));
    let payload: Value = serde_json::from_slice(&record.payload_json).unwrap();
    assert_eq!(payload["id"], "PU1");

    let decision = seal_page_program_v2(&SourceExecutionLifecycleEnvelopeV2 {
        request: Some(SourceExecutionLifecycleRequestV1 {
            plan: Some(plan),
            context: Some(context),
            receipt: output.receipt,
            result: output.result,
            current_lease_generation: 11,
        }),
        metadata: Some(metadata),
    })
    .unwrap();
    assert_eq!(decision.admitted_records.len(), 1);
    assert_eq!(decision.checkpoint_cursor, "PU1");
}

#[test]
fn provider_offset_and_durable_checkpoint_remain_separate() {
    let dispatcher = SourceExecutionDispatcher;
    let plan = plan(dispatcher);
    let metadata = metadata();
    let first_context = context("", 1);
    let first_execution = plan_page(dispatcher, &plan, &first_context, &metadata);
    let first = decode_page(
        dispatcher,
        &plan,
        &first_context,
        &metadata,
        &first_execution,
        200,
        br#"{"users":[{"id":"PU1"},{"id":"PU2"}],"limit":2,"offset":0,"more":true}"#,
    )
    .unwrap();
    assert_eq!(first.result.as_ref().unwrap().next_cursor, "2");
    let first_decision = seal_page_program_v2(&SourceExecutionLifecycleEnvelopeV2 {
        request: Some(SourceExecutionLifecycleRequestV1 {
            plan: Some(plan.clone()),
            context: Some(first_context),
            receipt: first.receipt,
            result: first.result,
            current_lease_generation: 11,
        }),
        metadata: Some(metadata.clone()),
    })
    .unwrap();
    assert_eq!(first_decision.checkpoint_cursor, "2");

    let second_context = context("2", 2);
    let second_execution = plan_page(dispatcher, &plan, &second_context, &metadata);
    assert_eq!(
        second_execution.request.as_ref().unwrap().url,
        "https://api.pagerduty.com/users?limit=2&offset=2"
    );
    let second = decode_page(
        dispatcher,
        &plan,
        &second_context,
        &metadata,
        &second_execution,
        200,
        br#"{"users":[{"id":"PU3"}],"limit":2,"offset":2,"more":false}"#,
    )
    .unwrap();
    assert!(second.result.as_ref().unwrap().next_cursor.is_empty());
    let second_decision = seal_page_program_v2(&SourceExecutionLifecycleEnvelopeV2 {
        request: Some(SourceExecutionLifecycleRequestV1 {
            plan: Some(plan),
            context: Some(second_context),
            receipt: second.receipt,
            result: second.result,
            current_lease_generation: 11,
        }),
        metadata: Some(metadata),
    })
    .unwrap();
    assert_eq!(second_decision.checkpoint_cursor, "PU3");
}

#[test]
fn origin_cursor_status_and_identity_fail_closed() {
    let dispatcher = SourceExecutionDispatcher;
    let plan = plan(dispatcher);
    let execution_context = context("", 1);

    let mut wrong_origin = metadata();
    wrong_origin
        .public_config
        .insert("base_url".to_owned(), "https://other.invalid".to_owned());
    assert_eq!(
        dispatcher
            .dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(plan.clone()),
                    context: Some(execution_context.clone()),
                }),
                metadata: Some(wrong_origin),
            })
            .unwrap_err(),
        SourceExecutionError::MissingConfiguration
    );

    let invalid_cursor = context("PU1", 2);
    assert_eq!(
        dispatcher
            .dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(plan.clone()),
                    context: Some(invalid_cursor),
                }),
                metadata: Some(metadata()),
            })
            .unwrap_err(),
        SourceExecutionError::InvalidCursor
    );

    let metadata = metadata();
    let execution = plan_page(dispatcher, &plan, &execution_context, &metadata);
    assert_eq!(
        decode_page(
            dispatcher,
            &plan,
            &execution_context,
            &metadata,
            &execution,
            401,
            b"{}",
        )
        .unwrap_err(),
        SourceExecutionError::AuthenticationRejected
    );

    let mut output = decode_page(
        dispatcher,
        &plan,
        &execution_context,
        &metadata,
        &execution,
        200,
        br#"{"users":[{"id":"PU1"}],"limit":2,"offset":0,"more":false}"#,
    )
    .unwrap();
    let mut record = output.result.take().unwrap().records.remove(0);
    record.event_id = "pagerduty-other-identity".to_owned();
    assert_eq!(
        crate::source_execution::SourceExecutionAdapter::validate_record_identity_v2(
            &PAGERDUTY_SOURCE_EXECUTION_ADAPTERS[0],
            &execution_context,
            &record,
            &metadata,
        ),
        Err(SourceExecutionError::TenantMismatch)
    );
}
