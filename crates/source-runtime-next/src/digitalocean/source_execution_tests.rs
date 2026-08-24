use std::collections::HashMap;

use serde_json::{Value, json};

use crate::source_execution::{
    SourceExecutionDispatcher, SourceExecutionError, SourceExecutionLifecycleEnvelopeV2,
    SourceExecutionLifecycleRequestV1, SourceExecutionPlanV1, SourceExecutionSelectionRequestV1,
    SourceWorkerDecodeEnvelopeV2, SourceWorkerDecodeOutputV2, SourceWorkerDecodeRequestV1,
    SourceWorkerExecutionContextV1, SourceWorkerHttpExecutionV2, SourceWorkerPlanEnvelopeV2,
    SourceWorkerPlanRequestV1, SourceWorkerRuntimeMetadataV2, seal_page_program_v2,
};

use super::{DEFAULT_BASE_URL, DIGITALOCEAN_SOURCE_EXECUTION_ADAPTERS};

const OBSERVED_AT_MILLIS: i64 = 1_780_444_800_000;
const DROPLETS_FIXTURE: &[u8] =
    include_bytes!("../../../../sources/digitalocean/testdata/read_droplets.json");
const VPCS_FIXTURE: &[u8] =
    include_bytes!("../../../../sources/digitalocean/testdata/read_vpcs.json");
const FIREWALLS_FIXTURE: &[u8] =
    include_bytes!("../../../../sources/digitalocean/testdata/read_firewalls.json");

fn context(cursor: &str, page: u32) -> SourceWorkerExecutionContextV1 {
    SourceWorkerExecutionContextV1 {
        tenant_id: "tenant".to_owned(),
        runtime_id: "digitalocean-runtime".to_owned(),
        logical_page_id: format!("source-page-v2:digitalocean-{page}"),
        prior_cursor: cursor.to_owned(),
        runtime_generation: 7,
        lease_generation: 11,
        observed_at_unix_millis: OBSERVED_AT_MILLIS,
    }
}

fn metadata() -> SourceWorkerRuntimeMetadataV2 {
    SourceWorkerRuntimeMetadataV2 {
        public_config: HashMap::from([("per_page".to_owned(), "2".to_owned())]),
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    }
}

fn plan(dispatcher: SourceExecutionDispatcher, family: &str) -> SourceExecutionPlanV1 {
    dispatcher
        .compile_plan(&SourceExecutionSelectionRequestV1 {
            source_id: "digitalocean".to_owned(),
            family_id: family.to_owned(),
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
fn closed_dispatcher_registers_all_cataloged_digitalocean_families() {
    let dispatcher = SourceExecutionDispatcher;
    let droplets = plan(dispatcher, "droplets");
    assert_eq!(droplets.plan_id, "source-plan-v1:digitalocean:droplets");
    assert_eq!(droplets.provider_kernel, "digitalocean.droplets");
    assert_eq!(droplets.origin, DEFAULT_BASE_URL);
    assert_eq!(droplets.path, "/v2/droplets");
    assert_eq!(droplets.record_selector, "$.droplets[*]");
    assert_eq!(droplets.event_kind, "digitalocean.droplets");
    assert_eq!(droplets.schema_ref, "digitalocean/droplets/v1");
    assert_eq!(droplets.max_response_bytes, 8 << 20);

    let vpcs = plan(dispatcher, "vpcs");
    assert_eq!(vpcs.plan_id, "source-plan-v1:digitalocean:vpcs");
    assert_eq!(vpcs.provider_kernel, "digitalocean.vpcs");
    assert_eq!(vpcs.path, "/v2/vpcs");
    assert_eq!(vpcs.record_selector, "$.vpcs[*]");
    assert_eq!(vpcs.event_kind, "digitalocean.vpcs");
    assert_eq!(vpcs.schema_ref, "digitalocean/vpcs/v1");

    let firewalls = plan(dispatcher, "firewalls");
    assert_eq!(firewalls.plan_id, "source-plan-v1:digitalocean:firewalls");
    assert_eq!(firewalls.provider_kernel, "digitalocean.firewalls");
    assert_eq!(firewalls.path, "/v2/firewalls");
    assert_eq!(firewalls.record_selector, "$.firewalls[*]");
    assert_eq!(firewalls.event_kind, "digitalocean.firewalls");
    assert_eq!(firewalls.schema_ref, "digitalocean/firewalls/v1");

    for family in ["", "future"] {
        assert_eq!(
            dispatcher.compile_plan(&SourceExecutionSelectionRequestV1 {
                source_id: "digitalocean".to_owned(),
                family_id: family.to_owned(),
            }),
            Err(SourceExecutionError::UnknownAdapter),
            "{family}"
        );
    }

    let mut modified = droplets;
    modified.path = "/v2/account".to_owned();
    let error = dispatcher
        .dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(modified),
                context: Some(context("", 1)),
            }),
            metadata: Some(metadata()),
        })
        .unwrap_err();
    assert_eq!(error, SourceExecutionError::InvalidPlan);
}

#[test]
fn droplets_plan_and_decode_are_credential_free_tenant_scoped_and_sealable() {
    let dispatcher = SourceExecutionDispatcher;
    let plan = plan(dispatcher, "droplets");
    let execution_context = context("", 1);
    let metadata = metadata();
    let execution = plan_page(dispatcher, &plan, &execution_context, &metadata);
    assert_eq!(execution.credential_operation, "source.bearer");
    assert_eq!(execution.allowed_origin, DEFAULT_BASE_URL);
    assert!(execution.body.is_empty());
    assert!(execution.declared_headers.is_empty());
    let request = execution.request.as_ref().unwrap();
    assert_eq!(request.method, "GET");
    assert_eq!(
        request.url,
        "https://api.digitalocean.com/v2/droplets?page=1&per_page=2"
    );
    assert!(!request.url.contains("token"));

    let output = decode_page(
        dispatcher,
        &plan,
        &execution_context,
        &metadata,
        &execution,
        200,
        DROPLETS_FIXTURE,
    )
    .unwrap();
    let receipt = output.receipt.as_ref().unwrap();
    assert_eq!(receipt.credential_operation, "source.bearer");
    let result = output.result.as_ref().unwrap();
    assert_eq!(result.records.len(), 2);
    assert!(result.next_cursor.is_empty());
    let first = &result.records[0];
    assert_eq!(first.provider_id, "3164444");
    assert_eq!(first.attributes["tenant_id"], "tenant");
    assert_eq!(first.attributes["source_event_id"], "3164444");
    assert_eq!(
        first.attributes["resource_urn"],
        "urn:cerebro:tenant:digitalocean_droplets:3164444"
    );
    let payload: Value = serde_json::from_slice(&first.payload_json).unwrap();
    assert_eq!(payload["id"], 3_164_444);
    assert_eq!(payload["vpc_uuid"], "vpc-1111");

    let decision = seal_page_program_v2(&SourceExecutionLifecycleEnvelopeV2 {
        request: Some(SourceExecutionLifecycleRequestV1 {
            plan: Some(plan),
            context: Some(execution_context),
            receipt: output.receipt,
            result: output.result,
            current_lease_generation: 11,
        }),
        metadata: Some(metadata),
    })
    .unwrap();
    assert_eq!(decision.admitted_records.len(), 2);
    assert!(decision.checkpoint_cursor.is_empty());
    assert_eq!(decision.checkpoint_watermark_unix_millis, 1_780_272_000_000);
}

#[test]
fn vpcs_plan_and_decode_use_the_shared_credential_free_execution_contract() {
    let dispatcher = SourceExecutionDispatcher;
    let plan = plan(dispatcher, "vpcs");
    let execution_context = context("", 1);
    let metadata = metadata();
    let execution = plan_page(dispatcher, &plan, &execution_context, &metadata);
    assert_eq!(execution.credential_operation, "source.bearer");
    assert_eq!(execution.allowed_origin, DEFAULT_BASE_URL);
    assert!(execution.body.is_empty());
    assert!(execution.declared_headers.is_empty());
    assert_eq!(
        execution.request.as_ref().unwrap().url,
        "https://api.digitalocean.com/v2/vpcs?page=1&per_page=2"
    );

    let output = decode_page(
        dispatcher,
        &plan,
        &execution_context,
        &metadata,
        &execution,
        200,
        VPCS_FIXTURE,
    )
    .unwrap();
    let result = output.result.as_ref().unwrap();
    assert_eq!(result.records.len(), 1);
    assert!(result.next_cursor.is_empty());
    let record = &result.records[0];
    assert_eq!(record.provider_id, "vpc-1111");
    assert_eq!(record.attributes["tenant_id"], "tenant");
    assert_eq!(record.attributes["resource_type"], "vpc");
    assert_eq!(
        record.attributes["resource_urn"],
        "urn:cerebro:tenant:digitalocean_vpcs:vpc-1111"
    );
    let payload: Value = serde_json::from_slice(&record.payload_json).unwrap();
    assert_eq!(payload["id"], "vpc-1111");
    assert_eq!(payload["ip_range"], "192.0.2.0/24");
    assert_eq!(payload["default"], true);

    crate::source_execution::SourceExecutionAdapter::validate_record_identity(
        &DIGITALOCEAN_SOURCE_EXECUTION_ADAPTERS[1],
        &execution_context,
        record,
    )
    .unwrap();
}

#[test]
fn firewalls_plan_and_decode_preserve_security_projection_fields() {
    let dispatcher = SourceExecutionDispatcher;
    let plan = plan(dispatcher, "firewalls");
    let execution_context = context("", 1);
    let metadata = metadata();
    let execution = plan_page(dispatcher, &plan, &execution_context, &metadata);
    assert_eq!(execution.credential_operation, "source.bearer");
    assert_eq!(execution.allowed_origin, DEFAULT_BASE_URL);
    assert!(execution.body.is_empty());
    assert!(execution.declared_headers.is_empty());
    assert_eq!(
        execution.request.as_ref().unwrap().url,
        "https://api.digitalocean.com/v2/firewalls?page=1&per_page=2"
    );

    let output = decode_page(
        dispatcher,
        &plan,
        &execution_context,
        &metadata,
        &execution,
        200,
        FIREWALLS_FIXTURE,
    )
    .unwrap();
    let result = output.result.as_ref().unwrap();
    assert_eq!(result.records.len(), 1);
    assert!(result.next_cursor.is_empty());
    let record = &result.records[0];
    assert_eq!(record.provider_id, "fw-2222");
    assert_eq!(record.attributes["tenant_id"], "tenant");
    assert_eq!(record.attributes["resource_type"], "firewall");
    assert_eq!(record.attributes["public_ingress"], "true");
    assert_eq!(record.attributes["droplet_ids"], "3164444,3164445");
    assert_eq!(
        record.attributes["resource_urn"],
        "urn:cerebro:tenant:digitalocean_firewalls:fw-2222"
    );
    let payload: Value = serde_json::from_slice(&record.payload_json).unwrap();
    assert_eq!(payload["id"], "fw-2222");
    assert_eq!(payload["public"], true);
    assert_eq!(payload["droplet_ids"], json!([3_164_444, 3_164_445]));

    crate::source_execution::SourceExecutionAdapter::validate_record_identity(
        &DIGITALOCEAN_SOURCE_EXECUTION_ADAPTERS[2],
        &execution_context,
        record,
    )
    .unwrap();
}

#[test]
fn provider_pagination_round_trips_as_a_bounded_numeric_cursor() {
    let dispatcher = SourceExecutionDispatcher;
    let plan = plan(dispatcher, "droplets");
    let first_context = context("", 1);
    let metadata = metadata();
    let first_execution = plan_page(dispatcher, &plan, &first_context, &metadata);
    let mut body: Value = serde_json::from_slice(DROPLETS_FIXTURE).unwrap();
    body["links"] = json!({
        "pages": {"next": "https://untrusted.invalid/v2/droplets?page=999"}
    });
    let output = decode_page(
        dispatcher,
        &plan,
        &first_context,
        &metadata,
        &first_execution,
        200,
        &serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    assert_eq!(output.result.unwrap().next_cursor, "2");

    let resumed_context = context("2", 2);
    let resumed = plan_page(dispatcher, &plan, &resumed_context, &metadata);
    assert_eq!(
        resumed.request.unwrap().url,
        "https://api.digitalocean.com/v2/droplets?page=2&per_page=2"
    );
}

#[test]
fn public_config_status_cursor_and_provider_tenant_inputs_fail_closed() {
    let dispatcher = SourceExecutionDispatcher;
    let plan = plan(dispatcher, "droplets");
    let execution_context = context("", 1);

    let mut secret_metadata = metadata();
    secret_metadata
        .public_config
        .insert("token".to_owned(), "must-not-cross".to_owned());
    assert_eq!(
        dispatcher
            .dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(plan.clone()),
                    context: Some(execution_context.clone()),
                }),
                metadata: Some(secret_metadata),
            })
            .unwrap_err(),
        SourceExecutionError::InvalidExecutionContext
    );

    let mut wrong_origin = metadata();
    wrong_origin
        .public_config
        .insert("base_url".to_owned(), "https://other.invalid/v2".to_owned());
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

    let invalid_cursor = context("next", 2);
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

    let mut poisoned: Value = serde_json::from_slice(DROPLETS_FIXTURE).unwrap();
    poisoned["droplets"][0]["tenant_id"] = json!("provider-tenant");
    assert_eq!(
        decode_page(
            dispatcher,
            &plan,
            &execution_context,
            &metadata,
            &execution,
            200,
            &serde_json::to_vec(&poisoned).unwrap(),
        )
        .unwrap_err(),
        SourceExecutionError::TenantMismatch
    );
}

#[test]
fn adapter_identity_validation_matches_the_provider_kernel() {
    let dispatcher = SourceExecutionDispatcher;
    let plan = plan(dispatcher, "droplets");
    let context = context("", 1);
    let metadata = metadata();
    let execution = plan_page(dispatcher, &plan, &context, &metadata);
    let mut output = decode_page(
        dispatcher,
        &plan,
        &context,
        &metadata,
        &execution,
        200,
        DROPLETS_FIXTURE,
    )
    .unwrap();
    let mut record = output.result.take().unwrap().records.remove(0);
    record.event_id = "id-deadbeef".to_owned();
    assert_eq!(
        crate::source_execution::SourceExecutionAdapter::validate_record_identity(
            &DIGITALOCEAN_SOURCE_EXECUTION_ADAPTERS[0],
            &context,
            &record,
        ),
        Err(SourceExecutionError::TenantMismatch)
    );
}
