use std::collections::{BTreeMap, HashMap};

use cerebro_source_catalog::{HttpMethod, SourceCatalog};
use serde::Deserialize;
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::source_execution::{
    SourceExecutionAdapter, SourceExecutionError, SourceExecutionLifecycleEnvelopeV2,
    SourceExecutionLifecycleRequestV1, SourceExecutionPlanV1, SourceWorkerDecodeEnvelopeV2,
    SourceWorkerDecodeRequestV1, SourceWorkerDecodeResultV1, SourceWorkerExecutionContextV1,
    SourceWorkerHttpExecutionV2, SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1,
    SourceWorkerRuntimeMetadataV2, SourceWorkerSafeReceiptV1, response_digest,
    seal_page_program_v2,
};

use super::{
    CloudflareFamily, CloudflareScope,
    source_execution::{
        CLOUDFLARE_SOURCE_EXECUTION_ADAPTERS, CREDENTIAL_OPERATION,
        CloudflareSourceExecutionAdapter, catalog_path, scope_key,
    },
};

const OBSERVED_AT_MILLIS: i64 = 1_780_272_000_000;
const ORIGIN: &str = "https://api.cloudflare.com/client/v4";
const ACCOUNT_SCOPE: &str = "acct-1";
const ZONE_SCOPE: &str = "zone-1";

#[derive(Deserialize)]
struct OracleEvent {
    attributes: BTreeMap<String, String>,
    payload: Value,
}

fn family_adapter(family: CloudflareFamily) -> &'static CloudflareSourceExecutionAdapter {
    CLOUDFLARE_SOURCE_EXECUTION_ADAPTERS
        .iter()
        .find(|adapter| adapter.family_id() == family.as_str())
        .unwrap()
}

fn oracle(family: CloudflareFamily) -> OracleEvent {
    let payload = match family {
        CloudflareFamily::AccessApplication => {
            include_str!("../../../../sources/cloudflare/testdata/read_access_application.json")
        }
        CloudflareFamily::AccessGroup => {
            include_str!("../../../../sources/cloudflare/testdata/read_access_group.json")
        }
        CloudflareFamily::Account => {
            include_str!("../../../../sources/cloudflare/testdata/read_account.json")
        }
        CloudflareFamily::AccountRuleset => {
            include_str!("../../../../sources/cloudflare/testdata/read_account_ruleset.json")
        }
        CloudflareFamily::AuditLog => {
            include_str!("../../../../sources/cloudflare/testdata/read_audit_log.json")
        }
        CloudflareFamily::Member => {
            include_str!("../../../../sources/cloudflare/testdata/read_member.json")
        }
        CloudflareFamily::GatewayRule => {
            include_str!("../../../../sources/cloudflare/testdata/read_gateway_rule.json")
        }
        CloudflareFamily::LoadBalancer => {
            include_str!("../../../../sources/cloudflare/testdata/read_load_balancer.json")
        }
        CloudflareFamily::LoadBalancerPool => {
            include_str!("../../../../sources/cloudflare/testdata/read_load_balancer_pool.json")
        }
        CloudflareFamily::Role => {
            include_str!("../../../../sources/cloudflare/testdata/read_role.json")
        }
        CloudflareFamily::WorkerScript => {
            include_str!("../../../../sources/cloudflare/testdata/read_worker_script.json")
        }
        CloudflareFamily::Zone => {
            include_str!("../../../../sources/cloudflare/testdata/read_zone.json")
        }
        CloudflareFamily::ZoneAccessApplication => include_str!(
            "../../../../sources/cloudflare/testdata/read_zone_access_application.json"
        ),
        CloudflareFamily::ZoneAccessGroup => {
            include_str!("../../../../sources/cloudflare/testdata/read_zone_access_group.json")
        }
        CloudflareFamily::ZoneRuleset => {
            include_str!("../../../../sources/cloudflare/testdata/read_zone_ruleset.json")
        }
        CloudflareFamily::DnsRecord => {
            include_str!("../../../../sources/cloudflare/testdata/read_dns_record.json")
        }
    };
    serde_json::from_str::<Vec<OracleEvent>>(payload)
        .unwrap()
        .into_iter()
        .next()
        .unwrap()
}

/// The Go oracle fixtures carry their own account or zone scope; the bridge
/// must plan and decode under exactly that scope.
fn oracle_scope(family: CloudflareFamily, event: &OracleEvent) -> Option<String> {
    let key = scope_key(family)?;
    Some(
        event
            .attributes
            .get(key)
            .cloned()
            .unwrap_or_else(|| default_scope(family).unwrap().to_owned()),
    )
}

const fn default_scope(family: CloudflareFamily) -> Option<&'static str> {
    match family.scope() {
        CloudflareScope::None => None,
        CloudflareScope::Account => Some(ACCOUNT_SCOPE),
        CloudflareScope::Zone => Some(ZONE_SCOPE),
    }
}

fn response(records: Vec<Value>, page: u64, total_pages: u64) -> Vec<u8> {
    let total_count = records.len();
    serde_json::to_vec(&json!({
        "success": true,
        "errors": [],
        "messages": [],
        "result": records,
        "result_info": {
            "page": page,
            "per_page": 100,
            "total_pages": total_pages,
            "total_count": total_count
        }
    }))
    .unwrap()
}

fn context(cursor: &str, page: u32) -> SourceWorkerExecutionContextV1 {
    SourceWorkerExecutionContextV1 {
        tenant_id: "tenant".to_owned(),
        runtime_id: "cloudflare-runtime".to_owned(),
        logical_page_id: format!("source-page-v2:cloudflare-{page}"),
        prior_cursor: cursor.to_owned(),
        runtime_generation: 7,
        lease_generation: 11,
        observed_at_unix_millis: OBSERVED_AT_MILLIS,
    }
}

/// The host forwards both declared Cloudflare selectors regardless of family;
/// the bridge must read only the selector the selected family needs.
fn family_metadata(family: CloudflareFamily) -> SourceWorkerRuntimeMetadataV2 {
    scoped_metadata(family, default_scope(family))
}

fn scoped_metadata(family: CloudflareFamily, scope: Option<&str>) -> SourceWorkerRuntimeMetadataV2 {
    let mut public_config = HashMap::from([
        ("family".to_owned(), family.as_str().to_owned()),
        ("account_id".to_owned(), ACCOUNT_SCOPE.to_owned()),
        ("zone_id".to_owned(), ZONE_SCOPE.to_owned()),
    ]);
    if let (Some(key), Some(scope)) = (scope_key(family), scope) {
        public_config.insert(key.to_owned(), scope.to_owned());
    }
    SourceWorkerRuntimeMetadataV2 {
        public_config,
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    }
}

fn plan_page(
    adapter: &CloudflareSourceExecutionAdapter,
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    metadata: &SourceWorkerRuntimeMetadataV2,
) -> SourceWorkerHttpExecutionV2 {
    plan_result(adapter, plan, context, metadata).unwrap()
}

fn plan_error(
    adapter: &CloudflareSourceExecutionAdapter,
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    metadata: &SourceWorkerRuntimeMetadataV2,
) -> SourceExecutionError {
    plan_result(adapter, plan, context, metadata).unwrap_err()
}

fn plan_result(
    adapter: &CloudflareSourceExecutionAdapter,
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    metadata: &SourceWorkerRuntimeMetadataV2,
) -> Result<SourceWorkerHttpExecutionV2, SourceExecutionError> {
    adapter.plan_v2(&SourceWorkerPlanEnvelopeV2 {
        request: Some(SourceWorkerPlanRequestV1 {
            plan: Some(plan.clone()),
            context: Some(context.clone()),
        }),
        metadata: Some(metadata.clone()),
    })
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
    adapter: &CloudflareSourceExecutionAdapter,
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

fn millis(rfc3339: &str) -> i64 {
    i64::try_from(
        OffsetDateTime::parse(rfc3339, &Rfc3339)
            .unwrap()
            .unix_timestamp_nanos()
            / 1_000_000,
    )
    .unwrap()
}

#[test]
fn cloudflare_adapter_set_covers_every_catalog_family() {
    assert_eq!(CLOUDFLARE_SOURCE_EXECUTION_ADAPTERS.len(), 16);
    assert_eq!(
        CLOUDFLARE_SOURCE_EXECUTION_ADAPTERS.len(),
        CloudflareFamily::ALL.len()
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let catalog = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )
    .unwrap();
    let source = catalog.get("cloudflare").unwrap();
    for (adapter, family) in CLOUDFLARE_SOURCE_EXECUTION_ADAPTERS
        .iter()
        .zip(CloudflareFamily::ALL)
    {
        let plan = adapter.compiled_plan();
        assert_eq!(adapter.source_id(), "cloudflare");
        assert_eq!(adapter.family_id(), family.as_str());
        assert_eq!(adapter.provider_kernel(), family.event_kind());
        assert_eq!(
            plan.plan_id,
            format!("source-plan-v1:cloudflare:{}", family.as_str())
        );
        assert_eq!(plan.source_id, "cloudflare");
        assert_eq!(plan.family_id, family.as_str());
        assert_eq!(plan.provider_kernel, family.event_kind());
        assert_eq!(plan.event_kind, family.event_kind());
        assert_eq!(plan.schema_ref, family.schema_ref());
        assert_eq!(plan.origin, ORIGIN);
        assert_eq!(plan.method, "GET");
        assert_eq!(plan.max_response_bytes, 8 << 20);
        assert_eq!(plan.required_payload_fields, vec!["id".to_owned()]);
        assert!(
            plan.required_attributes
                .contains(&family.id_attribute().to_owned())
        );
        assert!(!plan.plan_digest_sha256.is_empty());

        let cataloged = source
            .families()
            .iter()
            .find(|cataloged| cataloged.id() == family.as_str())
            .unwrap();
        assert_eq!(cataloged.method(), HttpMethod::Get);
        assert_eq!(plan.path, format!("/client/v4{}", cataloged.path()));
        assert_eq!(plan.path, format!("/client/v4{}", catalog_path(family)));
        assert_eq!(plan.record_selector, cataloged.record_selector());
        assert_eq!(plan.id_field, cataloged.id_field());
        assert_eq!(
            cataloged
                .path_parameters()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            scope_key(family).into_iter().collect::<Vec<_>>(),
            "{} path parameters",
            family.as_str()
        );
    }
}

#[test]
fn cloudflare_plans_every_family_without_credentials() {
    for family in CloudflareFamily::ALL {
        let adapter = family_adapter(family);
        let plan = adapter.compiled_plan();
        let scoped_path = match default_scope(family) {
            Some(scope) => family.path_template().replace("{scope}", scope),
            None => family.path_template().to_owned(),
        };
        for (cursor, page) in [("", 1), ("3", 3)] {
            let context = context(cursor, page);
            let metadata = family_metadata(family);
            let execution = plan_page(adapter, &plan, &context, &metadata);
            assert_eq!(execution.credential_operation, CREDENTIAL_OPERATION);
            assert_eq!(execution.credential_operation, "source.bearer");
            assert_eq!(execution.allowed_origin, ORIGIN);
            assert!(execution.body.is_empty());
            assert!(execution.declared_headers.is_empty());
            assert!(!execution.execution_intent_digest_sha256.is_empty());
            let request = execution.request.unwrap();
            assert_eq!(request.plan_id, plan.plan_id);
            assert_eq!(request.plan_digest_sha256, plan.plan_digest_sha256);
            assert_eq!(request.method, "GET");
            assert_eq!(request.accept, "application/json");
            assert_eq!(request.max_response_bytes, 8 << 20);
            assert_eq!(
                request.url,
                format!("{ORIGIN}{scoped_path}?page={page}&per_page=100"),
                "{} page {page}",
                family.as_str()
            );
            assert!(!request.request_intent_digest.is_empty());
            for secret_marker in ["authorization", "bearer", "token", "secret", "key="] {
                assert!(!request.url.to_ascii_lowercase().contains(secret_marker));
            }
        }
    }
}

#[test]
fn cloudflare_decodes_go_oracle_fixtures_with_exact_contract_and_seals() {
    for family in CloudflareFamily::ALL {
        let adapter = family_adapter(family);
        let plan = adapter.compiled_plan();
        let context = context("", 1);
        let oracle = oracle(family);
        let scope = oracle_scope(family, &oracle);
        let metadata = scoped_metadata(family, scope.as_deref());
        let execution = plan_page(adapter, &plan, &context, &metadata);
        let body = response(vec![oracle.payload.clone()], 1, 1);
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
        assert!(result.next_cursor.is_empty(), "{}", family.as_str());
        assert_eq!(result.records.len(), 1, "{}", family.as_str());
        let record = &result.records[0];
        assert_eq!(record.provider_id, oracle.payload["id"].as_str().unwrap());
        assert_eq!(record.attributes["tenant_id"], "tenant");
        assert_eq!(record.attributes["source_event_id"], record.provider_id);
        assert_eq!(record.attributes["external_id"], record.provider_id);
        assert_eq!(record.attributes["family"], family.as_str());
        assert_eq!(record.attributes["provider"], "cloudflare");
        assert_eq!(
            record.attributes.get(family.id_attribute()),
            oracle.attributes.get(family.id_attribute()),
            "{} ID attribute",
            family.as_str()
        );
        if let (Some(key), Some(scope)) = (scope_key(family), scope.as_deref()) {
            assert_eq!(record.attributes[key], scope, "{} scope", family.as_str());
        }
        assert!(
            record
                .event_id
                .starts_with(&format!("cloudflare-{}-", family.as_str()))
        );
        assert!(!record.event_id.contains("tenant"));
        match oracle.attributes.get("observed_at") {
            Some(observed_at) => {
                assert_eq!(record.occurred_at_unix_millis, millis(observed_at))
            }
            None => assert_eq!(record.occurred_at_unix_millis, OBSERVED_AT_MILLIS),
        }
        for attribute in &plan.required_attributes {
            assert!(
                record
                    .attributes
                    .get(attribute)
                    .is_some_and(|value| !value.is_empty()),
                "{} missing required attribute {attribute}",
                family.as_str()
            );
        }
        let payload: Value = serde_json::from_slice(&record.payload_json).unwrap();
        assert_eq!(payload, oracle.payload);
        for field in &plan.required_payload_fields {
            assert!(
                payload.get(field).is_some_and(|value| !value.is_null()),
                "{} missing required payload field {field}",
                family.as_str()
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
        assert_eq!(decision.admitted_records.len(), 1, "{}", family.as_str());
        assert!(decision.checkpoint_cursor.is_empty());
    }
}

#[test]
fn cloudflare_pagination_and_provider_failures_are_typed() {
    let family = CloudflareFamily::Member;
    let adapter = family_adapter(family);
    let plan = adapter.compiled_plan();
    let metadata = family_metadata(family);
    let member = json!({"id": "member-1", "account_id": ACCOUNT_SCOPE, "status": "accepted"});
    let first = decode_page(
        adapter,
        &plan,
        &context("", 1),
        &metadata,
        200,
        &response(vec![member.clone()], 1, 3),
        HashMap::new(),
    )
    .unwrap();
    assert_eq!(first.next_cursor, "2");
    let second = decode_page(
        adapter,
        &plan,
        &context("2", 2),
        &metadata,
        200,
        &response(vec![member.clone()], 2, 3),
        HashMap::new(),
    )
    .unwrap();
    assert_eq!(second.next_cursor, "3");
    let last = decode_page(
        adapter,
        &plan,
        &context("3", 3),
        &metadata,
        200,
        &response(vec![member.clone()], 3, 3),
        HashMap::new(),
    )
    .unwrap();
    assert!(last.next_cursor.is_empty());
    assert_eq!(
        decode_page(
            adapter,
            &plan,
            &context("2", 2),
            &metadata,
            200,
            &response(vec![member], 3, 3),
            HashMap::new(),
        ),
        Err(SourceExecutionError::InvalidCursor)
    );

    let family = CloudflareFamily::Zone;
    let adapter = family_adapter(family);
    let plan = adapter.compiled_plan();
    let context = context("", 1);
    let metadata = family_metadata(family);
    for (status, expected) in [
        (401, SourceExecutionError::AuthenticationRejected),
        (403, SourceExecutionError::RequiredProviderScopeMissing),
        (404, SourceExecutionError::UnexpectedProviderStatus),
        (500, SourceExecutionError::UnexpectedProviderStatus),
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
            Err(expected),
            "status {status}"
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
    assert_eq!(
        decode_page(
            adapter,
            &plan,
            &context,
            &metadata,
            429,
            b"{}",
            HashMap::from([("retry-after".to_owned(), "3601".to_owned())]),
        ),
        Err(SourceExecutionError::UnexpectedProviderStatus)
    );
    assert_eq!(
        decode_page(
            adapter,
            &plan,
            &context,
            &metadata,
            200,
            br#"{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}"#,
            HashMap::new(),
        ),
        Err(SourceExecutionError::UnexpectedProviderStatus)
    );
    assert_eq!(
        decode_page(
            adapter,
            &plan,
            &context,
            &metadata,
            200,
            b"not json",
            HashMap::new(),
        ),
        Err(SourceExecutionError::MalformedResponse)
    );
}

#[test]
fn cloudflare_rejects_bad_cursor_family_scope_plan_duplicates_and_secret_material() {
    let family = CloudflareFamily::DnsRecord;
    let adapter = family_adapter(family);
    let plan = adapter.compiled_plan();
    let metadata = family_metadata(family);
    for cursor in ["0", "-1", "next", "10001"] {
        assert_eq!(
            plan_error(adapter, &plan, &context(cursor, 2), &metadata),
            SourceExecutionError::InvalidCursor,
            "cursor {cursor}"
        );
    }

    let mut wrong_family = metadata.clone();
    wrong_family
        .public_config
        .insert("family".to_owned(), "zone".to_owned());
    assert_eq!(
        plan_error(adapter, &plan, &context("", 1), &wrong_family),
        SourceExecutionError::MissingConfiguration
    );

    let mut missing_zone = metadata.clone();
    missing_zone.public_config.remove("zone_id");
    assert_eq!(
        plan_error(adapter, &plan, &context("", 1), &missing_zone),
        SourceExecutionError::MissingConfiguration
    );
    let mut blank_zone = metadata.clone();
    blank_zone
        .public_config
        .insert("zone_id".to_owned(), "  ".to_owned());
    assert_eq!(
        plan_error(adapter, &plan, &context("", 1), &blank_zone),
        SourceExecutionError::MissingConfiguration
    );
    let mut missing_account = family_metadata(CloudflareFamily::Member);
    missing_account.public_config.remove("account_id");
    assert_eq!(
        plan_error(
            family_adapter(CloudflareFamily::Member),
            &family_adapter(CloudflareFamily::Member).compiled_plan(),
            &context("", 1),
            &missing_account,
        ),
        SourceExecutionError::MissingConfiguration
    );
    // Global families never read a selector, so forwarded account and zone
    // IDs do not change their planned request.
    let mut no_selectors = family_metadata(CloudflareFamily::Account);
    no_selectors.public_config.remove("account_id");
    no_selectors.public_config.remove("zone_id");
    let account_adapter = family_adapter(CloudflareFamily::Account);
    let account_plan = account_adapter.compiled_plan();
    assert_eq!(
        plan_page(
            account_adapter,
            &account_plan,
            &context("", 1),
            &no_selectors
        )
        .request,
        plan_page(
            account_adapter,
            &account_plan,
            &context("", 1),
            &family_metadata(CloudflareFamily::Account),
        )
        .request
    );

    let mut bad_origin = metadata.clone();
    bad_origin.public_config.insert(
        "base_url".to_owned(),
        "http://api.cloudflare.com/client/v4".to_owned(),
    );
    assert_eq!(
        plan_error(adapter, &plan, &context("", 1), &bad_origin),
        SourceExecutionError::MissingConfiguration
    );

    let mut tampered = plan.clone();
    tampered.path = "/client/v4/zones/{zone_id}/dns_records/export".to_owned();
    assert_eq!(
        plan_error(adapter, &tampered, &context("", 1), &metadata),
        SourceExecutionError::InvalidPlan
    );
    assert_eq!(
        plan_error(
            adapter,
            &family_adapter(CloudflareFamily::Zone).compiled_plan(),
            &context("", 1),
            &metadata,
        ),
        SourceExecutionError::InvalidPlan
    );

    let execution_context = context("", 1);
    let original = json!({
        "id": "record-1",
        "zone_id": ZONE_SCOPE,
        "name": "www.example.com",
        "type": "A",
        "content": "192.0.2.1",
        "proxied": true,
        "modified_on": "2026-06-01T00:00:00Z"
    });
    let result = decode_page(
        adapter,
        &plan,
        &execution_context,
        &metadata,
        200,
        &response(vec![original.clone(), original.clone()], 1, 1),
        HashMap::new(),
    )
    .unwrap();
    assert_eq!(result.records.len(), 1);
    assert_eq!(
        result.records[0].occurred_at_unix_millis,
        millis("2026-06-01T00:00:00Z")
    );

    let mut conflicting = original.clone();
    conflicting["content"] = Value::from("198.51.100.7");
    assert_eq!(
        decode_page(
            adapter,
            &plan,
            &execution_context,
            &metadata,
            200,
            &response(vec![original.clone(), conflicting], 1, 1),
            HashMap::new(),
        ),
        Err(SourceExecutionError::DuplicateConflict)
    );

    let mut secret = original.clone();
    secret["nested"] = json!({"api_token": "credential-material"});
    let error = decode_page(
        adapter,
        &plan,
        &execution_context,
        &metadata,
        200,
        &response(vec![secret], 1, 1),
        HashMap::new(),
    )
    .unwrap_err();
    assert_eq!(error, SourceExecutionError::InvalidProviderRecord);
    assert!(!format!("{error:?}").contains("credential-material"));

    // Provider data cannot replace the authenticated tenant: the kernel binds
    // identity to trusted context and ignores a provider-supplied tenant.
    let mut untrusted_scope = original.clone();
    untrusted_scope["tenant_id"] = Value::from("untrusted-tenant");
    untrusted_scope["nested"] = json!({"tenant_id": "untrusted-tenant"});
    let result = decode_page(
        adapter,
        &plan,
        &execution_context,
        &metadata,
        200,
        &response(vec![untrusted_scope], 1, 1),
        HashMap::new(),
    )
    .unwrap();
    assert_eq!(result.records[0].attributes["tenant_id"], "tenant");
    assert!(!result.records[0].event_id.contains("untrusted"));
    adapter
        .validate_record_identity_v2(&execution_context, &result.records[0], &metadata)
        .unwrap();

    let mut foreign_zone = original.clone();
    foreign_zone["zone_id"] = Value::from("zone-2");
    assert_eq!(
        decode_page(
            adapter,
            &plan,
            &execution_context,
            &metadata,
            200,
            &response(vec![foreign_zone], 1, 1),
            HashMap::new(),
        ),
        Err(SourceExecutionError::InvalidProviderRecord)
    );

    let mut missing_id = original.clone();
    missing_id.as_object_mut().unwrap().remove("id");
    assert_eq!(
        decode_page(
            adapter,
            &plan,
            &execution_context,
            &metadata,
            200,
            &response(vec![missing_id], 1, 1),
            HashMap::new(),
        ),
        Err(SourceExecutionError::MissingStableIdentity)
    );

    let mut bad_timestamp = original;
    bad_timestamp["modified_on"] = Value::from("yesterday");
    assert_eq!(
        decode_page(
            adapter,
            &plan,
            &execution_context,
            &metadata,
            200,
            &response(vec![bad_timestamp], 1, 1),
            HashMap::new(),
        ),
        Err(SourceExecutionError::InvalidProviderRecord)
    );
}

#[test]
fn cloudflare_identity_validation_is_bound_to_tenant_and_scope() {
    let family = CloudflareFamily::AuditLog;
    let adapter = family_adapter(family);
    let plan = adapter.compiled_plan();
    let execution_context = context("", 1);
    let metadata = family_metadata(family);
    let body = response(
        vec![json!({
            "id": "audit-1",
            "when": "2026-06-01T00:00:00Z",
            "action": {"type": "zone.settings.update"},
            "actor": {"email": "admin@example.com", "ip": "198.51.100.10"},
            "resource": {"id": "zone-1", "type": "zone"},
            "account": {"id": ACCOUNT_SCOPE}
        })],
        1,
        1,
    );
    let result = decode_page(
        adapter,
        &plan,
        &execution_context,
        &metadata,
        200,
        &body,
        HashMap::new(),
    )
    .unwrap();
    let record = &result.records[0];
    adapter
        .validate_record_identity_v2(&execution_context, record, &metadata)
        .unwrap();

    let mut other_tenant = execution_context.clone();
    other_tenant.tenant_id = "other-tenant".to_owned();
    assert_eq!(
        adapter.validate_record_identity_v2(&other_tenant, record, &metadata),
        Err(SourceExecutionError::TenantMismatch)
    );
    let mut other_scope = metadata.clone();
    other_scope
        .public_config
        .insert("account_id".to_owned(), "acct-2".to_owned());
    assert_eq!(
        adapter.validate_record_identity_v2(&execution_context, record, &other_scope),
        Err(SourceExecutionError::TenantMismatch)
    );
    let mut forged = record.clone();
    forged.event_id = "cloudflare-audit_log-000000000000000000000000".to_owned();
    assert_eq!(
        adapter.validate_record_identity_v2(&execution_context, &forged, &metadata),
        Err(SourceExecutionError::TenantMismatch)
    );
    // Scoped families cannot be re-validated without the public selector that
    // bound their identity.
    assert_eq!(
        adapter.validate_record_identity(&execution_context, record),
        Err(SourceExecutionError::MissingConfiguration)
    );
    let zone_adapter = family_adapter(CloudflareFamily::Zone);
    let zone_plan = zone_adapter.compiled_plan();
    let zone_result = decode_page(
        zone_adapter,
        &zone_plan,
        &execution_context,
        &family_metadata(CloudflareFamily::Zone),
        200,
        &response(vec![json!({"id": "zone-1", "name": "example.com"})], 1, 1),
        HashMap::new(),
    )
    .unwrap();
    zone_adapter
        .validate_record_identity(&execution_context, &zone_result.records[0])
        .unwrap();
}
