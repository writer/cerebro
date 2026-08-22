use std::{collections::BTreeMap, fs, path::PathBuf};

use cerebro_source_catalog::{CollectionAuthority, SourceCatalog};
use serde::Deserialize;
use serde_json::{Value, json};

use super::*;

const OBSERVED_AT: &str = "2026-06-01T00:00:00Z";

#[derive(Debug, Deserialize)]
struct GoOracleEvent {
    id: String,
    tenant_id: String,
    source_id: String,
    kind: String,
    occurred_at: String,
    schema_ref: String,
    payload: Value,
    attributes: BTreeMap<String, String>,
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn reports_kernel(tenant: &str) -> AbuseIpDbKernel {
    AbuseIpDbKernel::new(
        "https://api.abuseipdb.com/api/v2",
        tenant,
        AbuseIpDbFamily::Reports,
        AbuseIpDbFilters {
            ip_address: Some("192.0.2.10".to_owned()),
            max_age_in_days: Some(30),
            ..AbuseIpDbFilters::default()
        },
        OBSERVED_AT,
    )
    .unwrap()
}

fn ip_kernel(tenant: &str) -> AbuseIpDbKernel {
    AbuseIpDbKernel::new(
        "https://api.abuseipdb.com/api/v2",
        tenant,
        AbuseIpDbFamily::IpAddresses,
        AbuseIpDbFilters {
            confidence_minimum: Some(90),
            ip_version: Some(4),
            ..AbuseIpDbFilters::default()
        },
        OBSERVED_AT,
    )
    .unwrap()
}

fn report_raw() -> Value {
    json!({
        "reportedAt": "2026-06-01T00:00:00Z",
        "reporterId": 43121,
        "comment": "SSH login attempts",
        "categories": [18, 22],
        "reporterCountryCode": "US"
    })
}

fn ip_raw() -> Value {
    json!({
        "ipAddress": "192.0.2.10",
        "abuseConfidenceScore": 100,
        "countryCode": "US",
        "lastReportedAt": "2026-06-01T00:00:00Z"
    })
}

fn response(family: AbuseIpDbFamily, records: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec(&match family {
        AbuseIpDbFamily::Reports => json!({"data": {"results": records}}),
        AbuseIpDbFamily::IpAddresses => json!({"data": records}),
    })
    .unwrap()
}

fn go_event_fixture(family: AbuseIpDbFamily) -> GoOracleEvent {
    let file = match family {
        AbuseIpDbFamily::Reports => "read_reports.json",
        AbuseIpDbFamily::IpAddresses => "read_ip_addresses.json",
    };
    let bytes = fs::read(
        repository_root()
            .join("sources/abuseipdb/testdata")
            .join(file),
    )
    .unwrap();
    serde_json::from_slice::<Vec<GoOracleEvent>>(&bytes)
        .unwrap()
        .pop()
        .unwrap()
}

#[test]
fn catalog_and_kernel_close_the_exact_authoritative_family_set() {
    let root = repository_root();
    let catalog = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )
    .unwrap();
    let source = catalog.get("abuseipdb").unwrap();
    assert_eq!(source.authority(), CollectionAuthority::Authoritative);
    assert_eq!(
        source
            .families()
            .iter()
            .map(|family| family.id())
            .collect::<Vec<_>>(),
        ["reports", "ip_addresses"]
    );
    assert!(
        source
            .families()
            .iter()
            .all(|family| family.is_authoritative())
    );
    assert_eq!(
        AbuseIpDbFamily::ALL.map(AbuseIpDbFamily::as_str),
        ["reports", "ip_addresses"]
    );
    for family in AbuseIpDbFamily::ALL {
        let definition = AbuseIpDbRuntimeDefinition::compile(family).unwrap();
        assert_eq!(definition.source_id, "abuseipdb");
        assert!(definition.pull);
        assert_eq!(definition.event_contract.kind, family.event_kind());
        assert_eq!(definition.event_contract.schema_ref, family.schema_ref());
    }
}

#[test]
fn requests_are_bounded_origin_restricted_and_credential_free() {
    let reports = reports_kernel("tenant");
    let first = reports.plan(None).unwrap();
    assert_eq!(first.method(), "GET");
    assert_eq!(
        first.url().as_str(),
        "https://api.abuseipdb.com/api/v2/reports?ipAddress=192.0.2.10&maxAgeInDays=30&perPage=100&page=1"
    );
    assert_eq!(first.authentication_header(), "Key");
    assert_eq!(first.authentication_scheme(), "");
    assert!(first.credential_reference_required());
    assert_eq!(first.accept(), "application/json");
    assert_eq!(first.record_limit(), 100);
    assert_eq!(first.max_response_bytes(), 8 * 1024 * 1024);
    assert_eq!(first.required_scope(), "AbuseIPDB API read access");
    assert!(!first.contains_credentials());
    assert!(!first.allows_redirects());
    assert!(!AbuseIpDbKernel::requires_credentials());
    assert_eq!(
        reports
            .plan(Some("2"))
            .unwrap()
            .url()
            .query_pairs()
            .last()
            .unwrap()
            .1,
        "2"
    );

    let blacklist = ip_kernel("tenant").plan(None).unwrap();
    assert_eq!(
        blacklist.url().as_str(),
        "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&ipVersion=4&limit=10000"
    );
    assert_eq!(blacklist.record_limit(), 10_000);
    assert_eq!(
        ip_kernel("tenant").plan(Some("2")),
        Err(AbuseIpDbError::InvalidCursor)
    );

    let debug = format!("{reports:?}{first:?}{blacklist:?}");
    for secret in ["sentinel-token-value", "Key: sentinel", "credential:"] {
        assert!(!debug.contains(secret));
    }
}

#[test]
fn origins_cursors_and_family_configuration_fail_closed() {
    for origin in [
        "http://api.abuseipdb.com/api/v2",
        "https://localhost/api/v2",
        "https://127.0.0.1/api/v2",
        "https://user@api.abuseipdb.com/api/v2",
        "https://api.abuseipdb.com:8443/api/v2",
        "https://api.abuseipdb.com/api/v1",
        "https://api.abuseipdb.com/api/v2?token=value",
    ] {
        assert!(
            AbuseIpDbKernel::new(
                origin,
                "tenant",
                AbuseIpDbFamily::Reports,
                AbuseIpDbFilters {
                    ip_address: Some("192.0.2.10".to_owned()),
                    ..AbuseIpDbFilters::default()
                },
                OBSERVED_AT,
            )
            .is_err()
        );
    }
    assert_eq!(
        reports_kernel("tenant").plan(Some("0")),
        Err(AbuseIpDbError::InvalidCursor)
    );
    assert_eq!(
        reports_kernel("tenant").plan(Some("10001")),
        Err(AbuseIpDbError::InvalidCursor)
    );
    assert_eq!(
        AbuseIpDbKernel::new(
            "https://api.abuseipdb.com/api/v2",
            "tenant",
            AbuseIpDbFamily::Reports,
            AbuseIpDbFilters::default(),
            OBSERVED_AT,
        )
        .unwrap_err(),
        AbuseIpDbError::MissingConfiguration("ip_address")
    );
}

#[test]
fn reports_response_matches_the_existing_go_oracle_semantically() {
    let kernel = reports_kernel("tenant");
    let request = kernel.plan(None).unwrap();
    let page = kernel
        .decode(
            &request,
            200,
            None,
            &response(AbuseIpDbFamily::Reports, vec![report_raw()]),
        )
        .unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.next_cursor, None);
    let record = &page.records[0];
    let oracle = go_event_fixture(AbuseIpDbFamily::Reports);
    assert_eq!(record.tenant_id, oracle.tenant_id);
    assert_eq!(oracle.source_id, "abuseipdb");
    assert_eq!(record.kind, oracle.kind);
    assert_eq!(record.schema_ref, oracle.schema_ref);
    assert_eq!(record.occurred_at, oracle.occurred_at);
    assert_eq!(record.payload, oracle.payload);
    assert_eq!(record.attributes, oracle.attributes);
    assert_eq!(record.provider_id, "2026-06-01T00:00:00Z:43121");
    assert_eq!(
        record.event_id,
        "abuseipdb-tenant-cc8ad95318cd-reports-2026-06-01T00-00-00Z-43121"
    );
    assert_eq!(
        oracle.id,
        "abuseipdb-tenant-reports-2026-06-01t00-00-00z-43121"
    );

    let projection = project_abuseipdb_records(&page.records);
    assert_eq!(projection.entities.len(), 1);
    assert_eq!(projection.relations.len(), 1);
    assert_eq!(projection.entities[0].entity_type, "finding");
    assert_eq!(projection.entities[0].label, "SSH login attempts");
    assert_eq!(projection.relations[0].relation, "affects");
    assert_eq!(
        projection.relations[0].to_urn,
        "urn:cerebro:tenant:abuseipdb_ip_address:192.0.2.10"
    );
}

#[test]
fn blacklist_response_matches_the_existing_go_oracle_semantically() {
    let kernel = ip_kernel("tenant");
    let request = kernel.plan(None).unwrap();
    let page = kernel
        .decode(
            &request,
            200,
            None,
            &response(AbuseIpDbFamily::IpAddresses, vec![ip_raw()]),
        )
        .unwrap();
    let record = &page.records[0];
    let oracle = go_event_fixture(AbuseIpDbFamily::IpAddresses);
    assert_eq!(record.tenant_id, oracle.tenant_id);
    assert_eq!(oracle.source_id, "abuseipdb");
    assert_eq!(record.kind, oracle.kind);
    assert_eq!(record.schema_ref, oracle.schema_ref);
    assert_eq!(record.occurred_at, oracle.occurred_at);
    assert_eq!(record.payload, oracle.payload);
    assert_eq!(record.attributes, oracle.attributes);
    assert_eq!(record.provider_id, "192.0.2.10");
    assert_eq!(
        record.event_id,
        "abuseipdb-tenant-d9cb64b1547c-ip_addresses-192.0.2.10"
    );
    assert_eq!(oracle.id, "abuseipdb-tenant-blacklist-192-0-2-10");

    let projection = project_abuseipdb_records(&page.records);
    assert_eq!(
        projection.entities,
        vec![AbuseIpDbEntityFact {
            urn: "urn:cerebro:tenant:abuseipdb_ip_address:192.0.2.10".to_owned(),
            entity_type: "runtime.ip.address".to_owned(),
            label: "192.0.2.10".to_owned(),
        }]
    );
    assert!(projection.relations.is_empty());
}

#[test]
fn reports_pagination_and_checkpoint_are_round_trippable() {
    let kernel = reports_kernel("tenant");
    let request = kernel.plan(None).unwrap();
    let records = (1..=100)
        .map(|reporter| {
            json!({
                "reportedAt": "2026-06-01T00:00:00Z",
                "reporterId": reporter,
                "comment": format!("report-{reporter}")
            })
        })
        .collect();
    let page = kernel
        .decode(
            &request,
            200,
            None,
            &response(AbuseIpDbFamily::Reports, records),
        )
        .unwrap();
    assert_eq!(page.records.len(), 100);
    assert_eq!(page.next_cursor.as_deref(), Some("2"));
    assert!(kernel.plan(page.next_cursor.as_deref()).is_ok());
    let checkpoint = kernel
        .checkpoint_candidate(&request, &page, Some("2026-05-01T00:00:00Z"))
        .unwrap();
    assert_eq!(checkpoint.cursor.as_deref(), Some("2"));
    assert_eq!(checkpoint.watermark, OBSERVED_AT);

    let second = kernel.plan(Some("2")).unwrap();
    let terminal = kernel
        .decode(
            &second,
            200,
            None,
            &response(AbuseIpDbFamily::Reports, Vec::new()),
        )
        .unwrap();
    assert_eq!(terminal.next_cursor, None);
    assert_eq!(
        kernel
            .checkpoint_candidate(&second, &terminal, None)
            .unwrap()
            .watermark,
        OBSERVED_AT
    );
}

#[test]
fn duplicate_identity_is_idempotent_but_conflicting_content_fails() {
    let kernel = reports_kernel("tenant");
    let request = kernel.plan(None).unwrap();
    let identical = kernel
        .decode(
            &request,
            200,
            None,
            &response(AbuseIpDbFamily::Reports, vec![report_raw(), report_raw()]),
        )
        .unwrap();
    assert_eq!(identical.records.len(), 1);
    let mut conflicting = report_raw();
    conflicting["comment"] = Value::String("different".to_owned());
    assert_eq!(
        kernel.decode(
            &request,
            200,
            None,
            &response(AbuseIpDbFamily::Reports, vec![report_raw(), conflicting]),
        ),
        Err(AbuseIpDbError::ConflictingDuplicate)
    );
}

#[test]
fn typed_provider_statuses_remain_distinct_and_bounded() {
    let kernel = reports_kernel("tenant");
    let request = kernel.plan(None).unwrap();
    for (status, expected) in [
        (401, AbuseIpDbError::AuthenticationRejected),
        (403, AbuseIpDbError::RequiredScopeMissing),
        (404, AbuseIpDbError::ProviderResourceNotFound),
        (
            429,
            AbuseIpDbError::RateLimited {
                retry_after_seconds: Some(60),
            },
        ),
        (503, AbuseIpDbError::ProviderUnavailable { status: 503 }),
        (418, AbuseIpDbError::UnexpectedStatus { status: 418 }),
    ] {
        assert_eq!(
            kernel.decode(&request, status, Some(60), b"{}"),
            Err(expected)
        );
    }
    assert_eq!(
        kernel.decode(&request, 429, Some(3_601), b"{}"),
        Err(AbuseIpDbError::InvalidRetryAfter)
    );
    let oversized = vec![b' '; request.max_response_bytes() + 1];
    assert_eq!(
        kernel.decode(&request, 200, None, &oversized),
        Err(AbuseIpDbError::ResponseTooLarge)
    );
}

#[test]
fn tenant_provider_scope_and_secret_material_cannot_cross_the_kernel() {
    let kernel = reports_kernel("tenant");
    let request = kernel.plan(None).unwrap();
    for (field, expected) in [
        ("tenant_id", AbuseIpDbError::TenantMismatch),
        ("access_token", AbuseIpDbError::CredentialMaterial),
        ("authorization", AbuseIpDbError::CredentialMaterial),
        ("private_key", AbuseIpDbError::CredentialMaterial),
    ] {
        let mut raw = report_raw();
        raw[field] = Value::String("sentinel-secret-value".to_owned());
        let error = kernel
            .decode(
                &request,
                200,
                None,
                &response(AbuseIpDbFamily::Reports, vec![raw]),
            )
            .unwrap_err();
        assert_eq!(error, expected);
        assert!(!error.to_string().contains("sentinel-secret-value"));
        assert!(!format!("{error:?}").contains("sentinel-secret-value"));
    }

    let mut wrong_ip = report_raw();
    wrong_ip["ipAddress"] = Value::String("192.0.2.11".to_owned());
    assert_eq!(
        kernel.decode(
            &request,
            200,
            None,
            &response(AbuseIpDbFamily::Reports, vec![wrong_ip])
        ),
        Err(AbuseIpDbError::ProviderIdentityMismatch)
    );
}

#[test]
fn identity_is_deterministic_and_tenant_scoped() {
    let body = response(AbuseIpDbFamily::IpAddresses, vec![ip_raw()]);
    let first_kernel = ip_kernel("tenant-a");
    let first_request = first_kernel.plan(None).unwrap();
    let first = first_kernel
        .decode(&first_request, 200, None, &body)
        .unwrap();
    let replay = first_kernel
        .decode(&first_request, 200, None, &body)
        .unwrap();
    assert_eq!(first, replay);

    let other_kernel = ip_kernel("tenant-b");
    let other_request = other_kernel.plan(None).unwrap();
    let other = other_kernel
        .decode(&other_request, 200, None, &body)
        .unwrap();
    assert_eq!(first.records[0].provider_id, other.records[0].provider_id);
    assert_ne!(first.records[0].event_id, other.records[0].event_id);
    assert_ne!(
        first.records[0].attributes["resource_urn"],
        other.records[0].attributes["resource_urn"]
    );
}

#[test]
fn errors_expose_bounded_operator_actions() {
    assert_eq!(
        AbuseIpDbError::AuthenticationRejected.operator_action(),
        "repair credential binding"
    );
    assert_eq!(
        AbuseIpDbError::RequiredScopeMissing.operator_action(),
        "grant AbuseIPDB read access"
    );
    assert_eq!(
        AbuseIpDbError::RateLimited {
            retry_after_seconds: Some(30)
        }
        .operator_action(),
        "retry the collection later"
    );
    assert_eq!(
        AbuseIpDbError::InvalidCursor.operator_action(),
        "restart from the last committed checkpoint"
    );
}
