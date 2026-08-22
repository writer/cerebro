use std::{collections::BTreeMap, str::FromStr};

use cerebro_source_catalog::{AuthModel, CollectionAuthority, Pagination, SourceCatalog};
use serde::Deserialize;
use serde_json::{Value, json};

use super::*;

const BASE_URL: &str = "https://api.cloudflare.com/client/v4";

#[derive(Deserialize)]
struct OracleEvent {
    tenant_id: String,
    kind: String,
    schema_ref: String,
    attributes: BTreeMap<String, String>,
    payload: Value,
}

fn kernel(family: CloudflareFamily, scope: Option<&str>) -> CloudflareKernel {
    CloudflareKernel::new(BASE_URL, "tenant", family, scope, Some(100)).unwrap()
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

fn scope_for(family: CloudflareFamily, event: &OracleEvent) -> Option<String> {
    match family.scope() {
        CloudflareScope::None => None,
        CloudflareScope::Account => Some(
            event
                .attributes
                .get("account_id")
                .cloned()
                .unwrap_or_else(|| "account-1".to_owned()),
        ),
        CloudflareScope::Zone => Some(
            event
                .attributes
                .get("zone_id")
                .cloned()
                .unwrap_or_else(|| "zone-1".to_owned()),
        ),
    }
}

#[test]
fn family_vocabulary_is_closed_and_contract_bound() {
    assert_eq!(CloudflareFamily::ALL.len(), 16);
    for family in CloudflareFamily::ALL {
        assert_eq!(CloudflareFamily::from_str(family.as_str()).unwrap(), family);
        assert_eq!(
            family.event_kind(),
            format!("cloudflare.{}", family.as_str())
        );
        assert_eq!(
            family.schema_ref(),
            format!("cloudflare/{}/v1", family.as_str())
        );
        assert!(family.path_template().starts_with('/'));
    }
    assert_eq!(
        CloudflareFamily::from_str("unknown"),
        Err(CloudflareError::InvalidFamily)
    );
}

#[test]
fn checked_in_catalog_compiles_the_closed_cloudflare_runtime() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let catalog = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )
    .unwrap();
    let source = catalog.get("cloudflare").unwrap();
    assert_eq!(source.auth(), &AuthModel::BearerToken);
    assert_eq!(source.authority(), CollectionAuthority::ShadowOnly);
    let compiled = source
        .families()
        .iter()
        .map(|family| family.id())
        .collect::<std::collections::BTreeSet<_>>();
    let expected = CloudflareFamily::ALL
        .iter()
        .map(|family| family.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(compiled, expected);
    for family in source.families() {
        assert!(!family.is_authoritative(), "{} collection", family.id());
        assert!(
            family.is_projection_authoritative(),
            "{} projection",
            family.id()
        );
        assert_eq!(
            family.pagination(),
            &Pagination::Page {
                parameter: "page".to_owned(),
                start: 1,
                page_size_parameter: Some("per_page".to_owned()),
                page_size: 100,
            },
            "{} pagination",
            family.id()
        );
    }
}

#[test]
fn every_go_oracle_family_normalizes_with_semantic_parity() {
    for family in CloudflareFamily::ALL {
        let oracle = oracle(family);
        let scope = scope_for(family, &oracle);
        let kernel = kernel(family, scope.as_deref());
        let request = kernel.plan(None).unwrap();
        let body = serde_json::to_vec(&json!({
            "success": true,
            "errors": [],
            "messages": [],
            "result": [oracle.payload],
            "result_info": {"page": 1, "per_page": 100, "total_pages": 1, "total_count": 1}
        }))
        .unwrap();
        let page = kernel.decode(&request, &body).unwrap();
        assert_eq!(page.scanned_count, 1, "{}", family.as_str());
        assert_eq!(page.records.len(), 1, "{}", family.as_str());
        assert_eq!(page.next_cursor, None, "{}", family.as_str());
        let record = &page.records[0];
        assert_eq!(oracle.kind, family.event_kind(), "{}", family.as_str());
        assert_eq!(
            oracle.schema_ref,
            family.schema_ref(),
            "{}",
            family.as_str()
        );
        assert_eq!(oracle.tenant_id, "tenant");
        assert_eq!(record.family, family.as_str());
        assert_eq!(record.event_kind, oracle.kind, "{}", family.as_str());
        assert_eq!(record.schema_ref, oracle.schema_ref, "{}", family.as_str());
        assert_eq!(
            record.attributes.get("tenant_id").map(String::as_str),
            Some("tenant")
        );
        assert_eq!(
            record.attributes.get("provider").map(String::as_str),
            Some("cloudflare")
        );
        assert_eq!(
            record.attributes.get(family.id_attribute()),
            oracle.attributes.get(family.id_attribute()),
            "{} ID attribute",
            family.as_str()
        );
        for (key, expected) in &oracle.attributes {
            if matches!(key.as_str(), "resource_urn" | "observed_at") {
                continue;
            }
            let actual = record
                .attributes
                .get(key)
                .unwrap_or_else(|| panic!("{} missing attribute {key}", family.as_str()));
            if let (Ok(actual_json), Ok(expected_json)) = (
                serde_json::from_str::<Value>(actual),
                serde_json::from_str::<Value>(expected),
            ) {
                assert_eq!(
                    actual_json,
                    expected_json,
                    "{} JSON attribute {key}",
                    family.as_str()
                );
                continue;
            }
            assert_eq!(actual, expected, "{} attribute {key}", family.as_str());
        }
    }
}

#[test]
fn request_plans_are_origin_locked_credential_free_and_paginated() {
    let kernel = CloudflareKernel::new(
        BASE_URL,
        "tenant-a",
        CloudflareFamily::Member,
        Some("acct-1"),
        Some(15),
    )
    .unwrap();
    let first = kernel.plan(None).unwrap();
    assert_eq!(
        first.url().as_str(),
        "https://api.cloudflare.com/client/v4/accounts/acct-1/members?page=1&per_page=15"
    );
    assert_eq!(first.authorization_header(), "Authorization");
    assert_eq!(first.authorization_scheme(), "Bearer");
    assert!(!first.contains_credentials());
    assert!(!first.allows_redirects());
    assert_eq!(first.max_response_bytes(), 8 << 20);
    assert_eq!(first.accept(), "application/json");
    let third = kernel.plan(Some("3")).unwrap();
    assert_eq!(third.page(), 3);
    assert!(third.url().as_str().ends_with("?page=3&per_page=15"));
}

#[test]
fn provider_cursor_round_trips_and_rejects_invalid_progress() {
    let kernel = kernel(CloudflareFamily::Member, Some("acct-1"));
    let first = kernel.plan(None).unwrap();
    let body = br#"{"success":true,"result":[{"id":"m1"}],"result_info":{"page":1,"per_page":100,"total_pages":3,"total_count":201}}"#;
    let page = kernel.decode(&first, body).unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("2"));
    let second = kernel.plan(page.next_cursor.as_deref()).unwrap();
    assert_eq!(second.page(), 2);
    let mismatch = br#"{"success":true,"result":[],"result_info":{"page":3,"total_pages":3}}"#;
    assert_eq!(
        kernel.decode(&second, mismatch),
        Err(CloudflareError::InvalidCursor)
    );
    for cursor in ["0", "10001", "-1", "next", "1/2"] {
        assert_eq!(
            kernel.plan(Some(cursor)),
            Err(CloudflareError::InvalidCursor)
        );
    }
}

#[test]
fn detail_requests_enrich_only_declared_families() {
    let ruleset_kernel = kernel(CloudflareFamily::AccountRuleset, Some("acct-1"));
    let request = ruleset_kernel.plan_detail("ruleset-1").unwrap();
    assert_eq!(
        request.url().as_str(),
        "https://api.cloudflare.com/client/v4/accounts/acct-1/rulesets/ruleset-1"
    );
    assert!(
        matches!(request.kind(), CloudflareRequestKind::Detail { provider_id } if provider_id == "ruleset-1")
    );
    let page = ruleset_kernel.decode(&request, br#"{"success":true,"result":{"id":"ruleset-1","rules":[{"id":"rule-1","action":"block"}]}}"#).unwrap();
    assert!(page.records[0].attributes["rules"].contains("rule-1"));
    assert_eq!(
        kernel(CloudflareFamily::Member, Some("acct-1")).plan_detail("member-1"),
        Err(CloudflareError::RequestScopeMismatch)
    );
}

#[test]
fn tenant_and_scope_are_part_of_stable_identity() {
    let body =
        br#"{"success":true,"result":[{"id":"app-1"}],"result_info":{"page":1,"total_pages":1}}"#;
    let a = CloudflareKernel::new(
        BASE_URL,
        "tenant-a",
        CloudflareFamily::AccessApplication,
        Some("acct-a"),
        None,
    )
    .unwrap();
    let b = CloudflareKernel::new(
        BASE_URL,
        "tenant-b",
        CloudflareFamily::AccessApplication,
        Some("acct-a"),
        None,
    )
    .unwrap();
    let c = CloudflareKernel::new(
        BASE_URL,
        "tenant-a",
        CloudflareFamily::AccessApplication,
        Some("acct-b"),
        None,
    )
    .unwrap();
    let a_record = a
        .decode(&a.plan(None).unwrap(), body)
        .unwrap()
        .records
        .remove(0);
    let b_record = b
        .decode(&b.plan(None).unwrap(), body)
        .unwrap()
        .records
        .remove(0);
    let c_record = c
        .decode(&c.plan(None).unwrap(), body)
        .unwrap()
        .records
        .remove(0);
    assert_ne!(a_record.event_id, b_record.event_id);
    assert_ne!(a_record.event_id, c_record.event_id);
    assert_ne!(a_record.scoped_provider_id, c_record.scoped_provider_id);
    assert_eq!(
        a_record.event_id,
        a.decode(&a.plan(None).unwrap(), body).unwrap().records[0].event_id
    );
}

#[test]
fn duplicates_are_idempotent_and_conflicts_fail_closed() {
    let kernel = kernel(CloudflareFamily::Zone, None);
    let request = kernel.plan(None).unwrap();
    let duplicate = br#"{"success":true,"result":[{"id":"z1","name":"one"},{"name":"one","id":"z1"}],"result_info":{"page":1,"total_pages":1}}"#;
    assert_eq!(kernel.decode(&request, duplicate).unwrap().records.len(), 1);
    let conflicting = br#"{"success":true,"result":[{"id":"z1","name":"one"},{"id":"z1","name":"two"}],"result_info":{"page":1,"total_pages":1}}"#;
    assert_eq!(
        kernel.decode(&request, conflicting),
        Err(CloudflareError::ConflictingDuplicate)
    );
}

#[test]
fn provider_scope_conflicts_fail_closed() {
    let kernel = kernel(CloudflareFamily::Member, Some("acct-1"));
    let body = br#"{"success":true,"result":[{"id":"m1","account_id":"acct-2"}],"result_info":{"page":1,"total_pages":1}}"#;
    assert_eq!(
        kernel.decode(&kernel.plan(None).unwrap(), body),
        Err(CloudflareError::ProviderScopeMismatch)
    );
}

#[test]
fn typed_provider_failures_remain_distinct() {
    let kernel = kernel(CloudflareFamily::Account, None);
    let request = kernel.plan(None).unwrap();
    assert_eq!(
        kernel.decode_http(&request, 401, None, b"{}"),
        Err(CloudflareError::AuthenticationRejected)
    );
    assert_eq!(
        kernel.decode_http(&request, 403, None, b"{}"),
        Err(CloudflareError::RequiredScopeMissing)
    );
    assert_eq!(
        kernel.decode_http(&request, 429, Some(12), b"{}"),
        Err(CloudflareError::RateLimited {
            retry_after_seconds: Some(12)
        })
    );
    assert_eq!(
        kernel.decode_http(&request, 503, None, b"{}"),
        Err(CloudflareError::ProviderUnavailable { status: 503 })
    );
    assert_eq!(
        kernel.decode_http(&request, 400, None, b"{}"),
        Err(CloudflareError::UnexpectedStatus { status: 400 })
    );
    assert_eq!(
        kernel.decode_http(&request, 429, Some(3_601), b"{}"),
        Err(CloudflareError::InvalidRetryAfter)
    );
    assert_eq!(
        kernel.decode(&request, br#"{"success":false,"errors":[{"code":10000}]}"#),
        Err(CloudflareError::ProviderRejected)
    );
    assert_eq!(
        CloudflareError::AuthenticationRejected.operator_action(),
        "repair credential binding"
    );
    assert_eq!(
        CloudflareError::RateLimited {
            retry_after_seconds: None
        }
        .operator_action(),
        "retry later"
    );
}

#[test]
fn credential_material_never_enters_request_or_normalized_output() {
    let marker = "credential-marker-should-not-survive";
    let kernel = kernel(CloudflareFamily::Account, None);
    let request = kernel.plan(None).unwrap();
    assert!(!format!("{request:?}").contains(marker));
    let body = format!(
        r#"{{"success":true,"result":[{{"id":"a1","api_token":"{marker}"}}],"result_info":{{"page":1,"total_pages":1}}}}"#
    );
    assert_eq!(
        kernel.decode(&request, body.as_bytes()),
        Err(CloudflareError::CredentialMaterial)
    );
    let clean = kernel.decode(&request, br#"{"success":true,"result":[{"id":"a1","name":"Account"}],"result_info":{"page":1,"total_pages":1}}"#).unwrap();
    assert!(!format!("{:?}", clean.records[0]).contains(marker));
}

#[test]
fn authenticated_tenant_context_cannot_be_replaced_by_provider_data() {
    let kernel = CloudflareKernel::new(
        BASE_URL,
        "tenant-authenticated",
        CloudflareFamily::Account,
        None,
        None,
    )
    .unwrap();
    let request = kernel.plan(None).unwrap();
    let page = kernel
        .decode(
            &request,
            br#"{"success":true,"result":[{"id":"a1","tenant_id":"tenant-untrusted"}],"result_info":{"page":1,"total_pages":1}}"#,
        )
        .unwrap();
    assert_eq!(
        page.records[0].attributes["tenant_id"],
        "tenant-authenticated"
    );
    assert!(!page.records[0].event_id.contains("tenant-untrusted"));
}

#[test]
fn origin_scope_size_and_record_bounds_are_enforced() {
    for origin in [
        "http://api.cloudflare.com/client/v4",
        "https://127.0.0.1/client/v4",
        "https://localhost/client/v4",
        "https://api.cloudflare.com:8443/client/v4",
        "https://user@api.cloudflare.com/client/v4",
    ] {
        assert_eq!(
            CloudflareKernel::new(origin, "tenant", CloudflareFamily::Account, None, None),
            Err(CloudflareError::InvalidBaseUrl)
        );
    }
    assert_eq!(
        CloudflareKernel::new(BASE_URL, "", CloudflareFamily::Account, None, None),
        Err(CloudflareError::InvalidTenantId)
    );
    assert_eq!(
        CloudflareKernel::new(BASE_URL, "tenant", CloudflareFamily::Member, None, None),
        Err(CloudflareError::InvalidScopeId)
    );
    assert_eq!(
        CloudflareKernel::new(
            BASE_URL,
            "tenant",
            CloudflareFamily::Account,
            Some("acct"),
            None
        ),
        Err(CloudflareError::InvalidScopeId)
    );
    assert_eq!(
        CloudflareKernel::new(
            BASE_URL,
            "tenant",
            CloudflareFamily::Account,
            None,
            Some(1_001)
        ),
        Err(CloudflareError::InvalidPageSize)
    );
    let kernel = kernel(CloudflareFamily::Account, None);
    let request = kernel.plan(None).unwrap();
    assert_eq!(
        kernel.decode(&request, &vec![b'x'; (8 << 20) + 1]),
        Err(CloudflareError::ResponseTooLarge)
    );
    assert_eq!(
        kernel.decode(
            &request,
            br#"{"success":true,"result":[{"name":"missing-id"}]}"#
        ),
        Err(CloudflareError::MissingProviderIdentity)
    );
}
