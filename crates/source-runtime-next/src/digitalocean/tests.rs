use std::{collections::BTreeSet, fs, path::PathBuf, str::FromStr};

use cerebro_source_catalog::{AuthModel, HttpMethod, Pagination, SourceCatalog};
use serde_json::{Value, json};

use super::*;

const OBSERVED_AT: &str = "2026-06-03T00:00:00Z";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn kernel(tenant: &str, family: DigitalOceanFamily) -> DigitalOceanKernel {
    DigitalOceanKernel::new(None, tenant, family, None, OBSERVED_AT).unwrap()
}

fn fixture(family: DigitalOceanFamily) -> Vec<u8> {
    fs::read(root().join(format!(
        "sources/digitalocean/testdata/read_{}.json",
        family.as_str()
    )))
    .unwrap()
}

fn page(family: DigitalOceanFamily, tenant: &str) -> DigitalOceanPage {
    let kernel = kernel(tenant, family);
    let request = kernel.plan(DigitalOceanOperation::Read, None).unwrap();
    kernel
        .decode(&request, 200, None, &fixture(family))
        .unwrap()
}

#[test]
fn catalog_and_kernel_close_the_exact_three_families_after_go_runtime_retirement() {
    let catalog = SourceCatalog::load(
        root().join("internal/connectorcatalog/catalog"),
        root().join("sources"),
    )
    .unwrap();
    let source = catalog.get("digitalocean").unwrap();
    assert_eq!(source.auth(), &AuthModel::BearerToken);
    let compiled = source
        .families()
        .iter()
        .map(|family| family.id())
        .collect::<BTreeSet<_>>();
    assert_eq!(compiled, BTreeSet::from(["droplets", "firewalls", "vpcs"]));
    for family in source.families() {
        assert_eq!(family.method(), HttpMethod::Get);
        assert_eq!(
            family.pagination(),
            &Pagination::Page {
                parameter: "page".to_owned(),
                start: 1,
                page_size_parameter: Some("per_page".to_owned()),
                page_size: 50,
            }
        );
    }
    assert_eq!(DigitalOceanFamily::ALL.len(), 3);
    for family in DigitalOceanFamily::ALL {
        assert_eq!(DigitalOceanFamily::from_str(family.as_str()), Ok(family));
    }
    assert_eq!(
        DigitalOceanFamily::from_str("unknown"),
        Err(DigitalOceanError::InvalidFamily)
    );
    assert!(!root().join("sources/digitalocean/source.go").exists());
    assert!(!root().join("sources/digitalocean/source_test.go").exists());
    assert!(
        root()
            .join("crates/source-runtime-next/src/digitalocean/source_execution.rs")
            .exists()
    );
}

#[test]
fn check_uses_the_selected_family_while_catalog_verification_uses_account() {
    for family in DigitalOceanFamily::ALL {
        let kernel = kernel("tenant", family);
        let check = kernel.plan_check().unwrap();
        assert_eq!(check.operation(), DigitalOceanOperation::Check);
        assert_eq!(check.family(), family);
        assert_eq!(check.url().path(), family.path());
        assert_eq!(check.url().query(), Some("page=1&per_page=50"));
        assert_ne!(check.url().path(), "/v2/account");

        let verification = kernel.plan_account_verification().unwrap();
        assert_eq!(
            verification.operation(),
            DigitalOceanOperation::AccountVerification
        );
        assert_eq!(verification.url().path(), "/v2/account");
        assert_eq!(verification.url().query(), None);
    }
}

#[test]
fn requests_default_to_fifty_and_keep_bearer_auth_outside_the_kernel() {
    let default = kernel("tenant", DigitalOceanFamily::Droplets);
    let request = default.plan(DigitalOceanOperation::Read, None).unwrap();
    assert_eq!(request.method(), "GET");
    assert_eq!(
        request.url().as_str(),
        "https://api.digitalocean.com/v2/droplets?page=1&per_page=50"
    );
    assert_eq!(request.authentication_header(), "Authorization");
    assert_eq!(request.authentication_scheme(), "Bearer");
    assert!(request.credential_reference_required());
    assert!(!request.contains_credentials());
    assert!(!request.allows_redirects());
    assert_eq!(request.accept(), "application/json");
    assert_eq!(request.record_limit(), 50);
    assert_eq!(request.max_response_bytes(), 8 * 1024 * 1024);
    assert_eq!(request.required_scope(), "DigitalOcean read access");
    assert!(!DigitalOceanKernel::requires_credentials());

    let explicit = DigitalOceanKernel::new(
        Some("https://api.digitalocean.com"),
        "tenant",
        DigitalOceanFamily::Vpcs,
        Some(200),
        OBSERVED_AT,
    )
    .unwrap();
    assert_eq!(
        explicit
            .plan(DigitalOceanOperation::Discover, None)
            .unwrap()
            .url()
            .as_str(),
        "https://api.digitalocean.com/v2/vpcs?page=1&per_page=200"
    );
}

#[test]
fn origin_tenant_page_size_and_cursor_inputs_fail_closed() {
    for origin in [
        "http://api.digitalocean.com/v2",
        "https://user@api.digitalocean.com/v2",
        "https://api.digitalocean.com:8443/v2",
        "https://other.digitalocean.com/v2",
        "https://api.digitalocean.com/v3",
        "https://api.digitalocean.com/v2?token=value",
    ] {
        assert_eq!(
            DigitalOceanKernel::new(
                Some(origin),
                "tenant",
                DigitalOceanFamily::Droplets,
                None,
                OBSERVED_AT
            )
            .unwrap_err(),
            DigitalOceanError::InvalidBaseUrl
        );
    }
    for tenant in ["", "bad:tenant", "bad/tenant", "bad\ntenant"] {
        assert!(
            DigitalOceanKernel::new(
                None,
                tenant,
                DigitalOceanFamily::Droplets,
                None,
                OBSERVED_AT
            )
            .is_err()
        );
    }
    for page_size in [0, 201, usize::MAX] {
        assert!(
            DigitalOceanKernel::new(
                None,
                "tenant",
                DigitalOceanFamily::Droplets,
                Some(page_size),
                OBSERVED_AT
            )
            .is_err()
        );
    }
    for cursor in ["", "0", "01", "-1", "1000001", "next", "1\n2"] {
        assert_eq!(
            kernel("tenant", DigitalOceanFamily::Droplets)
                .plan(DigitalOceanOperation::Read, Some(cursor)),
            Err(DigitalOceanError::InvalidCursor)
        );
    }
}

#[test]
fn checked_provider_fixtures_match_go_event_and_projection_semantics() {
    let droplets = page(DigitalOceanFamily::Droplets, "tenant");
    assert_eq!(droplets.records.len(), 2);
    let droplet = &droplets.records[0];
    assert_eq!(droplet.provider_id, "3164444");
    assert_eq!(droplet.kind, "digitalocean.droplets");
    assert_eq!(droplet.schema_ref, "digitalocean/droplets/v1");
    assert_eq!(droplet.occurred_at, "2026-06-01T00:00:00Z");
    assert_eq!(droplet.attributes["region"], "nyc3");
    assert_eq!(droplet.attributes["vpc_uuid"], "vpc-1111");
    assert_eq!(
        droplet.attributes["resource_urn"],
        "urn:cerebro:tenant:digitalocean_droplets:3164444"
    );
    assert_eq!(droplet.payload["region"], "nyc3");
    assert_eq!(droplet.payload["vpc_uuid"], "vpc-1111");

    let vpcs = page(DigitalOceanFamily::Vpcs, "tenant");
    let vpc = &vpcs.records[0];
    assert_eq!(vpc.attributes["region"], "nyc3");
    assert_eq!(vpc.payload["default"], true);
    assert_eq!(vpc.payload["ip_range"], "192.0.2.0/24");

    let firewalls = page(DigitalOceanFamily::Firewalls, "tenant");
    let firewall = &firewalls.records[0];
    assert_eq!(firewall.attributes["droplet_ids"], "3164444,3164445");
    assert_eq!(firewall.attributes["public_ingress"], "true");
    assert_eq!(firewall.payload["droplet_ids"], json!([3164444, 3164445]));
    assert_eq!(firewall.payload["public"], true);
    assert!(firewall.payload.get("inbound_rules").is_none());

    let all = droplets
        .records
        .into_iter()
        .chain(vpcs.records)
        .chain(firewalls.records)
        .collect::<Vec<_>>();
    let projection = project_digitalocean_records(&all);
    assert_eq!(projection.entities.len(), 4);
    assert_eq!(projection.links.len(), 6);
    assert!(projection.links.iter().any(|link| {
        link.from_urn.ends_with(":digitalocean_droplets:3164444")
            && link.relation == "belongs_to"
            && link.to_urn.ends_with(":digitalocean_vpcs:vpc-1111")
    }));
    assert!(projection.links.iter().any(|link| {
        link.from_urn.ends_with(":digitalocean_firewalls:fw-2222")
            && link.relation == "attached_to"
            && link.to_urn.ends_with(":digitalocean_droplets:3164444")
    }));
    assert!(projection.links.iter().any(|link| {
        link.from_urn.ends_with(":digitalocean_firewalls:fw-2222")
            && link.relation == "can_reach"
            && link.to_urn.ends_with(":digitalocean_droplets:3164444")
            && link.attributes.get("exposure").map(String::as_str) == Some("public")
    }));
}

#[test]
fn provider_links_terminal_behavior_and_restart_checkpoint_round_trip() {
    let family = DigitalOceanFamily::Droplets;
    let kernel = kernel("tenant", family);
    let first_request = kernel.plan(DigitalOceanOperation::Read, None).unwrap();
    let mut body: Value = serde_json::from_slice(&fixture(family)).unwrap();
    body["links"] = json!({
        "pages": {
            "next": "https://other.invalid/v2/droplets?page=987"
        }
    });
    let first = kernel
        .decode(
            &first_request,
            200,
            None,
            &serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();
    assert_eq!(first.next_cursor.as_deref(), Some("2"));
    let checkpoint = kernel
        .checkpoint_candidate(&first_request, &first, Some("2026-06-01T00:00:00Z"))
        .unwrap();
    assert_eq!(checkpoint.cursor.as_deref(), Some("2"));
    assert_eq!(checkpoint.watermark, OBSERVED_AT);
    let resumed = kernel
        .plan(DigitalOceanOperation::Read, checkpoint.cursor.as_deref())
        .unwrap();
    assert_eq!(resumed.url().query(), Some("page=2&per_page=50"));

    body["links"] = json!({});
    body["droplets"] = json!([]);
    let terminal = kernel
        .decode(&resumed, 200, None, &serde_json::to_vec(&body).unwrap())
        .unwrap();
    assert_eq!(terminal.next_cursor, None);
    let terminal_checkpoint = kernel
        .checkpoint_candidate(&resumed, &terminal, Some(OBSERVED_AT))
        .unwrap();
    assert_eq!(terminal_checkpoint.cursor, None);
    assert_eq!(terminal_checkpoint.watermark, OBSERVED_AT);
}

#[test]
fn statuses_bounds_duplicates_scope_and_secret_material_fail_closed() {
    let family = DigitalOceanFamily::Firewalls;
    let kernel = kernel("tenant", family);
    let request = kernel.plan(DigitalOceanOperation::Read, None).unwrap();
    for (status, expected) in [
        (401, DigitalOceanError::AuthenticationRejected),
        (403, DigitalOceanError::RequiredScopeMissing),
        (
            429,
            DigitalOceanError::RateLimited {
                retry_after_seconds: Some(60),
            },
        ),
        (503, DigitalOceanError::ProviderUnavailable { status: 503 }),
        (418, DigitalOceanError::UnexpectedStatus { status: 418 }),
    ] {
        assert_eq!(
            kernel.decode(&request, status, Some(60), b"{}"),
            Err(expected)
        );
    }
    let oversized = vec![b' '; request.max_response_bytes() + 1];
    assert_eq!(
        kernel.decode(&request, 200, None, &oversized),
        Err(DigitalOceanError::ResponseTooLarge)
    );

    let mut body: Value = serde_json::from_slice(&fixture(family)).unwrap();
    let record = body["firewalls"][0].clone();
    body["firewalls"] = json!([record.clone(), record]);
    assert_eq!(
        kernel
            .decode(&request, 200, None, &serde_json::to_vec(&body).unwrap())
            .unwrap()
            .records
            .len(),
        1
    );
    body["firewalls"][1]["name"] = json!("conflict");
    assert_eq!(
        kernel.decode(&request, 200, None, &serde_json::to_vec(&body).unwrap()),
        Err(DigitalOceanError::ConflictingDuplicate)
    );
    for (field, expected) in [
        ("tenant_id", DigitalOceanError::TenantMismatch),
        ("token", DigitalOceanError::CredentialMaterial),
        ("authorization", DigitalOceanError::CredentialMaterial),
        ("private_key", DigitalOceanError::CredentialMaterial),
    ] {
        let mut body: Value = serde_json::from_slice(&fixture(family)).unwrap();
        body["firewalls"][0][field] = json!("sentinel-secret-value");
        let error = kernel
            .decode(&request, 200, None, &serde_json::to_vec(&body).unwrap())
            .unwrap_err();
        assert_eq!(error, expected);
        assert!(!error.to_string().contains("sentinel-secret-value"));
        assert!(!format!("{error:?}").contains("sentinel-secret-value"));
    }
}

#[test]
fn identity_is_deterministic_and_tenant_scoped() {
    let family = DigitalOceanFamily::Droplets;
    let first = page(family, "tenant-a");
    let repeated = page(family, "tenant-a");
    let other = page(family, "tenant-b");
    assert_eq!(first, repeated);
    assert_ne!(first.records[0].event_id, other.records[0].event_id);
    assert_ne!(
        first.records[0].attributes["resource_urn"],
        other.records[0].attributes["resource_urn"]
    );
    assert_eq!(first.records[0].provider_id, other.records[0].provider_id);
}
