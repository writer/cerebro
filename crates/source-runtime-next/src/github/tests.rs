use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::*;

const AUDIT_RESPONSE: &[u8] =
    include_bytes!("../../../../sources/github/testdata/api/audit/audit_log/response.json");
const AUDIT_ORACLE: &[u8] = include_bytes!("../../../../sources/github/testdata/read_audit.json");
const DEPENDABOT_RESPONSE: &[u8] = include_bytes!(
    "../../../../sources/github/testdata/api/dependabot_alert/dependabot_alerts/response.json"
);
const DEPENDABOT_ORACLE: &[u8] =
    include_bytes!("../../../../sources/github/testdata/read_dependabot_alert.json");
const ORG_RESPONSE: &[u8] =
    include_bytes!("../../../../sources/github/testdata/api/org_inventory/members/response.json");
const ORG_ORACLE: &[u8] =
    include_bytes!("../../../../sources/github/testdata/read_org_inventory.json");
const PR_RESPONSE: &[u8] = include_bytes!(
    "../../../../sources/github/testdata/api/pull_request/pull_requests/response.json"
);
const PR_ORACLE: &[u8] =
    include_bytes!("../../../../sources/github/testdata/read_pull_request.json");
const REPOSITORY_RESPONSE: &[u8] =
    include_bytes!("../../../../sources/github/testdata/api/repository/repository/response.json");
const REPOSITORY_ORACLE: &[u8] =
    include_bytes!("../../../../sources/github/testdata/read_repository.json");
const SECRET_RESPONSE: &[u8] = include_bytes!(
    "../../../../sources/github/testdata/api/secret_scanning_alert/secret_scanning_alerts/response.json"
);
const SECRET_ORACLE: &[u8] =
    include_bytes!("../../../../sources/github/testdata/read_secret_scanning_alert.json");
const CATALOG: &[u8] = include_bytes!("../../../../sources/github/catalog.yaml");

#[derive(serde::Deserialize)]
struct CatalogWire {
    event_contracts: Vec<EventContractWire>,
}

#[derive(serde::Deserialize)]
struct EventContractWire {
    kind: String,
    schema_ref: String,
    required_attributes: Vec<String>,
    required_payload_fields: Vec<String>,
}

fn kernel(
    tenant: &str,
    owner: &str,
    repository: Option<&str>,
    family: GitHubFamily,
) -> GitHubKernel {
    GitHubKernel::new(
        "https://api.github.com",
        tenant,
        owner,
        repository,
        family,
        GitHubFilters::default(),
        Some(100),
    )
    .expect("valid github fixture kernel")
}

#[test]
fn compiles_only_the_six_bespoke_catalog_families() {
    let families = [
        GitHubFamily::Audit,
        GitHubFamily::Repository,
        GitHubFamily::DependabotAlert,
        GitHubFamily::OrganizationInventory,
        GitHubFamily::PullRequest,
        GitHubFamily::SecretScanningAlert,
    ];
    let contracts = families
        .into_iter()
        .flat_map(|family| {
            GitHubRuntimeDefinition::compile(family)
                .expect("compiled family")
                .event_contracts
        })
        .map(|contract| contract.kind)
        .collect::<Vec<_>>();
    assert_eq!(contracts.len(), 7);
    assert!(contracts.contains(&"github.audit"));
    assert!(contracts.contains(&"github.org_member"));
    assert!(contracts.contains(&"github.org_installation"));
    assert!(
        !contracts
            .iter()
            .any(|kind| matches!(*kind, "github.issue" | "github.event" | "github.email"))
    );
    assert_eq!(
        "issue".parse::<GitHubFamily>(),
        Err(GitHubError::InvalidFamily)
    );
}

#[test]
fn compiled_contracts_match_the_provider_catalog_exactly() {
    let catalog: CatalogWire = serde_saphyr::from_slice(CATALOG).expect("GitHub catalog YAML");
    let families = [
        GitHubFamily::Audit,
        GitHubFamily::Repository,
        GitHubFamily::DependabotAlert,
        GitHubFamily::OrganizationInventory,
        GitHubFamily::PullRequest,
        GitHubFamily::SecretScanningAlert,
    ];
    let compiled = families
        .into_iter()
        .flat_map(|family| {
            GitHubRuntimeDefinition::compile(family)
                .expect("compiled family")
                .event_contracts
        })
        .collect::<Vec<_>>();
    assert_eq!(catalog.event_contracts.len(), compiled.len());
    for expected in catalog.event_contracts {
        let actual = compiled
            .iter()
            .find(|contract| contract.kind == expected.kind)
            .expect("catalog contract compiled");
        assert_eq!(actual.schema_ref, expected.schema_ref);
        assert!(
            actual
                .required_attributes
                .iter()
                .copied()
                .eq(expected.required_attributes.iter().map(String::as_str))
        );
        assert!(
            actual
                .required_payload_fields
                .iter()
                .copied()
                .eq(expected.required_payload_fields.iter().map(String::as_str))
        );
    }
}

#[test]
fn plans_every_catalog_endpoint_without_credentials_or_redirects() {
    let cases = [
        (GitHubFamily::Audit, None, "/orgs/writer/audit-log"),
        (GitHubFamily::Repository, None, "/orgs/writer/repos"),
        (
            GitHubFamily::Repository,
            Some("cerebro"),
            "/repos/writer/cerebro",
        ),
        (
            GitHubFamily::DependabotAlert,
            Some("cerebro"),
            "/repos/writer/cerebro/dependabot/alerts",
        ),
        (
            GitHubFamily::OrganizationInventory,
            None,
            "/orgs/writer/members",
        ),
        (
            GitHubFamily::PullRequest,
            Some("cerebro"),
            "/repos/writer/cerebro/pulls",
        ),
        (
            GitHubFamily::SecretScanningAlert,
            None,
            "/orgs/writer/secret-scanning/alerts",
        ),
    ];
    for (family, repository, path) in cases {
        let request = kernel("tenant-a", "writer", repository, family)
            .plan(None)
            .expect("planned request");
        assert_eq!(request.method(), "GET");
        assert_eq!(request.url().path(), path);
        assert_eq!(request.authorization_header(), "Authorization");
        assert_eq!(request.authorization_schemes(), &["Bearer", "token"]);
        assert!(!request.contains_credentials());
        assert!(!request.allows_redirects());
        assert_eq!(request.max_response_bytes(), 8 * 1024 * 1024);
        let serialized = format!("{request:?}").to_ascii_lowercase();
        for forbidden in ["ghp_", "github_pat_", "client_secret", "private_key"] {
            assert!(!serialized.contains(forbidden));
        }
    }
}

#[test]
fn repository_fallback_and_inventory_cursor_stages_are_origin_restricted() {
    let repository = kernel("tenant-a", "writer", None, GitHubFamily::Repository);
    let primary = repository.plan(None).expect("org repositories");
    let fallback = repository
        .plan_repository_user_fallback(&primary)
        .expect("user fallback");
    assert_eq!(fallback.url().path(), "/users/writer/repos");
    assert_eq!(fallback.url().origin(), primary.url().origin());

    let inventory = kernel(
        "tenant-a",
        "writer",
        None,
        GitHubFamily::OrganizationInventory,
    );
    let members = inventory.plan(None).expect("members");
    let page = inventory
        .decode(
            &members,
            GitHubContinuation::default(),
            b"[]",
            Some("2026-08-21T00:00:00Z"),
            &[],
        )
        .expect("members page");
    let outside = inventory
        .plan(page.next_cursor.as_deref())
        .expect("outside collaborators");
    assert_eq!(outside.url().path(), "/orgs/writer/outside_collaborators");
    let page = inventory
        .decode(
            &outside,
            GitHubContinuation::default(),
            b"[]",
            Some("2026-08-21T00:00:00Z"),
            &[],
        )
        .expect("outside page");
    let installations = inventory
        .plan(page.next_cursor.as_deref())
        .expect("installations");
    assert_eq!(installations.url().path(), "/orgs/writer/installations");
}

#[test]
fn github_fixture_outputs_match_the_go_oracle() {
    let audit = kernel(
        "api-playground",
        "codeforamerica",
        None,
        GitHubFamily::Audit,
    );
    let audit_page = audit
        .decode(
            &audit.plan(None).expect("audit request"),
            GitHubContinuation::default(),
            AUDIT_RESPONSE,
            None,
            &[GitHubActorResolution {
                actor: "octokit".to_owned(),
                actor_type: "Unresolved".to_owned(),
                actor_id: None,
                actor_email: None,
            }],
        )
        .expect("audit fixture");
    assert_oracle(&audit_page.records, AUDIT_ORACLE);

    let dependabot = kernel(
        "coopernetes",
        "coopernetes",
        Some("PyGithub"),
        GitHubFamily::DependabotAlert,
    );
    let dependabot_page = dependabot
        .decode(
            &dependabot.plan(None).expect("dependabot request"),
            GitHubContinuation::default(),
            DEPENDABOT_RESPONSE,
            None,
            &[],
        )
        .expect("dependabot fixture");
    assert_oracle(&dependabot_page.records, DEPENDABOT_ORACLE);

    let org = kernel(
        "github",
        "github",
        None,
        GitHubFamily::OrganizationInventory,
    );
    let org_page = org
        .decode(
            &org.plan(None).expect("member request"),
            GitHubContinuation::default(),
            ORG_RESPONSE,
            Some("2026-07-18T08:32:55Z"),
            &[],
        )
        .expect("org fixture");
    assert_oracle(&org_page.records, ORG_ORACLE);

    let pull = kernel(
        "octocat",
        "octocat",
        Some("Hello-World"),
        GitHubFamily::PullRequest,
    );
    let pull_page = pull
        .decode(
            &pull.plan(None).expect("pull request"),
            GitHubContinuation::default(),
            PR_RESPONSE,
            None,
            &[],
        )
        .expect("pull fixture");
    assert_oracle(&pull_page.records, PR_ORACLE);

    let repository = kernel(
        "octocat",
        "octocat",
        Some("Hello-World"),
        GitHubFamily::Repository,
    );
    let repository_page = repository
        .decode(
            &repository.plan(None).expect("repository request"),
            GitHubContinuation::default(),
            REPOSITORY_RESPONSE,
            None,
            &[],
        )
        .expect("repository fixture");
    assert_oracle(&repository_page.records, REPOSITORY_ORACLE);

    let secret = kernel("github", "github", None, GitHubFamily::SecretScanningAlert);
    let secret_page = secret
        .decode(
            &secret.plan(None).expect("secret request"),
            GitHubContinuation::default(),
            SECRET_RESPONSE,
            None,
            &[],
        )
        .expect("secret fixture");
    assert_oracle(&secret_page.records, SECRET_ORACLE);
}

#[test]
fn organization_installation_contract_is_admitted_exactly() {
    let inventory = kernel(
        "tenant-a",
        "writer",
        None,
        GitHubFamily::OrganizationInventory,
    );
    let request = inventory
        .plan(Some("github-v1|installations|page|1"))
        .expect("installation request");
    let body = serde_json::to_vec(&json!({"installations": [{
        "id": 42,
        "app_slug": "dependabot",
        "target_type": "Organization",
        "repository_selection": "all",
        "permissions": {"metadata": "read", "security_events": "read"},
        "events": ["secret_scanning_alert"]
    }]}))
    .expect("fixture json");
    let page = inventory
        .decode(
            &request,
            GitHubContinuation::default(),
            &body,
            Some("2026-08-21T00:00:00Z"),
            &[],
        )
        .expect("installation page");
    let record = &page.records[0];
    assert_eq!(record.kind, "github.org_installation");
    assert_eq!(record.schema_ref, "github/org_installation/v1");
    assert_eq!(record.attributes["installation_id"], "42");
    assert_eq!(record.payload["org"], "writer");
    assert_eq!(page.next_cursor, None);
}

#[test]
fn audit_actor_resolution_is_explicit_and_bounded() {
    let audit = kernel("tenant-a", "writer", None, GitHubFamily::Audit);
    let request = audit.plan(None).expect("audit request");
    let error = audit
        .decode(
            &request,
            GitHubContinuation::default(),
            br#"[{"@timestamp":1661836610662,"action":"org.add_member","actor":"octokit","org":"writer","user":"new"}]"#,
            None,
            &[],
        )
        .expect_err("resolution required");
    assert_eq!(
        error,
        GitHubError::ActorResolutionRequired {
            actor: "octokit".to_owned()
        }
    );
    let lookup = audit
        .plan_actor_resolution("octokit")
        .expect("lookup request");
    assert_eq!(lookup.url().path(), "/users/octokit");
    let unresolved = audit
        .decode_actor_resolution(&lookup, 404, b"{}")
        .expect("unresolved actor");
    assert_eq!(unresolved.actor_type, "Unresolved");
}

#[test]
fn rejects_secrets_tenant_injection_conflicting_duplicates_and_unsafe_cursors() {
    let repository = kernel(
        "tenant-a",
        "writer",
        Some("cerebro"),
        GitHubFamily::Repository,
    );
    let request = repository.plan(None).expect("request");
    for body in [
        br#"{"id":1,"name":"cerebro","full_name":"writer/cerebro","updated_at":"2026-08-21T00:00:00Z","access_token":"credential-bytes"}"#.as_slice(),
        br#"{"id":1,"name":"cerebro","full_name":"writer/cerebro","updated_at":"2026-08-21T00:00:00Z","tenant_id":"attacker"}"#.as_slice(),
    ] {
        assert!(repository
            .decode(&request, GitHubContinuation::default(), body, None, &[])
            .is_err());
    }
    let list = kernel("tenant-a", "writer", None, GitHubFamily::Repository);
    let list_request = list.plan(None).expect("list request");
    let conflict = br#"[
      {"id":1,"name":"a","full_name":"writer/a","updated_at":"2026-08-21T00:00:00Z"},
      {"id":1,"name":"b","full_name":"writer/b","updated_at":"2026-08-21T00:00:00Z"}
    ]"#;
    assert_eq!(
        list.decode(
            &list_request,
            GitHubContinuation::default(),
            conflict,
            None,
            &[]
        ),
        Err(GitHubError::ConflictingDuplicate)
    );
    assert_eq!(
        list.plan(Some("https://evil.example/page/2")),
        Err(GitHubError::InvalidCursor)
    );
    assert_eq!(
        list.decode(
            &list_request,
            GitHubContinuation {
                after: Some("abc".to_owned()),
                page: Some(2),
            },
            b"[]",
            None,
            &[],
        ),
        Err(GitHubError::InvalidCursor)
    );
}

#[test]
fn classifies_provider_failures_without_collapsing_them() {
    let audit = kernel("tenant-a", "writer", None, GitHubFamily::Audit);
    let request = audit.plan(None).expect("request");
    let cases = [
        (401, None, GitHubError::AuthenticationRejected),
        (403, None, GitHubError::RequiredScopeMissing),
        (
            403,
            Some(30),
            GitHubError::RateLimited {
                retry_after_seconds: Some(30),
            },
        ),
        (
            429,
            Some(30),
            GitHubError::RateLimited {
                retry_after_seconds: Some(30),
            },
        ),
        (503, None, GitHubError::ProviderUnavailable { status: 503 }),
        (418, None, GitHubError::UnexpectedStatus { status: 418 }),
    ];
    for (status, retry_after, expected) in cases {
        assert_eq!(
            audit.decode_http(
                &request,
                status,
                retry_after,
                GitHubContinuation::default(),
                b"{}",
                None,
                &[],
            ),
            Err(expected)
        );
    }
}

#[test]
fn event_identity_is_stable_and_tenant_scoped() {
    let body = br#"{"id":1,"name":"cerebro","full_name":"writer/cerebro","updated_at":"2026-08-21T00:00:00Z"}"#;
    let first = normalized_repository("tenant-a", body);
    let repeated = normalized_repository("tenant-a", body);
    let other_tenant = normalized_repository("tenant-b", body);
    assert_eq!(first.event_id, repeated.event_id);
    assert_ne!(first.event_id, other_tenant.event_id);
    assert_eq!(first.provider_id, other_tenant.provider_id);
    assert_eq!(first.tenant_id, "tenant-a");
}

#[test]
fn checkpoint_candidate_round_trips_and_preserves_prior_progress() {
    let repository = kernel("tenant-a", "writer", None, GitHubFamily::Repository);
    let request = repository.plan(None).expect("first page");
    let page = repository
        .decode(
            &request,
            GitHubContinuation {
                after: None,
                page: Some(2),
            },
            br#"[{"id":1,"name":"cerebro","full_name":"writer/cerebro","updated_at":"2026-08-21T00:00:00Z"}]"#,
            None,
            &[],
        )
        .expect("normalized first page");
    let checkpoint = repository
        .checkpoint_candidate(&request, &page, Some("2026-08-20T00:00:00Z"))
        .expect("checkpoint candidate");
    assert_eq!(checkpoint.tenant_id, "tenant-a");
    assert_eq!(checkpoint.family, GitHubFamily::Repository);
    assert_eq!(
        checkpoint.watermark.as_deref(),
        Some("2026-08-21T00:00:00Z")
    );
    let resumed = repository
        .plan(checkpoint.cursor.as_deref())
        .expect("round-tripped cursor");
    assert_eq!(
        resumed
            .url()
            .query_pairs()
            .find(|(key, _)| key == "page")
            .map(|(_, value)| value.into_owned()),
        Some("2".to_owned())
    );
}

fn normalized_repository(tenant: &str, body: &[u8]) -> GitHubRecord {
    let kernel = kernel(tenant, "writer", Some("cerebro"), GitHubFamily::Repository);
    kernel
        .decode(
            &kernel.plan(None).expect("request"),
            GitHubContinuation::default(),
            body,
            None,
            &[],
        )
        .expect("record")
        .records
        .remove(0)
}

fn assert_oracle(records: &[GitHubRecord], oracle: &[u8]) {
    let oracle: Vec<Value> = serde_json::from_slice(oracle).expect("Go oracle JSON");
    assert_eq!(records.len(), oracle.len());
    for (record, expected) in records.iter().zip(oracle) {
        assert_eq!(record.tenant_id, expected["tenant_id"]);
        assert_eq!(record.source_id, expected["source_id"]);
        assert_eq!(record.kind, expected["kind"]);
        assert_eq!(record.schema_ref, expected["schema_ref"]);
        assert_eq!(record.attributes, attributes(&expected["attributes"]));
        assert_eq!(record.payload, expected["payload"]);
    }
}

fn attributes(value: &Value) -> BTreeMap<String, String> {
    value
        .as_object()
        .expect("oracle attributes")
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                value.as_str().expect("string attribute").to_owned(),
            )
        })
        .collect()
}
