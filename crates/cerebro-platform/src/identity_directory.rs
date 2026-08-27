//! Native Rust parity for the Go identity-directory reads.
//!
//! Mirrors `internal/sourcehttp/identitydirectory` for the persisted half of
//! the directory: the Go handler also merges identities derived from the Go
//! auth configuration (API keys, API credentials, MCP OAuth clients and
//! entitlements). That configuration lives with the Go trusted host until the
//! auth pipeline moves to Rust, so these responses always report
//! `meta.configured: 0` and serve the Postgres-persisted directory with the
//! Go route's exact filter, ordering, and response contract.

use serde::{Deserialize, Serialize};

use cerebro_organizational_store::{
    IdentityDirectoryQuery, StoredIdentityOrganization, StoredIdentityUser,
};

const DEFAULT_DIRECTORY_LIMIT: u32 = 100;
const MAX_DIRECTORY_LIMIT: u32 = 500;
const DEFAULT_DIRECTORY_SOURCE: &str = "identity_directory";

/// Query parameters accepted by both directory list routes; `status` is only
/// meaningful for the users route, matching the Go handlers.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct IdentityDirectoryRequestParams {
    pub tenant_id: Option<String>,
    pub org_id: Option<String>,
    pub provider: Option<String>,
    pub source: Option<String>,
    pub status: Option<String>,
    pub q: Option<String>,
    pub limit: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct OrganizationResponse {
    pub org_id: String,
    pub tenant_id: String,
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub slug: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub domain: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub provider: String,
    pub source: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub external_id: String,
    pub user_count: i32,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub last_synced_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub created_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct UserResponse {
    pub user_id: String,
    pub tenant_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub org_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub subject: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub email: String,
    pub display_name: String,
    pub status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub provider: String,
    pub source: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub last_seen_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub last_synced_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub created_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ListMeta {
    pub limit: u32,
    pub loaded: usize,
    pub configured: usize,
    pub persisted: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct ListOrganizationsResponse {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tenant_id: String,
    pub organizations: Vec<OrganizationResponse>,
    pub meta: ListMeta,
}

#[derive(Debug, Serialize)]
pub(crate) struct ListUsersResponse {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tenant_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub org_id: String,
    pub users: Vec<UserResponse>,
    pub meta: ListMeta,
}

/// Mirrors the Go `directoryLimit` parse: unparseable or zero falls back to
/// the default, larger values clamp to the maximum.
pub(crate) fn directory_limit(raw: Option<&str>) -> u32 {
    match raw.map(str::trim).unwrap_or_default().parse::<u32>() {
        Ok(0) | Err(_) => DEFAULT_DIRECTORY_LIMIT,
        Ok(parsed) if parsed > MAX_DIRECTORY_LIMIT => MAX_DIRECTORY_LIMIT,
        Ok(parsed) => parsed,
    }
}

/// Builds the store scope shared by both routes from the request parameters.
pub(crate) fn store_query(
    params: &IdentityDirectoryRequestParams,
    tenant_id: &str,
    include_status: bool,
) -> IdentityDirectoryQuery {
    let field = |value: &Option<String>| {
        value
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .to_owned()
    };
    IdentityDirectoryQuery {
        tenant_id: tenant_id.trim().to_owned(),
        org_id: field(&params.org_id),
        user_id: String::new(),
        provider: field(&params.provider),
        source: field(&params.source),
        status: if include_status {
            field(&params.status)
        } else {
            String::new()
        },
        text: field(&params.q),
        limit: directory_limit(params.limit.as_deref()),
    }
}

/// Truncates a microsecond RFC 3339 UTC store timestamp to the Go route's
/// second-precision display form; empty input stays empty.
pub(crate) fn display_time(micro: &str) -> String {
    if micro.len() >= 20 {
        format!("{}Z", &micro[..19])
    } else {
        micro.to_owned()
    }
}

fn first_non_empty(primary: &str, fallback: &str) -> String {
    let primary = primary.trim();
    if primary.is_empty() {
        fallback.to_owned()
    } else {
        primary.to_owned()
    }
}

/// Mirrors the Go `normalized` helper: trim, drop empties, dedupe in order.
pub(crate) fn normalized(values: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .filter(|value| seen.insert(value.to_owned()))
        .map(str::to_owned)
        .collect()
}

/// Applies the Go merge ordering for organizations: name, then org id.
pub(crate) fn sort_organizations(organizations: &mut [StoredIdentityOrganization]) {
    organizations.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.org_id.cmp(&right.org_id))
    });
}

/// Applies the Go merge ordering for users: most recently seen first (never
/// seen last), then display name, then user id. Microsecond RFC 3339 UTC
/// strings order the same way as the underlying instants.
pub(crate) fn sort_users(users: &mut [StoredIdentityUser]) {
    users.sort_by(|left, right| {
        right
            .last_seen_at
            .cmp(&left.last_seen_at)
            .then_with(|| left.display_name.cmp(&right.display_name))
            .then_with(|| left.user_id.cmp(&right.user_id))
    });
}

pub(crate) fn organizations_response(
    tenant_id: &str,
    limit: u32,
    mut organizations: Vec<StoredIdentityOrganization>,
) -> ListOrganizationsResponse {
    sort_organizations(&mut organizations);
    let persisted = organizations.len();
    let organizations: Vec<OrganizationResponse> = organizations
        .into_iter()
        .map(|org| OrganizationResponse {
            org_id: org.org_id.trim().to_owned(),
            tenant_id: org.tenant_id.trim().to_owned(),
            name: org.name.trim().to_owned(),
            slug: org.slug.trim().to_owned(),
            domain: org.domain.trim().to_owned(),
            provider: org.provider.trim().to_owned(),
            source: first_non_empty(&org.source, DEFAULT_DIRECTORY_SOURCE),
            external_id: org.external_id.trim().to_owned(),
            user_count: org.user_count,
            last_synced_at: display_time(&org.last_synced_at),
            created_at: display_time(&org.created_at),
            updated_at: display_time(&org.updated_at),
        })
        .collect();
    ListOrganizationsResponse {
        tenant_id: tenant_id.trim().to_owned(),
        meta: ListMeta {
            limit,
            loaded: organizations.len(),
            configured: 0,
            persisted,
        },
        organizations,
    }
}

pub(crate) fn users_response(
    tenant_id: &str,
    org_id: &str,
    limit: u32,
    mut users: Vec<StoredIdentityUser>,
) -> ListUsersResponse {
    sort_users(&mut users);
    let persisted = users.len();
    let users: Vec<UserResponse> = users
        .into_iter()
        .map(|user| UserResponse {
            user_id: user.user_id.trim().to_owned(),
            tenant_id: user.tenant_id.trim().to_owned(),
            org_id: user.org_id.trim().to_owned(),
            subject: user.subject.trim().to_owned(),
            email: user.email.trim().to_owned(),
            display_name: user.display_name.trim().to_owned(),
            status: first_non_empty(&user.status, "active"),
            provider: user.provider.trim().to_owned(),
            source: first_non_empty(&user.source, DEFAULT_DIRECTORY_SOURCE),
            roles: normalized(&user.roles),
            groups: normalized(&user.groups),
            last_seen_at: display_time(&user.last_seen_at),
            last_synced_at: display_time(&user.last_synced_at),
            created_at: display_time(&user.created_at),
            updated_at: display_time(&user.updated_at),
        })
        .collect();
    ListUsersResponse {
        tenant_id: tenant_id.trim().to_owned(),
        org_id: org_id.trim().to_owned(),
        meta: ListMeta {
            limit,
            loaded: users.len(),
            configured: 0,
            persisted,
        },
        users,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn org(name: &str, org_id: &str) -> StoredIdentityOrganization {
        StoredIdentityOrganization {
            tenant_id: "tenant-a".to_owned(),
            org_id: org_id.to_owned(),
            name: name.to_owned(),
            source: String::new(),
            user_count: 3,
            created_at: "2026-08-01T00:00:00.000000Z".to_owned(),
            updated_at: "2026-08-02T00:00:00.000000Z".to_owned(),
            ..StoredIdentityOrganization::default()
        }
    }

    fn user(display_name: &str, user_id: &str, last_seen_at: &str) -> StoredIdentityUser {
        StoredIdentityUser {
            tenant_id: "tenant-a".to_owned(),
            user_id: user_id.to_owned(),
            display_name: display_name.to_owned(),
            status: "active".to_owned(),
            last_seen_at: last_seen_at.to_owned(),
            ..StoredIdentityUser::default()
        }
    }

    #[test]
    fn directory_limit_matches_go_bounds() {
        assert_eq!(directory_limit(None), 100);
        assert_eq!(directory_limit(Some("")), 100);
        assert_eq!(directory_limit(Some("abc")), 100);
        assert_eq!(directory_limit(Some("0")), 100);
        assert_eq!(directory_limit(Some("-5")), 100);
        assert_eq!(directory_limit(Some(" 42 ")), 42);
        assert_eq!(directory_limit(Some("500")), 500);
        assert_eq!(directory_limit(Some("501")), 500);
    }

    #[test]
    fn store_query_trims_and_scopes_fields() {
        let params = IdentityDirectoryRequestParams {
            tenant_id: None,
            org_id: Some(" org-1 ".to_owned()),
            provider: Some("okta".to_owned()),
            source: Some(" api_key ".to_owned()),
            status: Some("inactive".to_owned()),
            q: Some(" search ".to_owned()),
            limit: Some("9".to_owned()),
        };
        let orgs = store_query(&params, "tenant-a", false);
        assert_eq!(orgs.org_id, "org-1");
        assert_eq!(orgs.text, "search");
        assert_eq!(orgs.status, "");
        assert_eq!(orgs.limit, 9);
        let users = store_query(&params, "tenant-a", true);
        assert_eq!(users.status, "inactive");
    }

    #[test]
    fn display_time_truncates_microseconds_to_seconds() {
        assert_eq!(
            display_time("2026-08-26T12:34:56.123456Z"),
            "2026-08-26T12:34:56Z"
        );
        assert_eq!(display_time(""), "");
    }

    #[test]
    fn organizations_sort_by_name_then_id_and_default_source() {
        let response = organizations_response(
            "tenant-a",
            100,
            vec![org("Beta", "b"), org("Alpha", "z"), org("Alpha", "a")],
        );
        let ids: Vec<&str> = response
            .organizations
            .iter()
            .map(|org| org.org_id.as_str())
            .collect();
        assert_eq!(ids, ["a", "z", "b"]);
        assert!(
            response
                .organizations
                .iter()
                .all(|org| org.source == "identity_directory")
        );
        assert_eq!(response.meta.loaded, 3);
        assert_eq!(response.meta.configured, 0);
        assert_eq!(response.meta.persisted, 3);
        assert_eq!(response.organizations[0].updated_at, "2026-08-02T00:00:00Z");
    }

    #[test]
    fn users_sort_recently_seen_first_and_never_seen_last() {
        let response = users_response(
            "tenant-a",
            "",
            100,
            vec![
                user("Never Seen", "n", ""),
                user("Older", "o", "2026-08-01T00:00:00.000000Z"),
                user("Newer", "w", "2026-08-02T00:00:00.500000Z"),
                user("Also Newer", "a", "2026-08-02T00:00:00.500000Z"),
            ],
        );
        let ids: Vec<&str> = response
            .users
            .iter()
            .map(|user| user.user_id.as_str())
            .collect();
        assert_eq!(ids, ["a", "w", "o", "n"]);
        assert_eq!(response.users[0].last_seen_at, "2026-08-02T00:00:00Z");
    }

    #[test]
    fn user_roles_and_groups_are_normalized() {
        let mut record = user("User", "u", "");
        record.roles = vec![" admin ".to_owned(), "".to_owned(), "admin".to_owned()];
        record.groups = vec!["ops".to_owned(), "ops".to_owned()];
        let response = users_response("tenant-a", "", 100, vec![record]);
        assert_eq!(response.users[0].roles, ["admin"]);
        assert_eq!(response.users[0].groups, ["ops"]);
    }

    #[test]
    fn empty_lists_serialize_with_go_field_names() {
        let payload =
            serde_json::to_value(organizations_response("tenant-a", 100, Vec::new())).unwrap();
        assert_eq!(payload["tenant_id"], "tenant-a");
        assert!(payload["organizations"].as_array().unwrap().is_empty());
        assert_eq!(payload["meta"]["limit"], 100);
        assert_eq!(payload["meta"]["configured"], 0);
        let users =
            serde_json::to_value(users_response("tenant-a", "org-1", 5, Vec::new())).unwrap();
        assert_eq!(users["org_id"], "org-1");
        assert!(users["users"].as_array().unwrap().is_empty());
    }
}
