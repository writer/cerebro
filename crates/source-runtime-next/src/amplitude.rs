//! Amplitude SCIM request and response kernel.
//!
//! The kernel implements the portable Amplitude users and groups collection
//! contract. It plans credential-free requests and decodes SCIM list responses
//! without owning credentials, egress policy, deployment routes, or tenant
//! authorization.

use std::{collections::BTreeMap, error::Error, fmt, net::IpAddr, str::FromStr};

use reqwest::Url;
use serde_json::Value;

const DEFAULT_PAGE_SIZE: usize = 100;
const MAX_PAGE_SIZE: usize = 1_000;

/// One documented Amplitude SCIM collection family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AmplitudeFamily {
    /// Organization users exposed through SCIM.
    Users,
    /// Permission groups exposed through SCIM.
    Groups,
}

impl AmplitudeFamily {
    /// Return the source-catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Users => "users",
            Self::Groups => "groups",
        }
    }

    /// Return the emitted provider kind.
    pub const fn provider_kind(self) -> &'static str {
        match self {
            Self::Users => "amplitude.users",
            Self::Groups => "amplitude.groups",
        }
    }

    const fn path(self) -> &'static str {
        match self {
            Self::Users => "/scim/1/Users",
            Self::Groups => "/scim/1/Groups",
        }
    }
}

impl FromStr for AmplitudeFamily {
    type Err = AmplitudeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "users" => Ok(Self::Users),
            "groups" => Ok(Self::Groups),
            _ => Err(AmplitudeError::InvalidFamily),
        }
    }
}

/// One credential-free Amplitude SCIM request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmplitudeRequest {
    url: Url,
    family: AmplitudeFamily,
    start_index: usize,
}

impl AmplitudeRequest {
    /// Return the exact provider URL. The caller must authorize it before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return the required `Authorization` scheme without credential material.
    pub const fn authorization_scheme(&self) -> &'static str {
        "Bearer"
    }

    /// Return the accepted SCIM response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }
}

/// One normalized Amplitude SCIM resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmplitudeRecord {
    /// Source-catalog family identifier.
    pub family: String,
    /// Emitted provider kind.
    pub provider_kind: String,
    /// Stable provider-owned resource identifier.
    pub provider_id: String,
    /// Portable scalar fields used by source mapping.
    pub fields: BTreeMap<String, String>,
    /// Original SCIM resource, with no credentials or tenant metadata added.
    pub payload: Value,
}

/// One bounded Amplitude SCIM list page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmplitudePage {
    /// Normalized resources in provider order.
    pub records: Vec<AmplitudeRecord>,
    /// SCIM `startIndex` for the next page, when more results remain.
    pub next_cursor: Option<String>,
}

/// Portable request, response, and cursor kernel for Amplitude SCIM.
#[derive(Clone, Debug)]
pub struct AmplitudeKernel {
    base_url: Url,
    family: AmplitudeFamily,
    page_size: usize,
}

impl AmplitudeKernel {
    /// Build a kernel for one Amplitude origin and SCIM family.
    ///
    /// Planned requests still require the shared live-egress decision and an
    /// operation-scoped credential lease. This type never accepts or stores a
    /// credential value.
    pub fn new(
        base_url: &str,
        family: AmplitudeFamily,
        page_size: Option<usize>,
    ) -> Result<Self, AmplitudeError> {
        let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE);
        if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
            return Err(AmplitudeError::InvalidPageSize);
        }
        Ok(Self {
            base_url: validate_origin(base_url)?,
            family,
            page_size,
        })
    }

    /// Plan one credential-free SCIM list request.
    pub fn plan(&self, cursor: Option<&str>) -> Result<AmplitudeRequest, AmplitudeError> {
        let start_index = parse_cursor(cursor)?;
        let mut url = self
            .base_url
            .join(self.family.path())
            .map_err(|_| AmplitudeError::InvalidBaseUrl)?;
        url.query_pairs_mut()
            .append_pair("startIndex", &start_index.to_string())
            .append_pair("itemsPerPage", &self.page_size.to_string());
        Ok(AmplitudeRequest {
            url,
            family: self.family,
            start_index,
        })
    }

    /// Decode one SCIM list response for a request produced by this kernel.
    pub fn decode(
        &self,
        request: &AmplitudeRequest,
        body: &[u8],
    ) -> Result<AmplitudePage, AmplitudeError> {
        self.validate_request(request)?;
        let response: Value =
            serde_json::from_slice(body).map_err(|_| AmplitudeError::InvalidResponse)?;
        let resources = response
            .get("Resources")
            .and_then(Value::as_array)
            .ok_or(AmplitudeError::InvalidResponse)?;
        let total_results = response
            .get("totalResults")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(AmplitudeError::InvalidResponse)?;
        let response_start = response
            .get("startIndex")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(AmplitudeError::InvalidResponse)?;
        let response_page_size = response
            .get("itemsPerPage")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(AmplitudeError::InvalidResponse)?;
        if response_start != request.start_index || response_page_size == 0 {
            return Err(AmplitudeError::InvalidResponse);
        }

        let records = resources
            .iter()
            .map(|payload| self.normalize_record(payload))
            .collect::<Result<Vec<_>, _>>()?;
        let next_index = response_start.saturating_add(response_page_size);
        let next_cursor = (next_index < total_results).then(|| next_index.to_string());
        Ok(AmplitudePage {
            records,
            next_cursor,
        })
    }

    fn validate_request(&self, request: &AmplitudeRequest) -> Result<(), AmplitudeError> {
        if request.family != self.family {
            return Err(AmplitudeError::RequestScopeMismatch);
        }
        let expected = self.plan(Some(&request.start_index.to_string()))?;
        if request.url != expected.url {
            return Err(AmplitudeError::RequestScopeMismatch);
        }
        Ok(())
    }

    fn normalize_record(&self, payload: &Value) -> Result<AmplitudeRecord, AmplitudeError> {
        if !payload.is_object() {
            return Err(AmplitudeError::InvalidResponse);
        }
        match self.family {
            AmplitudeFamily::Users => {
                if first_nonblank([payload.get("id"), payload.get("userName")]).is_none() {
                    return Err(AmplitudeError::InvalidResponse);
                }
            }
            AmplitudeFamily::Groups => {
                if scalar_string(payload.get("id")).is_empty()
                    || scalar_string(payload.get("displayName")).is_empty()
                {
                    return Err(AmplitudeError::InvalidResponse);
                }
            }
        }
        let provider_id = match self.family {
            AmplitudeFamily::Users => first_nonblank([
                payload.get("id"),
                payload.get("userName"),
                first_email_value(payload),
            ]),
            AmplitudeFamily::Groups => {
                first_nonblank([payload.get("id"), payload.get("displayName"), None])
            }
        }
        .ok_or(AmplitudeError::MissingIdentity)?;
        Ok(AmplitudeRecord {
            family: self.family.as_str().to_owned(),
            provider_kind: self.family.provider_kind().to_owned(),
            fields: normalize_fields(self.family, payload),
            provider_id,
            payload: payload.clone(),
        })
    }
}

/// Stable Amplitude SCIM kernel failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AmplitudeError {
    /// The configured base URL is not an allowed secure origin.
    InvalidBaseUrl,
    /// The requested family is not a documented Amplitude SCIM family.
    InvalidFamily,
    /// The configured SCIM page size is outside the bounded range.
    InvalidPageSize,
    /// The supplied cursor is not a positive SCIM `startIndex`.
    InvalidCursor,
    /// The response is not a valid bounded SCIM list page.
    InvalidResponse,
    /// A SCIM resource has no stable provider-owned identity.
    MissingIdentity,
    /// A response request does not match this kernel's origin, family, and query.
    RequestScopeMismatch,
}

impl fmt::Display for AmplitudeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidBaseUrl => "amplitude base URL must be a secure origin",
            Self::InvalidFamily => "amplitude SCIM family is not supported",
            Self::InvalidPageSize => "amplitude SCIM page size must be between 1 and 1000",
            Self::InvalidCursor => "amplitude SCIM cursor must be a positive startIndex",
            Self::InvalidResponse => "amplitude response must be a bounded SCIM list page",
            Self::MissingIdentity => "amplitude SCIM resource is missing a stable identity",
            Self::RequestScopeMismatch => "amplitude request does not match the kernel",
        })
    }
}

impl Error for AmplitudeError {}

fn parse_cursor(cursor: Option<&str>) -> Result<usize, AmplitudeError> {
    let Some(cursor) = cursor.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(1);
    };
    let value = cursor
        .parse::<usize>()
        .map_err(|_| AmplitudeError::InvalidCursor)?;
    if value == 0 {
        return Err(AmplitudeError::InvalidCursor);
    }
    Ok(value)
}

fn normalize_fields(family: AmplitudeFamily, payload: &Value) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    insert_field(
        &mut fields,
        "created_at",
        scalar_at(payload, &["meta", "created"]),
    );
    insert_field(
        &mut fields,
        "observed_at",
        first_nonblank_values([
            value_at_path(payload, &["meta", "lastModified"]),
            value_at_path(payload, &["meta", "created"]),
            None,
        ]),
    );
    match family {
        AmplitudeFamily::Users => normalize_user_fields(&mut fields, payload),
        AmplitudeFamily::Groups => normalize_group_fields(&mut fields, payload),
    }
    fields
}

fn normalize_user_fields(fields: &mut BTreeMap<String, String>, payload: &Value) {
    let first_email = first_email_value(payload);
    let id = payload.get("id");
    let user_name = payload.get("userName");
    let email = first_nonblank_values([first_email, user_name, id]);
    let first_name = scalar_at(payload, &["name", "givenName"]);
    let last_name = scalar_at(payload, &["name", "familyName"]);
    let display_name = first_nonblank_values([
        payload.get("displayName"),
        value_at_path(payload, &["name", "formatted"]),
        user_name,
    ]);
    insert_field(fields, "active", scalar_string(payload.get("active")));
    insert_field(fields, "display_name", display_name);
    insert_field(fields, "email", email.clone());
    insert_field(fields, "first_name", first_name);
    insert_field(fields, "last_name", last_name);
    insert_field(
        fields,
        "login",
        first_nonblank_values([user_name, first_email, id]),
    );
    insert_field(fields, "primary_email", email);
    insert_field(
        fields,
        "resource_id",
        first_nonblank_values([id, user_name, None]),
    );
    insert_field(
        fields,
        "resource_name",
        first_nonblank_values([payload.get("displayName"), user_name, first_email]),
    );
    insert_field(fields, "resource_type", "amplitude_scim_user".to_owned());
    insert_field(
        fields,
        "source_event_id",
        first_nonblank_values([id, user_name, None]),
    );
    insert_field(fields, "status", scalar_string(payload.get("active")));
    insert_field(
        fields,
        "user_id",
        first_nonblank_values([id, user_name, None]),
    );
}

fn normalize_group_fields(fields: &mut BTreeMap<String, String>, payload: &Value) {
    let group_name = scalar_string(payload.get("displayName"));
    insert_field(fields, "group_id", scalar_string(payload.get("id")));
    insert_field(fields, "group_name", group_name.clone());
    insert_field(
        fields,
        "member_count",
        payload
            .get("members")
            .and_then(Value::as_array)
            .map_or_else(String::new, |members| members.len().to_string()),
    );
    insert_field(fields, "resource_id", scalar_string(payload.get("id")));
    insert_field(fields, "resource_name", group_name);
    insert_field(fields, "resource_type", "amplitude_scim_group".to_owned());
    insert_field(fields, "source_event_id", scalar_string(payload.get("id")));
}

fn insert_field(fields: &mut BTreeMap<String, String>, name: &str, value: String) {
    let value = value.trim();
    if !value.is_empty() {
        fields.insert(name.to_owned(), value.to_owned());
    }
}

fn first_email_value(payload: &Value) -> Option<&Value> {
    let emails = payload.get("emails")?.as_array()?;
    emails.first()?.get("value")
}

fn scalar_at(payload: &Value, path: &[&str]) -> String {
    scalar_string(value_at_path(payload, path))
}

fn value_at_path<'a>(payload: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter()
        .try_fold(payload, |value, segment| value.as_object()?.get(*segment))
}

fn first_nonblank<const N: usize>(values: [Option<&Value>; N]) -> Option<String> {
    values.into_iter().find_map(|value| {
        let value = scalar_string(value);
        (!value.is_empty()).then_some(value)
    })
}

fn first_nonblank_values<const N: usize>(values: [Option<&Value>; N]) -> String {
    first_nonblank(values).unwrap_or_default()
}

fn scalar_string(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.trim().to_owned(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        _ => String::new(),
    }
}

fn validate_origin(raw: &str) -> Result<Url, AmplitudeError> {
    let mut url = Url::parse(raw.trim()).map_err(|_| AmplitudeError::InvalidBaseUrl)?;
    let host = url.host_str().ok_or(AmplitudeError::InvalidBaseUrl)?;
    let loopback =
        host == "localhost" || IpAddr::from_str(host).is_ok_and(|address| address.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(AmplitudeError::InvalidBaseUrl);
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(AmplitudeError::InvalidBaseUrl);
    }
    if IpAddr::from_str(host).is_ok_and(|address| unsafe_ip_literal(address, loopback)) {
        return Err(AmplitudeError::InvalidBaseUrl);
    }
    if url.port().is_some_and(|port| port != 443) && !loopback {
        return Err(AmplitudeError::InvalidBaseUrl);
    }
    url.set_path("/");
    Ok(url)
}

fn unsafe_ip_literal(address: IpAddr, loopback: bool) -> bool {
    if loopback {
        return false;
    }
    match address {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_documentation()
                || address.is_unspecified()
                || address.is_multicast()
        }
        IpAddr::V6(address) => {
            address.is_unique_local()
                || address.is_unicast_link_local()
                || address.is_unspecified()
                || address.is_multicast()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DISCOVER_USERS: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sources/amplitude/testdata/discover_users.json"
    ));
    const DISCOVER_GROUPS: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sources/amplitude/testdata/discover_groups.json"
    ));
    const READ_USERS: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sources/amplitude/testdata/read_users.json"
    ));
    const READ_GROUPS: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sources/amplitude/testdata/read_groups.json"
    ));

    fn kernel(family: AmplitudeFamily) -> AmplitudeKernel {
        AmplitudeKernel::new("https://core.amplitude.com", family, None).unwrap()
    }

    #[test]
    fn plans_exact_scim_paths_pagination_and_credential_free_auth() {
        let users = kernel(AmplitudeFamily::Users);
        let request = users.plan(None).unwrap();
        assert_eq!(
            request.url().as_str(),
            "https://core.amplitude.com/scim/1/Users?startIndex=1&itemsPerPage=100"
        );
        assert_eq!(request.authorization_scheme(), "Bearer");
        assert_eq!(request.accept(), "application/json");

        let groups = kernel(AmplitudeFamily::Groups);
        assert_eq!(
            groups.plan(Some("101")).unwrap().url().as_str(),
            "https://core.amplitude.com/scim/1/Groups?startIndex=101&itemsPerPage=100"
        );
    }

    #[test]
    fn checked_in_scim_fixtures_bind_both_families() {
        for (family, discover, read) in [
            (AmplitudeFamily::Users, DISCOVER_USERS, READ_USERS),
            (AmplitudeFamily::Groups, DISCOVER_GROUPS, READ_GROUPS),
        ] {
            let kernel = kernel(family);
            let request = kernel.plan(None).unwrap();
            let page = kernel.decode(&request, read).unwrap();
            assert_eq!(page.next_cursor, None);
            assert_eq!(page.records.len(), 1);
            let record = &page.records[0];
            assert_eq!(record.family, family.as_str());
            assert_eq!(record.provider_kind, family.provider_kind());

            let discover: Value = serde_json::from_slice(discover).unwrap();
            let discover_id = discover["Resources"][0]["id"].as_str().unwrap();
            assert_eq!(record.provider_id, discover_id);
            assert_eq!(record.fields["source_event_id"], discover_id);
            assert_eq!(record.fields["resource_id"], discover_id);
        }

        let users = kernel(AmplitudeFamily::Users);
        let user_page = users
            .decode(&users.plan(None).unwrap(), READ_USERS)
            .unwrap();
        let user = &user_page.records[0];
        assert_eq!(user.fields["email"], "datamonster@example.com");
        assert_eq!(user.fields["display_name"], "datamonster@example.com");
        assert_eq!(user.fields["user_id"], "datamonster@example.com");

        let groups = kernel(AmplitudeFamily::Groups);
        let group_page = groups
            .decode(&groups.plan(None).unwrap(), READ_GROUPS)
            .unwrap();
        let group = &group_page.records[0];
        assert_eq!(group.fields["group_name"], "Datamonster Party");
        assert_eq!(group.fields["member_count"], "1");
    }

    #[test]
    fn advances_scim_cursor_by_the_response_page_size() {
        let kernel = kernel(AmplitudeFamily::Users);
        let request = kernel.plan(None).unwrap();
        let body = br#"{
            "startIndex":1,
            "itemsPerPage":100,
            "totalResults":200,
            "Resources":[{"id":"first@example.com"}]
        }"#;
        let page = kernel.decode(&request, body).unwrap();
        assert_eq!(page.next_cursor.as_deref(), Some("101"));
        assert_eq!(
            kernel
                .plan(page.next_cursor.as_deref())
                .unwrap()
                .url()
                .as_str(),
            "https://core.amplitude.com/scim/1/Users?startIndex=101&itemsPerPage=100"
        );
    }

    #[test]
    fn matches_go_user_selector_order_and_fallbacks() {
        let kernel = kernel(AmplitudeFamily::Users);
        let request = kernel.plan(None).unwrap();
        let body = br#"{
            "startIndex":1,
            "itemsPerPage":100,
            "totalResults":1,
            "Resources":[{
                "id":"provider-id",
                "userName":"user@example.com",
                "name":{"givenName":"Not","familyName":"A Display Name"},
                "emails":[
                    {"value":"first@example.com","primary":false},
                    {"value":"primary@example.com","primary":true}
                ]
            }]
        }"#;
        let page = kernel.decode(&request, body).unwrap();
        let record = &page.records[0];
        assert_eq!(record.provider_id, "provider-id");
        assert_eq!(record.fields["display_name"], "user@example.com");
        assert_eq!(record.fields["email"], "first@example.com");
        assert_eq!(record.fields["primary_email"], "first@example.com");
        assert_eq!(record.fields["login"], "user@example.com");
        assert_eq!(record.fields["resource_id"], "provider-id");
        assert_eq!(record.fields["user_id"], "provider-id");

        let body = br#"{
            "startIndex":1,
            "itemsPerPage":100,
            "totalResults":1,
            "Resources":[{"emails":[{"value":"email-only@example.com"}]}]
        }"#;
        assert_eq!(
            kernel.decode(&request, body).unwrap_err(),
            AmplitudeError::InvalidResponse
        );
    }

    #[test]
    fn rejects_display_name_only_groups_before_catalog_admission() {
        let kernel = kernel(AmplitudeFamily::Groups);
        let request = kernel.plan(None).unwrap();
        let body = br#"{
            "startIndex":1,
            "itemsPerPage":100,
            "totalResults":1,
            "Resources":[{"displayName":"Fallback Group","members":[]}]
        }"#;
        assert_eq!(
            kernel.decode(&request, body).unwrap_err(),
            AmplitudeError::InvalidResponse
        );
    }

    #[test]
    fn rejects_groups_without_the_catalog_required_group_name() {
        let kernel = kernel(AmplitudeFamily::Groups);
        let request = kernel.plan(None).unwrap();
        for resource in [r#"{"id":"632"}"#, r#"{"id":"632","displayName":{}}"#] {
            let body = format!(
                r#"{{
                    "startIndex":1,
                    "itemsPerPage":100,
                    "totalResults":1,
                    "Resources":[{resource}]
                }}"#
            );
            assert_eq!(
                kernel.decode(&request, body.as_bytes()).unwrap_err(),
                AmplitudeError::InvalidResponse
            );
        }
    }

    #[test]
    fn matches_go_strict_total_results_cursor_boundary() {
        let kernel = kernel(AmplitudeFamily::Users);
        let request = kernel.plan(None).unwrap();
        for (total_results, expected) in [(101, None), (102, Some("101"))] {
            let body = format!(
                r#"{{
                    "startIndex":1,
                    "itemsPerPage":100,
                    "totalResults":{total_results},
                    "Resources":[{{"id":"user@example.com"}}]
                }}"#
            );
            let page = kernel.decode(&request, body.as_bytes()).unwrap();
            assert_eq!(page.next_cursor.as_deref(), expected);
        }
    }

    #[test]
    fn preserves_the_raw_scim_resource() {
        let kernel = kernel(AmplitudeFamily::Groups);
        let page = kernel
            .decode(&kernel.plan(None).unwrap(), READ_GROUPS)
            .unwrap();
        assert_eq!(
            page.records[0].payload["members"][0]["display"],
            "Data Monster"
        );
        assert_eq!(
            page.records[0].fields["observed_at"],
            "2022-02-03T21:25:25.000Z"
        );
    }

    #[test]
    fn rejects_unsafe_origins_invalid_cursors_and_page_sizes() {
        for base_url in [
            "http://core.amplitude.com",
            "https://user@core.amplitude.com",
            "https://core.amplitude.com/scim",
            "https://core.amplitude.com?token=secret",
            "https://10.0.0.1",
        ] {
            assert_eq!(
                AmplitudeKernel::new(base_url, AmplitudeFamily::Users, None).unwrap_err(),
                AmplitudeError::InvalidBaseUrl
            );
        }
        assert_eq!(
            AmplitudeKernel::new(
                "https://core.amplitude.com",
                AmplitudeFamily::Users,
                Some(0)
            )
            .unwrap_err(),
            AmplitudeError::InvalidPageSize
        );
        let kernel = kernel(AmplitudeFamily::Users);
        for cursor in ["0", "-1", "next", "1.5"] {
            assert_eq!(
                kernel.plan(Some(cursor)).unwrap_err(),
                AmplitudeError::InvalidCursor
            );
        }
    }

    #[test]
    fn rejects_request_scope_mismatches_and_malformed_pages() {
        let users = kernel(AmplitudeFamily::Users);
        let groups = kernel(AmplitudeFamily::Groups);
        let group_request = groups.plan(None).unwrap();
        assert_eq!(
            users.decode(&group_request, READ_USERS).unwrap_err(),
            AmplitudeError::RequestScopeMismatch
        );
        let mut request = users.plan(None).unwrap();
        request.url.set_path("/scim/1/Groups");
        assert_eq!(
            users.decode(&request, READ_USERS).unwrap_err(),
            AmplitudeError::RequestScopeMismatch
        );
        let request = users.plan(None).unwrap();
        for body in [
            br#"[]"#.as_slice(),
            br#"{"Resources":{}}"#.as_slice(),
            br#"{"Resources":[{}],"startIndex":1,"itemsPerPage":100,"totalResults":1}"#.as_slice(),
        ] {
            assert!(users.decode(&request, body).is_err());
        }
    }
}
