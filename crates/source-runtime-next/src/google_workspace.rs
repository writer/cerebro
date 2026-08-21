//! Google Workspace request, response, and role-assignee fanout kernel.
//!
//! The kernel plans credential-free Admin SDK requests and decodes bounded
//! provider pages. Live egress and OAuth credential ownership remain outside
//! this module. Role assignment pages preserve the Go provider's per-page
//! user lookup cache without moving provider calls into the kernel.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    net::IpAddr,
    str::FromStr,
};

use reqwest::Url;
use serde_json::{Map, Value};

const DEFAULT_CUSTOMER_ID: &str = "my_customer";
const DEFAULT_APPLICATION: &str = "admin";
const DEFAULT_PAGE_SIZE: usize = 10;
const MAX_PAGE_SIZE: usize = 200;

/// A Google Workspace Admin SDK family with a provider-owned collection contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GoogleWorkspaceFamily {
    /// Reports API administrative activity.
    Audit,
    /// Directory groups.
    Group,
    /// Directory members for one configured group.
    GroupMember,
    /// Directory administrative role assignments.
    RoleAssignment,
    /// Directory users.
    User,
}

impl GoogleWorkspaceFamily {
    /// Return the source-catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Audit => "audit",
            Self::Group => "group",
            Self::GroupMember => "group_member",
            Self::RoleAssignment => "role_assignment",
            Self::User => "user",
        }
    }

    /// Return the emitted provider kind.
    pub const fn provider_kind(self) -> &'static str {
        match self {
            Self::Audit => "google_workspace.audit",
            Self::Group => "google_workspace.group",
            Self::GroupMember => "google_workspace.group_member",
            Self::RoleAssignment => "google_workspace.role_assignment",
            Self::User => "google_workspace.user",
        }
    }

    const fn response_field(self) -> &'static str {
        match self {
            Self::User => "users",
            Self::Group => "groups",
            Self::GroupMember => "members",
            Self::RoleAssignment | Self::Audit => "items",
        }
    }
}

impl FromStr for GoogleWorkspaceFamily {
    type Err = GoogleWorkspaceError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "audit" => Ok(Self::Audit),
            "group" => Ok(Self::Group),
            "group_member" => Ok(Self::GroupMember),
            "role_assignment" => Ok(Self::RoleAssignment),
            "user" => Ok(Self::User),
            _ => Err(GoogleWorkspaceError::InvalidFamily),
        }
    }
}

/// Provider scopes accepted by Google Workspace collection families.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GoogleWorkspaceFilters {
    /// Admin SDK customer identifier; defaults to `my_customer`.
    pub customer_id: Option<String>,
    /// Group key required for the `group_member` family.
    pub group_key: Option<String>,
    /// Reports API application name; defaults to `admin`.
    pub application: Option<String>,
}

/// One credential-free HTTP request planned by the Google Workspace kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoogleWorkspaceRequest {
    url: Url,
    family: GoogleWorkspaceFamily,
    stage: RequestStage,
    role_state: Option<Box<RoleAssignmentState>>,
}

impl GoogleWorkspaceRequest {
    /// Return the exact provider URL. The caller must authorize it before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return the required `Authorization` scheme without credential material.
    pub const fn authorization_scheme(&self) -> &'static str {
        "Bearer"
    }

    /// Return the required response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }
}

/// One normalized Google Workspace provider record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoogleWorkspaceRecord {
    /// Source-catalog family identifier.
    pub family: String,
    /// Emitted provider kind.
    pub provider_kind: String,
    /// Stable provider-owned identity, group-scoped for memberships.
    pub provider_id: String,
    /// Provider-specific scalar fields used by source mapping.
    pub fields: BTreeMap<String, String>,
    /// Original provider record, with no credentials added.
    pub payload: Value,
}

/// A bounded Google Workspace page and its opaque provider cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoogleWorkspacePage {
    /// Normalized records in provider order.
    pub records: Vec<GoogleWorkspaceRecord>,
    /// `nextPageToken` for the next provider page.
    pub next_cursor: Option<String>,
}

/// Result of decoding one Google Workspace response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GoogleWorkspaceOutcome {
    /// Role-assignee enrichment requires one bounded user lookup.
    Request(GoogleWorkspaceRequest),
    /// The provider response completed one source-runtime page.
    Page(GoogleWorkspacePage),
}

/// Provider-specific Google Workspace request and response state machine.
#[derive(Clone, Debug)]
pub struct GoogleWorkspaceKernel {
    base_url: Url,
    domain: String,
    family: GoogleWorkspaceFamily,
    customer_id: String,
    group_key: Option<String>,
    application: String,
    page_size: usize,
}

impl GoogleWorkspaceKernel {
    /// Build a kernel for one Admin SDK origin, tenant domain, and family.
    ///
    /// The returned requests still require the shared live-egress decision and
    /// an operation-scoped bearer credential before network access.
    pub fn new(
        base_url: &str,
        domain: &str,
        family: GoogleWorkspaceFamily,
        filters: GoogleWorkspaceFilters,
        page_size: Option<usize>,
    ) -> Result<Self, GoogleWorkspaceError> {
        let base_url = validate_origin(base_url)?;
        let domain = required_value(domain, GoogleWorkspaceError::MissingDomain)?;
        let customer_id = optional_value(filters.customer_id, DEFAULT_CUSTOMER_ID);
        let group_key = nonblank(filters.group_key);
        if family == GoogleWorkspaceFamily::GroupMember && group_key.is_none() {
            return Err(GoogleWorkspaceError::MissingGroupKey);
        }
        let application = optional_value(filters.application, DEFAULT_APPLICATION);
        let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE);
        if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
            return Err(GoogleWorkspaceError::InvalidPageSize);
        }
        Ok(Self {
            base_url,
            domain,
            family,
            customer_id,
            group_key,
            application,
            page_size,
        })
    }

    /// Plan the credential-free request for one provider page.
    pub fn plan(
        &self,
        cursor: Option<&str>,
    ) -> Result<GoogleWorkspaceRequest, GoogleWorkspaceError> {
        let cursor = cursor.map(str::trim).filter(|value| !value.is_empty());
        let mut url = match self.family {
            GoogleWorkspaceFamily::User => self.endpoint(&["admin", "directory", "v1", "users"])?,
            GoogleWorkspaceFamily::Group => {
                self.endpoint(&["admin", "directory", "v1", "groups"])?
            }
            GoogleWorkspaceFamily::GroupMember => self.endpoint(&[
                "admin",
                "directory",
                "v1",
                "groups",
                self.group_key
                    .as_deref()
                    .ok_or(GoogleWorkspaceError::MissingGroupKey)?,
                "members",
            ])?,
            GoogleWorkspaceFamily::RoleAssignment => self.endpoint(&[
                "admin",
                "directory",
                "v1",
                "customer",
                &self.customer_id,
                "roleassignments",
            ])?,
            GoogleWorkspaceFamily::Audit => self.endpoint(&[
                "admin",
                "reports",
                "v1",
                "activity",
                "users",
                "all",
                "applications",
                &self.application,
            ])?,
        };
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("maxResults", &self.page_size.to_string());
            if let Some(cursor) = cursor {
                query.append_pair("pageToken", cursor);
            }
            match self.family {
                GoogleWorkspaceFamily::User | GoogleWorkspaceFamily::Group => {
                    query.append_pair("customer", &self.customer_id);
                }
                GoogleWorkspaceFamily::Audit => {
                    query.append_pair("customerId", &self.customer_id);
                }
                GoogleWorkspaceFamily::GroupMember | GoogleWorkspaceFamily::RoleAssignment => {}
            }
        }
        Ok(GoogleWorkspaceRequest {
            url,
            family: self.family,
            stage: RequestStage::Direct,
            role_state: None,
        })
    }

    /// Decode a response for a request produced by this kernel.
    pub fn decode(
        &self,
        request: &GoogleWorkspaceRequest,
        body: &[u8],
    ) -> Result<GoogleWorkspaceOutcome, GoogleWorkspaceError> {
        if request.family != self.family || request.url.origin() != self.base_url.origin() {
            return Err(GoogleWorkspaceError::RequestScopeMismatch);
        }
        match request.stage {
            RequestStage::Direct => self.decode_direct(body),
            RequestStage::ResolveRoleUser => self.decode_role_user(request, body),
        }
    }

    fn decode_direct(&self, body: &[u8]) -> Result<GoogleWorkspaceOutcome, GoogleWorkspaceError> {
        let decoded = decode_page(body, self.family.response_field())?;
        if self.family != GoogleWorkspaceFamily::RoleAssignment {
            return self
                .normalize_page(decoded.records, decoded.next_cursor, &BTreeMap::new())
                .map(GoogleWorkspaceOutcome::Page);
        }
        let lookups = role_user_lookups(&decoded.records)?;
        if lookups.is_empty() {
            return self
                .normalize_page(decoded.records, decoded.next_cursor, &BTreeMap::new())
                .map(GoogleWorkspaceOutcome::Page);
        }
        self.role_user_request(RoleAssignmentState {
            records: decoded.records,
            next_cursor: decoded.next_cursor,
            lookups,
            lookup_index: 0,
            users: BTreeMap::new(),
        })
        .map(GoogleWorkspaceOutcome::Request)
    }

    fn decode_role_user(
        &self,
        request: &GoogleWorkspaceRequest,
        body: &[u8],
    ) -> Result<GoogleWorkspaceOutcome, GoogleWorkspaceError> {
        let mut state = request
            .role_state
            .as_deref()
            .cloned()
            .ok_or(GoogleWorkspaceError::MissingRoleState)?;
        let lookup = state
            .lookups
            .get(state.lookup_index)
            .cloned()
            .ok_or(GoogleWorkspaceError::MissingRoleState)?;
        let user = decode_object(body)?;
        state.users.insert(
            lookup,
            ResolvedUser {
                email: nested_scalar(&user, &["primaryEmail"]).unwrap_or_default(),
                name: nested_scalar(&user, &["name", "fullName"]).unwrap_or_default(),
            },
        );
        state.lookup_index += 1;
        if state.lookup_index < state.lookups.len() {
            return self
                .role_user_request(state)
                .map(GoogleWorkspaceOutcome::Request);
        }
        self.normalize_page(state.records, state.next_cursor, &state.users)
            .map(GoogleWorkspaceOutcome::Page)
    }

    fn role_user_request(
        &self,
        state: RoleAssignmentState,
    ) -> Result<GoogleWorkspaceRequest, GoogleWorkspaceError> {
        let user_key = state
            .lookups
            .get(state.lookup_index)
            .ok_or(GoogleWorkspaceError::MissingRoleState)?;
        Ok(GoogleWorkspaceRequest {
            url: self.endpoint(&["admin", "directory", "v1", "users", user_key])?,
            family: self.family,
            stage: RequestStage::ResolveRoleUser,
            role_state: Some(Box::new(state)),
        })
    }

    fn normalize_page(
        &self,
        payloads: Vec<Value>,
        next_cursor: Option<String>,
        users: &BTreeMap<String, ResolvedUser>,
    ) -> Result<GoogleWorkspacePage, GoogleWorkspaceError> {
        let records = payloads
            .into_iter()
            .map(|payload| self.normalize_record(payload, users))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(GoogleWorkspacePage {
            records,
            next_cursor,
        })
    }

    fn normalize_record(
        &self,
        payload: Value,
        users: &BTreeMap<String, ResolvedUser>,
    ) -> Result<GoogleWorkspaceRecord, GoogleWorkspaceError> {
        let object = payload
            .as_object()
            .ok_or(GoogleWorkspaceError::InvalidRecord)?;
        let mut fields = BTreeMap::new();
        insert(&mut fields, "domain", self.domain.clone());
        insert(&mut fields, "family", self.family.as_str().to_owned());
        let provider_id = match self.family {
            GoogleWorkspaceFamily::User => normalize_user(object, &mut fields)?,
            GoogleWorkspaceFamily::Group => normalize_group(object, &mut fields)?,
            GoogleWorkspaceFamily::GroupMember => {
                normalize_group_member(object, &mut fields, self.group_key.as_deref())?
            }
            GoogleWorkspaceFamily::RoleAssignment => {
                normalize_role_assignment(object, &mut fields, users)?
            }
            GoogleWorkspaceFamily::Audit => normalize_audit(object, &mut fields)?,
        };
        Ok(GoogleWorkspaceRecord {
            family: self.family.as_str().to_owned(),
            provider_kind: self.family.provider_kind().to_owned(),
            provider_id,
            fields,
            payload,
        })
    }

    fn endpoint(&self, segments: &[&str]) -> Result<Url, GoogleWorkspaceError> {
        let mut url = self.base_url.clone();
        url.set_path("/");
        let mut path = url
            .path_segments_mut()
            .map_err(|_| GoogleWorkspaceError::InvalidBaseUrl)?;
        path.pop_if_empty();
        path.extend(segments.iter().copied());
        drop(path);
        Ok(url)
    }
}

/// Safe Google Workspace kernel failures. Messages never include credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GoogleWorkspaceError {
    /// Family identifier is not one of the five supported contracts.
    InvalidFamily,
    /// Base URL is not a secure provider origin.
    InvalidBaseUrl,
    /// Tenant domain is blank.
    MissingDomain,
    /// Group-member collection omitted its group key.
    MissingGroupKey,
    /// Page size is outside the provider's 1 through 200 bound.
    InvalidPageSize,
    /// Response JSON does not match the family page contract.
    InvalidResponse,
    /// A provider record is not an object.
    InvalidRecord,
    /// A provider record omitted its stable identity.
    MissingRecordIdentity,
    /// Role-assignee response decoding lost its request-bound state.
    MissingRoleState,
    /// A request was decoded by a kernel configured for another family or origin.
    RequestScopeMismatch,
}

impl fmt::Display for GoogleWorkspaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "google_workspace family is invalid",
            Self::InvalidBaseUrl => "google_workspace base URL must be a secure origin",
            Self::MissingDomain => "google_workspace domain is required",
            Self::MissingGroupKey => "google_workspace group key is required for group members",
            Self::InvalidPageSize => "google_workspace page size must be between 1 and 200",
            Self::InvalidResponse => "google_workspace response does not match the page contract",
            Self::InvalidRecord => "google_workspace record must be an object",
            Self::MissingRecordIdentity => "google_workspace record identity is missing",
            Self::MissingRoleState => "google_workspace role lookup state is missing",
            Self::RequestScopeMismatch => {
                "google_workspace request family or origin does not match the kernel"
            }
        })
    }
}

impl Error for GoogleWorkspaceError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestStage {
    Direct,
    ResolveRoleUser,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RoleAssignmentState {
    records: Vec<Value>,
    next_cursor: Option<String>,
    lookups: Vec<String>,
    lookup_index: usize,
    users: BTreeMap<String, ResolvedUser>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolvedUser {
    email: String,
    name: String,
}

struct DecodedPage {
    records: Vec<Value>,
    next_cursor: Option<String>,
}

fn validate_origin(raw: &str) -> Result<Url, GoogleWorkspaceError> {
    let mut url = Url::parse(raw.trim()).map_err(|_| GoogleWorkspaceError::InvalidBaseUrl)?;
    let host = url.host_str().ok_or(GoogleWorkspaceError::InvalidBaseUrl)?;
    let loopback =
        host == "localhost" || IpAddr::from_str(host).is_ok_and(|address| address.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(GoogleWorkspaceError::InvalidBaseUrl);
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(GoogleWorkspaceError::InvalidBaseUrl);
    }
    if IpAddr::from_str(host).is_ok_and(|address| unsafe_ip_literal(address, loopback)) {
        return Err(GoogleWorkspaceError::InvalidBaseUrl);
    }
    if url.port().is_some_and(|port| port != 443) && !loopback {
        return Err(GoogleWorkspaceError::InvalidBaseUrl);
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

fn required_value(
    value: &str,
    error: GoogleWorkspaceError,
) -> Result<String, GoogleWorkspaceError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(error);
    }
    Ok(value.to_owned())
}

fn optional_value(value: Option<String>, default: &str) -> String {
    nonblank(value).unwrap_or_else(|| default.to_owned())
}

fn nonblank(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn decode_page(body: &[u8], field: &str) -> Result<DecodedPage, GoogleWorkspaceError> {
    let root = decode_object(body)?;
    let records = match root.get(field) {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(records)) => records.clone(),
        Some(_) => return Err(GoogleWorkspaceError::InvalidResponse),
    };
    let next_cursor = match root.get("nextPageToken") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => {
            let value = value.trim();
            (!value.is_empty()).then(|| value.to_owned())
        }
        Some(_) => return Err(GoogleWorkspaceError::InvalidResponse),
    };
    Ok(DecodedPage {
        records,
        next_cursor,
    })
}

fn decode_object(body: &[u8]) -> Result<Map<String, Value>, GoogleWorkspaceError> {
    serde_json::from_slice::<Value>(body)
        .map_err(|_| GoogleWorkspaceError::InvalidResponse)?
        .as_object()
        .cloned()
        .ok_or(GoogleWorkspaceError::InvalidResponse)
}

fn role_user_lookups(records: &[Value]) -> Result<Vec<String>, GoogleWorkspaceError> {
    let mut seen = BTreeSet::new();
    let mut lookups = Vec::new();
    for record in records {
        let object = record
            .as_object()
            .ok_or(GoogleWorkspaceError::InvalidRecord)?;
        if scalar(object.get("assigneeType"))
            .is_some_and(|value| value.eq_ignore_ascii_case("user"))
            && let Some(user_key) = scalar(object.get("assignedTo"))
            && !user_key.is_empty()
            && seen.insert(user_key.clone())
        {
            lookups.push(user_key);
        }
    }
    Ok(lookups)
}

fn normalize_user(
    object: &Map<String, Value>,
    fields: &mut BTreeMap<String, String>,
) -> Result<String, GoogleWorkspaceError> {
    let provider_id = first_values(object, &["id", "primaryEmail"])
        .ok_or(GoogleWorkspaceError::MissingRecordIdentity)?;
    let email = scalar(object.get("primaryEmail")).unwrap_or_default();
    insert(
        fields,
        "user_id",
        scalar(object.get("id")).unwrap_or_default(),
    );
    insert(fields, "primary_email", email.clone());
    insert(fields, "email", email.clone());
    insert(fields, "login", email);
    insert(
        fields,
        "display_name",
        nested_scalar(object, &["name", "fullName"]).unwrap_or_default(),
    );
    for (source, target) in [
        ("creationTime", "created_at"),
        ("lastLoginTime", "last_login_at"),
        ("isAdmin", "is_admin"),
        ("isDelegatedAdmin", "is_delegated_admin"),
        ("isEnrolledIn2Sv", "mfa_enrolled"),
        ("isEnforcedIn2Sv", "mfa_enforced"),
        ("suspended", "suspended"),
        ("archived", "archived"),
        ("orgUnitPath", "org_unit_path"),
    ] {
        insert(
            fields,
            target,
            scalar(object.get(source)).unwrap_or_default(),
        );
    }
    Ok(provider_id)
}

fn normalize_group(
    object: &Map<String, Value>,
    fields: &mut BTreeMap<String, String>,
) -> Result<String, GoogleWorkspaceError> {
    let provider_id = first_values(object, &["id", "email"])
        .ok_or(GoogleWorkspaceError::MissingRecordIdentity)?;
    let email = scalar(object.get("email")).unwrap_or_default();
    let name = scalar(object.get("name")).unwrap_or_default();
    insert(
        fields,
        "group_id",
        scalar(object.get("id")).unwrap_or_default(),
    );
    insert(fields, "group_email", email.clone());
    insert(fields, "email", email);
    insert(fields, "group_name", name.clone());
    insert(fields, "name", name);
    for (source, target) in [
        ("description", "description"),
        ("adminCreated", "admin_created"),
        ("directMembersCount", "direct_members_count"),
    ] {
        insert(
            fields,
            target,
            scalar(object.get(source)).unwrap_or_default(),
        );
    }
    Ok(provider_id)
}

fn normalize_group_member(
    object: &Map<String, Value>,
    fields: &mut BTreeMap<String, String>,
    group_key: Option<&str>,
) -> Result<String, GoogleWorkspaceError> {
    let group_key = group_key.ok_or(GoogleWorkspaceError::MissingGroupKey)?;
    let member_id = first_values(object, &["id", "email"])
        .ok_or(GoogleWorkspaceError::MissingRecordIdentity)?;
    let email = scalar(object.get("email")).unwrap_or_default();
    insert(fields, "group_id", group_key.to_owned());
    insert(fields, "group_email", group_key.to_owned());
    insert(
        fields,
        "member_id",
        scalar(object.get("id")).unwrap_or_default(),
    );
    insert(fields, "member_email", email.clone());
    insert(
        fields,
        "member_user_id",
        scalar(object.get("id")).unwrap_or_default(),
    );
    insert(fields, "email", email);
    insert(fields, "member_type", lowercase_scalar(object.get("type")));
    insert(
        fields,
        "role",
        scalar(object.get("role")).unwrap_or_default(),
    );
    insert(
        fields,
        "member_status",
        scalar(object.get("status")).unwrap_or_default(),
    );
    insert(
        fields,
        "user_id",
        scalar(object.get("id")).unwrap_or_default(),
    );
    Ok(format!("{group_key}::{member_id}"))
}

fn normalize_role_assignment(
    object: &Map<String, Value>,
    fields: &mut BTreeMap<String, String>,
    users: &BTreeMap<String, ResolvedUser>,
) -> Result<String, GoogleWorkspaceError> {
    let provider_id = scalar(object.get("roleAssignmentId"))
        .filter(|value| !value.is_empty())
        .ok_or(GoogleWorkspaceError::MissingRecordIdentity)?;
    let assigned_to = scalar(object.get("assignedTo")).unwrap_or_default();
    let resolved = users.get(&assigned_to);
    let subject_email = resolved
        .map(|user| user.email.clone())
        .filter(|value| !value.is_empty())
        .or_else(|| email_like(&assigned_to))
        .unwrap_or_default();
    insert(fields, "role_assignment_id", provider_id.clone());
    insert(
        fields,
        "role_id",
        scalar(object.get("roleId")).unwrap_or_default(),
    );
    insert(fields, "subject_email", subject_email.clone());
    insert(fields, "subject_id", assigned_to.clone());
    insert(fields, "subject_login", subject_email);
    insert(
        fields,
        "subject_name",
        resolved.map(|user| user.name.clone()).unwrap_or_default(),
    );
    insert(fields, "assigned_to", assigned_to);
    let subject_type = lowercase_scalar(object.get("assigneeType"));
    insert(fields, "subject_type", subject_type.clone());
    insert(fields, "principal_type", subject_type);
    insert(
        fields,
        "scope_type",
        scalar(object.get("scopeType")).unwrap_or_default(),
    );
    insert(
        fields,
        "org_unit_id",
        scalar(object.get("orgUnitId")).unwrap_or_default(),
    );
    insert(fields, "event_type", "admin.role.assignment".to_owned());
    insert(fields, "action", "admin.role.assignment".to_owned());
    Ok(provider_id)
}

fn normalize_audit(
    object: &Map<String, Value>,
    fields: &mut BTreeMap<String, String>,
) -> Result<String, GoogleWorkspaceError> {
    let event = object
        .get("events")
        .and_then(Value::as_array)
        .and_then(|events| events.first())
        .and_then(Value::as_object);
    let event_name = event
        .and_then(|event| scalar(event.get("name")))
        .unwrap_or_default();
    let event_type = event
        .and_then(|event| scalar(event.get("type")))
        .unwrap_or_default();
    let provider_id = nested_scalar(object, &["id", "uniqueQualifier"])
        .or_else(|| (!event_name.is_empty()).then(|| event_name.clone()))
        .or_else(|| nested_scalar(object, &["id", "time"]))
        .ok_or(GoogleWorkspaceError::MissingRecordIdentity)?;
    let parameters = audit_parameters(event);
    let resource_id = first_nonempty([
        parameters.get("USER_EMAIL").cloned(),
        parameters.get("GROUP_EMAIL").cloned(),
        parameters.get("APP_NAME").cloned(),
        parameters.get("CLIENT_ID").cloned(),
        parameters.get("ROLE_NAME").cloned(),
        Some(event_name.clone()),
    ])
    .unwrap_or_default();
    let resource_type = first_nonempty([
        parameters.get("RESOURCE_TYPE").cloned(),
        Some(event_type),
        Some("security_setting".to_owned()),
    ])
    .unwrap_or_default();
    insert(fields, "event_type", event_name.clone());
    insert(fields, "event_name", event_name.clone());
    insert(fields, "action", event_name);
    insert(fields, "resource_id", resource_id.clone());
    insert(
        fields,
        "resource_type",
        normalize_resource_type(&resource_type),
    );
    insert(fields, "resource_name", resource_id);
    let actor_email = nested_scalar(object, &["actor", "email"]).unwrap_or_default();
    insert(fields, "actor_email", actor_email.clone());
    insert(
        fields,
        "actor_id",
        nested_scalar(object, &["actor", "profileId"]).unwrap_or_default(),
    );
    insert(fields, "actor_alternate_id", actor_email);
    insert(
        fields,
        "application",
        nested_scalar(object, &["id", "applicationName"]).unwrap_or_default(),
    );
    insert(
        fields,
        "customer_id",
        nested_scalar(object, &["id", "customerId"]).unwrap_or_default(),
    );
    Ok(provider_id)
}

fn audit_parameters(event: Option<&Map<String, Value>>) -> BTreeMap<String, String> {
    let mut parameters = BTreeMap::new();
    let Some(values) = event
        .and_then(|event| event.get("parameters"))
        .and_then(Value::as_array)
    else {
        return parameters;
    };
    for parameter in values.iter().filter_map(Value::as_object) {
        if let (Some(name), Some(value)) = (
            scalar(parameter.get("name")),
            scalar(parameter.get("value")),
        ) {
            parameters.insert(name.trim().to_uppercase(), value.trim().to_owned());
        }
    }
    parameters
}

fn first_values(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| scalar(object.get(*key)).filter(|value| !value.is_empty()))
}

fn nested_scalar(object: &Map<String, Value>, path: &[&str]) -> Option<String> {
    let (first, rest) = path.split_first()?;
    let mut value = object.get(*first)?;
    for segment in rest {
        value = value.as_object()?.get(*segment)?;
    }
    scalar(Some(value))
}

fn scalar(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(value) => Some(value.trim().to_owned()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn lowercase_scalar(value: Option<&Value>) -> String {
    scalar(value).unwrap_or_default().to_lowercase()
}

fn insert(fields: &mut BTreeMap<String, String>, key: &str, value: String) {
    if !value.trim().is_empty() {
        fields.insert(key.to_owned(), value);
    }
}

fn email_like(value: &str) -> Option<String> {
    let value = value.trim();
    value.contains('@').then(|| value.to_lowercase())
}

fn normalize_resource_type(value: &str) -> String {
    value.trim().to_lowercase().replace([' ', '-'], "_")
}

fn first_nonempty<const N: usize>(values: [Option<String>; N]) -> Option<String> {
    values
        .into_iter()
        .flatten()
        .find(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUDIT_FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sources/googleworkspace/testdata/read_audit.json"
    ));
    const GROUP_FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sources/googleworkspace/testdata/read_group.json"
    ));
    const GROUP_MEMBER_FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sources/googleworkspace/testdata/read_group_member.json"
    ));
    const ROLE_FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sources/googleworkspace/testdata/read_role_assignment.json"
    ));
    const USER_FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sources/googleworkspace/testdata/read_user.json"
    ));

    fn kernel(family: GoogleWorkspaceFamily) -> GoogleWorkspaceKernel {
        GoogleWorkspaceKernel::new(
            "https://admin.googleapis.com",
            "writer.com",
            family,
            GoogleWorkspaceFilters {
                customer_id: Some("C01".to_owned()),
                group_key: Some("security@writer.com".to_owned()),
                application: Some("admin".to_owned()),
            },
            Some(2),
        )
        .unwrap()
    }

    fn fixture_page(family: GoogleWorkspaceFamily, fixture: &[u8]) -> Vec<u8> {
        let records: Value = serde_json::from_slice(fixture).unwrap();
        serde_json::to_vec(&serde_json::json!({family.response_field(): records})).unwrap()
    }

    #[test]
    fn all_five_families_plan_exact_paths_queries_and_auth_contract() {
        let cases = [
            (
                GoogleWorkspaceFamily::Audit,
                "/admin/reports/v1/activity/users/all/applications/admin",
                Some(("customerId", "C01")),
            ),
            (
                GoogleWorkspaceFamily::Group,
                "/admin/directory/v1/groups",
                Some(("customer", "C01")),
            ),
            (
                GoogleWorkspaceFamily::GroupMember,
                "/admin/directory/v1/groups/security@writer.com/members",
                None,
            ),
            (
                GoogleWorkspaceFamily::RoleAssignment,
                "/admin/directory/v1/customer/C01/roleassignments",
                None,
            ),
            (
                GoogleWorkspaceFamily::User,
                "/admin/directory/v1/users",
                Some(("customer", "C01")),
            ),
        ];
        for (family, path, scope) in cases {
            let request = kernel(family).plan(Some("page-2")).unwrap();
            let query = request
                .url()
                .query_pairs()
                .into_owned()
                .collect::<BTreeMap<_, _>>();
            assert_eq!(request.url().path(), path);
            assert_eq!(query.get("maxResults").map(String::as_str), Some("2"));
            assert_eq!(query.get("pageToken").map(String::as_str), Some("page-2"));
            if let Some((key, value)) = scope {
                assert_eq!(query.get(key).map(String::as_str), Some(value));
            }
            assert_eq!(request.authorization_scheme(), "Bearer");
            assert_eq!(request.accept(), "application/json");
        }
    }

    #[test]
    fn go_fixtures_decode_for_all_families_with_source_specific_identities() {
        let cases = [
            (GoogleWorkspaceFamily::Audit, AUDIT_FIXTURE, "audit-1", 2),
            (GoogleWorkspaceFamily::Group, GROUP_FIXTURE, "group-1", 1),
            (
                GoogleWorkspaceFamily::GroupMember,
                GROUP_MEMBER_FIXTURE,
                "security@writer.com::member-1",
                2,
            ),
            (GoogleWorkspaceFamily::User, USER_FIXTURE, "1001", 2),
        ];
        for (family, fixture, provider_id, count) in cases {
            let kernel = kernel(family);
            let request = kernel.plan(None).unwrap();
            let outcome = kernel
                .decode(&request, &fixture_page(family, fixture))
                .unwrap();
            let GoogleWorkspaceOutcome::Page(page) = outcome else {
                panic!("expected direct fixture page")
            };
            assert_eq!(page.records.len(), count);
            assert_eq!(page.records[0].provider_id, provider_id);
            assert_eq!(page.records[0].provider_kind, family.provider_kind());
            assert_eq!(
                page.records[0].fields.get("domain").map(String::as_str),
                Some("writer.com")
            );
        }
    }

    #[test]
    fn provider_cursor_and_user_attributes_preserve_go_contract() {
        let kernel = kernel(GoogleWorkspaceFamily::User);
        let request = kernel.plan(None).unwrap();
        let records: Value = serde_json::from_slice(USER_FIXTURE).unwrap();
        let body = serde_json::to_vec(&serde_json::json!({
            "users": records,
            "nextPageToken": "page-2"
        }))
        .unwrap();
        let GoogleWorkspaceOutcome::Page(page) = kernel.decode(&request, &body).unwrap() else {
            panic!("expected user page")
        };
        assert_eq!(page.next_cursor.as_deref(), Some("page-2"));
        assert_eq!(
            page.records[0].fields.get("email").map(String::as_str),
            Some("admin@writer.com")
        );
        assert_eq!(
            page.records[0]
                .fields
                .get("mfa_enrolled")
                .map(String::as_str),
            Some("false")
        );
    }

    #[test]
    fn role_assignment_fanout_caches_unique_user_once_per_page() {
        let kernel = kernel(GoogleWorkspaceFamily::RoleAssignment);
        let request = kernel.plan(None).unwrap();
        let mut records: Vec<Value> = serde_json::from_slice(ROLE_FIXTURE).unwrap();
        let mut second = records[0].clone();
        second["roleAssignmentId"] = Value::String("ra-2".to_owned());
        records.push(second);
        let body = serde_json::to_vec(&serde_json::json!({
            "items": records,
            "nextPageToken": "roles-2"
        }))
        .unwrap();
        let GoogleWorkspaceOutcome::Request(user_request) = kernel.decode(&request, &body).unwrap()
        else {
            panic!("expected role user lookup")
        };
        assert_eq!(user_request.url().path(), "/admin/directory/v1/users/1001");
        let GoogleWorkspaceOutcome::Page(page) = kernel
            .decode(
                &user_request,
                br#"{"id":"1001","primaryEmail":"admin@writer.com","name":{"fullName":"Admin Writer"}}"#,
            )
            .unwrap()
        else {
            panic!("expected enriched role page")
        };
        assert_eq!(page.records.len(), 2);
        assert_eq!(page.next_cursor.as_deref(), Some("roles-2"));
        assert!(page.records.iter().all(|record| {
            record.fields.get("subject_email").map(String::as_str) == Some("admin@writer.com")
        }));
        assert!(page.records.iter().all(|record| {
            record.fields.get("subject_name").map(String::as_str) == Some("Admin Writer")
        }));
    }

    #[test]
    fn genuine_role_fixture_uses_one_bounded_lookup() {
        let kernel = kernel(GoogleWorkspaceFamily::RoleAssignment);
        let request = kernel.plan(None).unwrap();
        let outcome = kernel
            .decode(
                &request,
                &fixture_page(GoogleWorkspaceFamily::RoleAssignment, ROLE_FIXTURE),
            )
            .unwrap();
        let GoogleWorkspaceOutcome::Request(request) = outcome else {
            panic!("expected fixture lookup request")
        };
        assert_eq!(request.url().path(), "/admin/directory/v1/users/1001");
    }

    #[test]
    fn kernel_fails_closed_on_unsafe_origins_invalid_scope_and_bad_pages() {
        assert!(matches!(
            GoogleWorkspaceKernel::new(
                "http://169.254.169.254",
                "writer.com",
                GoogleWorkspaceFamily::User,
                GoogleWorkspaceFilters::default(),
                None,
            ),
            Err(GoogleWorkspaceError::InvalidBaseUrl)
        ));
        assert!(matches!(
            GoogleWorkspaceKernel::new(
                "https://admin.googleapis.com",
                "writer.com",
                GoogleWorkspaceFamily::GroupMember,
                GoogleWorkspaceFilters::default(),
                None,
            ),
            Err(GoogleWorkspaceError::MissingGroupKey)
        ));
        let user_kernel = kernel(GoogleWorkspaceFamily::User);
        let group_request = kernel(GoogleWorkspaceFamily::Group).plan(None).unwrap();
        assert!(matches!(
            user_kernel.decode(&group_request, br#"{"groups":[]}"#),
            Err(GoogleWorkspaceError::RequestScopeMismatch)
        ));
        let request = user_kernel.plan(None).unwrap();
        assert!(matches!(
            user_kernel.decode(&request, br#"{"users":{}}"#),
            Err(GoogleWorkspaceError::InvalidResponse)
        ));
    }
}
