//! Provider response decoding and record normalization.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    str::FromStr,
};

use reqwest::Url;
use serde_json::{Map, Value};

use super::GoogleWorkspaceError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RequestStage {
    Direct,
    ResolveRoleUser,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RoleAssignmentState {
    pub(super) records: Vec<Value>,
    pub(super) next_cursor: Option<String>,
    pub(super) lookups: Vec<String>,
    pub(super) lookup_index: usize,
    pub(super) users: BTreeMap<String, ResolvedUser>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResolvedUser {
    pub(super) email: String,
    pub(super) name: String,
}

pub(super) struct DecodedPage {
    pub(super) records: Vec<Value>,
    pub(super) next_cursor: Option<String>,
}

pub(super) fn validate_origin(raw: &str) -> Result<Url, GoogleWorkspaceError> {
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

pub(super) fn unsafe_ip_literal(address: IpAddr, loopback: bool) -> bool {
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

pub(super) fn required_value(
    value: &str,
    error: GoogleWorkspaceError,
) -> Result<String, GoogleWorkspaceError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(error);
    }
    Ok(value.to_owned())
}

pub(super) fn optional_value(value: Option<String>, default: &str) -> String {
    nonblank(value).unwrap_or_else(|| default.to_owned())
}

pub(super) fn nonblank(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

pub(super) fn decode_page(body: &[u8], field: &str) -> Result<DecodedPage, GoogleWorkspaceError> {
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

pub(super) fn decode_object(body: &[u8]) -> Result<Map<String, Value>, GoogleWorkspaceError> {
    serde_json::from_slice::<Value>(body)
        .map_err(|_| GoogleWorkspaceError::InvalidResponse)?
        .as_object()
        .cloned()
        .ok_or(GoogleWorkspaceError::InvalidResponse)
}

pub(super) fn role_user_lookups(records: &[Value]) -> Result<Vec<String>, GoogleWorkspaceError> {
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

pub(super) fn normalize_user(
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

pub(super) fn normalize_group(
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

pub(super) fn normalize_group_member(
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

pub(super) fn normalize_role_assignment(
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

pub(super) fn normalize_audit(
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

pub(super) fn audit_parameters(event: Option<&Map<String, Value>>) -> BTreeMap<String, String> {
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

pub(super) fn first_values(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| scalar(object.get(*key)).filter(|value| !value.is_empty()))
}

pub(super) fn nested_scalar(object: &Map<String, Value>, path: &[&str]) -> Option<String> {
    let (first, rest) = path.split_first()?;
    let mut value = object.get(*first)?;
    for segment in rest {
        value = value.as_object()?.get(*segment)?;
    }
    scalar(Some(value))
}

pub(super) fn scalar(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(value) => Some(value.trim().to_owned()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

pub(super) fn lowercase_scalar(value: Option<&Value>) -> String {
    scalar(value).unwrap_or_default().to_lowercase()
}

pub(super) fn insert(fields: &mut BTreeMap<String, String>, key: &str, value: String) {
    if !value.trim().is_empty() {
        fields.insert(key.to_owned(), value);
    }
}

pub(super) fn email_like(value: &str) -> Option<String> {
    let value = value.trim();
    value.contains('@').then(|| value.to_lowercase())
}

pub(super) fn normalize_resource_type(value: &str) -> String {
    value.trim().to_lowercase().replace([' ', '-'], "_")
}

pub(super) fn first_nonempty<const N: usize>(values: [Option<String>; N]) -> Option<String> {
    values
        .into_iter()
        .flatten()
        .find(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_owned())
}
