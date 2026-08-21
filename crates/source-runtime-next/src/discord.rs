//! Credential-free Discord request planning and response normalization kernel.
//!
//! The kernel models the public HTTP contract without holding a bot token or
//! performing network I/O. Checked-in test vectors are normalized examples;
//! they are not live provider captures and do not carry provider provenance.

use std::{collections::BTreeMap, error::Error, fmt, net::IpAddr, str::FromStr};

use reqwest::Url;
use serde_json::{Map, Value};

const AUDIT_DEFAULT_PAGE_SIZE: usize = 50;
const AUDIT_MAX_PAGE_SIZE: usize = 100;
const MEMBER_DEFAULT_PAGE_SIZE: usize = 1;
const MEMBER_MAX_PAGE_SIZE: usize = 1_000;
const MAX_CURSOR_BYTES: usize = 20;
// Provider-local defense-in-depth bounds. The HTTP host must independently
// enforce a response byte limit before handing a body to this kernel.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_NONPAGED_RECORDS: usize = 1_000;
const MAX_MEMBER_ROLES: usize = 250;
const MAX_COMMAND_PERMISSION_ENTRIES: usize = 100;

/// One Discord source-catalog family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscordFamily {
    /// Guild administrative audit entries.
    AuditLog,
    /// Guild members and their nested users.
    Member,
    /// Guild roles.
    Role,
    /// Guild application-command permission grants.
    Permission,
}

impl DiscordFamily {
    /// Return the source-catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuditLog => "audit_log",
            Self::Member => "member",
            Self::Role => "role",
            Self::Permission => "permission",
        }
    }

    /// Return the emitted provider kind.
    pub const fn provider_kind(self) -> &'static str {
        match self {
            Self::AuditLog => "discord.audit_log",
            Self::Member => "discord.member",
            Self::Role => "discord.role",
            Self::Permission => "discord.permission",
        }
    }

    const fn default_page_size(self) -> Option<usize> {
        match self {
            Self::AuditLog => Some(AUDIT_DEFAULT_PAGE_SIZE),
            Self::Member => Some(MEMBER_DEFAULT_PAGE_SIZE),
            Self::Role | Self::Permission => None,
        }
    }

    const fn max_page_size(self) -> Option<usize> {
        match self {
            Self::AuditLog => Some(AUDIT_MAX_PAGE_SIZE),
            Self::Member => Some(MEMBER_MAX_PAGE_SIZE),
            Self::Role | Self::Permission => None,
        }
    }
}

impl FromStr for DiscordFamily {
    type Err = DiscordError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "audit_log" => Ok(Self::AuditLog),
            "member" => Ok(Self::Member),
            "role" => Ok(Self::Role),
            "permission" => Ok(Self::Permission),
            _ => Err(DiscordError::InvalidFamily),
        }
    }
}

/// One credential-free Discord HTTP request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscordRequest {
    url: Url,
    family: DiscordFamily,
    cursor: Option<String>,
}

impl DiscordRequest {
    /// Return the exact provider URL. The caller must authorize it before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return the bot-token authorization scheme without credential material.
    pub const fn authorization_scheme(&self) -> &'static str {
        "Bot"
    }

    /// Return the required response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }
}

/// One normalized Discord provider record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscordRecord {
    /// Source-catalog family identifier.
    pub family: String,
    /// Emitted provider kind.
    pub provider_kind: String,
    /// Provider-owned Discord snowflake.
    pub provider_id: String,
    /// Portable scalar attributes selected by the Go source contract.
    pub fields: BTreeMap<String, String>,
    /// Original provider record without credential material.
    pub payload: Value,
}

/// One bounded Discord provider page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscordPage {
    /// Normalized records in provider order.
    pub records: Vec<DiscordRecord>,
    /// Highest audit-entry or member-user snowflake on a full page.
    pub next_cursor: Option<String>,
}

/// Provider-specific Discord request and response kernel.
#[derive(Clone, Debug)]
pub struct DiscordKernel {
    base_url: Url,
    guild_id: String,
    application_id: Option<String>,
    family: DiscordFamily,
    page_size: Option<usize>,
}

impl DiscordKernel {
    /// Build a kernel for one guild, family, and optional application.
    ///
    /// The caller still owns egress authorization and the operation-scoped bot
    /// credential lease. `application_id` is required only for `permission`.
    pub fn new(
        base_url: &str,
        guild_id: &str,
        application_id: Option<&str>,
        family: DiscordFamily,
        page_size: Option<usize>,
    ) -> Result<Self, DiscordError> {
        let base_url = validate_base_url(base_url)?;
        let guild_id = snowflake(guild_id, DiscordError::InvalidGuildId)?;
        let application_id = application_id
            .map(|value| snowflake(value, DiscordError::InvalidApplicationId))
            .transpose()?;
        if family == DiscordFamily::Permission && application_id.is_none() {
            return Err(DiscordError::MissingApplicationId);
        }
        let page_size = match family.max_page_size() {
            Some(maximum) => {
                let value = page_size.or(family.default_page_size()).unwrap_or_default();
                if !(1..=maximum).contains(&value) {
                    return Err(DiscordError::InvalidPageSize);
                }
                Some(value)
            }
            None if page_size.is_some() => return Err(DiscordError::UnsupportedPageSize),
            None => None,
        };
        Ok(Self {
            base_url,
            guild_id,
            application_id,
            family,
            page_size,
        })
    }

    /// Plan one credential-free provider request.
    ///
    /// Paged families start at `after=0`, which makes audit results ascend by
    /// entry ID and member results advance from the highest previous user ID.
    pub fn plan(&self, cursor: Option<&str>) -> Result<DiscordRequest, DiscordError> {
        let cursor = match (self.page_size, cursor) {
            (Some(_), Some(value)) => Some(snowflake(value, DiscordError::InvalidCursor)?),
            (Some(_), None) => None,
            (None, Some(value)) if !value.trim().is_empty() => {
                return Err(DiscordError::UnsupportedCursor);
            }
            (None, _) => None,
        };
        let path = match self.family {
            DiscordFamily::AuditLog => format!("/guilds/{}/audit-logs", self.guild_id),
            DiscordFamily::Member => format!("/guilds/{}/members", self.guild_id),
            DiscordFamily::Role => format!("/guilds/{}/roles", self.guild_id),
            DiscordFamily::Permission => format!(
                "/applications/{}/guilds/{}/commands/permissions",
                self.application_id.as_deref().unwrap_or_default(),
                self.guild_id
            ),
        };
        let mut url = self.endpoint(&path);
        if let Some(page_size) = self.page_size {
            let mut query = url.query_pairs_mut();
            query.append_pair("after", cursor.as_deref().unwrap_or("0"));
            query.append_pair("limit", &page_size.to_string());
        }
        Ok(DiscordRequest {
            url,
            family: self.family,
            cursor,
        })
    }

    /// Decode and normalize a response for a request produced by this kernel.
    pub fn decode(
        &self,
        request: &DiscordRequest,
        body: &[u8],
    ) -> Result<DiscordPage, DiscordError> {
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(DiscordError::ResponseTooLarge);
        }
        if request.family != self.family || request != &self.plan(request.cursor.as_deref())? {
            return Err(DiscordError::RequestScopeMismatch);
        }
        let payloads = decode_records(self.family, body)?;
        let record_limit = self.page_size.unwrap_or(MAX_NONPAGED_RECORDS);
        if payloads.len() > record_limit {
            return Err(DiscordError::TooManyRecords);
        }
        let records = payloads
            .into_iter()
            .map(|payload| normalize_record(self.family, payload))
            .collect::<Result<Vec<_>, _>>()?;
        if self.family == DiscordFamily::Permission {
            for record in &records {
                let values = record
                    .payload
                    .as_object()
                    .ok_or(DiscordError::InvalidRecord)?;
                if strict_string_at(values, "application_id").as_deref()
                    != self.application_id.as_deref()
                    || strict_string_at(values, "guild_id").as_deref()
                        != Some(self.guild_id.as_str())
                {
                    return Err(DiscordError::RequestScopeMismatch);
                }
            }
        }
        validate_ascending_page(self.family, &records)?;
        let next_cursor = if self.page_size.is_some_and(|limit| records.len() == limit) {
            match self.family {
                DiscordFamily::AuditLog => records.last().map(|record| record.provider_id.clone()),
                DiscordFamily::Member => highest_provider_id(&records)?,
                DiscordFamily::Role | DiscordFamily::Permission => None,
            }
        } else {
            None
        };
        Ok(DiscordPage {
            records,
            next_cursor,
        })
    }

    fn endpoint(&self, suffix: &str) -> Url {
        let mut url = self.base_url.clone();
        let path = format!("{}{}", self.base_url.path().trim_end_matches('/'), suffix);
        url.set_path(&path);
        url.set_query(None);
        url.set_fragment(None);
        url
    }
}

/// Safe Discord provider-kernel failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscordError {
    /// Family identifier is outside the four catalog contracts.
    InvalidFamily,
    /// Base URL is not a credential-free HTTPS provider URL.
    InvalidBaseUrl,
    /// Base URL contains an unsafe private, loopback, or link-local IP literal.
    UnsafeOrigin,
    /// Guild identifier is not a positive Discord snowflake.
    InvalidGuildId,
    /// Application identifier is not a positive Discord snowflake.
    InvalidApplicationId,
    /// Permission collection did not receive an application identifier.
    MissingApplicationId,
    /// Page size is outside the selected Discord endpoint's bound.
    InvalidPageSize,
    /// A page size was supplied for a non-paginated family.
    UnsupportedPageSize,
    /// Cursor is not a bounded Discord snowflake.
    InvalidCursor,
    /// A cursor was supplied for a non-paginated family.
    UnsupportedCursor,
    /// Response JSON does not match the selected endpoint envelope.
    InvalidResponse,
    /// Response body exceeds the kernel byte bound.
    ResponseTooLarge,
    /// Response contains more top-level records than the family bound.
    TooManyRecords,
    /// A provider record contains more nested entries than its field bound.
    TooManyNestedRecords,
    /// A provider record contains the wrong scalar or nested shape.
    InvalidRecord,
    /// A provider response contains credential-bearing material.
    CredentialMaterial,
    /// A record is missing its required provider snowflake.
    MissingProviderId,
    /// An `after` page is not strictly ascending by provider snowflake.
    InvalidPageOrder,
    /// A request was decoded by a kernel for another family or scope.
    RequestScopeMismatch,
}

impl fmt::Display for DiscordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "discord family is invalid",
            Self::InvalidBaseUrl => "discord base URL must be a credential-free HTTPS URL",
            Self::UnsafeOrigin => "discord base URL contains an unsafe IP literal",
            Self::InvalidGuildId => "discord guild ID must be a positive snowflake",
            Self::InvalidApplicationId => "discord application ID must be a positive snowflake",
            Self::MissingApplicationId => "discord permission family requires an application ID",
            Self::InvalidPageSize => "discord page size is outside the endpoint bound",
            Self::UnsupportedPageSize => "discord family does not support a page size",
            Self::InvalidCursor => "discord cursor must be a bounded snowflake",
            Self::UnsupportedCursor => "discord family does not support cursors",
            Self::InvalidResponse => "discord response JSON does not match the endpoint envelope",
            Self::ResponseTooLarge => "discord response exceeds the kernel byte bound",
            Self::TooManyRecords => "discord response exceeds the family record-count bound",
            Self::TooManyNestedRecords => "discord record exceeds a nested record-count bound",
            Self::InvalidRecord => "discord record does not match the provider scalar contract",
            Self::CredentialMaterial => "discord response contains credential material",
            Self::MissingProviderId => "discord record is missing a provider snowflake",
            Self::InvalidPageOrder => "discord after page is not strictly ascending",
            Self::RequestScopeMismatch => "discord request does not match the configured kernel",
        })
    }
}

impl Error for DiscordError {}

fn validate_base_url(value: &str) -> Result<Url, DiscordError> {
    let mut url = Url::parse(value.trim()).map_err(|_| DiscordError::InvalidBaseUrl)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(DiscordError::InvalidBaseUrl);
    }
    if let Some(host) = url.host_str()
        && let Ok(address) = host.parse::<IpAddr>()
        && unsafe_address(address)
    {
        return Err(DiscordError::UnsafeOrigin);
    }
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(if path.is_empty() { "/" } else { &path });
    Ok(url)
}

fn unsafe_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_unspecified()
        }
        IpAddr::V6(address) => {
            address.is_loopback()
                || address.is_multicast()
                || address.is_unspecified()
                || address.is_unique_local()
                || address.is_unicast_link_local()
        }
    }
}

fn snowflake(value: &str, error: DiscordError) -> Result<String, DiscordError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_CURSOR_BYTES
        || value
            .parse::<u64>()
            .ok()
            .filter(|number| *number > 0)
            .is_none()
    {
        return Err(error);
    }
    Ok(value.to_owned())
}

fn decode_records(family: DiscordFamily, body: &[u8]) -> Result<Vec<Value>, DiscordError> {
    let root: Value = serde_json::from_slice(body).map_err(|_| DiscordError::InvalidResponse)?;
    let records = match family {
        DiscordFamily::AuditLog => root
            .as_object()
            .and_then(|object| object.get("audit_log_entries"))
            .and_then(Value::as_array)
            .cloned()
            .ok_or(DiscordError::InvalidResponse),
        DiscordFamily::Member | DiscordFamily::Role | DiscordFamily::Permission => root
            .as_array()
            .cloned()
            .ok_or(DiscordError::InvalidResponse),
    }?;
    if records.iter().any(contains_credential_material) {
        return Err(DiscordError::CredentialMaterial);
    }
    Ok(records)
}

fn normalize_record(family: DiscordFamily, payload: Value) -> Result<DiscordRecord, DiscordError> {
    let values = payload.as_object().ok_or(DiscordError::InvalidResponse)?;
    validate_record_shape(family, values)?;
    let provider_id = match family {
        DiscordFamily::Member => strict_string_at(values, "user.id"),
        DiscordFamily::AuditLog | DiscordFamily::Role | DiscordFamily::Permission => {
            strict_string_at(values, "id")
        }
    }
    .ok_or(DiscordError::MissingProviderId)
    .and_then(|value| snowflake(&value, DiscordError::MissingProviderId))?;
    let mut fields = BTreeMap::from([
        ("family".to_owned(), family.as_str().to_owned()),
        ("provider".to_owned(), "discord".to_owned()),
        ("provider_id".to_owned(), provider_id.clone()),
        ("source_event_id".to_owned(), provider_id.clone()),
        ("source_provider".to_owned(), "discord".to_owned()),
    ]);
    match family {
        DiscordFamily::AuditLog => {
            fields.insert("id".to_owned(), provider_id.clone());
            copy_first(&mut fields, values, "event_type", &["action_type"]);
            copy_first(&mut fields, values, "actor_id", &["user_id"]);
            copy_first(&mut fields, values, "resource_id", &["target_id"]);
            copy_first(&mut fields, values, "reason", &["reason"]);
        }
        DiscordFamily::Member => {
            fields.insert("id".to_owned(), provider_id.clone());
            fields.insert("user_id".to_owned(), provider_id.clone());
            fields.insert("resource_id".to_owned(), provider_id.clone());
            copy_first(
                &mut fields,
                values,
                "name",
                &["nick", "user.global_name", "user.username"],
            );
            copy_first(
                &mut fields,
                values,
                "display_name",
                &["nick", "user.global_name", "user.username"],
            );
            copy_first(&mut fields, values, "login", &["user.username"]);
            copy_first(&mut fields, values, "username", &["user.username"]);
            copy_first(&mut fields, values, "global_name", &["user.global_name"]);
            copy_first(&mut fields, values, "avatar", &["avatar", "user.avatar"]);
            copy_first(&mut fields, values, "roles", &["roles"]);
            copy_first(&mut fields, values, "joined_at", &["joined_at"]);
            copy_first(&mut fields, values, "deaf", &["deaf"]);
            copy_first(&mut fields, values, "mute", &["mute"]);
            copy_first(&mut fields, values, "flags", &["flags"]);
            copy_first(&mut fields, values, "pending", &["pending"]);
            copy_first(
                &mut fields,
                values,
                "communication_disabled_until",
                &["communication_disabled_until"],
            );
        }
        DiscordFamily::Role => {
            fields.insert("id".to_owned(), provider_id.clone());
            fields.insert("group_id".to_owned(), provider_id.clone());
            copy_first(&mut fields, values, "name", &["name"]);
            copy_first(&mut fields, values, "group_name", &["name"]);
            copy_first(&mut fields, values, "description", &["description"]);
            copy_first(&mut fields, values, "permissions", &["permissions"]);
        }
        DiscordFamily::Permission => {
            fields.insert("id".to_owned(), provider_id.clone());
            fields.insert("resource_id".to_owned(), provider_id.clone());
            fields.insert("resource_type".to_owned(), "permission".to_owned());
            copy_first(&mut fields, values, "application_id", &["application_id"]);
            copy_first(&mut fields, values, "resource_name", &["application_id"]);
        }
    }
    Ok(DiscordRecord {
        family: family.as_str().to_owned(),
        provider_kind: family.provider_kind().to_owned(),
        provider_id,
        fields,
        payload,
    })
}

fn value_at(values: &Map<String, Value>, path: &str) -> Option<String> {
    let mut value = values.get(path.split('.').next()?)?;
    for part in path.split('.').skip(1) {
        value = value.as_object()?.get(part)?;
    }
    match value {
        Value::String(value) if !value.trim().is_empty() => Some(value.trim().to_owned()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Array(values) => values
            .iter()
            .map(|value| match value {
                Value::String(value) if !value.trim().is_empty() => Some(value.trim()),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
            .map(|values| values.join(",")),
        _ => None,
    }
}

fn strict_string_at(values: &Map<String, Value>, path: &str) -> Option<String> {
    let mut value = values.get(path.split('.').next()?)?;
    for part in path.split('.').skip(1) {
        value = value.as_object()?.get(part)?;
    }
    match value {
        Value::String(value) if !value.trim().is_empty() => Some(value.trim().to_owned()),
        _ => None,
    }
}

fn validate_record_shape(
    family: DiscordFamily,
    values: &Map<String, Value>,
) -> Result<(), DiscordError> {
    match family {
        DiscordFamily::AuditLog => {
            required_string(values.get("id"))?;
            required_nullable_snowflake(values.get("user_id"))?;
            required_unsigned_number(values.get("action_type"))?;
            required_nullable_snowflake(values.get("target_id"))?;
            nullable_string(values.get("reason"))?;
        }
        DiscordFamily::Member => {
            let user = values
                .get("user")
                .and_then(Value::as_object)
                .ok_or(DiscordError::InvalidRecord)?;
            required_string(user.get("id"))?;
            required_string(user.get("username"))?;
            nullable_string(user.get("global_name"))?;
            nullable_string(user.get("avatar"))?;
            nullable_string(values.get("nick"))?;
            nullable_string(values.get("avatar"))?;
            required_string(values.get("joined_at"))?;
            required_bool(values.get("deaf"))?;
            required_bool(values.get("mute"))?;
            optional_unsigned_number(values.get("flags"))?;
            optional_bool(values.get("pending"))?;
            nullable_string(values.get("communication_disabled_until"))?;
            let roles = values
                .get("roles")
                .and_then(Value::as_array)
                .ok_or(DiscordError::InvalidRecord)?;
            if roles.len() > MAX_MEMBER_ROLES {
                return Err(DiscordError::TooManyNestedRecords);
            }
            for role in roles {
                let role = required_string(Some(role))?;
                snowflake(role, DiscordError::InvalidRecord)?;
            }
        }
        DiscordFamily::Role => {
            required_string(values.get("id"))?;
            required_string(values.get("name"))?;
            required_string(values.get("permissions"))?;
            nullable_string(values.get("description"))?;
        }
        DiscordFamily::Permission => {
            required_string(values.get("id"))?;
            required_string(values.get("application_id"))?;
            required_string(values.get("guild_id"))?;
            let permissions = values
                .get("permissions")
                .and_then(Value::as_array)
                .ok_or(DiscordError::InvalidRecord)?;
            if permissions.len() > MAX_COMMAND_PERMISSION_ENTRIES {
                return Err(DiscordError::TooManyNestedRecords);
            }
            for permission in permissions {
                let permission = permission.as_object().ok_or(DiscordError::InvalidRecord)?;
                let id = required_string(permission.get("id"))?;
                snowflake(id, DiscordError::InvalidRecord)?;
                required_unsigned_number(permission.get("type"))?;
                required_bool(permission.get("permission"))?;
            }
        }
    }
    Ok(())
}

fn required_string(value: Option<&Value>) -> Result<&str, DiscordError> {
    match value {
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(value.trim()),
        _ => Err(DiscordError::InvalidRecord),
    }
}

fn nullable_string(value: Option<&Value>) -> Result<(), DiscordError> {
    match value {
        None | Some(Value::Null) | Some(Value::String(_)) => Ok(()),
        _ => Err(DiscordError::InvalidRecord),
    }
}

fn required_nullable_snowflake(value: Option<&Value>) -> Result<(), DiscordError> {
    match value {
        Some(Value::Null) => Ok(()),
        Some(Value::String(value)) => {
            snowflake(value, DiscordError::InvalidRecord)?;
            Ok(())
        }
        _ => Err(DiscordError::InvalidRecord),
    }
}

fn required_bool(value: Option<&Value>) -> Result<(), DiscordError> {
    match value {
        Some(Value::Bool(_)) => Ok(()),
        _ => Err(DiscordError::InvalidRecord),
    }
}

fn optional_bool(value: Option<&Value>) -> Result<(), DiscordError> {
    match value {
        None | Some(Value::Bool(_)) => Ok(()),
        _ => Err(DiscordError::InvalidRecord),
    }
}

fn required_unsigned_number(value: Option<&Value>) -> Result<(), DiscordError> {
    match value {
        Some(Value::Number(value)) if value.as_u64().is_some() => Ok(()),
        _ => Err(DiscordError::InvalidRecord),
    }
}

fn optional_unsigned_number(value: Option<&Value>) -> Result<(), DiscordError> {
    match value {
        None => Ok(()),
        value => required_unsigned_number(value),
    }
}

fn contains_credential_material(value: &Value) -> bool {
    match value {
        Value::Object(values) => values.iter().any(|(key, value)| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "authorization"
                    | "api_key"
                    | "api_token"
                    | "access_token"
                    | "refresh_token"
                    | "bot_token"
                    | "client_secret"
                    | "password"
                    | "secret"
                    | "token"
            ) || contains_credential_material(value)
        }),
        Value::Array(values) => values.iter().any(contains_credential_material),
        _ => false,
    }
}

fn copy_first(
    fields: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    output: &str,
    paths: &[&str],
) {
    if let Some(value) = paths.iter().find_map(|path| value_at(values, path)) {
        fields.insert(output.to_owned(), value);
    }
}

fn validate_ascending_page(
    family: DiscordFamily,
    records: &[DiscordRecord],
) -> Result<(), DiscordError> {
    if family != DiscordFamily::AuditLog {
        return Ok(());
    }
    let mut previous = None;
    for record in records {
        let current = record
            .provider_id
            .parse::<u64>()
            .map_err(|_| DiscordError::InvalidPageOrder)?;
        if previous.is_some_and(|value| current <= value) {
            return Err(DiscordError::InvalidPageOrder);
        }
        previous = Some(current);
    }
    Ok(())
}

fn highest_provider_id(records: &[DiscordRecord]) -> Result<Option<String>, DiscordError> {
    let mut highest = None;
    for record in records {
        let number = record
            .provider_id
            .parse::<u64>()
            .map_err(|_| DiscordError::InvalidRecord)?;
        if highest
            .as_ref()
            .is_none_or(|(current, _): &(u64, String)| number > *current)
        {
            highest = Some((number, record.provider_id.clone()));
        }
    }
    Ok(highest.map(|(_, id)| id))
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUDIT_FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sources/discord/testdata/read_audit_log.json"
    ));
    const MEMBER_FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sources/discord/testdata/read_member.json"
    ));
    const GUILD_ID: &str = "100000000000000000";
    const APPLICATION_ID: &str = "200000000000000000";

    fn kernel(family: DiscordFamily, page_size: Option<usize>) -> DiscordKernel {
        DiscordKernel::new(
            "https://discord.com/api/v10",
            GUILD_ID,
            Some(APPLICATION_ID),
            family,
            page_size,
        )
        .unwrap()
    }

    #[test]
    fn families_plan_exact_paths_and_bot_auth_contract() {
        let cases = [
            (
                DiscordFamily::AuditLog,
                "/api/v10/guilds/100000000000000000/audit-logs",
                Some(2),
            ),
            (
                DiscordFamily::Member,
                "/api/v10/guilds/100000000000000000/members",
                Some(2),
            ),
            (
                DiscordFamily::Role,
                "/api/v10/guilds/100000000000000000/roles",
                None,
            ),
            (
                DiscordFamily::Permission,
                "/api/v10/applications/200000000000000000/guilds/100000000000000000/commands/permissions",
                None,
            ),
        ];
        for (family, path, page_size) in cases {
            let request = kernel(family, page_size).plan(None).unwrap();
            assert_eq!(request.url().path(), path);
            assert_eq!(request.authorization_scheme(), "Bot");
            assert_eq!(request.accept(), "application/json");
            assert_eq!(
                family.provider_kind(),
                format!("discord.{}", family.as_str())
            );
            if page_size.is_some() {
                assert_eq!(request.url().query(), Some("after=0&limit=2"));
            } else {
                assert_eq!(request.url().query(), None);
            }
        }
    }

    #[test]
    fn normalized_audit_fixture_decodes_envelope_fields_and_cursor() {
        let kernel = kernel(DiscordFamily::AuditLog, Some(2));
        let request = kernel.plan(None).unwrap();
        let page = kernel.decode(&request, AUDIT_FIXTURE).unwrap();
        assert_eq!(page.records.len(), 2);
        assert_eq!(page.records[0].provider_kind, "discord.audit_log");
        assert_eq!(page.records[0].fields["event_type"], "10");
        assert_eq!(page.records[0].fields["actor_id"], "400000000000000001");
        assert_eq!(page.records[0].fields["resource_id"], "300000000000000001");
        assert_eq!(page.next_cursor.as_deref(), Some("100000000000000002"));
    }

    #[test]
    fn normalized_member_fixture_decodes_raw_array_and_nested_user_cursor() {
        let kernel = kernel(DiscordFamily::Member, Some(2));
        let request = kernel.plan(None).unwrap();
        let page = kernel.decode(&request, MEMBER_FIXTURE).unwrap();
        assert_eq!(page.records.len(), 2);
        assert_eq!(page.records[0].provider_kind, "discord.member");
        assert_eq!(page.records[0].fields["user_id"], "100000000000000001");
        assert_eq!(page.records[0].fields["display_name"], "Member One");
        assert_eq!(page.records[0].fields["avatar"], "normalized-avatar-one");
        assert_eq!(page.records[0].fields["roles"], "500000000000000001");
        assert_eq!(page.records[0].fields["deaf"], "false");
        assert_eq!(page.records[1].fields["login"], "member-two");
        assert_eq!(page.next_cursor.as_deref(), Some("100000000000000002"));
    }

    #[test]
    fn partial_pages_are_terminal_and_resume_after_highest_id() {
        let kernel = kernel(DiscordFamily::Member, Some(2));
        let request = kernel.plan(Some("100000000000000002")).unwrap();
        assert_eq!(
            request.url().query(),
            Some("after=100000000000000002&limit=2")
        );
        let page = kernel
            .decode(
                &request,
                br#"[{"user":{"id":"100000000000000003","username":"member-three"},"joined_at":"2026-06-03T00:00:00Z","deaf":false,"mute":false,"roles":[]}]"#,
            )
            .unwrap();
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.next_cursor, None);
    }

    #[test]
    fn nonpaged_envelopes_normalize_roles_and_permissions() {
        let role_kernel = kernel(DiscordFamily::Role, None);
        let role_request = role_kernel.plan(None).unwrap();
        let roles = role_kernel
            .decode(
                &role_request,
                br#"[{"id":"500000000000000001","name":"operator","permissions":"8"}]"#,
            )
            .unwrap();
        assert_eq!(roles.records[0].fields["group_name"], "operator");
        assert_eq!(roles.next_cursor, None);

        let permission_kernel = kernel(DiscordFamily::Permission, None);
        let permission_request = permission_kernel.plan(None).unwrap();
        let permissions = permission_kernel
            .decode(
                &permission_request,
                br#"[{"id":"600000000000000001","application_id":"200000000000000000","guild_id":"100000000000000000","permissions":[]}]"#,
            )
            .unwrap();
        assert_eq!(permissions.records[0].fields["resource_type"], "permission");
        assert_eq!(
            permissions.records[0].fields["resource_name"],
            APPLICATION_ID
        );
        let mismatched_scope = br#"[{"id":"600000000000000001","application_id":"200000000000000009","guild_id":"100000000000000000","permissions":[]}]"#;
        assert_eq!(
            permission_kernel.decode(&permission_request, mismatched_scope),
            Err(DiscordError::RequestScopeMismatch)
        );
    }

    #[test]
    fn kernel_rejects_unsafe_scope_invalid_bounds_and_wrong_envelopes() {
        assert!(matches!(
            DiscordKernel::new(
                "http://discord.com/api/v10",
                GUILD_ID,
                None,
                DiscordFamily::Member,
                Some(2)
            ),
            Err(DiscordError::InvalidBaseUrl)
        ));
        assert!(matches!(
            DiscordKernel::new(
                "https://127.0.0.1",
                GUILD_ID,
                None,
                DiscordFamily::Member,
                Some(2)
            ),
            Err(DiscordError::UnsafeOrigin)
        ));
        assert!(matches!(
            DiscordKernel::new(
                "https://discord.com/api/v10",
                "guild",
                None,
                DiscordFamily::Member,
                Some(2)
            ),
            Err(DiscordError::InvalidGuildId)
        ));
        assert!(matches!(
            DiscordKernel::new(
                "https://discord.com/api/v10",
                GUILD_ID,
                None,
                DiscordFamily::Permission,
                None
            ),
            Err(DiscordError::MissingApplicationId)
        ));
        assert!(matches!(
            DiscordKernel::new(
                "https://discord.com/api/v10",
                GUILD_ID,
                None,
                DiscordFamily::AuditLog,
                Some(101)
            ),
            Err(DiscordError::InvalidPageSize)
        ));
        assert_eq!(
            kernel(DiscordFamily::Role, None).plan(Some("1")),
            Err(DiscordError::UnsupportedCursor)
        );
        assert_eq!(
            kernel(DiscordFamily::Member, Some(2)).plan(Some("not-a-snowflake")),
            Err(DiscordError::InvalidCursor)
        );
        let audit_kernel = kernel(DiscordFamily::AuditLog, Some(2));
        let audit_request = audit_kernel.plan(None).unwrap();
        assert_eq!(
            audit_kernel.decode(&audit_request, br#"[{"id":"100000000000000001"}]"#),
            Err(DiscordError::InvalidResponse)
        );
        assert_eq!(
            audit_kernel.decode(&audit_request, br#"{"items":[]}"#),
            Err(DiscordError::InvalidResponse)
        );
        for family in [
            DiscordFamily::Member,
            DiscordFamily::Role,
            DiscordFamily::Permission,
        ] {
            let kernel = kernel(family, matches!(family, DiscordFamily::Member).then_some(2));
            let request = kernel.plan(None).unwrap();
            assert_eq!(
                kernel.decode(&request, br#"{"items":[]}"#),
                Err(DiscordError::InvalidResponse)
            );
        }
        assert_eq!(
            kernel(DiscordFamily::Member, Some(2)).decode(&audit_request, MEMBER_FIXTURE),
            Err(DiscordError::RequestScopeMismatch)
        );
    }

    #[test]
    fn paged_contract_rejects_missing_ids_and_wrong_scalar_types() {
        let kernel = kernel(DiscordFamily::Member, Some(2));
        let request = kernel.plan(None).unwrap();
        assert_eq!(
            kernel.decode(&request, br#"[{"user":{"username":"missing-id"}}]"#),
            Err(DiscordError::InvalidRecord)
        );
        assert_eq!(
            kernel.decode(
                &request,
                br#"[{"user":{"id":100000000000000001,"username":"number-id"},"joined_at":"2026-06-01T00:00:00Z","deaf":false,"mute":false,"roles":[]}]"#,
            ),
            Err(DiscordError::InvalidRecord)
        );
        assert_eq!(
            kernel.decode(
                &request,
                br#"[{"user":{"id":"100000000000000001","username":"leak"},"joined_at":"2026-06-01T00:00:00Z","deaf":false,"mute":false,"roles":[],"access_token":"redacted-fixture-value"}]"#,
            ),
            Err(DiscordError::CredentialMaterial)
        );
    }

    #[test]
    fn member_full_page_uses_numeric_maximum_without_order_assumption() {
        let kernel = kernel(DiscordFamily::Member, Some(2));
        let request = kernel.plan(None).unwrap();
        let page = kernel
            .decode(
                &request,
                br#"[
                    {"user":{"id":"100000000000000009","username":"later"},"joined_at":"2026-06-09T00:00:00Z","deaf":false,"mute":false,"roles":[]},
                    {"user":{"id":"100000000000000003","username":"earlier"},"joined_at":"2026-06-03T00:00:00Z","deaf":false,"mute":false,"roles":[]}
                ]"#,
            )
            .unwrap();
        assert_eq!(page.next_cursor.as_deref(), Some("100000000000000009"));
    }

    #[test]
    fn audit_after_page_requires_strictly_ascending_entry_ids() {
        let kernel = kernel(DiscordFamily::AuditLog, Some(2));
        let request = kernel.plan(None).unwrap();
        assert_eq!(
            kernel.decode(
                &request,
                br#"{"audit_log_entries":[
                    {"id":"100000000000000002","user_id":null,"action_type":10,"target_id":null},
                    {"id":"100000000000000001","user_id":null,"action_type":10,"target_id":null}
                ]}"#,
            ),
            Err(DiscordError::InvalidPageOrder)
        );
    }

    #[test]
    fn audit_contract_rejects_field_specific_scalar_mismatches() {
        let kernel = kernel(DiscordFamily::AuditLog, Some(2));
        let request = kernel.plan(None).unwrap();
        let invalid_records = [
            serde_json::json!({"id":1,"user_id":null,"action_type":10,"target_id":null}),
            serde_json::json!({"id":"100000000000000001","user_id":1,"action_type":10,"target_id":null}),
            serde_json::json!({"id":"100000000000000001","user_id":null,"action_type":"10","target_id":null}),
            serde_json::json!({"id":"100000000000000001","user_id":null,"action_type":10,"target_id":1}),
        ];
        for record in invalid_records {
            let body = serde_json::to_vec(&serde_json::json!({
                "audit_log_entries":[record]
            }))
            .unwrap();
            assert_eq!(
                kernel.decode(&request, &body),
                Err(DiscordError::InvalidRecord)
            );
        }
    }

    #[test]
    fn top_level_and_nested_record_counts_are_bounded() {
        let roles = vec![
            serde_json::json!({"id":"500000000000000001","name":"role","permissions":"0"});
            MAX_NONPAGED_RECORDS + 1
        ];
        let role_kernel = kernel(DiscordFamily::Role, None);
        let role_request = role_kernel.plan(None).unwrap();
        assert_eq!(
            role_kernel.decode(&role_request, &serde_json::to_vec(&roles).unwrap()),
            Err(DiscordError::TooManyRecords)
        );

        let permission_kernel = kernel(DiscordFamily::Permission, None);
        let permission_request = permission_kernel.plan(None).unwrap();
        let permission_records = vec![
            serde_json::json!({
                "id":"600000000000000001",
                "application_id":APPLICATION_ID,
                "guild_id":GUILD_ID,
                "permissions":[]
            });
            MAX_NONPAGED_RECORDS + 1
        ];
        assert_eq!(
            permission_kernel.decode(
                &permission_request,
                &serde_json::to_vec(&permission_records).unwrap()
            ),
            Err(DiscordError::TooManyRecords)
        );

        let permissions = vec![
            serde_json::json!({
                "id":"700000000000000001","type":1,"permission":true
            });
            MAX_COMMAND_PERMISSION_ENTRIES + 1
        ];
        let permission_body = serde_json::to_vec(&vec![serde_json::json!({
            "id":"600000000000000001",
            "application_id":APPLICATION_ID,
            "guild_id":GUILD_ID,
            "permissions":permissions
        })])
        .unwrap();
        assert_eq!(
            permission_kernel.decode(&permission_request, &permission_body),
            Err(DiscordError::TooManyNestedRecords)
        );

        let member_roles =
            vec![Value::String("500000000000000001".to_owned()); MAX_MEMBER_ROLES + 1];
        let member_body = serde_json::to_vec(&vec![serde_json::json!({
            "user":{"id":"100000000000000001","username":"member"},
            "joined_at":"2026-06-01T00:00:00Z",
            "deaf":false,
            "mute":false,
            "roles":member_roles
        })])
        .unwrap();
        let member_kernel = kernel(DiscordFamily::Member, Some(2));
        let member_request = member_kernel.plan(None).unwrap();
        assert_eq!(
            member_kernel.decode(&member_request, &member_body),
            Err(DiscordError::TooManyNestedRecords)
        );
    }

    #[test]
    fn response_byte_count_is_bounded_before_json_decode() {
        let role_kernel = kernel(DiscordFamily::Role, None);
        let request = role_kernel.plan(None).unwrap();
        let body = vec![b' '; MAX_RESPONSE_BYTES + 1];
        assert_eq!(
            role_kernel.decode(&request, &body),
            Err(DiscordError::ResponseTooLarge)
        );
    }
}
