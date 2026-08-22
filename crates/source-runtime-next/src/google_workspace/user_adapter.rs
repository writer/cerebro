//! Users-family host adapter contract.
//!
//! The shared host owns credentials, egress, redirects, deadlines, retries,
//! and response collection. This adapter accepts only a provider status and
//! already-bounded response bytes, then returns deterministic user events.

use std::collections::BTreeMap;

use reqwest::StatusCode;
use serde_json::Value;

use super::{
    GoogleWorkspaceError, GoogleWorkspaceFamily, GoogleWorkspaceFilters, GoogleWorkspaceKernel,
    GoogleWorkspaceOutcome, GoogleWorkspacePage, GoogleWorkspaceRecord, GoogleWorkspaceRequest,
    RequestStage, materialization::GoogleWorkspaceEventPage,
};

const DIRECTORY_USER_READ_SCOPE: &str =
    "https://www.googleapis.com/auth/admin.directory.user.readonly";
const MAX_CURSOR_BYTES: usize = 4 << 10;
const MAX_RESPONSE_BYTES: usize = 8 << 20;

impl GoogleWorkspaceRequest {
    /// Return the exact HTTP method for a users-list request.
    pub const fn method(&self) -> &'static str {
        "GET"
    }
}

impl GoogleWorkspaceKernel {
    /// Build the provider-local users adapter without accepting credentials.
    pub fn new_user_adapter(
        base_url: &str,
        tenant_domain: &str,
        customer_id: Option<String>,
        page_size: Option<usize>,
    ) -> Result<Self, GoogleWorkspaceError> {
        if !valid_tenant_domain(tenant_domain) {
            return Err(GoogleWorkspaceError::InvalidTenantIdentity);
        }
        if customer_id
            .as_deref()
            .is_some_and(|value| !valid_customer_id(value))
        {
            return Err(GoogleWorkspaceError::InvalidCustomerId);
        }
        Self::new(
            base_url,
            tenant_domain,
            GoogleWorkspaceFamily::User,
            GoogleWorkspaceFilters {
                customer_id,
                group_key: None,
                application: None,
            },
            page_size,
        )
    }

    /// Return whether this adapter accepts or stores credential values.
    pub const fn user_adapter_accepts_credential_values() -> bool {
        false
    }

    /// Return the least-privilege OAuth scope required by the users operation.
    pub const fn user_adapter_required_oauth_scope() -> &'static str {
        DIRECTORY_USER_READ_SCOPE
    }

    /// Plan one exact users-list request with a fixed provider origin.
    pub fn plan_user_page(
        &self,
        cursor: Option<&str>,
    ) -> Result<GoogleWorkspaceRequest, GoogleWorkspaceError> {
        self.require_user_adapter()?;
        let cursor = bounded_cursor(cursor)?;
        let mut url = self.endpoint(&["admin", "directory", "v1", "users"])?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("customer", &self.customer_id);
            query.append_pair("maxResults", &self.page_size.to_string());
            if let Some(cursor) = cursor.as_deref() {
                query.append_pair("pageToken", cursor);
            }
        }
        Ok(GoogleWorkspaceRequest {
            url,
            family: GoogleWorkspaceFamily::User,
            stage: RequestStage::Direct,
            role_state: None,
        })
    }

    /// Decode one users-list response supplied by the trusted HTTP host.
    ///
    /// Non-success responses return typed, body-redacted failures. Successful
    /// pages are byte- and record-bounded, deduplicated by stable provider ID,
    /// materialized with Go-compatible event fields, and scoped to the tenant
    /// domain before the caller can admit them.
    pub fn decode_user_response(
        &self,
        request: &GoogleWorkspaceRequest,
        status: StatusCode,
        body: &[u8],
        observed_at: &str,
    ) -> Result<GoogleWorkspaceEventPage, GoogleWorkspaceError> {
        self.require_user_adapter()?;
        self.validate_user_request(request)?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(GoogleWorkspaceError::ResponseTooLarge);
        }
        validate_provider_status(status, body)?;
        let GoogleWorkspaceOutcome::Page(page) = self.decode(request, body)? else {
            return Err(GoogleWorkspaceError::RequestScopeMismatch);
        };
        let page = self.validate_and_deduplicate_users(page)?;
        let mut materialized = page.materialize(observed_at)?;
        if materialized.events.is_empty() {
            materialized.next_cursor.clone_from(&page.next_cursor);
            materialized.checkpoint_cursor.clone_from(&page.next_cursor);
        }
        self.validate_materialized_users(&materialized)?;
        Ok(materialized)
    }

    fn require_user_adapter(&self) -> Result<(), GoogleWorkspaceError> {
        if self.family != GoogleWorkspaceFamily::User {
            return Err(GoogleWorkspaceError::UserFamilyRequired);
        }
        if !valid_tenant_domain(&self.domain) {
            return Err(GoogleWorkspaceError::InvalidTenantIdentity);
        }
        Ok(())
    }

    fn validate_user_request(
        &self,
        request: &GoogleWorkspaceRequest,
    ) -> Result<(), GoogleWorkspaceError> {
        let mut cursor = None;
        for (name, value) in request.url.query_pairs() {
            if name == "pageToken" && cursor.is_none() {
                cursor = Some(value.into_owned());
            }
        }
        let expected = self.plan_user_page(cursor.as_deref())?;
        if request != &expected {
            return Err(GoogleWorkspaceError::RequestScopeMismatch);
        }
        Ok(())
    }

    fn validate_and_deduplicate_users(
        &self,
        mut page: GoogleWorkspacePage,
    ) -> Result<GoogleWorkspacePage, GoogleWorkspaceError> {
        if page.records.len() > self.page_size {
            return Err(GoogleWorkspaceError::TooManyUserRecords);
        }
        page.next_cursor = bounded_cursor(page.next_cursor.as_deref())?;
        let mut seen = BTreeMap::<String, usize>::new();
        let mut records = Vec::<GoogleWorkspaceRecord>::with_capacity(page.records.len());
        for mut record in page.records {
            enforce_go_user_wire_semantics(&mut record)?;
            let user_id = record
                .fields
                .get("user_id")
                .map(String::as_str)
                .filter(|value| valid_provider_identity(value))
                .ok_or(GoogleWorkspaceError::MissingRecordIdentity)?;
            if record.provider_id != user_id
                || record.family != GoogleWorkspaceFamily::User.as_str()
                || record.provider_kind != GoogleWorkspaceFamily::User.provider_kind()
            {
                return Err(GoogleWorkspaceError::MissingRecordIdentity);
            }
            if let Some(index) = seen.get(user_id).copied() {
                if records.get(index) != Some(&record) {
                    return Err(GoogleWorkspaceError::ConflictingUserIdentity);
                }
                continue;
            }
            seen.insert(user_id.to_owned(), records.len());
            records.push(record);
        }
        page.records = records;
        Ok(page)
    }

    fn validate_materialized_users(
        &self,
        page: &GoogleWorkspaceEventPage,
    ) -> Result<(), GoogleWorkspaceError> {
        let urn_prefix = format!("urn:cerebro:{}:google_workspace_user:", self.domain);
        for event in &page.events {
            let user_id = event
                .attributes
                .get("user_id")
                .map(String::as_str)
                .filter(|value| valid_provider_identity(value))
                .ok_or(GoogleWorkspaceError::MissingRecordIdentity)?;
            if event.tenant_id != self.domain
                || event.source_id != "google_workspace"
                || event.provider_kind != GoogleWorkspaceFamily::User.provider_kind()
                || event.schema_ref != GoogleWorkspaceFamily::User.schema_ref()
                || event.event_id != format!("google-workspace-user-{user_id}")
                || event.discovery_urn != format!("{urn_prefix}{user_id}")
                || event.attributes.get("domain") != Some(&self.domain)
                || event.attributes.get("family").map(String::as_str) != Some("user")
                || event.payload.get("id").and_then(Value::as_str) != Some(user_id)
                || event.payload.get("domain").and_then(Value::as_str) != Some(self.domain.as_str())
            {
                return Err(GoogleWorkspaceError::InvalidTenantIdentity);
            }
        }
        let expected_checkpoint = page
            .next_cursor
            .as_deref()
            .or_else(|| page.events.last().map(|event| event.event_id.as_str()));
        let expected_watermark = page.events.last().map(|event| event.occurred_at.as_str());
        if page.checkpoint_cursor.as_deref() != expected_checkpoint
            || page.watermark.as_deref() != expected_watermark
        {
            return Err(GoogleWorkspaceError::InvalidResponse);
        }
        Ok(())
    }
}

fn enforce_go_user_wire_semantics(
    record: &mut GoogleWorkspaceRecord,
) -> Result<(), GoogleWorkspaceError> {
    let object = record
        .payload
        .as_object()
        .ok_or(GoogleWorkspaceError::InvalidRecord)?;
    for field in [
        "id",
        "primaryEmail",
        "creationTime",
        "lastLoginTime",
        "orgUnitPath",
    ] {
        if object
            .get(field)
            .is_some_and(|value| !value.is_null() && !value.is_string())
        {
            return Err(GoogleWorkspaceError::InvalidRecord);
        }
    }
    if let Some(name) = object.get("name")
        && !name.is_null()
        && (!name.is_object()
            || name
                .get("fullName")
                .is_some_and(|value| !value.is_null() && !value.is_string()))
    {
        return Err(GoogleWorkspaceError::InvalidRecord);
    }
    for (provider_field, attribute) in [
        ("isAdmin", "is_admin"),
        ("isDelegatedAdmin", "is_delegated_admin"),
        ("isEnrolledIn2Sv", "mfa_enrolled"),
        ("isEnforcedIn2Sv", "mfa_enforced"),
        ("suspended", "suspended"),
        ("archived", "archived"),
    ] {
        match object.get(provider_field) {
            None | Some(Value::Null) => {
                record
                    .fields
                    .insert(attribute.to_owned(), "false".to_owned());
            }
            Some(Value::Bool(value)) => {
                record
                    .fields
                    .insert(attribute.to_owned(), value.to_string());
            }
            Some(_) => return Err(GoogleWorkspaceError::InvalidRecord),
        }
    }
    Ok(())
}

fn bounded_cursor(raw: Option<&str>) -> Result<Option<String>, GoogleWorkspaceError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let cursor = raw.trim();
    if cursor.is_empty() {
        return Ok(None);
    }
    if cursor.len() > MAX_CURSOR_BYTES || cursor.chars().any(char::is_control) {
        return Err(GoogleWorkspaceError::InvalidCursor);
    }
    Ok(Some(cursor.to_owned()))
}

fn valid_tenant_domain(raw: &str) -> bool {
    let domain = raw.trim();
    !domain.is_empty()
        && domain.len() <= 253
        && domain == raw
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
        })
}

fn valid_provider_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@'))
}

fn valid_customer_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn validate_provider_status(status: StatusCode, body: &[u8]) -> Result<(), GoogleWorkspaceError> {
    if status.is_success() {
        return Ok(());
    }
    match status {
        StatusCode::UNAUTHORIZED => Err(GoogleWorkspaceError::AuthenticationRejected),
        StatusCode::FORBIDDEN => Err(classify_forbidden(body)),
        StatusCode::TOO_MANY_REQUESTS => Err(GoogleWorkspaceError::RateLimited),
        status if status.is_server_error() => {
            Err(GoogleWorkspaceError::ProviderUnavailable(status.as_u16()))
        }
        status => Err(GoogleWorkspaceError::UnexpectedProviderStatus(
            status.as_u16(),
        )),
    }
}

fn classify_forbidden(body: &[u8]) -> GoogleWorkspaceError {
    let Ok(Value::Object(root)) = serde_json::from_slice::<Value>(body) else {
        return GoogleWorkspaceError::PermissionDenied;
    };
    let Some(Value::Object(error)) = root.get("error") else {
        return GoogleWorkspaceError::PermissionDenied;
    };
    if error.get("status").and_then(Value::as_str) == Some("RESOURCE_EXHAUSTED") {
        return GoogleWorkspaceError::RateLimited;
    }
    let legacy_reason = error
        .get("errors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .filter_map(|entry| entry.get("reason").and_then(Value::as_str));
    let detail_reason = error
        .get("details")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .filter_map(|entry| entry.get("reason").and_then(Value::as_str));
    let reasons = legacy_reason.chain(detail_reason).collect::<Vec<_>>();
    if reasons.iter().any(|reason| {
        matches!(
            *reason,
            "dailyLimitExceeded" | "quotaExceeded" | "rateLimitExceeded" | "userRateLimitExceeded"
        )
    }) {
        return GoogleWorkspaceError::RateLimited;
    }
    if reasons.iter().any(|reason| {
        matches!(
            *reason,
            "insufficientPermissions" | "ACCESS_TOKEN_SCOPE_INSUFFICIENT" | "insufficient_scope"
        )
    }) {
        return GoogleWorkspaceError::RequiredUserScopeMissing;
    }
    GoogleWorkspaceError::PermissionDenied
}
