use std::collections::BTreeMap;

use serde_json::Value;

use super::{
    SlackCheckpoint, SlackError, SlackFamily, SlackKernel, SlackPage, SlackRequest, cursor,
    normalize,
};

pub(super) const MAX_RESPONSE_BYTES: usize = 8 << 20;
const MAX_UNPAGED_RECORDS: usize = 1_000;

pub(super) fn decode(
    kernel: &SlackKernel,
    request: &SlackRequest,
    status: u16,
    retry_after: Option<&str>,
    body: &[u8],
) -> Result<SlackPage, SlackError> {
    validate_request(kernel, request)?;
    classify_status(status, retry_after)?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(SlackError::ResponseTooLarge);
    }
    let root: Value = serde_json::from_slice(body).map_err(|_| SlackError::MalformedResponse)?;
    classify_slack_envelope(&root)?;
    let items = records(kernel.family, &root)?;
    let maximum = if kernel.family == SlackFamily::UserGroup {
        MAX_UNPAGED_RECORDS
    } else {
        request.page_size
    };
    if items.len() > maximum {
        return Err(SlackError::MalformedResponse);
    }
    let mut by_identity = BTreeMap::<String, Vec<u8>>::new();
    let mut records = Vec::with_capacity(items.len());
    for item in items {
        let record = normalize::normalize(kernel, item)?;
        let canonical =
            serde_json::to_vec(&record.payload).map_err(|_| SlackError::InvalidRecord)?;
        match by_identity.get(&record.event_id) {
            Some(existing) if existing == &canonical => continue,
            Some(_) => return Err(SlackError::ConflictingDuplicate),
            None => {
                by_identity.insert(record.event_id.clone(), canonical);
                records.push(record);
            }
        }
    }
    let next_cursor = next_cursor(kernel.family, request, &root)?;
    let watermark_unix_millis = records
        .iter()
        .map(|record| record.occurred_at_unix_millis)
        .max();
    Ok(SlackPage {
        records,
        next_cursor: next_cursor.clone(),
        checkpoint: SlackCheckpoint {
            next_cursor,
            watermark_unix_millis,
        },
    })
}

fn validate_request(kernel: &SlackKernel, request: &SlackRequest) -> Result<(), SlackError> {
    let origin = if kernel.family.uses_audit_origin() {
        &kernel.audit_origin
    } else {
        &kernel.web_origin
    };
    let expected_path = format!(
        "{}{}",
        origin.path().trim_end_matches('/'),
        kernel.family.path()
    );
    if request.family != kernel.family
        || request.method != kernel.family.method()
        || request.url.origin() != origin.origin()
        || request.url.path() != expected_path
        || request.page_size != kernel.page_size
    {
        return Err(SlackError::RequestScopeMismatch);
    }
    Ok(())
}

fn classify_status(status: u16, retry_after: Option<&str>) -> Result<(), SlackError> {
    match status {
        200..=299 => Ok(()),
        401 => Err(SlackError::AuthenticationRejected),
        403 => Err(SlackError::RequiredScopeMissing),
        429 => Err(SlackError::RateLimited {
            retry_after_seconds: retry_after
                .and_then(|value| value.trim().parse::<u64>().ok())
                .filter(|value| *value <= 3_600),
        }),
        500..=599 => Err(SlackError::ProviderUnavailable { status }),
        _ => Err(SlackError::UnexpectedStatus { status }),
    }
}

fn classify_slack_envelope(root: &Value) -> Result<(), SlackError> {
    let Some(object) = root.as_object() else {
        return Err(SlackError::MalformedResponse);
    };
    match object.get("ok") {
        None | Some(Value::Bool(true)) => Ok(()),
        Some(Value::Bool(false)) => {
            let code = object
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or_default();
            match code.trim() {
                "invalid_auth" | "account_inactive" | "token_revoked" | "not_authed" => {
                    Err(SlackError::AuthenticationRejected)
                }
                "missing_scope" | "not_allowed_token_type" => Err(SlackError::RequiredScopeMissing),
                "ratelimited" => Err(SlackError::RateLimited {
                    retry_after_seconds: None,
                }),
                _ => Err(SlackError::MalformedResponse),
            }
        }
        Some(_) => Err(SlackError::MalformedResponse),
    }
}

fn records(family: SlackFamily, root: &Value) -> Result<&[Value], SlackError> {
    let key = match family {
        SlackFamily::Team => "teams",
        SlackFamily::User => "members",
        SlackFamily::Channel => "channels",
        SlackFamily::UserGroup => "usergroups",
        SlackFamily::AccessLog => "logins",
        SlackFamily::ChannelMember => "members",
        SlackFamily::UserGroupMember => "users",
        SlackFamily::AuditLog => "entries",
    };
    root.get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(SlackError::MalformedResponse)
}

fn next_cursor(
    family: SlackFamily,
    request: &SlackRequest,
    root: &Value,
) -> Result<Option<String>, SlackError> {
    if family == SlackFamily::UserGroup {
        return Ok(None);
    }
    if family == SlackFamily::AccessLog {
        let Some(paging) = root.get("paging").and_then(Value::as_object) else {
            return Ok(None);
        };
        let page = paging.get("page").and_then(Value::as_u64).unwrap_or(0);
        let pages = paging.get("pages").and_then(Value::as_u64).unwrap_or(0);
        if page == 0 || pages == 0 || page >= pages {
            return Ok(None);
        }
        return page
            .checked_add(1)
            .map(|page| Some(page.to_string()))
            .ok_or(SlackError::InvalidCursor);
    }
    let token = root
        .get("response_metadata")
        .and_then(Value::as_object)
        .and_then(|metadata| {
            metadata
                .get("next_cursor")
                .or_else(|| metadata.get("cursor"))
        })
        .and_then(Value::as_str)
        .unwrap_or_default();
    if family == SlackFamily::AuditLog {
        cursor::audit_next(token, request.audit_window.as_ref())
    } else if token.trim().is_empty() {
        Ok(None)
    } else if token.len() > 4_096 || token.chars().any(char::is_control) {
        Err(SlackError::InvalidCursor)
    } else {
        Ok(Some(token.trim().to_owned()))
    }
}
