use serde_json::{Map, Value};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    JumpCloudError, JumpCloudFamily, JumpCloudFilters, JumpCloudKernel, JumpCloudRequest, origin,
};

const MAX_CURSOR_BYTES: usize = 4_096;
const MAX_PAGE_SIZE: usize = 1_000;

pub(super) fn new_kernel(
    directory_origin: &str,
    insights_origin: &str,
    tenant_id: &str,
    family: JumpCloudFamily,
    mut filters: JumpCloudFilters,
    page_size: Option<usize>,
    observed_at: &str,
) -> Result<JumpCloudKernel, JumpCloudError> {
    let directory_origin = origin::directory(directory_origin)?;
    let insights_origin = origin::insights(insights_origin)?;
    let tenant_id = origin::bounded(tenant_id, 128).ok_or(JumpCloudError::InvalidTenantId)?;
    let page_size = page_size.unwrap_or(if family == JumpCloudFamily::AuditEvents {
        1_000
    } else {
        100
    });
    if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
        return Err(JumpCloudError::InvalidConfiguration("page_size"));
    }
    OffsetDateTime::parse(observed_at, &Rfc3339)
        .map_err(|_| JumpCloudError::InvalidConfiguration("observed_at"))?;
    validate_filters(family, &mut filters)?;
    Ok(JumpCloudKernel {
        directory_origin,
        insights_origin,
        tenant_id,
        family,
        filters,
        page_size,
        observed_at: observed_at.to_owned(),
    })
}

pub(super) fn plan(
    kernel: &JumpCloudKernel,
    cursor: Option<&str>,
) -> Result<JumpCloudRequest, JumpCloudError> {
    plan_with_checkpoint(kernel, cursor, None)
}

pub(super) fn plan_with_checkpoint(
    kernel: &JumpCloudKernel,
    cursor: Option<&str>,
    prior_watermark: Option<&str>,
) -> Result<JumpCloudRequest, JumpCloudError> {
    let origin = if kernel.family.uses_insights_origin() {
        &kernel.insights_origin
    } else {
        &kernel.directory_origin
    };
    let path = if kernel.family == JumpCloudFamily::GroupMembers {
        let group_id = kernel
            .filters
            .group_id
            .as_deref()
            .ok_or(JumpCloudError::MissingConfiguration("group_id"))?;
        kernel.family.path().replace("{group_id}", group_id)
    } else {
        kernel.family.path().to_owned()
    };
    let mut url = origin.clone();
    url.set_path(&format!("{}{}", origin.path().trim_end_matches('/'), path));
    if url.origin() != origin.origin() {
        return Err(JumpCloudError::InvalidOrigin);
    }
    let (cursor, body) = if kernel.family == JumpCloudFamily::AuditEvents {
        let cursor = cursor.map(validate_audit_cursor).transpose()?;
        (
            cursor.clone(),
            Some(audit_body(kernel, cursor.as_deref(), prior_watermark)?),
        )
    } else {
        let offset = cursor.map(validate_offset).transpose()?.unwrap_or(0);
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("limit", &kernel.page_size.to_string());
            query.append_pair("skip", &offset.to_string());
        }
        (cursor.map(str::to_owned), None)
    };
    Ok(JumpCloudRequest {
        family: kernel.family,
        url,
        method: kernel.family.method(),
        page_size: kernel.page_size,
        cursor,
        body,
        org_id: kernel.filters.org_id.clone(),
        checkpoint_watermark: prior_watermark.map(normalize_watermark).transpose()?,
    })
}

pub(super) fn validate_request(
    kernel: &JumpCloudKernel,
    request: &JumpCloudRequest,
) -> Result<(), JumpCloudError> {
    if request
        != &plan_with_checkpoint(
            kernel,
            request.cursor.as_deref(),
            request.checkpoint_watermark.as_deref(),
        )?
    {
        return Err(JumpCloudError::RequestScopeMismatch);
    }
    Ok(())
}

pub(super) fn validate_offset(value: &str) -> Result<usize, JumpCloudError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 16 || value.chars().any(char::is_control) {
        return Err(JumpCloudError::InvalidCursor);
    }
    value
        .parse::<usize>()
        .ok()
        .filter(|offset| *offset <= 10_000_000)
        .ok_or(JumpCloudError::InvalidCursor)
}

pub(super) fn validate_audit_cursor(value: &str) -> Result<String, JumpCloudError> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_CURSOR_BYTES || value.chars().any(char::is_control) {
        return Err(JumpCloudError::InvalidCursor);
    }
    let parsed: Value = serde_json::from_str(value).map_err(|_| JumpCloudError::InvalidCursor)?;
    if parsed.is_null() {
        return Err(JumpCloudError::InvalidCursor);
    }
    reject_depth(&parsed, 0)?;
    serde_json::to_string(&parsed).map_err(|_| JumpCloudError::InvalidCursor)
}

fn validate_filters(
    family: JumpCloudFamily,
    filters: &mut JumpCloudFilters,
) -> Result<(), JumpCloudError> {
    for value in [&filters.org_id, &filters.group_id].into_iter().flatten() {
        origin::bounded(value, 256).ok_or(JumpCloudError::InvalidConfiguration("scope"))?;
    }
    if family == JumpCloudFamily::GroupMembers && filters.group_id.is_none() {
        return Err(JumpCloudError::MissingConfiguration("group_id"));
    }
    for value in [&filters.audit_start_time, &filters.audit_end_time]
        .into_iter()
        .flatten()
    {
        OffsetDateTime::parse(value, &Rfc3339)
            .map_err(|_| JumpCloudError::InvalidConfiguration("audit_time"))?;
    }
    if filters.audit_services.is_empty() {
        filters.audit_services.push("all".to_owned());
    }
    if filters.audit_services.len() > 32 {
        return Err(JumpCloudError::InvalidConfiguration("audit_services"));
    }
    for service in &filters.audit_services {
        origin::bounded(service, 128)
            .ok_or(JumpCloudError::InvalidConfiguration("audit_services"))?;
    }
    let sort = filters.audit_sort.get_or_insert_with(|| "ASC".to_owned());
    *sort = sort.trim().to_ascii_uppercase();
    if sort != "ASC" && sort != "DESC" {
        return Err(JumpCloudError::InvalidConfiguration("audit_sort"));
    }
    Ok(())
}

fn audit_body(
    kernel: &JumpCloudKernel,
    cursor: Option<&str>,
    prior_watermark: Option<&str>,
) -> Result<Vec<u8>, JumpCloudError> {
    let start_time = match &kernel.filters.audit_start_time {
        Some(configured) => configured.clone(),
        None => match prior_watermark {
            Some(watermark) => normalize_watermark(watermark)?,
            None => (OffsetDateTime::parse(&kernel.observed_at, &Rfc3339)
                .map_err(|_| JumpCloudError::InvalidConfiguration("observed_at"))?
                - Duration::days(1))
            .replace_nanosecond(0)
            .map_err(|_| JumpCloudError::InvalidConfiguration("observed_at"))?
            .format(&Rfc3339)
            .map_err(|_| JumpCloudError::InternalRuntimeFailure)?,
        },
    };
    let mut body = Map::from_iter([
        (
            "service".to_owned(),
            Value::Array(
                kernel
                    .filters
                    .audit_services
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        ),
        ("start_time".to_owned(), Value::String(start_time)),
        ("limit".to_owned(), Value::from(kernel.page_size)),
        (
            "sort".to_owned(),
            Value::String(
                kernel
                    .filters
                    .audit_sort
                    .clone()
                    .unwrap_or_else(|| "ASC".to_owned()),
            ),
        ),
    ]);
    if let Some(end) = &kernel.filters.audit_end_time {
        body.insert("end_time".to_owned(), Value::String(end.clone()));
    }
    if let Some(cursor) = cursor {
        let value = serde_json::from_str(cursor).map_err(|_| JumpCloudError::InvalidCursor)?;
        body.insert("search_after".to_owned(), value);
    }
    serde_json::to_vec(&Value::Object(body)).map_err(|_| JumpCloudError::InternalRuntimeFailure)
}

fn normalize_watermark(value: &str) -> Result<String, JumpCloudError> {
    OffsetDateTime::parse(value.trim(), &Rfc3339)
        .map_err(|_| JumpCloudError::InvalidConfiguration("checkpoint_watermark"))?
        .replace_nanosecond(0)
        .map_err(|_| JumpCloudError::InvalidConfiguration("checkpoint_watermark"))?
        .format(&Rfc3339)
        .map_err(|_| JumpCloudError::InternalRuntimeFailure)
}

fn reject_depth(value: &Value, depth: usize) -> Result<(), JumpCloudError> {
    if depth > 8 {
        return Err(JumpCloudError::InvalidCursor);
    }
    match value {
        Value::Array(values) => {
            for value in values {
                reject_depth(value, depth + 1)?;
            }
        }
        Value::Object(values) => {
            if values.len() > 32 {
                return Err(JumpCloudError::InvalidCursor);
            }
            for value in values.values() {
                reject_depth(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
