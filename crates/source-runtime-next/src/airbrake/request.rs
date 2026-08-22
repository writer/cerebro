use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{AirbrakeError, AirbrakeFamily, AirbrakeKernel, AirbrakeRequest, origin};

const PAGE_SIZE: usize = 100;

pub(super) fn new_kernel(
    base_url: &str,
    tenant_id: &str,
    family: AirbrakeFamily,
    project_id: Option<&str>,
    observed_at: &str,
) -> Result<AirbrakeKernel, AirbrakeError> {
    let base_url = origin::validate(base_url)?;
    let tenant_id = origin::tenant(tenant_id).ok_or(AirbrakeError::InvalidTenantId)?;
    let project_id = if family.project_scoped() {
        Some(origin::project(project_id).ok_or(AirbrakeError::MissingProjectId)?)
    } else {
        None
    };
    let observed = OffsetDateTime::parse(observed_at, &Rfc3339)
        .map_err(|_| AirbrakeError::InvalidConfiguration("observed_at"))?;
    let observed_at = observed
        .format(&Rfc3339)
        .map_err(|_| AirbrakeError::InvalidConfiguration("observed_at"))?;
    Ok(AirbrakeKernel {
        base_url,
        tenant_id,
        family,
        project_id,
        observed_at,
    })
}

pub(super) fn plan(
    kernel: &AirbrakeKernel,
    cursor: Option<&str>,
) -> Result<AirbrakeRequest, AirbrakeError> {
    if !kernel.family.cursor_paginated() && cursor.is_some() {
        return Err(AirbrakeError::InvalidCursor);
    }
    let cursor = cursor.map(validate_cursor).transpose()?;
    let path = kernel.family.path(kernel.project_id.as_deref())?;
    let mut url = kernel.base_url.clone();
    url.set_path(&path);
    if url.origin() != kernel.base_url.origin() {
        return Err(AirbrakeError::InvalidOrigin);
    }
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("limit", &PAGE_SIZE.to_string());
        if let Some(cursor) = &cursor {
            query.append_pair("start", cursor);
        }
    }
    Ok(AirbrakeRequest {
        url,
        family: kernel.family,
        cursor,
        page_size: PAGE_SIZE,
    })
}

pub(super) fn validate_request(
    kernel: &AirbrakeKernel,
    request: &AirbrakeRequest,
) -> Result<(), AirbrakeError> {
    if request != &plan(kernel, request.cursor.as_deref())? {
        return Err(AirbrakeError::RequestScopeMismatch);
    }
    Ok(())
}

pub(super) fn validate_cursor(value: &str) -> Result<String, AirbrakeError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 512
        || value.chars().any(char::is_control)
        || value.contains(['&', '=', '#', '?'])
    {
        return Err(AirbrakeError::InvalidCursor);
    }
    Ok(value.to_owned())
}
