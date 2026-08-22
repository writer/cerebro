use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{AcunetixError, AcunetixFamily, AcunetixKernel, AcunetixRequest, origin};

const PAGE_SIZE: usize = 100;
const MAX_CURSOR_BYTES: usize = 2_048;

pub(super) fn new_kernel(
    base_url: &str,
    tenant_id: &str,
    family: AcunetixFamily,
    observed_at: &str,
) -> Result<AcunetixKernel, AcunetixError> {
    let base_url = origin::validate(base_url)?;
    let tenant_id = origin::tenant(tenant_id).ok_or(AcunetixError::InvalidTenantId)?;
    let observed = OffsetDateTime::parse(observed_at, &Rfc3339)
        .map_err(|_| AcunetixError::InvalidConfiguration("observed_at"))?;
    let observed_at = observed
        .format(&Rfc3339)
        .map_err(|_| AcunetixError::InvalidConfiguration("observed_at"))?;
    Ok(AcunetixKernel {
        base_url,
        tenant_id,
        family,
        observed_at,
    })
}

pub(super) fn plan(
    kernel: &AcunetixKernel,
    cursor: Option<&str>,
) -> Result<AcunetixRequest, AcunetixError> {
    let mut url = kernel.base_url.clone();
    url.set_path(&format!("/api/v1{}", kernel.family.path()));
    if url.origin() != kernel.base_url.origin() {
        return Err(AcunetixError::InvalidOrigin);
    }
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("l", &PAGE_SIZE.to_string());
        if let Some(cursor) = cursor {
            query.append_pair("c", validate_cursor(cursor)?);
        }
    }
    Ok(AcunetixRequest {
        url,
        family: kernel.family,
        cursor: cursor.map(str::to_owned),
        page_size: PAGE_SIZE,
    })
}

pub(super) fn validate_request(
    kernel: &AcunetixKernel,
    request: &AcunetixRequest,
) -> Result<(), AcunetixError> {
    if request != &plan(kernel, request.cursor.as_deref())? {
        return Err(AcunetixError::RequestScopeMismatch);
    }
    Ok(())
}

pub(super) fn validate_cursor(value: &str) -> Result<&str, AcunetixError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_CURSOR_BYTES
        || value.chars().any(char::is_control)
        || value.contains(['/', '\\'])
    {
        return Err(AcunetixError::InvalidCursor);
    }
    Ok(value)
}
