use super::{
    error::DopplerError,
    family::DopplerFamily,
    origin,
    types::{DopplerKernel, DopplerRequest},
};

pub(super) const PAGE_SIZE: usize = 100;
const MAX_CURSOR_BYTES: usize = 4096;

pub(super) fn new_kernel(
    base_url: Option<&str>,
    tenant_id: &str,
    family: DopplerFamily,
    observed_at_unix_millis: i64,
) -> Result<DopplerKernel, DopplerError> {
    if observed_at_unix_millis <= 0 {
        return Err(DopplerError::InvalidProviderRecord);
    }
    Ok(DopplerKernel {
        base_url: origin::validate(base_url)?,
        tenant_id: origin::tenant(tenant_id)?,
        family,
        observed_at_unix_millis,
    })
}

pub(super) fn plan(
    kernel: &DopplerKernel,
    cursor: Option<&str>,
) -> Result<DopplerRequest, DopplerError> {
    let cursor = cursor.map(validate_cursor).transpose()?;
    let mut url = kernel.base_url.clone();
    url.set_path(kernel.family.path());
    {
        let mut query = url.query_pairs_mut();
        if let Some(cursor) = cursor.as_deref() {
            query.append_pair("cursor", cursor);
        }
        query.append_pair("limit", &PAGE_SIZE.to_string());
    }
    if url.origin() != kernel.base_url.origin() || url.path() != kernel.family.path() {
        return Err(DopplerError::RequestScopeMismatch);
    }
    Ok(DopplerRequest {
        url,
        family: kernel.family,
        cursor,
    })
}

pub(super) fn validate_request(
    kernel: &DopplerKernel,
    request: &DopplerRequest,
) -> Result<(), DopplerError> {
    if request != &plan(kernel, request.cursor.as_deref())? {
        return Err(DopplerError::RequestScopeMismatch);
    }
    Ok(())
}

pub(super) fn validate_cursor(value: &str) -> Result<String, DopplerError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_CURSOR_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character == '\u{7f}')
    {
        return Err(DopplerError::InvalidCursor);
    }
    Ok(value.to_owned())
}
