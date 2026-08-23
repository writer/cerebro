use reqwest::Url;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{AdaSupportError, AdaSupportFamily, AdaSupportKernel, AdaSupportRequest, origin};

const PAGE_SIZE: usize = 100;
const MAX_CURSOR_BYTES: usize = 2_048;

pub(super) fn new_kernel(
    base_url: &str,
    tenant_id: &str,
    family: AdaSupportFamily,
    observed_at: &str,
) -> Result<AdaSupportKernel, AdaSupportError> {
    let base_url = origin::validate(base_url)?;
    let tenant_id = origin::tenant(tenant_id).ok_or(AdaSupportError::InvalidTenantId)?;
    let observed = OffsetDateTime::parse(observed_at, &Rfc3339)
        .map_err(|_| AdaSupportError::InvalidConfiguration("observed_at"))?;
    let observed_at = observed
        .format(&Rfc3339)
        .map_err(|_| AdaSupportError::InvalidConfiguration("observed_at"))?;
    Ok(AdaSupportKernel {
        base_url,
        tenant_id,
        family,
        observed_at,
    })
}

pub(super) fn plan(
    kernel: &AdaSupportKernel,
    cursor: Option<&str>,
) -> Result<AdaSupportRequest, AdaSupportError> {
    let mut url = kernel.base_url.clone();
    url.set_path(&format!("/api{}", kernel.family.path()));
    if url.origin() != kernel.base_url.origin() {
        return Err(AdaSupportError::InvalidOrigin);
    }
    {
        let mut query = url.query_pairs_mut();
        query.append_pair(
            if kernel.family == AdaSupportFamily::Conversations {
                "page_size"
            } else {
                "limit"
            },
            &PAGE_SIZE.to_string(),
        );
        if let Some(cursor) = cursor {
            query.append_pair("cursor", validate_cursor(kernel, cursor)?);
        }
    }
    Ok(AdaSupportRequest {
        url,
        family: kernel.family,
        cursor: cursor.map(str::to_owned),
        page_size: PAGE_SIZE,
    })
}

pub(super) fn validate_request(
    kernel: &AdaSupportKernel,
    request: &AdaSupportRequest,
) -> Result<(), AdaSupportError> {
    if request != &plan(kernel, request.cursor.as_deref())? {
        return Err(AdaSupportError::RequestScopeMismatch);
    }
    Ok(())
}

pub(super) fn validate_cursor<'a>(
    kernel: &AdaSupportKernel,
    value: &'a str,
) -> Result<&'a str, AdaSupportError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_CURSOR_BYTES
        || value.chars().any(char::is_control)
        || value.contains('\\')
    {
        return Err(AdaSupportError::InvalidCursor);
    }
    if value.starts_with("http://") || value.starts_with("https://") {
        let url = Url::parse(value).map_err(|_| AdaSupportError::InvalidCursor)?;
        let expected_path = format!("/api{}", kernel.family.path());
        if url.origin() != kernel.base_url.origin()
            || url.path() != expected_path
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(AdaSupportError::InvalidCursor);
        }
    } else if value.starts_with('/') {
        let expected_path = format!("/api{}", kernel.family.path());
        let path = value.split('?').next().unwrap_or_default();
        if path != expected_path {
            return Err(AdaSupportError::InvalidCursor);
        }
    } else if value.contains(['/', ':', '#']) {
        return Err(AdaSupportError::InvalidCursor);
    }
    Ok(value)
}
