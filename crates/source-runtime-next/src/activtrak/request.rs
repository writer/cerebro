use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{ActivTrakError, ActivTrakFamily, ActivTrakKernel, ActivTrakRequest, origin};

const MAX_OFFSET: usize = 10_000_000;
const MAX_CURSOR_BYTES: usize = 2_048;

pub(super) fn new_kernel(
    base_url: &str,
    tenant_id: &str,
    family: ActivTrakFamily,
    observed_at: &str,
) -> Result<ActivTrakKernel, ActivTrakError> {
    let base_url = origin::validate(base_url)?;
    let tenant_id = origin::tenant(tenant_id).ok_or(ActivTrakError::InvalidTenantId)?;
    let observed = OffsetDateTime::parse(observed_at, &Rfc3339)
        .map_err(|_| ActivTrakError::InvalidConfiguration("observed_at"))?;
    let observed_at = observed
        .format(&Rfc3339)
        .map_err(|_| ActivTrakError::InvalidConfiguration("observed_at"))?;
    Ok(ActivTrakKernel {
        base_url,
        tenant_id,
        family,
        observed_at,
    })
}

pub(super) fn plan(
    kernel: &ActivTrakKernel,
    cursor: Option<&str>,
) -> Result<ActivTrakRequest, ActivTrakError> {
    let mut url = kernel.base_url.clone();
    url.set_path(kernel.family.path());
    if url.origin() != kernel.base_url.origin() {
        return Err(ActivTrakError::InvalidOrigin);
    }
    let offset = match kernel.family {
        ActivTrakFamily::Groups | ActivTrakFamily::Users => {
            let offset = cursor.map(validate_offset).transpose()?.unwrap_or(1);
            let mut query = url.query_pairs_mut();
            query.append_pair("count", &kernel.family.page_size().to_string());
            query.append_pair("startIndex", &offset.to_string());
            Some(offset)
        }
        ActivTrakFamily::ActivityLog => {
            let mut query = url.query_pairs_mut();
            query.append_pair("pageSize", &kernel.family.page_size().to_string());
            if let Some(cursor) = cursor {
                query.append_pair("cursor", validate_opaque(cursor)?);
            }
            None
        }
        ActivTrakFamily::Clients | ActivTrakFamily::Consumers => {
            if cursor.is_some() {
                return Err(ActivTrakError::InvalidCursor);
            }
            None
        }
    };
    Ok(ActivTrakRequest {
        url,
        family: kernel.family,
        cursor: cursor.map(str::to_owned),
        offset,
        page_size: kernel.family.page_size(),
    })
}

pub(super) fn validate_request(
    kernel: &ActivTrakKernel,
    request: &ActivTrakRequest,
) -> Result<(), ActivTrakError> {
    if request != &plan(kernel, request.cursor.as_deref())? {
        return Err(ActivTrakError::RequestScopeMismatch);
    }
    Ok(())
}

pub(super) fn validate_offset(value: &str) -> Result<usize, ActivTrakError> {
    value
        .trim()
        .parse::<usize>()
        .ok()
        .filter(|offset| (1..=MAX_OFFSET).contains(offset))
        .ok_or(ActivTrakError::InvalidCursor)
}

pub(super) fn validate_opaque(value: &str) -> Result<&str, ActivTrakError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_CURSOR_BYTES
        || value.chars().any(char::is_control)
        || value.contains(['/', '\\'])
    {
        return Err(ActivTrakError::InvalidCursor);
    }
    Ok(value)
}
