use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{AdpError, AdpFamily, AdpKernel, AdpRequest, origin};

const PAGE_SIZE: usize = 100;
const MAX_OFFSET: usize = 10_000_000;
const MAX_EVENTS: usize = 1_000;

pub(super) fn new_kernel(
    base_url: &str,
    tenant_id: &str,
    family: AdpFamily,
    observed_at: &str,
) -> Result<AdpKernel, AdpError> {
    let base_url = origin::validate(base_url)?;
    let tenant_id = origin::tenant(tenant_id).ok_or(AdpError::InvalidTenantId)?;
    let observed = OffsetDateTime::parse(observed_at, &Rfc3339)
        .map_err(|_| AdpError::InvalidConfiguration("observed_at"))?;
    let observed_at = observed
        .format(&Rfc3339)
        .map_err(|_| AdpError::InvalidConfiguration("observed_at"))?;
    Ok(AdpKernel {
        base_url,
        tenant_id,
        family,
        observed_at,
    })
}

pub(super) fn plan(kernel: &AdpKernel, cursor: Option<&str>) -> Result<AdpRequest, AdpError> {
    if kernel.family == AdpFamily::EventNotifications && cursor.is_some() {
        return Err(AdpError::InvalidCursor);
    }
    let offset = cursor.map(validate_cursor).transpose()?.unwrap_or(0);
    let mut url = kernel.base_url.clone();
    url.set_path(kernel.family.path());
    if url.origin() != kernel.base_url.origin() {
        return Err(AdpError::InvalidOrigin);
    }
    let record_limit = if kernel.family == AdpFamily::Users {
        let mut query = url.query_pairs_mut();
        query.append_pair("$top", &PAGE_SIZE.to_string());
        query.append_pair("$skip", &offset.to_string());
        PAGE_SIZE
    } else {
        MAX_EVENTS
    };
    Ok(AdpRequest {
        url,
        family: kernel.family,
        cursor: cursor.map(str::to_owned),
        offset,
        record_limit,
    })
}

pub(super) fn validate_request(kernel: &AdpKernel, request: &AdpRequest) -> Result<(), AdpError> {
    if request != &plan(kernel, request.cursor.as_deref())? {
        return Err(AdpError::RequestScopeMismatch);
    }
    Ok(())
}

pub(super) fn validate_cursor(value: &str) -> Result<usize, AdpError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 16 || value.chars().any(char::is_control) {
        return Err(AdpError::InvalidCursor);
    }
    value
        .parse::<usize>()
        .ok()
        .filter(|offset| *offset <= MAX_OFFSET)
        .ok_or(AdpError::InvalidCursor)
}
