use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    DigitalOceanError, DigitalOceanFamily, DigitalOceanKernel, DigitalOceanOperation,
    DigitalOceanRequest, origin,
};

const DEFAULT_PAGE_SIZE: usize = 50;
const MAX_PAGE_SIZE: usize = 200;
const MAX_PAGE: u32 = 1_000_000;

pub(super) fn new_kernel(
    base_url: Option<&str>,
    tenant_id: &str,
    family: DigitalOceanFamily,
    page_size: Option<usize>,
    observed_at: &str,
) -> Result<DigitalOceanKernel, DigitalOceanError> {
    let base_url = origin::validate(base_url)?;
    let tenant_id = origin::tenant(tenant_id).ok_or(DigitalOceanError::InvalidTenantId)?;
    let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE);
    if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
        return Err(DigitalOceanError::InvalidPageSize);
    }
    let observed = OffsetDateTime::parse(observed_at, &Rfc3339)
        .map_err(|_| DigitalOceanError::InvalidProviderRecord)?;
    let observed_at = observed
        .format(&Rfc3339)
        .map_err(|_| DigitalOceanError::InvalidProviderRecord)?;
    Ok(DigitalOceanKernel {
        base_url,
        tenant_id,
        family,
        page_size,
        observed_at,
    })
}

pub(super) fn plan(
    kernel: &DigitalOceanKernel,
    operation: DigitalOceanOperation,
    cursor: Option<&str>,
) -> Result<DigitalOceanRequest, DigitalOceanError> {
    if matches!(
        operation,
        DigitalOceanOperation::Check | DigitalOceanOperation::AccountVerification
    ) && cursor.is_some()
    {
        return Err(DigitalOceanError::InvalidCursor);
    }
    let page = cursor.map(validate_cursor).transpose()?.unwrap_or(1);
    let mut url = kernel.base_url.clone();
    url.set_path(match operation {
        DigitalOceanOperation::AccountVerification => "/v2/account",
        DigitalOceanOperation::Check
        | DigitalOceanOperation::Discover
        | DigitalOceanOperation::Read => kernel.family.path(),
    });
    if url.origin() != kernel.base_url.origin() {
        return Err(DigitalOceanError::InvalidBaseUrl);
    }
    if operation != DigitalOceanOperation::AccountVerification {
        let mut query = url.query_pairs_mut();
        query.append_pair("page", &page.to_string());
        query.append_pair("per_page", &kernel.page_size.to_string());
    }
    Ok(DigitalOceanRequest {
        url,
        family: kernel.family,
        operation,
        cursor: cursor.map(str::to_owned),
        page,
        page_size: kernel.page_size,
    })
}

pub(super) fn validate_request(
    kernel: &DigitalOceanKernel,
    request: &DigitalOceanRequest,
) -> Result<(), DigitalOceanError> {
    if request != &plan(kernel, request.operation, request.cursor.as_deref())? {
        return Err(DigitalOceanError::RequestScopeMismatch);
    }
    Ok(())
}

pub(super) fn validate_cursor(value: &str) -> Result<u32, DigitalOceanError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 7
        || value.starts_with('0')
        || value.chars().any(char::is_control)
    {
        return Err(DigitalOceanError::InvalidCursor);
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|page| (1..=MAX_PAGE).contains(page))
        .ok_or(DigitalOceanError::InvalidCursor)
}

pub(super) fn next_page(page: u32) -> Result<String, DigitalOceanError> {
    page.checked_add(1)
        .filter(|next| *next <= MAX_PAGE)
        .map(|next| next.to_string())
        .ok_or(DigitalOceanError::InvalidCursor)
}
