use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    AbnormalSecurityError, AbnormalSecurityFamily, AbnormalSecurityKernel, AbnormalSecurityRequest,
    origin,
};

const PAGE_SIZE: usize = 100;
const MAX_PAGE_NUMBER: u64 = 10_000_000;

pub(super) fn new_kernel(
    base_url: &str,
    tenant_id: &str,
    family: AbnormalSecurityFamily,
    observed_at: &str,
) -> Result<AbnormalSecurityKernel, AbnormalSecurityError> {
    let base_url = origin::validate(base_url)?;
    let tenant_id = origin::tenant(tenant_id).ok_or(AbnormalSecurityError::InvalidTenantId)?;
    let observed = OffsetDateTime::parse(observed_at, &Rfc3339)
        .map_err(|_| AbnormalSecurityError::InvalidConfiguration("observed_at"))?;
    let observed_at = observed
        .format(&Rfc3339)
        .map_err(|_| AbnormalSecurityError::InvalidConfiguration("observed_at"))?;
    Ok(AbnormalSecurityKernel {
        base_url,
        tenant_id,
        family,
        observed_at,
    })
}

pub(super) fn plan(
    kernel: &AbnormalSecurityKernel,
    cursor: Option<&str>,
) -> Result<AbnormalSecurityRequest, AbnormalSecurityError> {
    let mut url = kernel.base_url.clone();
    url.set_path(&format!("/v1{}", kernel.family.path()));
    if url.origin() != kernel.base_url.origin() {
        return Err(AbnormalSecurityError::InvalidOrigin);
    }
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("pageSize", &PAGE_SIZE.to_string());
        if let Some(cursor) = cursor {
            query.append_pair("pageNumber", validate_cursor(cursor)?);
        }
    }
    Ok(AbnormalSecurityRequest {
        url,
        family: kernel.family,
        cursor: cursor.map(str::to_owned),
        page_size: PAGE_SIZE,
    })
}

pub(super) fn validate_request(
    kernel: &AbnormalSecurityKernel,
    request: &AbnormalSecurityRequest,
) -> Result<(), AbnormalSecurityError> {
    if request != &plan(kernel, request.cursor.as_deref())? {
        return Err(AbnormalSecurityError::RequestScopeMismatch);
    }
    Ok(())
}

pub(super) fn validate_cursor(value: &str) -> Result<&str, AbnormalSecurityError> {
    let value = value.trim();
    value
        .parse::<u64>()
        .ok()
        .filter(|page| (1..=MAX_PAGE_NUMBER).contains(page))
        .map(|_| value)
        .ok_or(AbnormalSecurityError::InvalidCursor)
}
