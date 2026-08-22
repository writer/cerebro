use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    ActiveCampaignError, ActiveCampaignFamily, ActiveCampaignKernel, ActiveCampaignRequest, origin,
};

const PAGE_SIZE: usize = 100;
const MAX_OFFSET: usize = 10_000_000;

pub(super) fn new_kernel(
    base_url: &str,
    tenant_id: &str,
    family: ActiveCampaignFamily,
    observed_at: &str,
) -> Result<ActiveCampaignKernel, ActiveCampaignError> {
    let base_url = origin::validate(base_url)?;
    let tenant_id = origin::tenant(tenant_id).ok_or(ActiveCampaignError::InvalidTenantId)?;
    let observed = OffsetDateTime::parse(observed_at, &Rfc3339)
        .map_err(|_| ActiveCampaignError::InvalidConfiguration("observed_at"))?;
    let observed_at = observed
        .format(&Rfc3339)
        .map_err(|_| ActiveCampaignError::InvalidConfiguration("observed_at"))?;
    Ok(ActiveCampaignKernel {
        base_url,
        tenant_id,
        family,
        observed_at,
    })
}

pub(super) fn plan(
    kernel: &ActiveCampaignKernel,
    cursor: Option<&str>,
) -> Result<ActiveCampaignRequest, ActiveCampaignError> {
    let offset = cursor.map(validate_cursor).transpose()?.unwrap_or(0);
    let mut url = kernel.base_url.clone();
    url.set_path(kernel.family.path());
    if url.origin() != kernel.base_url.origin() {
        return Err(ActiveCampaignError::InvalidOrigin);
    }
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("limit", &PAGE_SIZE.to_string());
        query.append_pair("offset", &offset.to_string());
    }
    Ok(ActiveCampaignRequest {
        url,
        family: kernel.family,
        offset,
        cursor: cursor.map(str::to_owned),
        page_size: PAGE_SIZE,
    })
}

pub(super) fn validate_request(
    kernel: &ActiveCampaignKernel,
    request: &ActiveCampaignRequest,
) -> Result<(), ActiveCampaignError> {
    if request != &plan(kernel, request.cursor.as_deref())? {
        return Err(ActiveCampaignError::RequestScopeMismatch);
    }
    Ok(())
}

pub(super) fn validate_cursor(value: &str) -> Result<usize, ActiveCampaignError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 16 || value.chars().any(char::is_control) {
        return Err(ActiveCampaignError::InvalidCursor);
    }
    value
        .parse::<usize>()
        .ok()
        .filter(|offset| *offset <= MAX_OFFSET)
        .ok_or(ActiveCampaignError::InvalidCursor)
}
