use serde_json::json;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{AddigyError, AddigyFamily, AddigyKernel, AddigyRequest, origin};

const PAGE_SIZE: usize = 100;
const MAX_PAGE: u32 = 1_000_000;

pub(super) fn new_kernel(
    base_url: &str,
    tenant_id: &str,
    family: AddigyFamily,
    organization_id: Option<&str>,
    observed_at: &str,
) -> Result<AddigyKernel, AddigyError> {
    let base_url = origin::validate(base_url)?;
    let tenant_id = origin::tenant(tenant_id).ok_or(AddigyError::InvalidTenantId)?;
    let organization_id = match organization_id {
        Some(_) => Some(
            origin::organization(organization_id)
                .ok_or(AddigyError::InvalidConfiguration("organization_id"))?,
        ),
        None => None,
    };
    if matches!(family, AddigyFamily::Groups | AddigyFamily::Users) && organization_id.is_none() {
        return Err(AddigyError::MissingOrganizationId);
    }
    let observed = OffsetDateTime::parse(observed_at, &Rfc3339)
        .map_err(|_| AddigyError::InvalidConfiguration("observed_at"))?;
    let observed_at = observed
        .format(&Rfc3339)
        .map_err(|_| AddigyError::InvalidConfiguration("observed_at"))?;
    Ok(AddigyKernel {
        base_url,
        tenant_id,
        family,
        organization_id,
        observed_at,
    })
}

pub(super) fn plan(
    kernel: &AddigyKernel,
    cursor: Option<&str>,
) -> Result<AddigyRequest, AddigyError> {
    if !kernel.family.paginated() && cursor.is_some() {
        return Err(AddigyError::InvalidCursor);
    }
    let page = cursor.map(validate_cursor).transpose()?.unwrap_or(1);
    let path = kernel.family.path(kernel.organization_id.as_deref())?;
    let mut url = kernel.base_url.clone();
    url.set_path(&format!("/api/v2{path}"));
    if url.origin() != kernel.base_url.origin() {
        return Err(AddigyError::InvalidOrigin);
    }
    if kernel.family.paginated() {
        let mut query = url.query_pairs_mut();
        query.append_pair("per_page", &PAGE_SIZE.to_string());
        query.append_pair("page", &page.to_string());
    }
    Ok(AddigyRequest {
        url,
        family: kernel.family,
        cursor: cursor.map(str::to_owned),
        page,
        page_size: PAGE_SIZE,
        body: json!({}),
    })
}

pub(super) fn validate_request(
    kernel: &AddigyKernel,
    request: &AddigyRequest,
) -> Result<(), AddigyError> {
    if request != &plan(kernel, request.cursor.as_deref())? {
        return Err(AddigyError::RequestScopeMismatch);
    }
    Ok(())
}

pub(super) fn validate_cursor(value: &str) -> Result<u32, AddigyError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 7 || value.chars().any(char::is_control) {
        return Err(AddigyError::InvalidCursor);
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|page| (1..=MAX_PAGE).contains(page))
        .ok_or(AddigyError::InvalidCursor)
}
