use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{AhaError, AhaFamily, AhaKernel, AhaRequest, origin};

const PAGE_SIZE: usize = 100;
const MAX_PAGE: u32 = 1_000_000;

pub(super) fn new_kernel(
    base_url: &str,
    tenant_id: &str,
    family: AhaFamily,
    product_id: Option<&str>,
    observed_at: &str,
) -> Result<AhaKernel, AhaError> {
    let base_url = origin::validate(base_url)?;
    let tenant_id = origin::tenant(tenant_id).ok_or(AhaError::InvalidTenantId)?;
    let product_id = if family == AhaFamily::Releases {
        Some(origin::product(product_id).ok_or(AhaError::MissingProductId)?)
    } else {
        None
    };
    let observed = OffsetDateTime::parse(observed_at, &Rfc3339)
        .map_err(|_| AhaError::InvalidConfiguration("observed_at"))?;
    let observed_at = observed
        .format(&Rfc3339)
        .map_err(|_| AhaError::InvalidConfiguration("observed_at"))?;
    Ok(AhaKernel {
        base_url,
        tenant_id,
        family,
        product_id,
        observed_at,
    })
}

pub(super) fn plan(kernel: &AhaKernel, cursor: Option<&str>) -> Result<AhaRequest, AhaError> {
    let page = cursor.map(validate_cursor).transpose()?.unwrap_or(1);
    let path = kernel.family.path(kernel.product_id.as_deref())?;
    let mut url = kernel.base_url.clone();
    url.set_path(&format!("/api/v1{path}"));
    if url.origin() != kernel.base_url.origin() {
        return Err(AhaError::InvalidOrigin);
    }
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("per_page", &PAGE_SIZE.to_string());
        query.append_pair("page", &page.to_string());
    }
    Ok(AhaRequest {
        url,
        family: kernel.family,
        cursor: cursor.map(str::to_owned),
        page,
        page_size: PAGE_SIZE,
    })
}

pub(super) fn validate_request(kernel: &AhaKernel, request: &AhaRequest) -> Result<(), AhaError> {
    if request != &plan(kernel, request.cursor.as_deref())? {
        return Err(AhaError::RequestScopeMismatch);
    }
    Ok(())
}

pub(super) fn validate_cursor(value: &str) -> Result<u32, AhaError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 7 || value.chars().any(char::is_control) {
        return Err(AhaError::InvalidCursor);
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|page| (1..=MAX_PAGE).contains(page))
        .ok_or(AhaError::InvalidCursor)
}
