use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{AkeneoError, AkeneoFamily, AkeneoKernel, AkeneoRequest, AkeneoScope, origin};

const COLLECTION_LIMIT: usize = 100;

pub(super) fn new_kernel(
    base_url: &str,
    tenant_id: &str,
    family: AkeneoFamily,
    scope: AkeneoScope,
    observed_at: &str,
) -> Result<AkeneoKernel, AkeneoError> {
    let base_url = origin::validate(base_url)?;
    let tenant_id = origin::tenant(tenant_id).ok_or(AkeneoError::InvalidTenantId)?;
    let scope = scope.validate()?;
    family.path(&scope)?;
    let observed = OffsetDateTime::parse(observed_at, &Rfc3339)
        .map_err(|_| AkeneoError::InvalidConfiguration("observed_at"))?;
    let observed_at = observed
        .format(&Rfc3339)
        .map_err(|_| AkeneoError::InvalidConfiguration("observed_at"))?;
    Ok(AkeneoKernel {
        base_url,
        tenant_id,
        family,
        scope,
        observed_at,
    })
}

pub(super) fn plan(
    kernel: &AkeneoKernel,
    cursor: Option<&str>,
) -> Result<AkeneoRequest, AkeneoError> {
    if cursor.is_some() {
        return Err(AkeneoError::InvalidCursor);
    }
    let path = kernel.family.path(&kernel.scope)?;
    let mut url = kernel.base_url.clone();
    url.set_path(&path);
    if url.origin() != kernel.base_url.origin() || url.query().is_some() {
        return Err(AkeneoError::InvalidOrigin);
    }
    Ok(AkeneoRequest {
        url,
        family: kernel.family,
        record_limit: if kernel.family.collection() {
            COLLECTION_LIMIT
        } else {
            1
        },
    })
}

pub(super) fn validate_request(
    kernel: &AkeneoKernel,
    request: &AkeneoRequest,
) -> Result<(), AkeneoError> {
    if request != &plan(kernel, None)? {
        return Err(AkeneoError::RequestScopeMismatch);
    }
    Ok(())
}
