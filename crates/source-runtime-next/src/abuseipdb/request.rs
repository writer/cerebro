use std::net::IpAddr;

use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    AbuseIpDbError, AbuseIpDbFamily, AbuseIpDbFilters, AbuseIpDbKernel, AbuseIpDbRequest, origin,
};

const MAX_PAGE: usize = 10_000;
const REPORTS_PAGE_SIZE: usize = 100;
const BLACKLIST_LIMIT: usize = 10_000;

pub(super) fn new_kernel(
    base_url: &str,
    tenant_id: &str,
    family: AbuseIpDbFamily,
    mut filters: AbuseIpDbFilters,
    observed_at: &str,
) -> Result<AbuseIpDbKernel, AbuseIpDbError> {
    let base_url = origin::validate(base_url)?;
    let tenant_id = origin::tenant(tenant_id).ok_or(AbuseIpDbError::InvalidTenantId)?;
    let observed = OffsetDateTime::parse(observed_at, &Rfc3339)
        .map_err(|_| AbuseIpDbError::InvalidConfiguration("observed_at"))?;
    let observed_at = observed
        .format(&Rfc3339)
        .map_err(|_| AbuseIpDbError::InvalidConfiguration("observed_at"))?;
    validate_filters(family, &mut filters)?;
    Ok(AbuseIpDbKernel {
        base_url,
        tenant_id,
        family,
        filters,
        observed_at,
    })
}

pub(super) fn plan(
    kernel: &AbuseIpDbKernel,
    cursor: Option<&str>,
) -> Result<AbuseIpDbRequest, AbuseIpDbError> {
    let mut url = kernel.base_url.clone();
    url.set_path(&format!(
        "{}{}",
        kernel.base_url.path().trim_end_matches('/'),
        kernel.family.path()
    ));
    if url.origin() != kernel.base_url.origin() {
        return Err(AbuseIpDbError::InvalidOrigin);
    }
    let (page, cursor, record_limit) = match kernel.family {
        AbuseIpDbFamily::Reports => {
            let page = cursor.map(validate_cursor).transpose()?.unwrap_or(1);
            let ip_address = kernel
                .filters
                .ip_address
                .as_deref()
                .ok_or(AbuseIpDbError::MissingConfiguration("ip_address"))?;
            let mut query = url.query_pairs_mut();
            query.append_pair("ipAddress", ip_address);
            if let Some(days) = kernel.filters.max_age_in_days {
                query.append_pair("maxAgeInDays", &days.to_string());
            }
            query.append_pair("perPage", &REPORTS_PAGE_SIZE.to_string());
            query.append_pair("page", &page.to_string());
            (page, cursor.map(str::to_owned), REPORTS_PAGE_SIZE)
        }
        AbuseIpDbFamily::IpAddresses => {
            if cursor.is_some() {
                return Err(AbuseIpDbError::InvalidCursor);
            }
            let mut query = url.query_pairs_mut();
            query.append_pair(
                "confidenceMinimum",
                &kernel.filters.confidence_minimum.unwrap_or(90).to_string(),
            );
            if let Some(version) = kernel.filters.ip_version {
                query.append_pair("ipVersion", &version.to_string());
            }
            query.append_pair("limit", &BLACKLIST_LIMIT.to_string());
            (1, None, BLACKLIST_LIMIT)
        }
    };
    Ok(AbuseIpDbRequest {
        url,
        family: kernel.family,
        page,
        cursor,
        record_limit,
    })
}

pub(super) fn validate_request(
    kernel: &AbuseIpDbKernel,
    request: &AbuseIpDbRequest,
) -> Result<(), AbuseIpDbError> {
    if request != &plan(kernel, request.cursor.as_deref())? {
        return Err(AbuseIpDbError::RequestScopeMismatch);
    }
    Ok(())
}

pub(super) fn validate_cursor(value: &str) -> Result<usize, AbuseIpDbError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 5 || value.chars().any(char::is_control) {
        return Err(AbuseIpDbError::InvalidCursor);
    }
    value
        .parse::<usize>()
        .ok()
        .filter(|page| (1..=MAX_PAGE).contains(page))
        .ok_or(AbuseIpDbError::InvalidCursor)
}

fn validate_filters(
    family: AbuseIpDbFamily,
    filters: &mut AbuseIpDbFilters,
) -> Result<(), AbuseIpDbError> {
    match family {
        AbuseIpDbFamily::Reports => {
            let ip = filters
                .ip_address
                .as_deref()
                .ok_or(AbuseIpDbError::MissingConfiguration("ip_address"))?
                .trim()
                .parse::<IpAddr>()
                .map_err(|_| AbuseIpDbError::InvalidConfiguration("ip_address"))?;
            filters.ip_address = Some(ip.to_string());
            if filters
                .max_age_in_days
                .is_some_and(|days| !(1..=365).contains(&days))
            {
                return Err(AbuseIpDbError::InvalidConfiguration("max_age_in_days"));
            }
            if filters.confidence_minimum.is_some() || filters.ip_version.is_some() {
                return Err(AbuseIpDbError::InvalidConfiguration("blacklist_filter"));
            }
        }
        AbuseIpDbFamily::IpAddresses => {
            if filters.ip_address.is_some() || filters.max_age_in_days.is_some() {
                return Err(AbuseIpDbError::InvalidConfiguration("reports_filter"));
            }
            if filters
                .confidence_minimum
                .is_some_and(|value| !(25..=100).contains(&value))
            {
                return Err(AbuseIpDbError::InvalidConfiguration("confidence_minimum"));
            }
            if filters
                .ip_version
                .is_some_and(|value| value != 4 && value != 6)
            {
                return Err(AbuseIpDbError::InvalidConfiguration("ip_version"));
            }
        }
    }
    Ok(())
}
