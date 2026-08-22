//! PagerDuty API-origin validation.

use reqwest::Url;

use super::PagerDutyError;

pub(super) const DEFAULT_BASE_URL: &str = "https://api.pagerduty.com";

pub(super) fn validate_origin(raw: Option<&str>) -> Result<Url, PagerDutyError> {
    let mut url = Url::parse(raw.unwrap_or(DEFAULT_BASE_URL).trim())
        .map_err(|_| PagerDutyError::InvalidBaseUrl)?;
    let host = url.host_str().ok_or(PagerDutyError::InvalidBaseUrl)?;
    if url.scheme() != "https"
        || !matches!(host, "api.pagerduty.com" | "api.eu.pagerduty.com")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some_and(|port| port != 443)
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(PagerDutyError::InvalidBaseUrl);
    }
    url.set_path("/");
    Ok(url)
}

pub(super) fn origin_string(url: &Url) -> String {
    url.origin().ascii_serialization()
}
