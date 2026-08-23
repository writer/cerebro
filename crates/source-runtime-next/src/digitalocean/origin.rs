use reqwest::Url;

use super::DigitalOceanError;

pub(super) const DEFAULT_BASE_URL: &str = "https://api.digitalocean.com/v2";

pub(super) fn validate(value: Option<&str>) -> Result<Url, DigitalOceanError> {
    let value = value
        .unwrap_or(DEFAULT_BASE_URL)
        .trim()
        .trim_end_matches('/');
    let mut url = Url::parse(value).map_err(|_| DigitalOceanError::InvalidBaseUrl)?;
    if url.scheme() != "https"
        || url.host_str() != Some("api.digitalocean.com")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/" | "/v2")
    {
        return Err(DigitalOceanError::InvalidBaseUrl);
    }
    url.set_path("/v2");
    Ok(url)
}

pub(super) fn tenant(value: &str) -> Option<String> {
    safe_segment(value, 128)
}

pub(super) fn provider_id(value: &str) -> Option<String> {
    safe_segment(value, 512)
}

fn safe_segment(value: &str, limit: usize) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()
        && value.len() <= limit
        && !value.chars().any(char::is_control)
        && !value.contains([':', '/', '\\']))
    .then(|| value.to_owned())
}
