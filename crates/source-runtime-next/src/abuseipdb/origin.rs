use reqwest::Url;

use super::AbuseIpDbError;

const HOST: &str = "api.abuseipdb.com";
const BASE_PATH: &str = "/api/v2";

pub(super) fn validate(value: &str) -> Result<Url, AbuseIpDbError> {
    let mut url = Url::parse(value.trim().trim_end_matches('/'))
        .map_err(|_| AbuseIpDbError::InvalidOrigin)?;
    let host = url.host_str().unwrap_or_default().trim_end_matches('.');
    if url.scheme() != "https"
        || !host.eq_ignore_ascii_case(HOST)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path().trim_end_matches('/') != BASE_PATH
    {
        return Err(AbuseIpDbError::InvalidOrigin);
    }
    url.set_path(BASE_PATH);
    Ok(url)
}

pub(super) fn tenant(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()
        && value.len() <= 128
        && !value.chars().any(char::is_control)
        && !value.contains(['/', '\\', ':']))
    .then(|| value.to_owned())
}
