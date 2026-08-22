use reqwest::Url;

use super::AddigyError;

pub(super) fn validate(value: &str) -> Result<Url, AddigyError> {
    let mut url =
        Url::parse(value.trim().trim_end_matches('/')).map_err(|_| AddigyError::InvalidOrigin)?;
    if url.scheme() != "https"
        || url.host_str() != Some("api.addigy.com")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/api/v2"
    {
        return Err(AddigyError::InvalidOrigin);
    }
    url.set_path("/api/v2");
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

pub(super) fn organization(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    (!value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
    .then(|| value.to_owned())
}
