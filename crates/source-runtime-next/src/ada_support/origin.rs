use reqwest::Url;

use super::AdaSupportError;

pub(super) fn validate(value: &str) -> Result<Url, AdaSupportError> {
    let mut url = Url::parse(value.trim().trim_end_matches('/'))
        .map_err(|_| AdaSupportError::InvalidOrigin)?;
    let host = url.host_str().unwrap_or_default().trim_end_matches('.');
    if url.scheme() != "https"
        || host.is_empty()
        || host.len() > 253
        || !host.ends_with(".ada.support")
        || host.trim_end_matches(".ada.support").is_empty()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/api"
    {
        return Err(AdaSupportError::InvalidOrigin);
    }
    url.set_path("/api");
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
