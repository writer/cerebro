use reqwest::Url;

use super::AbnormalSecurityError;

pub(super) fn validate(value: &str) -> Result<Url, AbnormalSecurityError> {
    let mut url = Url::parse(value.trim().trim_end_matches('/'))
        .map_err(|_| AbnormalSecurityError::InvalidOrigin)?;
    let host = url.host_str().unwrap_or_default();
    if url.scheme() != "https"
        || host.is_empty()
        || host.len() > 253
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/v1"
    {
        return Err(AbnormalSecurityError::InvalidOrigin);
    }
    url.set_path("/v1");
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
