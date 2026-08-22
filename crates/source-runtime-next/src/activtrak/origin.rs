use reqwest::Url;

use super::ActivTrakError;

pub(super) fn validate(value: &str) -> Result<Url, ActivTrakError> {
    let mut url = Url::parse(value.trim().trim_end_matches('/'))
        .map_err(|_| ActivTrakError::InvalidOrigin)?;
    if url.scheme() != "https"
        || url.host_str() != Some("api.activtrak.com")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(ActivTrakError::InvalidOrigin);
    }
    url.set_path("");
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
