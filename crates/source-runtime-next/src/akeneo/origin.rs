use reqwest::Url;

use super::AkeneoError;

pub(super) fn validate(value: &str) -> Result<Url, AkeneoError> {
    let mut url =
        Url::parse(value.trim().trim_end_matches('/')).map_err(|_| AkeneoError::InvalidOrigin)?;
    let host = url.host_str().ok_or(AkeneoError::InvalidOrigin)?;
    let account = host
        .strip_suffix(".akeneo.com")
        .ok_or(AkeneoError::InvalidOrigin)?;
    if url.scheme() != "https"
        || account.is_empty()
        || account.contains('.')
        || !account
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || account.starts_with('-')
        || account.ends_with('-')
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(AkeneoError::InvalidOrigin);
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
