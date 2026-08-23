use reqwest::Url;

use super::AhaError;

const HOST_SUFFIX: &str = ".aha.io";

pub(super) fn validate(value: &str) -> Result<Url, AhaError> {
    let mut url =
        Url::parse(value.trim().trim_end_matches('/')).map_err(|_| AhaError::InvalidOrigin)?;
    let host = url.host_str().unwrap_or_default().trim_end_matches('.');
    let account = host.strip_suffix(HOST_SUFFIX).unwrap_or_default();
    if url.scheme() != "https"
        || account.is_empty()
        || account.len() > 63
        || account.contains('.')
        || account.starts_with('-')
        || account.ends_with('-')
        || account
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-')
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(AhaError::InvalidOrigin);
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

pub(super) fn product(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    (!value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
    .then(|| value.to_owned())
}
