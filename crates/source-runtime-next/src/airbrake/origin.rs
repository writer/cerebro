use reqwest::Url;

use super::AirbrakeError;

pub(super) fn validate(value: &str) -> Result<Url, AirbrakeError> {
    let mut url =
        Url::parse(value.trim().trim_end_matches('/')).map_err(|_| AirbrakeError::InvalidOrigin)?;
    if url.scheme() != "https"
        || url.host_str() != Some("api.airbrake.io")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(AirbrakeError::InvalidOrigin);
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

pub(super) fn project(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    (!value.is_empty()
        && value.len() <= 20
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u64>().ok().is_some_and(|number| number > 0))
    .then(|| value.to_owned())
}
