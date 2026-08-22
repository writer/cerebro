use reqwest::Url;

use super::JumpCloudError;

const DIRECTORY_HOST: &str = "console.jumpcloud.com";
const INSIGHTS_HOSTS: [&str; 3] = [
    "api.jumpcloud.com",
    "api.eu.jumpcloud.com",
    "api.in.jumpcloud.com",
];

pub(super) fn directory(value: &str) -> Result<Url, JumpCloudError> {
    validate(value, &[DIRECTORY_HOST], "/api")
}

pub(super) fn insights(value: &str) -> Result<Url, JumpCloudError> {
    validate(value, &INSIGHTS_HOSTS, "/insights/directory/v1")
}

fn validate(value: &str, hosts: &[&str], expected_path: &str) -> Result<Url, JumpCloudError> {
    let mut url = Url::parse(value.trim().trim_end_matches('/'))
        .map_err(|_| JumpCloudError::InvalidOrigin)?;
    let host = url.host_str().unwrap_or_default().trim_end_matches('.');
    if url.scheme() != "https"
        || !hosts
            .iter()
            .any(|allowed| host.eq_ignore_ascii_case(allowed))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path().trim_end_matches('/') != expected_path
    {
        return Err(JumpCloudError::InvalidOrigin);
    }
    url.set_path(expected_path);
    Ok(url)
}

pub(super) fn bounded(value: &str, maximum: usize) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()
        && value.len() <= maximum
        && !value.chars().any(char::is_control)
        && !value.contains(['/', '\\', ':']))
    .then(|| value.to_owned())
}
