use std::net::IpAddr;

use reqwest::Url;

use super::AsanaError;

pub(super) fn validate_origin(value: &str) -> Result<Url, AsanaError> {
    let mut url = Url::parse(value.trim()).map_err(|_| AsanaError::InvalidBaseUrl)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(AsanaError::InvalidBaseUrl);
    }
    let host = url.host_str().unwrap_or_default().trim_end_matches('.');
    if host.eq_ignore_ascii_case("localhost")
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || !host.contains('.')
        || host.parse::<IpAddr>().is_ok_and(unsafe_ip)
    {
        return Err(AsanaError::UnsafeOrigin);
    }
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(&path);
    Ok(url)
}

pub(super) fn bounded(value: &str, max: usize) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()
        && value.len() <= max
        && !value.chars().any(char::is_control)
        && !value.contains(['/', '\\', ':']))
    .then(|| value.to_owned())
}

fn unsafe_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
        }
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unspecified() || ip.is_multicast(),
    }
}
