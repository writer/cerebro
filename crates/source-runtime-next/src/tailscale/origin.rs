use std::net::IpAddr;

use super::TailscaleError;

pub(super) fn validate_origin(value: &str) -> Result<reqwest::Url, TailscaleError> {
    let mut url = reqwest::Url::parse(value.trim()).map_err(|_| TailscaleError::InvalidBaseUrl)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
        || url.port_or_known_default() != Some(443)
    {
        return Err(TailscaleError::InvalidBaseUrl);
    }
    let host = url.host_str().ok_or(TailscaleError::InvalidBaseUrl)?;
    if host.eq_ignore_ascii_case("localhost")
        || host.ends_with(".localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| !is_public(ip))
    {
        return Err(TailscaleError::InvalidBaseUrl);
    }
    let path = url.path().trim_end_matches('/');
    if path.is_empty() {
        url.set_path("");
    } else if path != "/api/v2" {
        return Err(TailscaleError::InvalidBaseUrl);
    }
    Ok(url)
}

pub(super) fn bounded(value: &str, max: usize) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()
        && value.len() <= max
        && !value.chars().any(char::is_control)
        && !value.contains(['\0', '\r', '\n']))
    .then(|| value.to_owned())
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified())
        }
        IpAddr::V6(ip) => {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local())
        }
    }
}
