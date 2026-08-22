use std::net::IpAddr;

use reqwest::Url;

use super::CloudflareError;

pub(super) fn validate_origin(value: &str) -> Result<Url, CloudflareError> {
    let mut url = Url::parse(value.trim()).map_err(|_| CloudflareError::InvalidBaseUrl)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(CloudflareError::InvalidBaseUrl);
    }
    let host = url
        .host_str()
        .ok_or(CloudflareError::InvalidBaseUrl)?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || !host.contains('.')
        || host.parse::<IpAddr>().ok().is_some_and(unsafe_address)
    {
        return Err(CloudflareError::InvalidBaseUrl);
    }
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(if path.is_empty() { "/" } else { &path });
    Ok(url)
}

fn unsafe_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_unspecified()
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            address.is_loopback()
                || address.is_multicast()
                || address.is_unspecified()
                || address.is_unique_local()
                || address.is_unicast_link_local()
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}
