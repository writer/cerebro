use std::net::IpAddr;

use reqwest::Url;

use super::error::DopplerError;

pub(super) const DEFAULT_BASE_URL: &str = "https://api.doppler.com";

pub(super) fn validate(value: Option<&str>) -> Result<Url, DopplerError> {
    let value = value
        .unwrap_or(DEFAULT_BASE_URL)
        .trim()
        .trim_end_matches('/');
    let mut url = Url::parse(value).map_err(|_| DopplerError::InvalidBaseUrl)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(DopplerError::InvalidBaseUrl);
    }
    let host = url
        .host_str()
        .ok_or(DopplerError::InvalidBaseUrl)?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || !host.contains('.')
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| !is_public_address(address))
    {
        return Err(DopplerError::InvalidBaseUrl);
    }
    url.set_path("/");
    Ok(url)
}

pub(super) fn tenant(value: &str) -> Result<String, DopplerError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte))
    {
        return Err(DopplerError::InvalidTenantId);
    }
    Ok(value.to_owned())
}

pub(super) fn provider_id(value: &str) -> Result<String, DopplerError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(DopplerError::MissingStableIdentity);
    }
    Ok(value.to_owned())
}

fn is_public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            !(address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_unspecified()
                || octets[0] == 0
                || octets[0] >= 224
                || (octets[0] == 100 && (64..=127).contains(&octets[1])))
        }
        IpAddr::V6(address) => {
            !(address.is_loopback()
                || address.is_multicast()
                || address.is_unspecified()
                || address.is_unique_local()
                || address.is_unicast_link_local())
        }
    }
}
