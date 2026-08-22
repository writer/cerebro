//! Secure Linode API-origin and v4 base-path validation.

use std::{net::IpAddr, str::FromStr};

use reqwest::Url;

use super::LinodeError;

pub(super) fn validate_base_url(raw: &str) -> Result<Url, LinodeError> {
    let mut url = Url::parse(raw.trim()).map_err(|_| LinodeError::InvalidBaseUrl)?;
    let host = url.host_str().ok_or(LinodeError::InvalidBaseUrl)?;
    let loopback =
        host == "localhost" || IpAddr::from_str(host).is_ok_and(|address| address.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(LinodeError::InvalidBaseUrl);
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "/v4" | "/v4/")
    {
        return Err(LinodeError::InvalidBaseUrl);
    }
    if IpAddr::from_str(host).is_ok_and(|address| unsafe_ip_literal(address, loopback)) {
        return Err(LinodeError::InvalidBaseUrl);
    }
    if url.port().is_some_and(|port| port != 443) && !loopback {
        return Err(LinodeError::InvalidBaseUrl);
    }
    url.set_path("/v4/");
    Ok(url)
}

pub(super) fn scope_base(url: &Url) -> String {
    format!("{}/v4", url.origin().unicode_serialization())
}

fn unsafe_ip_literal(address: IpAddr, loopback: bool) -> bool {
    if loopback {
        return false;
    }
    match address {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_documentation()
                || address.is_unspecified()
                || address.is_multicast()
        }
        IpAddr::V6(address) => {
            address.is_unique_local()
                || address.is_unicast_link_local()
                || address.is_unspecified()
                || address.is_multicast()
        }
    }
}
