//! Secure Okta origin validation.

use std::{net::IpAddr, str::FromStr};

use reqwest::Url;

use super::OktaError;

pub(super) fn validate_origin(raw: &str) -> Result<Url, OktaError> {
    let mut url = Url::parse(raw.trim()).map_err(|_| OktaError::InvalidBaseUrl)?;
    let host = url.host_str().ok_or(OktaError::InvalidBaseUrl)?;
    if url.scheme() != "https" {
        return Err(OktaError::InvalidBaseUrl);
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(OktaError::InvalidBaseUrl);
    }
    if host == "localhost" || IpAddr::from_str(host).is_ok_and(unsafe_ip_literal) {
        return Err(OktaError::InvalidBaseUrl);
    }
    if url.port().is_some_and(|port| port != 443) {
        return Err(OktaError::InvalidBaseUrl);
    }
    url.set_path("/");
    Ok(url)
}

pub(super) fn origin_string(url: &Url) -> String {
    url.origin().unicode_serialization()
}

fn unsafe_ip_literal(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_loopback()
                || address.is_private()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_documentation()
                || address.is_unspecified()
                || address.is_multicast()
        }
        IpAddr::V6(address) => {
            address.is_loopback()
                || address.is_unique_local()
                || address.is_unicast_link_local()
                || address.is_unspecified()
                || address.is_multicast()
        }
    }
}
