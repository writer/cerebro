//! Secure GCP IAM API-origin validation.

use std::{net::IpAddr, str::FromStr};

use reqwest::Url;

use super::GcpIamError;

pub(super) fn validate_gcp_origin(raw: &str) -> Result<Url, GcpIamError> {
    let mut url = Url::parse(raw.trim()).map_err(|_| GcpIamError::InvalidBaseUrl)?;
    let host = url.host_str().ok_or(GcpIamError::InvalidBaseUrl)?;
    let loopback =
        host == "localhost" || IpAddr::from_str(host).is_ok_and(|address| address.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(GcpIamError::InvalidBaseUrl);
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(GcpIamError::InvalidBaseUrl);
    }
    if IpAddr::from_str(host).is_ok_and(|address| unsafe_gcp_ip_literal(address, loopback)) {
        return Err(GcpIamError::InvalidBaseUrl);
    }
    if url.port().is_some_and(|port| port != 443) && !loopback {
        return Err(GcpIamError::InvalidBaseUrl);
    }
    url.set_path("/");
    Ok(url)
}

fn unsafe_gcp_ip_literal(address: IpAddr, loopback: bool) -> bool {
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
