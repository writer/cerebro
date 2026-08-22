use std::net::IpAddr;

use reqwest::Url;

use super::GitHubError;

const MAX_NAME_BYTES: usize = 100;
const MAX_TENANT_BYTES: usize = 128;

pub(super) fn validate_base_url(value: &str) -> Result<Url, GitHubError> {
    let mut url = Url::parse(value.trim()).map_err(|_| GitHubError::InvalidBaseUrl)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(GitHubError::InvalidBaseUrl);
    }
    let host = url
        .host_str()
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || !host.contains('.')
        || host.parse::<IpAddr>().is_ok_and(unsafe_address)
    {
        return Err(GitHubError::UnsafeOrigin);
    }
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(if path.is_empty() { "/" } else { &path });
    Ok(url)
}

pub(super) fn validate_tenant_id(value: &str) -> Result<String, GitHubError> {
    bounded(value, MAX_TENANT_BYTES, GitHubError::InvalidTenantId)
}

pub(super) fn name(value: &str, field: &'static str) -> Result<String, GitHubError> {
    let value = bounded(
        value,
        MAX_NAME_BYTES,
        GitHubError::InvalidConfiguration(field),
    )?;
    if value.contains(['/', '?', '#', '\\']) || value == "." || value == ".." {
        return Err(GitHubError::InvalidConfiguration(field));
    }
    Ok(value)
}

fn bounded(value: &str, maximum: usize, error: GitHubError) -> Result<String, GitHubError> {
    let value = value.trim();
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(error);
    }
    Ok(value.to_owned())
}

fn unsafe_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => {
            let bytes = value.octets();
            value.is_private()
                || value.is_loopback()
                || value.is_link_local()
                || value.is_multicast()
                || value.is_unspecified()
                || (bytes[0] == 100 && (64..=127).contains(&bytes[1]))
                || (bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 2)
                || (bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100)
                || (bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113)
        }
        IpAddr::V6(value) => {
            let segments = value.segments();
            value.is_loopback()
                || value.is_multicast()
                || value.is_unspecified()
                || value.is_unique_local()
                || value.is_unicast_link_local()
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}
