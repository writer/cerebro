use std::net::IpAddr;

use reqwest::Url;

use super::{
    AnthropicError, AnthropicKernel, AnthropicRequest, AnthropicScope, family::PaginationKind,
};

pub(super) const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub(super) const MAX_RECORDS: usize = 1_000;
const DEFAULT_PAGE_SIZE: usize = 100;
const MAX_CURSOR_BYTES: usize = 4_096;
const MAX_TENANT_BYTES: usize = 256;

impl AnthropicRequest {
    /// Return the provider method for this read-only operation.
    pub const fn method(&self) -> &'static str {
        "GET"
    }

    /// Return the exact provider URL for trusted-host authorization and I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return the required credential capability without credential material.
    pub const fn authentication(&self) -> super::AnthropicAuthentication {
        self.authentication
    }

    /// Return the static provider API-version header.
    pub const fn api_version_header(&self) -> (&'static str, &'static str) {
        ("anthropic-version", "2023-06-01")
    }

    /// The portable request never contains resolved credential bytes.
    pub const fn contains_credentials(&self) -> bool {
        false
    }

    /// Redirects are denied so authentication cannot leave the compiled origin.
    pub const fn allows_redirects(&self) -> bool {
        false
    }

    /// Return the response byte bound the host must enforce before decode.
    pub const fn max_response_bytes(&self) -> usize {
        MAX_RESPONSE_BYTES
    }
}

impl AnthropicKernel {
    /// Compile one family into a closed, credential-free runtime definition.
    pub fn new(
        base_url: &str,
        tenant_id: &str,
        family: super::AnthropicFamily,
        scope: AnthropicScope,
        page_size: Option<usize>,
    ) -> Result<Self, AnthropicError> {
        let base_url = validate_base_url(base_url)?;
        let tenant_id = validate_tenant(tenant_id)?;
        let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE);
        if !(1..=MAX_RECORDS).contains(&page_size) {
            return Err(AnthropicError::InvalidPageSize);
        }
        validate_scope(family, &scope)?;
        Ok(Self {
            base_url,
            tenant_id,
            family,
            scope,
            page_size,
        })
    }

    /// Plan one origin-restricted provider request from a prior checkpoint.
    pub fn plan(&self, cursor: Option<&str>) -> Result<AnthropicRequest, AnthropicError> {
        let cursor = validate_cursor(self.family.pagination(), cursor)?;
        let mut path = self.family.path().to_owned();
        for name in self.family.path_parameters() {
            let value = self
                .scope
                .path_parameters
                .get(*name)
                .ok_or(AnthropicError::MissingPathParameter)?;
            path = path.replace(&format!("{{{name}}}"), &encode_path_segment(value));
        }
        let mut url = self.base_url.clone();
        let full_path = format!("{}{}", self.base_url.path().trim_end_matches('/'), path);
        url.set_path(&full_path);
        url.set_query(None);
        {
            let mut query = url.query_pairs_mut();
            for (provider_name, scope_name) in self.family.query_parameters() {
                if let Some(value) = self.scope.query_parameters.get(*scope_name) {
                    if provider_name.ends_with("[]") {
                        for part in value
                            .split(',')
                            .map(str::trim)
                            .filter(|part| !part.is_empty())
                        {
                            query.append_pair(provider_name, part);
                        }
                    } else {
                        query.append_pair(provider_name, value);
                    }
                }
            }
            match self.family.pagination() {
                PaginationKind::None => {}
                PaginationKind::AfterId => {
                    query.append_pair("limit", &self.page_size.to_string());
                    if let Some(cursor) = cursor.as_deref() {
                        query.append_pair("after_id", cursor);
                    }
                }
                PaginationKind::Page => {
                    query.append_pair("limit", &self.page_size.to_string());
                    if let Some(cursor) = cursor.as_deref() {
                        query.append_pair("page", cursor);
                    }
                }
            }
        }
        Ok(AnthropicRequest {
            url,
            operation_path: path,
            family: self.family,
            cursor,
            authentication: self.family.authentication(),
        })
    }
}

fn validate_base_url(value: &str) -> Result<Url, AnthropicError> {
    let mut url = Url::parse(value.trim()).map_err(|_| AnthropicError::InvalidBaseUrl)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(AnthropicError::InvalidBaseUrl);
    }
    let host = url.host_str().ok_or(AnthropicError::InvalidBaseUrl)?;
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || !host.contains('.')
        || host.parse::<IpAddr>().is_ok_and(unsafe_address)
    {
        return Err(AnthropicError::InvalidBaseUrl);
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

fn validate_tenant(value: &str) -> Result<String, AnthropicError> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_TENANT_BYTES || value.chars().any(char::is_control) {
        return Err(AnthropicError::MissingTenantId);
    }
    Ok(value.to_owned())
}

fn validate_scope(
    family: super::AnthropicFamily,
    scope: &AnthropicScope,
) -> Result<(), AnthropicError> {
    for required in family.path_parameters() {
        let value = scope
            .path_parameters
            .get(*required)
            .ok_or(AnthropicError::MissingPathParameter)?;
        validate_parameter(value)?;
    }
    if scope.path_parameters.keys().any(|key| {
        !family
            .path_parameters()
            .iter()
            .any(|declared| declared == key)
    }) || scope.query_parameters.keys().any(|key| {
        !family
            .query_parameters()
            .iter()
            .any(|(_, declared)| declared == key)
    }) {
        return Err(AnthropicError::InvalidParameter);
    }
    for value in scope.query_parameters.values() {
        validate_parameter(value)?;
    }
    Ok(())
}

fn validate_parameter(value: &str) -> Result<(), AnthropicError> {
    if value.is_empty()
        || value.len() > 4_096
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(AnthropicError::InvalidParameter);
    }
    Ok(())
}

fn encode_path_segment(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                char::from(*byte).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

fn validate_cursor(
    pagination: PaginationKind,
    value: Option<&str>,
) -> Result<Option<String>, AnthropicError> {
    let Some(value) = value else { return Ok(None) };
    let value = value.trim();
    if pagination == PaginationKind::None
        || value.is_empty()
        || value.len() > MAX_CURSOR_BYTES
        || value.chars().any(char::is_control)
        || value.contains("://")
    {
        return Err(AnthropicError::InvalidCursor);
    }
    Ok(Some(value.to_owned()))
}
