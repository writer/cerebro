use std::net::IpAddr;

use reqwest::Url;

use super::{DeepSeekError, DeepSeekFamily, DeepSeekKernel, DeepSeekRequest};

pub(super) const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

impl DeepSeekRequest {
    /// HTTP method.
    pub const fn method(&self) -> &'static str {
        "GET"
    }

    /// Exact origin-restricted provider URL.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Family owning this request.
    pub const fn family(&self) -> DeepSeekFamily {
        self.family
    }

    /// Header populated by the trusted host.
    pub const fn authorization_header(&self) -> &'static str {
        "Authorization"
    }

    /// Scheme applied outside this kernel.
    pub const fn authorization_scheme(&self) -> &'static str {
        "Bearer"
    }

    /// Required provider response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }

    /// Portable requests contain no credential bytes or references.
    pub const fn contains_credentials(&self) -> bool {
        false
    }

    /// Redirects are disabled by the trusted host.
    pub const fn allows_redirects(&self) -> bool {
        false
    }

    /// Host response byte limit.
    pub const fn max_response_bytes(&self) -> usize {
        MAX_RESPONSE_BYTES
    }

    /// Provider access required by both families.
    pub const fn required_scope(&self) -> &'static str {
        "DeepSeek account read access"
    }
}

impl DeepSeekKernel {
    /// Construct a closed credential-free kernel.
    pub fn new(
        base_url: &str,
        tenant_id: &str,
        family: DeepSeekFamily,
    ) -> Result<Self, DeepSeekError> {
        let base_url = validate_origin(base_url)?;
        let tenant_id = bounded(tenant_id, 128).ok_or(DeepSeekError::InvalidTenantId)?;
        Ok(Self {
            base_url,
            tenant_id,
            family,
        })
    }

    /// Kernel protocol never accepts credential material.
    pub const fn requires_credentials() -> bool {
        false
    }

    /// Plan one bounded terminal provider request.
    pub fn plan(&self, cursor: Option<&str>) -> Result<DeepSeekRequest, DeepSeekError> {
        if cursor.is_some() {
            return Err(DeepSeekError::InvalidCursor);
        }
        let mut url = self.base_url.clone();
        url.set_path(self.family.path());
        Ok(DeepSeekRequest {
            url,
            family: self.family,
        })
    }

    pub(super) fn validate_request(&self, request: &DeepSeekRequest) -> Result<(), DeepSeekError> {
        if request != &self.plan(None)? {
            return Err(DeepSeekError::RequestScopeMismatch);
        }
        Ok(())
    }
}

fn validate_origin(value: &str) -> Result<Url, DeepSeekError> {
    let url = Url::parse(value).map_err(|_| DeepSeekError::InvalidBaseUrl)?;
    if url.scheme() != "https"
        || url.host_str() != Some("api.deepseek.com")
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url
            .host_str()
            .and_then(|host| host.parse::<IpAddr>().ok())
            .is_some()
    {
        return Err(DeepSeekError::UnsafeOrigin);
    }
    if !matches!(url.path(), "" | "/") {
        return Err(DeepSeekError::InvalidBaseUrl);
    }
    Ok(url)
}

pub(super) fn bounded(value: &str, max: usize) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && value.len() <= max && !value.chars().any(char::is_control))
        .then(|| value.to_owned())
}
