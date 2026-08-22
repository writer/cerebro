use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    TailscaleError, TailscaleFamily, TailscaleKernel, TailscaleRequest,
    origin::{bounded, validate_origin},
};

pub(super) const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CURSOR_BYTES: usize = 4_096;
const MAX_PAGE_SIZE: usize = 500;

impl TailscaleRequest {
    /// HTTP method.
    pub const fn method(&self) -> &'static str {
        "GET"
    }

    /// Exact origin-restricted URL.
    pub fn url(&self) -> &reqwest::Url {
        &self.url
    }

    /// Family owning the request.
    pub const fn family(&self) -> TailscaleFamily {
        self.family
    }

    /// Optional continuation included in the request.
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }

    /// Header populated by the trusted host.
    pub const fn authorization_header(&self) -> &'static str {
        "Authorization"
    }

    /// Provider authentication scheme applied outside this kernel.
    pub const fn authorization_scheme(&self) -> &'static str {
        "Bearer"
    }

    /// Portable request plans never contain credential bytes or references.
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

    /// Provider permission required for this read-only operation.
    pub const fn required_scope(&self) -> &'static str {
        "Tailscale tailnet read access"
    }
}

impl TailscaleKernel {
    /// Construct a closed credential-free provider kernel.
    pub fn new(
        base_url: &str,
        tenant_id: &str,
        tailnet: &str,
        family: TailscaleFamily,
        page_size: Option<usize>,
        observed_at: &str,
    ) -> Result<Self, TailscaleError> {
        let base_url = validate_origin(base_url)?;
        let tenant_id = bounded(tenant_id, 128).ok_or(TailscaleError::InvalidTenantId)?;
        let tailnet =
            bounded(tailnet, 256).ok_or(TailscaleError::MissingConfiguration("tailnet"))?;
        if tailnet.contains(['/', '?', '#']) {
            return Err(TailscaleError::InvalidConfiguration("tailnet"));
        }
        let page_size = page_size.unwrap_or(100);
        if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
            return Err(TailscaleError::InvalidConfiguration("page_size"));
        }
        OffsetDateTime::parse(observed_at, &Rfc3339)
            .map_err(|_| TailscaleError::InvalidConfiguration("observed_at"))?;
        Ok(Self {
            base_url,
            tenant_id,
            tailnet,
            family,
            page_size,
            observed_at: observed_at.to_owned(),
        })
    }

    /// Kernel protocol never accepts credential material.
    pub const fn requires_credentials() -> bool {
        false
    }

    /// Plan one bounded, origin-restricted request.
    pub fn plan(&self, cursor: Option<&str>) -> Result<TailscaleRequest, TailscaleError> {
        let cursor = cursor.map(validate_cursor).transpose()?;
        let mut url = self.base_url.clone();
        let path = format!(
            "{}{}",
            self.base_url.path().trim_end_matches('/'),
            self.family.path()
        );
        url.set_path(&path);
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("limit", &self.page_size.to_string());
            query.append_pair("per_page", &self.page_size.to_string());
            if let Some(cursor) = &cursor {
                query.append_pair("cursor", cursor);
            }
        }
        if url.origin() != self.base_url.origin() {
            return Err(TailscaleError::InvalidOrigin);
        }
        Ok(TailscaleRequest {
            family: self.family,
            url,
            cursor,
            page_size: self.page_size,
        })
    }

    pub(super) fn validate_request(
        &self,
        request: &TailscaleRequest,
    ) -> Result<(), TailscaleError> {
        if request != &self.plan(request.cursor.as_deref())? {
            return Err(TailscaleError::RequestScopeMismatch);
        }
        Ok(())
    }
}

pub(super) fn validate_cursor(value: &str) -> Result<String, TailscaleError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_CURSOR_BYTES
        || value.chars().any(char::is_control)
        || value.starts_with("http://")
        || value.starts_with("https://")
    {
        return Err(TailscaleError::InvalidCursor);
    }
    Ok(value.to_owned())
}
