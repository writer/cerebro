//! Credential-free Linode request planning and scope validation.

use reqwest::Url;

use super::{
    LinodeError,
    cursor::request_page,
    identity::require_event_identity,
    origin::{scope_base, validate_base_url},
};

const DEFAULT_BASE_URL: &str = "https://api.linode.com/v4";
const DEFAULT_PAGE_SIZE: usize = 100;
const MIN_PAGE_SIZE: usize = 25;
const MAX_PAGE_SIZE: usize = 500;
const ISSUE_PATH: &str = "/v4/managed/issues";

/// One credential-free Linode managed-issues request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinodeRequest {
    pub(super) url: Url,
    pub(super) page: u32,
}

impl LinodeRequest {
    /// Exact provider method.
    pub const fn method(&self) -> &'static str {
        "GET"
    }

    /// Return the exact provider URL. The caller must authorize it before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Authentication header applied only by the trusted host.
    pub const fn authorization_header(&self) -> &'static str {
        "Authorization"
    }

    /// Return the provider authorization scheme without credential material.
    pub const fn authorization_scheme(&self) -> &'static str {
        "Bearer"
    }

    /// Return the required response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }

    /// Requests never carry credential material across the kernel boundary.
    pub const fn contains_credentials(&self) -> bool {
        false
    }

    /// Redirects are outside the closed request contract.
    pub const fn allows_redirects(&self) -> bool {
        false
    }

    /// Maximum response bytes accepted by the decoder.
    pub const fn max_response_bytes(&self) -> usize {
        8 << 20
    }
}

/// Bounded request and response kernel for Linode managed issues.
#[derive(Clone, Debug)]
pub struct LinodeKernel {
    pub(super) base_url: Url,
    pub(super) scope_base: String,
    pub(super) tenant_id: String,
    pub(super) page_size: usize,
}

impl LinodeKernel {
    /// Build a kernel for one Linode v4 origin and authenticated tenant.
    ///
    /// Planned requests still require the trusted host's egress decision and
    /// an operation-scoped Bearer credential. This type never accepts or
    /// stores credential material.
    pub fn new(
        base_url: Option<&str>,
        tenant_id: &str,
        page_size: Option<usize>,
    ) -> Result<Self, LinodeError> {
        let base_url = validate_base_url(base_url.unwrap_or(DEFAULT_BASE_URL))?;
        let normalized_tenant_id = tenant_id.trim();
        if normalized_tenant_id.is_empty() {
            return Err(LinodeError::MissingTenantId);
        }
        require_event_identity(tenant_id)?;
        let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE);
        if !(MIN_PAGE_SIZE..=MAX_PAGE_SIZE).contains(&page_size) {
            return Err(LinodeError::InvalidPageSize);
        }
        Ok(Self {
            scope_base: scope_base(&base_url),
            base_url,
            tenant_id: normalized_tenant_id.to_owned(),
            page_size,
        })
    }

    /// Return whether this planning and decoding kernel accepts credentials.
    pub const fn requires_credentials() -> bool {
        false
    }

    /// Plan one bounded provider page without performing I/O.
    pub fn plan(&self, cursor: Option<&str>) -> Result<LinodeRequest, LinodeError> {
        let page = request_page(cursor)?;
        let mut url = self.endpoint()?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("page", &page.to_string());
            query.append_pair("page_size", &self.page_size.to_string());
        }
        Ok(LinodeRequest { url, page })
    }

    pub(super) fn validate_request(&self, request: &LinodeRequest) -> Result<(), LinodeError> {
        let expected = self.plan(Some(&request.page.to_string()))?;
        if request.url != expected.url {
            return Err(LinodeError::RequestScopeMismatch);
        }
        Ok(())
    }

    fn endpoint(&self) -> Result<Url, LinodeError> {
        let mut url = self.base_url.clone();
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| LinodeError::InvalidBaseUrl)?;
        segments.pop_if_empty().push("managed").push("issues");
        drop(segments);
        if url.path() != ISSUE_PATH {
            return Err(LinodeError::InvalidBaseUrl);
        }
        Ok(url)
    }
}
