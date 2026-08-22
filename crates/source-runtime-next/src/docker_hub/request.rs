use super::{
    DockerHubError, DockerHubFamily, DockerHubKernel, DockerHubRequest,
    origin::{bounded_scope, bounded_tenant, validate_origin},
};

pub(super) const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

impl DockerHubRequest {
    /// HTTP method.
    pub const fn method(&self) -> &'static str {
        "GET"
    }

    /// Exact origin-restricted provider URL.
    pub fn url(&self) -> &reqwest::Url {
        &self.url
    }

    /// Family owning this request.
    pub const fn family(&self) -> DockerHubFamily {
        self.family
    }

    /// Optional header populated by the trusted host for private repositories.
    pub const fn authorization_header(&self) -> &'static str {
        "Authorization"
    }

    /// Scheme applied outside this kernel.
    pub const fn authorization_scheme(&self) -> &'static str {
        "Bearer"
    }

    /// Public repository reads do not require a credential lease.
    pub const fn credential_reference_required(&self) -> bool {
        false
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

    /// Provider permission required for private repository reads.
    pub const fn required_scope(&self) -> &'static str {
        "repository read access"
    }
}

impl DockerHubKernel {
    /// Construct a closed credential-free repository kernel.
    pub fn new(
        base_url: &str,
        tenant_id: &str,
        namespace: &str,
        repository: &str,
    ) -> Result<Self, DockerHubError> {
        let base_url = validate_origin(base_url)?;
        let tenant_id = bounded_tenant(tenant_id).ok_or(DockerHubError::InvalidTenantId)?;
        let namespace = bounded_scope(namespace, 255)
            .ok_or(DockerHubError::MissingConfiguration("namespace"))?;
        let repository = bounded_scope(repository, 255)
            .ok_or(DockerHubError::MissingConfiguration("repository"))?;
        Ok(Self {
            base_url,
            tenant_id,
            namespace,
            repository,
            family: DockerHubFamily::Repositories,
        })
    }

    /// Kernel protocol never accepts credential material.
    pub const fn requires_credentials() -> bool {
        false
    }

    /// Plan the singleton repository detail request.
    pub fn plan(&self, cursor: Option<&str>) -> Result<DockerHubRequest, DockerHubError> {
        if cursor.is_some_and(|value| !value.trim().is_empty()) {
            return Err(DockerHubError::InvalidCursor);
        }
        let mut url = self.base_url.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| DockerHubError::InvalidBaseUrl)?;
            segments.pop_if_empty();
            segments.extend([
                "v2",
                "namespaces",
                &self.namespace,
                "repositories",
                &self.repository,
            ]);
        }
        Ok(DockerHubRequest {
            url,
            family: self.family,
        })
    }

    pub(super) fn validate_request(
        &self,
        request: &DockerHubRequest,
    ) -> Result<(), DockerHubError> {
        if request != &self.plan(None)? {
            return Err(DockerHubError::RequestScopeMismatch);
        }
        Ok(())
    }
}
