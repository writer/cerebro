use super::{
    AsanaError, AsanaFamily, AsanaKernel, AsanaRequest,
    origin::{bounded, validate_origin},
};

pub(super) const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CURSOR_BYTES: usize = 2_048;

impl AsanaRequest {
    /// HTTP method.
    pub const fn method(&self) -> &'static str {
        "GET"
    }

    /// Exact origin-restricted provider URL.
    pub fn url(&self) -> &reqwest::Url {
        &self.url
    }

    /// Family owning this request.
    pub const fn family(&self) -> AsanaFamily {
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

    /// Provider permission required by the family.
    pub const fn required_scope(&self) -> &'static str {
        match self.family {
            AsanaFamily::AuditEvents => "workspace audit log access",
            AsanaFamily::Users | AsanaFamily::Projects => "workspace read access",
        }
    }
}

impl AsanaKernel {
    /// Construct a closed credential-free kernel.
    pub fn new(
        base_url: &str,
        tenant_id: &str,
        workspace_gid: &str,
        family: AsanaFamily,
        page_size: Option<usize>,
    ) -> Result<Self, AsanaError> {
        let base_url = validate_origin(base_url)?;
        let tenant_id = bounded(tenant_id, 128).ok_or(AsanaError::InvalidTenantId)?;
        let workspace_gid =
            bounded(workspace_gid, 128).ok_or(AsanaError::MissingConfiguration("workspace_gid"))?;
        let page_size = page_size.unwrap_or(100);
        if !(1..=100).contains(&page_size) {
            return Err(AsanaError::InvalidConfiguration("page_size"));
        }
        Ok(Self {
            base_url,
            tenant_id,
            workspace_gid,
            family,
            page_size,
        })
    }

    /// Kernel protocol never accepts credential material.
    pub const fn requires_credentials() -> bool {
        false
    }

    /// Plan one bounded provider page from an optional durable offset.
    pub fn plan(&self, cursor: Option<&str>) -> Result<AsanaRequest, AsanaError> {
        let cursor = cursor.map(validate_cursor).transpose()?;
        let suffix = match self.family {
            AsanaFamily::Users => "/users".to_owned(),
            AsanaFamily::Projects => "/projects".to_owned(),
            AsanaFamily::AuditEvents => {
                format!("/workspaces/{}/audit_log_events", self.workspace_gid)
            }
        };
        let mut url = self.base_url.clone();
        url.set_path(&format!(
            "{}{}",
            self.base_url.path().trim_end_matches('/'),
            suffix
        ));
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("limit", &self.page_size.to_string());
            if matches!(self.family, AsanaFamily::Users | AsanaFamily::Projects) {
                query.append_pair("workspace", &self.workspace_gid);
            }
            if let Some(cursor) = &cursor {
                query.append_pair("offset", cursor);
            }
        }
        Ok(AsanaRequest {
            url,
            family: self.family,
            cursor,
        })
    }

    pub(super) fn validate_request(&self, request: &AsanaRequest) -> Result<(), AsanaError> {
        if request != &self.plan(request.cursor.as_deref())? {
            return Err(AsanaError::RequestScopeMismatch);
        }
        Ok(())
    }
}

pub(super) fn validate_cursor(value: &str) -> Result<String, AsanaError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_CURSOR_BYTES
        || value.chars().any(char::is_control)
        || value.contains(['&', '=', '#', '?'])
    {
        return Err(AsanaError::InvalidCursor);
    }
    Ok(value.to_owned())
}
