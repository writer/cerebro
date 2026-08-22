//! Credential-free Okta request planning and scope validation.

use super::{
    OktaError, OktaFamily, OktaFilters, OktaKernel, OktaRequest,
    cursor::{assignment_cursor, bounded_cursor},
    normalize::require_identity_component,
    origin::{origin_string, validate_origin},
};

const DEFAULT_PAGE_SIZE: usize = 10;
const MAX_PAGE_SIZE: usize = 200;

impl OktaKernel {
    /// Build a kernel for one tenant, Okta origin, and closed family.
    pub fn new(
        base_url: &str,
        tenant_id: &str,
        family: OktaFamily,
        filters: OktaFilters,
        page_size: Option<usize>,
    ) -> Result<Self, OktaError> {
        let base_url = validate_origin(base_url)?;
        let tenant_id = tenant_id.trim();
        if tenant_id.is_empty() {
            return Err(OktaError::MissingTenantId);
        }
        require_identity_component(tenant_id)?;
        let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE);
        if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
            return Err(OktaError::InvalidPageSize);
        }
        validate_filters(family, &filters)?;
        Ok(Self {
            base_origin: origin_string(&base_url),
            base_url,
            tenant_id: tenant_id.to_owned(),
            family,
            filters,
            page_size,
        })
    }

    /// This kernel never accepts or stores credential material.
    pub const fn requires_credentials() -> bool {
        false
    }

    /// Plan one bounded, origin-restricted provider page.
    pub fn plan(&self, cursor: Option<&str>) -> Result<OktaRequest, OktaError> {
        let (path, assignment_phase, cursor) = self.request_path(cursor)?;
        let mut url = self.base_url.clone();
        url.set_path(&path);
        if !self.family.singleton() {
            let mut query = url.query_pairs_mut();
            query.append_pair("limit", &self.page_size.to_string());
            if let Some(cursor) = cursor.as_deref() {
                query.append_pair("after", cursor);
            }
            for (name, value) in self.query_filters() {
                query.append_pair(name, &value);
            }
        }
        Ok(OktaRequest {
            url,
            family: self.family,
            assignment_phase,
        })
    }

    pub(super) fn validate_request(&self, request: &OktaRequest) -> Result<(), OktaError> {
        if request.family != self.family
            || request.url.origin() != self.base_url.origin()
            || request.url.fragment().is_some()
        {
            return Err(OktaError::RequestScopeMismatch);
        }
        let expected = self.request_path_from_phase(request.assignment_phase.as_deref())?;
        if request.url.path() != expected {
            return Err(OktaError::RequestScopeMismatch);
        }
        Ok(())
    }

    fn request_path(
        &self,
        cursor: Option<&str>,
    ) -> Result<(String, Option<String>, Option<String>), OktaError> {
        if self.family == OktaFamily::AppAssignment {
            let (phase, cursor) = assignment_cursor(cursor)?;
            return Ok((
                self.request_path_from_phase(Some(phase))?,
                Some(phase.to_owned()),
                cursor,
            ));
        }
        let cursor = bounded_cursor(cursor)?;
        Ok((self.request_path_from_phase(None)?, None, cursor))
    }

    fn request_path_from_phase(&self, phase: Option<&str>) -> Result<String, OktaError> {
        match self.family {
            OktaFamily::GroupMembership => Ok(scoped_path(
                "/api/v1/groups/",
                required(&self.filters.group_id, "group_id")?,
                "/users",
            )),
            OktaFamily::AppAssignment => Ok(scoped_path(
                "/api/v1/apps/",
                required(&self.filters.app_id, "app_id")?,
                if phase == Some("groups") {
                    "/groups"
                } else {
                    "/users"
                },
            )),
            OktaFamily::AdminRole => Ok(scoped_path(
                "/api/v1/users/",
                required(&self.filters.user_id, "user_id")?,
                "/roles",
            )),
            OktaFamily::PolicyRule => Ok(scoped_path(
                "/api/v1/policies/",
                required(&self.filters.policy_id, "policy_id")?,
                "/rules",
            )),
            family => Ok(family.endpoint().to_owned()),
        }
    }

    fn query_filters(&self) -> Vec<(&'static str, String)> {
        let mut values: Vec<(&'static str, String)> = Vec::new();
        let mut push = |name: &'static str, value: &Option<String>| {
            if let Some(value) = value
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                values.push((name, value.to_owned()));
            }
        };
        match self.family {
            OktaFamily::Audit => {
                push("filter", &self.filters.filter);
                push("q", &self.filters.q);
                push("since", &self.filters.since);
                push("until", &self.filters.until);
                values.push((
                    "sortOrder",
                    normalized_audit_sort(self.filters.sort_order.as_deref())
                        .expect("filters validated before request planning")
                        .to_owned(),
                ));
            }
            OktaFamily::User => {
                push("filter", &self.filters.filter);
                push("q", &self.filters.q);
                push("search", &self.filters.search);
                push("sortBy", &self.filters.sort_by);
                values.push((
                    "sortOrder",
                    normalized_user_sort(self.filters.sort_order.as_deref())
                        .expect("filters validated before request planning")
                        .to_owned(),
                ));
            }
            OktaFamily::Group => {
                push("q", &self.filters.q);
                push("search", &self.filters.search);
                push("sortBy", &self.filters.sort_by);
                push("sortOrder", &self.filters.sort_order);
            }
            OktaFamily::Application => {
                push("filter", &self.filters.filter);
                push("q", &self.filters.q);
            }
            OktaFamily::AuthorizationServer
            | OktaFamily::Brand
            | OktaFamily::IdentityProvider
            | OktaFamily::LogStream
            | OktaFamily::NetworkZone
            | OktaFamily::TrustedOrigin => {
                push("filter", &self.filters.filter);
                push("q", &self.filters.q);
            }
            _ => {}
        }
        values
    }
}

fn validate_filters(family: OktaFamily, filters: &OktaFilters) -> Result<(), OktaError> {
    let required = match family {
        OktaFamily::GroupMembership => Some((filters.group_id.as_ref(), "group_id")),
        OktaFamily::AppAssignment => Some((filters.app_id.as_ref(), "app_id")),
        OktaFamily::AdminRole => Some((filters.user_id.as_ref(), "user_id")),
        OktaFamily::PolicyRule => Some((filters.policy_id.as_ref(), "policy_id")),
        _ => None,
    };
    if let Some((value, name)) = required {
        let value = value.as_deref().ok_or(OktaError::MissingScope(name))?;
        require_identity_component(value).map_err(|_| OktaError::MissingScope(name))?;
    }
    if family == OktaFamily::Audit {
        if present(&filters.search) || present(&filters.sort_by) {
            return Err(OktaError::InvalidConfiguration("audit selectors"));
        }
        normalized_audit_sort(filters.sort_order.as_deref())?;
    } else if present(&filters.since) || present(&filters.until) {
        return Err(OktaError::InvalidConfiguration("since/until"));
    }
    if family == OktaFamily::User {
        normalized_user_sort(filters.sort_order.as_deref())?;
    }
    Ok(())
}

fn normalized_audit_sort(value: Option<&str>) -> Result<&'static str, OktaError> {
    match value
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "asc" | "ascending" => Ok("ASCENDING"),
        "desc" | "descending" => Ok("DESCENDING"),
        _ => Err(OktaError::InvalidConfiguration("audit sort_order")),
    }
}

fn normalized_user_sort(value: Option<&str>) -> Result<&'static str, OktaError> {
    match value
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "asc" | "ascending" => Ok("asc"),
        "desc" | "descending" => Ok("desc"),
        _ => Err(OktaError::InvalidConfiguration("user sort_order")),
    }
}

fn present(value: &Option<String>) -> bool {
    value
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
}

fn required<'a>(value: &'a Option<String>, name: &'static str) -> Result<&'a str, OktaError> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(OktaError::MissingScope(name))
}

fn scoped_path(prefix: &str, id: &str, suffix: &str) -> String {
    format!("{prefix}{}{suffix}", id.trim())
}
