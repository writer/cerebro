//! Credential-free PagerDuty request planning.

use reqwest::Url;

use super::{
    PagerDutyError, PagerDutyFamily, PagerDutyFilters, PagerDutyPlan,
    cursor::{CursorState, parse_cursor},
    normalize::{require_safe_identity, require_tenant},
    origin::{origin_string, validate_origin},
};

pub(super) const MAX_RESPONSE_BYTES: usize = 8 << 20;
pub(super) const MAX_RECORDS_PER_PAGE: usize = 100;
const DEFAULT_PAGE_SIZE: usize = 100;

/// One planned PagerDuty request without an authorization header or credential value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PagerDutyRequest {
    pub(super) url: Url,
    pub(super) family: PagerDutyFamily,
    pub(super) service_id: Option<String>,
    pub(super) cursor: CursorState,
}

impl PagerDutyRequest {
    /// Exact origin-restricted provider URL. A trusted host applies credentials before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Provider authentication scheme metadata without credential material.
    pub const fn authorization_scheme(&self) -> &'static str {
        "Token token="
    }

    /// Required response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }
}

/// Bounded request/response kernel for PagerDuty responder topology.
#[derive(Clone, Debug)]
pub struct PagerDutyKernel {
    pub(super) base_url: Url,
    pub(super) origin: String,
    pub(super) tenant_id: String,
    pub(super) family: PagerDutyFamily,
    pub(super) service_ids: Vec<String>,
    pub(super) page_size: usize,
}

impl PagerDutyKernel {
    /// Construct a kernel from public configuration only.
    pub fn new(
        base_url: Option<&str>,
        tenant_id: &str,
        family: PagerDutyFamily,
        filters: PagerDutyFilters,
        page_size: Option<usize>,
    ) -> Result<Self, PagerDutyError> {
        let base_url = validate_origin(base_url)?;
        let tenant_id = require_tenant(tenant_id)?;
        let mut service_ids = Vec::new();
        for service_id in filters.service_ids {
            let service_id = service_id.trim().to_owned();
            if service_id.is_empty() || service_ids.contains(&service_id) {
                continue;
            }
            require_safe_identity(&service_id).map_err(|_| PagerDutyError::InvalidServiceId)?;
            service_ids.push(service_id);
        }
        if family == PagerDutyFamily::Integration && service_ids.is_empty() {
            return Err(PagerDutyError::MissingServiceId);
        }
        if family != PagerDutyFamily::Integration && !service_ids.is_empty() {
            return Err(PagerDutyError::InvalidFamily);
        }
        let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE);
        if !(1..=MAX_RECORDS_PER_PAGE).contains(&page_size) {
            return Err(PagerDutyError::InvalidPageSize);
        }
        Ok(Self {
            origin: origin_string(&base_url),
            base_url,
            tenant_id,
            family,
            service_ids,
            page_size,
        })
    }

    /// This kernel cannot receive provider credential values.
    pub const fn requires_credentials() -> bool {
        false
    }

    /// Compile this family into its exact closed runtime definition.
    pub fn definition(&self) -> PagerDutyPlan {
        PagerDutyPlan {
            source_id: "pagerduty",
            family_id: self.family.as_str(),
            method: "GET",
            origin: self.origin.clone(),
            path_template: self.family.path_template(),
            record_selector: format!("$.{}[*]", self.family.response_key()),
            id_field: "id",
            event_kind: self.family.event_kind(),
            schema_ref: self.family.schema_ref(),
            required_attributes: vec![
                "external_id",
                "family",
                "source_provider",
                "source_product",
                self.family.identity_attribute(),
            ],
            required_payload_fields: vec!["id"],
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_records_per_page: MAX_RECORDS_PER_PAGE,
        }
    }

    /// Plan one bounded origin-restricted page without performing I/O.
    pub fn plan(&self, cursor: Option<&str>) -> Result<PagerDutyRequest, PagerDutyError> {
        let state = parse_cursor(self.family, self.service_ids.len(), cursor)?;
        let service_id = if self.family == PagerDutyFamily::Integration {
            Some(
                self.service_ids
                    .get(state.service_index)
                    .cloned()
                    .ok_or(PagerDutyError::InvalidCursor)?,
            )
        } else {
            None
        };
        let mut url = self.base_url.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| PagerDutyError::InvalidBaseUrl)?;
            match self.family {
                PagerDutyFamily::User => segments.push("users"),
                PagerDutyFamily::Team => segments.push("teams"),
                PagerDutyFamily::Service => segments.push("services"),
                PagerDutyFamily::Schedule => segments.push("schedules"),
                PagerDutyFamily::EscalationPolicy => segments.push("escalation_policies"),
                PagerDutyFamily::Integration => {
                    segments.push("services");
                    segments.push(
                        service_id
                            .as_deref()
                            .ok_or(PagerDutyError::MissingServiceId)?,
                    );
                    segments.push("integrations")
                }
                PagerDutyFamily::Vendor => segments.push("vendors"),
            };
        }
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("limit", &self.page_size.to_string());
            if let Some(offset) = state.offset {
                query.append_pair("offset", &offset.to_string());
            }
        }
        let request = PagerDutyRequest {
            url,
            family: self.family,
            service_id,
            cursor: state,
        };
        self.validate_request(&request)?;
        Ok(request)
    }

    pub(super) fn validate_request(
        &self,
        request: &PagerDutyRequest,
    ) -> Result<(), PagerDutyError> {
        if request.family != self.family
            || request.url.origin() != self.base_url.origin()
            || request.url.fragment().is_some()
            || request.url.path() != self.expected_path(request.service_id.as_deref())?
        {
            return Err(PagerDutyError::RequestScopeMismatch);
        }
        let mut limit = None;
        let mut offset = None;
        for (key, value) in request.url.query_pairs() {
            match key.as_ref() {
                "limit" if limit.is_none() => limit = Some(value.into_owned()),
                "offset" if offset.is_none() => offset = Some(value.into_owned()),
                _ => return Err(PagerDutyError::RequestScopeMismatch),
            }
        }
        let expected_limit = self.page_size.to_string();
        let expected_offset = request.cursor.offset.map(|value| value.to_string());
        if limit.as_deref() != Some(expected_limit.as_str())
            || offset.as_deref() != expected_offset.as_deref()
        {
            return Err(PagerDutyError::RequestScopeMismatch);
        }
        Ok(())
    }

    fn expected_path(&self, service_id: Option<&str>) -> Result<String, PagerDutyError> {
        Ok(match self.family {
            PagerDutyFamily::Integration => format!(
                "/services/{}/integrations",
                service_id.ok_or(PagerDutyError::MissingServiceId)?
            ),
            _ => self.family.path_template().to_owned(),
        })
    }
}
