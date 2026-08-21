//! Bounded credential-free GCP IAM request planning and page dispatch.

use reqwest::Url;
use serde_json::Value;
use time::OffsetDateTime;

use super::{
    GcpIamError, GcpIamFamily, GcpIamFilters, GcpIamPage, GcpIamRecord, GcpIamRequest,
    cursor::bounded_gcp_cursor,
    normalize::{nonblank_gcp, required_gcp_value},
    origin::validate_gcp_origin,
    service_account, service_account_key,
};

const DEFAULT_PAGE_SIZE: usize = 10;
const MAX_PAGE_SIZE: usize = 200;
pub(super) const MAX_RESPONSE_BYTES: usize = 8 << 20;
pub(super) const MAX_RECORDS_PER_PAGE: usize = 200;

/// Credential-free request and response kernel for GCP IAM inventory.
#[derive(Clone, Debug)]
pub struct GcpIamKernel {
    base_url: Url,
    tenant_id: String,
    project_id: String,
    family: GcpIamFamily,
    service_account_email: Option<String>,
    page_size: usize,
}

impl GcpIamKernel {
    /// Build a kernel for one IAM API origin and project.
    ///
    /// Planned requests still require the shared live-egress decision and an
    /// operation-scoped bearer credential. This type never accepts or stores a
    /// credential value.
    pub fn new(
        base_url: &str,
        tenant_id: &str,
        project_id: &str,
        family: GcpIamFamily,
        filters: GcpIamFilters,
        page_size: Option<usize>,
    ) -> Result<Self, GcpIamError> {
        let base_url = validate_gcp_origin(base_url)?;
        let tenant_id = required_gcp_value(tenant_id, GcpIamError::MissingTenantId)?;
        let project_id = required_gcp_value(project_id, GcpIamError::MissingProjectId)?;
        let service_account_email = nonblank_gcp(filters.service_account_email);
        if family == GcpIamFamily::ServiceAccountKey && service_account_email.is_none() {
            return Err(GcpIamError::MissingServiceAccountEmail);
        }
        let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE);
        if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
            return Err(GcpIamError::InvalidPageSize);
        }
        Ok(Self {
            base_url,
            tenant_id,
            project_id,
            family,
            service_account_email,
            page_size,
        })
    }

    /// Return whether this planning and decoding kernel accepts credential material.
    pub const fn requires_credentials() -> bool {
        false
    }

    /// Plan one provider page without performing I/O or accepting credentials.
    pub fn plan(&self, cursor: Option<&str>) -> Result<GcpIamRequest, GcpIamError> {
        let cursor = bounded_gcp_cursor(cursor)?;
        let mut url = self.endpoint()?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("pageSize", &self.page_size.to_string());
            if let Some(cursor) = cursor.as_deref() {
                query.append_pair("pageToken", cursor);
            }
        }
        Ok(GcpIamRequest {
            url,
            family: self.family,
        })
    }

    /// Decode one IAM response for a request produced by this kernel.
    pub fn decode(
        &self,
        request: &GcpIamRequest,
        body: &[u8],
        observed_at: OffsetDateTime,
    ) -> Result<GcpIamPage, GcpIamError> {
        self.validate_request(request)?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(GcpIamError::ResponseTooLarge);
        }
        let payload: Value =
            serde_json::from_slice(body).map_err(|_| GcpIamError::InvalidResponse)?;
        let object = payload.as_object().ok_or(GcpIamError::InvalidResponse)?;
        let empty_records = Vec::new();
        let raw_records = match object.get(self.family.response_field()) {
            Some(Value::Array(records)) => records,
            None | Some(Value::Null) => &empty_records,
            Some(_) => return Err(GcpIamError::InvalidResponse),
        };
        if raw_records.len() > MAX_RECORDS_PER_PAGE {
            return Err(GcpIamError::TooManyRecords);
        }
        let records = raw_records
            .iter()
            .map(|record| self.normalize_record(record.clone(), observed_at))
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = match object.get("nextPageToken") {
            Some(Value::String(value)) => bounded_gcp_cursor(Some(value))?,
            None | Some(Value::Null) => None,
            Some(_) => return Err(GcpIamError::InvalidResponse),
        };
        Ok(GcpIamPage {
            records,
            next_cursor,
        })
    }

    fn endpoint(&self) -> Result<Url, GcpIamError> {
        let mut url = self.base_url.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| GcpIamError::InvalidBaseUrl)?;
            segments.extend([
                "v1",
                "projects",
                self.project_id.as_str(),
                "serviceAccounts",
            ]);
            if self.family == GcpIamFamily::ServiceAccountKey {
                segments.extend([
                    self.service_account_email
                        .as_deref()
                        .ok_or(GcpIamError::MissingServiceAccountEmail)?,
                    "keys",
                ]);
            }
        }
        Ok(url)
    }

    fn validate_request(&self, request: &GcpIamRequest) -> Result<(), GcpIamError> {
        let endpoint = self.endpoint()?;
        if request.family != self.family
            || request.url.origin() != self.base_url.origin()
            || request.url.path() != endpoint.path()
            || request.url.fragment().is_some()
        {
            return Err(GcpIamError::RequestScopeMismatch);
        }
        let mut page_size = None;
        let mut page_token_seen = false;
        for (name, value) in request.url.query_pairs() {
            match name.as_ref() {
                "pageSize" if page_size.is_none() => page_size = Some(value.into_owned()),
                "pageToken" if !page_token_seen => page_token_seen = true,
                _ => return Err(GcpIamError::RequestScopeMismatch),
            }
        }
        let expected_page_size = self.page_size.to_string();
        if page_size.as_deref() != Some(expected_page_size.as_str()) {
            return Err(GcpIamError::RequestScopeMismatch);
        }
        Ok(())
    }

    fn normalize_record(
        &self,
        payload: Value,
        observed_at: OffsetDateTime,
    ) -> Result<GcpIamRecord, GcpIamError> {
        if !payload.is_object() {
            return Err(GcpIamError::InvalidResponse);
        }
        match self.family {
            GcpIamFamily::ServiceAccount => {
                service_account::normalize(payload, &self.tenant_id, &self.project_id, observed_at)
            }
            GcpIamFamily::ServiceAccountKey => service_account_key::normalize(
                payload,
                &self.tenant_id,
                &self.project_id,
                self.service_account_email
                    .as_deref()
                    .ok_or(GcpIamError::MissingServiceAccountEmail)?,
                observed_at,
            ),
        }
    }
}
