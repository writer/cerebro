//! Credential-free Twilio request planning and scope validation.

use reqwest::Url;

use super::{
    TwilioError, TwilioFamily, TwilioFilters,
    cursor::bounded_cursor,
    origin::{origin_string, validate_origin},
};

const DEFAULT_BASE_URL: &str = "https://api.twilio.com";
const DEFAULT_PAGE_SIZE: usize = 100;
const MAX_PAGE_SIZE: usize = 500;

/// One credential-free Twilio API request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TwilioRequest {
    pub(super) url: Url,
    pub(super) family: TwilioFamily,
}

impl TwilioRequest {
    /// Return the exact provider URL. The caller must authorize it before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return the provider authorization scheme without credential material.
    pub const fn authorization_scheme(&self) -> &'static str {
        "Basic"
    }

    /// Return the required response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }
}

/// Bounded request and response kernel for Twilio inventory.
#[derive(Clone, Debug)]
pub struct TwilioKernel {
    pub(super) base_url: Url,
    pub(super) base_origin: String,
    pub(super) tenant_id: String,
    pub(super) family: TwilioFamily,
    pub(super) account_sid: Option<String>,
    pub(super) page_size: usize,
}

impl TwilioKernel {
    /// Build a kernel for one Twilio origin, tenant, and family.
    ///
    /// Planned requests still require the shared live-egress decision and an
    /// operation-scoped Basic credential. This type never accepts or stores a
    /// credential value.
    pub fn new(
        base_url: Option<&str>,
        tenant_id: &str,
        family: TwilioFamily,
        filters: TwilioFilters,
        page_size: Option<usize>,
    ) -> Result<Self, TwilioError> {
        let base_url = validate_origin(base_url.unwrap_or(DEFAULT_BASE_URL))?;
        let tenant_id = required(tenant_id, TwilioError::MissingTenantId)?;
        let account_sid = filters
            .account_sid
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        if family == TwilioFamily::Keys && account_sid.is_none() {
            return Err(TwilioError::MissingAccountSid);
        }
        let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE);
        if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
            return Err(TwilioError::InvalidPageSize);
        }
        Ok(Self {
            base_origin: origin_string(&base_url),
            base_url,
            tenant_id,
            family,
            account_sid,
            page_size,
        })
    }

    /// Return whether this planning and decoding kernel accepts credentials.
    pub const fn requires_credentials() -> bool {
        false
    }

    /// Plan one bounded provider page without performing I/O.
    pub fn plan(&self, cursor: Option<&str>) -> Result<TwilioRequest, TwilioError> {
        let cursor = bounded_cursor(cursor)?;
        let mut url = self.endpoint()?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("limit", &self.page_size.to_string());
            if let Some(cursor) = cursor.as_deref() {
                query.append_pair("cursor", cursor);
            }
        }
        Ok(TwilioRequest {
            url,
            family: self.family,
        })
    }

    pub(super) fn endpoint(&self) -> Result<Url, TwilioError> {
        let mut url = self.base_url.clone();
        let segments: Vec<&str> = match self.family {
            TwilioFamily::Accounts => vec!["2010-04-01", "Accounts.json"],
            TwilioFamily::Keys => vec![
                "2010-04-01",
                "Accounts",
                self.account_sid
                    .as_deref()
                    .ok_or(TwilioError::MissingAccountSid)?,
                "Keys.json",
            ],
            TwilioFamily::AuditEvents => vec!["v1", "Events"],
        };
        url.path_segments_mut()
            .map_err(|_| TwilioError::InvalidBaseUrl)?
            .extend(segments);
        Ok(url)
    }

    pub(super) fn validate_request(&self, request: &TwilioRequest) -> Result<(), TwilioError> {
        let endpoint = self.endpoint()?;
        if request.family != self.family
            || request.url.origin() != self.base_url.origin()
            || request.url.path() != endpoint.path()
            || request.url.fragment().is_some()
        {
            return Err(TwilioError::RequestScopeMismatch);
        }
        let mut limit = None;
        let mut cursor_seen = false;
        for (name, value) in request.url.query_pairs() {
            match name.as_ref() {
                "limit" if limit.is_none() => limit = Some(value.into_owned()),
                "cursor" if !cursor_seen => cursor_seen = true,
                _ => return Err(TwilioError::RequestScopeMismatch),
            }
        }
        let expected = self.page_size.to_string();
        if limit.as_deref() != Some(expected.as_str()) {
            return Err(TwilioError::RequestScopeMismatch);
        }
        Ok(())
    }
}

fn required(value: &str, error: TwilioError) -> Result<String, TwilioError> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned()).ok_or(error)
}
