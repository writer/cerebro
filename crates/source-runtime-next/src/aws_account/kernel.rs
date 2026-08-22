use std::{net::IpAddr, str::FromStr};

use reqwest::{StatusCode, Url};

use super::{
    model::{
        AwsAccountContactError, AwsAccountContactOutcome, AwsAccountContactRequest,
        AwsAccountContactRequestKind,
    },
    response::{
        PRIMARY_CONTACT_STRING_MEMBERS, SECURITY_CONTACT_STRING_MEMBERS, build_page,
        decode_provider_response, optional_object, primary_contact_configured,
        validate_string_members,
    },
};

/// Provider-specific AWS account-contact request and response kernel.
#[derive(Clone, Debug)]
pub struct AwsAccountContactKernel {
    base_url: Url,
    account_id: String,
    signing_region: String,
}

impl AwsAccountContactKernel {
    /// Build a kernel for one AWS Account service origin and account.
    ///
    /// Planned requests contain no credential material. The trusted host must
    /// apply egress policy, an operation-scoped credential lease, and Signature
    /// Version 4 authorization before provider access.
    pub fn new(
        base_url: &str,
        account_id: &str,
        signing_region: &str,
    ) -> Result<Self, AwsAccountContactError> {
        let base_url = validate_origin(base_url)?;
        let account_id = account_id.trim();
        if account_id.len() != 12 || !account_id.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(AwsAccountContactError::InvalidAccountId);
        }
        let signing_region = signing_region.trim();
        if signing_region.is_empty()
            || signing_region.len() > 63
            || !signing_region
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(AwsAccountContactError::InvalidSigningRegion);
        }
        Ok(Self {
            base_url,
            account_id: account_id.to_owned(),
            signing_region: signing_region.to_owned(),
        })
    }

    /// Plan the first request for a new collection.
    pub fn plan(&self) -> Result<AwsAccountContactRequest, AwsAccountContactError> {
        self.plan_with_progress(None, None)
    }

    /// Plan a collection from separately supplied continuation and checkpoint state.
    ///
    /// This full-snapshot family never accepts a continuation. A restart may
    /// present the last committed account-ID checkpoint and will re-read the
    /// same singleton identity. The trusted runtime host remains responsible
    /// for committing the proposed checkpoint only after append and projection.
    pub fn plan_with_progress(
        &self,
        cursor: Option<&str>,
        checkpoint_cursor: Option<&str>,
    ) -> Result<AwsAccountContactRequest, AwsAccountContactError> {
        if cursor.is_some() {
            return Err(AwsAccountContactError::CursorNotSupported);
        }
        if checkpoint_cursor.is_some_and(|checkpoint| checkpoint != self.account_id.as_str()) {
            return Err(AwsAccountContactError::InvalidCheckpoint);
        }
        self.request(AwsAccountContactRequestKind::PrimaryContact, None)
    }

    /// Decode one bounded response for a request produced by this kernel.
    ///
    /// `provider_error_code` is the safe Smithy error identifier from provider
    /// response metadata, such as `x-amzn-errortype`. It must never contain a
    /// provider error message, response body, or credential value.
    pub fn decode(
        &self,
        request: &AwsAccountContactRequest,
        status: StatusCode,
        provider_error_code: Option<&str>,
        body: &[u8],
    ) -> Result<AwsAccountContactOutcome, AwsAccountContactError> {
        self.validate_request(request)?;
        let response = decode_provider_response(status, provider_error_code, body)?;
        match request.kind {
            AwsAccountContactRequestKind::PrimaryContact => {
                if request.primary_contact_configured.is_some() {
                    return Err(AwsAccountContactError::RequestStageMismatch);
                }
                let contact = optional_object(response.as_ref(), "ContactInformation")?;
                validate_string_members(contact, PRIMARY_CONTACT_STRING_MEMBERS)?;
                let configured = contact.is_some_and(primary_contact_configured);
                Ok(AwsAccountContactOutcome::Request(self.request(
                    AwsAccountContactRequestKind::SecurityAlternateContact,
                    Some(configured),
                )?))
            }
            AwsAccountContactRequestKind::SecurityAlternateContact => {
                let primary_contact_configured = request
                    .primary_contact_configured
                    .ok_or(AwsAccountContactError::RequestStageMismatch)?;
                let contact = optional_object(response.as_ref(), "AlternateContact")?;
                validate_string_members(contact, SECURITY_CONTACT_STRING_MEMBERS)?;
                Ok(AwsAccountContactOutcome::Page(build_page(
                    &self.account_id,
                    primary_contact_configured,
                    contact,
                )))
            }
        }
    }

    fn request(
        &self,
        kind: AwsAccountContactRequestKind,
        primary_contact_configured: Option<bool>,
    ) -> Result<AwsAccountContactRequest, AwsAccountContactError> {
        let url = self
            .base_url
            .join(kind.path().trim_start_matches('/'))
            .map_err(|_| AwsAccountContactError::InvalidBaseUrl)?;
        Ok(AwsAccountContactRequest {
            url,
            account_id: self.account_id.clone(),
            signing_region: self.signing_region.clone(),
            kind,
            primary_contact_configured,
        })
    }

    fn validate_request(
        &self,
        request: &AwsAccountContactRequest,
    ) -> Result<(), AwsAccountContactError> {
        if request.url.origin() != self.base_url.origin()
            || request.url.path() != request.kind.path()
            || request.url.query().is_some()
            || request.account_id != self.account_id
            || request.signing_region != self.signing_region
        {
            return Err(AwsAccountContactError::RequestScopeMismatch);
        }
        Ok(())
    }
}

fn validate_origin(raw: &str) -> Result<Url, AwsAccountContactError> {
    let mut url = Url::parse(raw.trim()).map_err(|_| AwsAccountContactError::InvalidBaseUrl)?;
    let host = url
        .host_str()
        .ok_or(AwsAccountContactError::InvalidBaseUrl)?;
    let loopback =
        host == "localhost" || IpAddr::from_str(host).is_ok_and(|address| address.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(AwsAccountContactError::InvalidBaseUrl);
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(AwsAccountContactError::InvalidBaseUrl);
    }
    if IpAddr::from_str(host).is_ok_and(|address| unsafe_ip_literal(address, loopback)) {
        return Err(AwsAccountContactError::InvalidBaseUrl);
    }
    if url.port().is_some_and(|port| port != 443) && !loopback {
        return Err(AwsAccountContactError::InvalidBaseUrl);
    }
    url.set_path("/");
    Ok(url)
}

fn unsafe_ip_literal(address: IpAddr, loopback: bool) -> bool {
    if loopback {
        return false;
    }
    match address {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_documentation()
                || address.is_unspecified()
                || address.is_multicast()
        }
        IpAddr::V6(address) => {
            address.is_unique_local()
                || address.is_unicast_link_local()
                || address.is_unspecified()
                || address.is_multicast()
        }
    }
}
