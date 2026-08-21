//! AWS account-contact request and response runtime kernel.
//!
//! The kernel plans the two credential-free AWS Account service requests used
//! to assess primary and security-contact posture. It deliberately emits only
//! presence and completeness booleans; provider contact values never cross
//! the source-runtime boundary.

use std::{collections::BTreeMap, error::Error, fmt, net::IpAddr, str::FromStr};

use reqwest::{StatusCode, Url};
use serde::Deserialize;
use serde_json::{Value, json};

const FAMILY: &str = "account_contact";
const PROVIDER_KIND: &str = "aws.account_contact";
const SCHEMA_REF: &str = "aws/account_contact/v1";
const SIGNING_SERVICE: &str = "account";
const SECURITY_CONTACT_TYPE: &str = "SECURITY";

/// Purpose of one AWS account-contact provider request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AwsAccountContactRequestKind {
    /// Read primary account contact information.
    PrimaryContact,
    /// Read the security alternate contact.
    SecurityAlternateContact,
}

impl AwsAccountContactRequestKind {
    const fn path(self) -> &'static str {
        match self {
            Self::PrimaryContact => "/getContactInformation",
            Self::SecurityAlternateContact => "/getAlternateContact",
        }
    }

    const fn body(self) -> &'static [u8] {
        match self {
            Self::PrimaryContact => b"{}",
            Self::SecurityAlternateContact => br#"{"AlternateContactType":"SECURITY"}"#,
        }
    }
}

/// One credential-free AWS Account service request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsAccountContactRequest {
    url: Url,
    account_id: String,
    signing_region: String,
    kind: AwsAccountContactRequestKind,
    primary_contact_configured: Option<bool>,
}

impl AwsAccountContactRequest {
    /// Return the exact provider URL. The caller must authorize it before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return the provider request purpose.
    pub const fn kind(&self) -> AwsAccountContactRequestKind {
        self.kind
    }

    /// Return the exact HTTP method.
    pub const fn method(&self) -> &'static str {
        "POST"
    }

    /// Return the exact credential-free JSON request body.
    pub const fn body(&self) -> &'static [u8] {
        self.kind.body()
    }

    /// Return the required request media type.
    pub const fn content_type(&self) -> &'static str {
        "application/json"
    }

    /// Return the required response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }

    /// Return the AWS Signature Version 4 service name.
    pub const fn signing_service(&self) -> &'static str {
        SIGNING_SERVICE
    }

    /// Return the AWS Signature Version 4 region.
    pub fn signing_region(&self) -> &str {
        &self.signing_region
    }
}

/// One normalized AWS account-contact posture record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsAccountContactRecord {
    /// Source-catalog family identifier.
    pub family: String,
    /// Emitted provider kind.
    pub provider_kind: String,
    /// Versioned provider schema reference.
    pub schema_ref: String,
    /// Stable Go-compatible source-event identity.
    pub provider_id: String,
    /// Portable scalar attributes used by source mapping.
    pub fields: BTreeMap<String, String>,
    /// Redacted normalized provider posture with no raw contact values.
    pub payload: Value,
}

/// Complete non-paginated AWS account-contact response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsAccountContactPage {
    /// The single account posture record.
    pub records: Vec<AwsAccountContactRecord>,
    /// AWS Account contact APIs expose no continuation cursor.
    pub next_cursor: Option<String>,
}

/// Result of decoding one AWS account-contact provider response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwsAccountContactOutcome {
    /// Primary posture is known and the security-contact request is required.
    Request(AwsAccountContactRequest),
    /// Both contact-posture requests are complete.
    Page(AwsAccountContactPage),
}

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
    /// Planned requests contain no credential material. The caller must apply
    /// the shared egress decision, operation-scoped credential lease, and
    /// Signature Version 4 authorization before provider access.
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

    /// Plan the primary-contact request that begins one collection.
    pub fn plan(&self) -> Result<AwsAccountContactRequest, AwsAccountContactError> {
        self.request(AwsAccountContactRequestKind::PrimaryContact, None)
    }

    /// Decode one response for a request produced by this kernel.
    ///
    /// `provider_error_code` is the safe Smithy error identifier from the
    /// provider response metadata, such as the `x-amzn-errortype` header. It
    /// must not contain a provider error message or credential value.
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
                let configured = optional_object(response.as_ref(), "ContactInformation")?
                    .is_some_and(primary_contact_configured);
                let next = self.request(
                    AwsAccountContactRequestKind::SecurityAlternateContact,
                    Some(configured),
                )?;
                Ok(AwsAccountContactOutcome::Request(next))
            }
            AwsAccountContactRequestKind::SecurityAlternateContact => {
                let primary_contact_configured = request
                    .primary_contact_configured
                    .ok_or(AwsAccountContactError::RequestStageMismatch)?;
                let contact = optional_object(response.as_ref(), "AlternateContact")?;
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

/// Safe AWS account-contact kernel failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwsAccountContactError {
    /// Base URL is not a secure provider origin.
    InvalidBaseUrl,
    /// Account identity is not exactly twelve ASCII digits.
    InvalidAccountId,
    /// Signing region is empty or contains an unsafe character.
    InvalidSigningRegion,
    /// Response JSON does not match the selected AWS Account operation.
    InvalidResponse,
    /// A request was not issued by this origin, account, region, or stage.
    RequestScopeMismatch,
    /// A request carries state that is invalid for its operation stage.
    RequestStageMismatch,
    /// The provider returned a non-optional error.
    Provider {
        /// HTTP status returned by the provider.
        status: u16,
        /// Safe Smithy provider error identifier, when available.
        code: Option<String>,
    },
}

impl fmt::Display for AwsAccountContactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBaseUrl => formatter.write_str("invalid AWS Account service base URL"),
            Self::InvalidAccountId => formatter.write_str("invalid AWS account identifier"),
            Self::InvalidSigningRegion => formatter.write_str("invalid AWS signing region"),
            Self::InvalidResponse => formatter.write_str("invalid AWS Account service response"),
            Self::RequestScopeMismatch => {
                formatter.write_str("AWS account-contact request scope mismatch")
            }
            Self::RequestStageMismatch => {
                formatter.write_str("AWS account-contact request stage mismatch")
            }
            Self::Provider { status, code } => {
                write!(formatter, "AWS Account service returned HTTP {status}")?;
                if let Some(code) = code {
                    write!(formatter, " ({code})")?;
                }
                Ok(())
            }
        }
    }
}

impl Error for AwsAccountContactError {}

fn decode_provider_response(
    status: StatusCode,
    provider_error_code: Option<&str>,
    body: &[u8],
) -> Result<Option<Value>, AwsAccountContactError> {
    if status.is_success() {
        let response: Value =
            serde_json::from_slice(body).map_err(|_| AwsAccountContactError::InvalidResponse)?;
        if !response.is_object() {
            return Err(AwsAccountContactError::InvalidResponse);
        }
        return Ok(Some(response));
    }
    let code = normalize_error_code(provider_error_code)
        .map(str::to_owned)
        .or_else(|| response_error_code(body));
    if code.as_deref() == Some("ResourceNotFoundException") {
        return Ok(None);
    }
    Err(AwsAccountContactError::Provider {
        status: status.as_u16(),
        code,
    })
}

fn normalize_error_code(raw: Option<&str>) -> Option<&str> {
    raw.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            let value = value.rsplit('#').next().unwrap_or(value);
            value.split(':').next().unwrap_or(value)
        })
        .filter(|value| {
            value.len() <= 128
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        })
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    #[serde(default, alias = "code", alias = "Code")]
    __type: Option<String>,
}

fn response_error_code(body: &[u8]) -> Option<String> {
    let envelope: ErrorEnvelope = serde_json::from_slice(body).ok()?;
    normalize_error_code(envelope.__type.as_deref()).map(str::to_owned)
}

fn optional_object<'a>(
    response: Option<&'a Value>,
    key: &str,
) -> Result<Option<&'a Value>, AwsAccountContactError> {
    let Some(value) = response.and_then(|response| response.get(key)) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    if !value.is_object() {
        return Err(AwsAccountContactError::InvalidResponse);
    }
    Ok(Some(value))
}

fn primary_contact_configured(value: &Value) -> bool {
    ["FullName", "PhoneNumber", "CountryCode"]
        .into_iter()
        .all(|key| populated(value.get(key)))
}

fn build_page(
    account_id: &str,
    primary_contact_configured: bool,
    security_contact: Option<&Value>,
) -> AwsAccountContactPage {
    let security_alternate_contact_present = security_contact.is_some();
    let security_contact_email_present =
        security_contact.is_some_and(|value| populated(value.get("EmailAddress")));
    let security_contact_name_present =
        security_contact.is_some_and(|value| populated(value.get("Name")));
    let security_contact_phone_present =
        security_contact.is_some_and(|value| populated(value.get("PhoneNumber")));
    let security_alternate_contact_complete = security_contact_email_present
        && security_contact_name_present
        && security_contact_phone_present;
    let bool_string = |value: bool| value.to_string();
    let fields = BTreeMap::from([
        (
            "account_alternate_contact_security_compliant".to_owned(),
            bool_string(security_alternate_contact_complete),
        ),
        ("account_id".to_owned(), account_id.to_owned()),
        (
            "account_security_contact_configured".to_owned(),
            bool_string(security_alternate_contact_complete),
        ),
        ("domain".to_owned(), account_id.to_owned()),
        ("family".to_owned(), FAMILY.to_owned()),
        (
            "primary_contact_configured".to_owned(),
            bool_string(primary_contact_configured),
        ),
        ("resource_id".to_owned(), account_id.to_owned()),
        ("resource_name".to_owned(), account_id.to_owned()),
        ("resource_provider".to_owned(), "aws".to_owned()),
        ("resource_type".to_owned(), "aws_account".to_owned()),
        (
            "security_alternate_contact_complete".to_owned(),
            bool_string(security_alternate_contact_complete),
        ),
        (
            "security_alternate_contact_present".to_owned(),
            bool_string(security_alternate_contact_present),
        ),
        (
            "security_contact_email_present".to_owned(),
            bool_string(security_contact_email_present),
        ),
        (
            "security_contact_name_present".to_owned(),
            bool_string(security_contact_name_present),
        ),
        (
            "security_contact_phone_present".to_owned(),
            bool_string(security_contact_phone_present),
        ),
    ]);
    let payload = json!({
        "account_id": account_id,
        "primary_contact": {
            "configured": primary_contact_configured,
        },
        "security_contact": {
            "alternate_contact_type": SECURITY_CONTACT_TYPE,
            "complete": security_alternate_contact_complete,
            "email_present": security_contact_email_present,
            "name_present": security_contact_name_present,
            "phone_present": security_contact_phone_present,
            "present": security_alternate_contact_present,
        },
    });
    AwsAccountContactPage {
        records: vec![AwsAccountContactRecord {
            family: FAMILY.to_owned(),
            provider_kind: PROVIDER_KIND.to_owned(),
            schema_ref: SCHEMA_REF.to_owned(),
            provider_id: format!("aws-account-contact-{account_id}"),
            fields,
            payload,
        }],
        next_cursor: None,
    }
}

fn populated(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
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

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT_ID: &str = "123456789012";
    const GENUINE_READ_FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sources/aws/testdata/read_account_contact.json"
    ));

    fn kernel(account_id: &str) -> AwsAccountContactKernel {
        AwsAccountContactKernel::new(
            "https://account.us-east-1.amazonaws.com",
            account_id,
            "us-east-1",
        )
        .unwrap()
    }

    fn security_request(kernel: &AwsAccountContactKernel, body: &[u8]) -> AwsAccountContactRequest {
        let primary = kernel.plan().unwrap();
        let AwsAccountContactOutcome::Request(security) =
            kernel.decode(&primary, StatusCode::OK, None, body).unwrap()
        else {
            panic!("expected security request")
        };
        security
    }

    #[test]
    fn plans_exact_credential_free_sigv4_requests() {
        let kernel = kernel(ACCOUNT_ID);
        let primary = kernel.plan().unwrap();
        assert_eq!(primary.kind(), AwsAccountContactRequestKind::PrimaryContact);
        assert_eq!(primary.method(), "POST");
        assert_eq!(primary.url().path(), "/getContactInformation");
        assert_eq!(primary.url().query(), None);
        assert_eq!(primary.body(), b"{}");
        assert_eq!(primary.content_type(), "application/json");
        assert_eq!(primary.accept(), "application/json");
        assert_eq!(primary.signing_service(), "account");
        assert_eq!(primary.signing_region(), "us-east-1");

        let security = security_request(
            &kernel,
            br#"{"ContactInformation":{"FullName":"Primary","PhoneNumber":"+1","CountryCode":"US"}}"#,
        );
        assert_eq!(
            security.kind(),
            AwsAccountContactRequestKind::SecurityAlternateContact
        );
        assert_eq!(security.method(), "POST");
        assert_eq!(security.url().path(), "/getAlternateContact");
        assert_eq!(security.body(), br#"{"AlternateContactType":"SECURITY"}"#);
    }

    #[test]
    fn genuine_fixture_matches_stable_redacted_output() {
        let kernel = kernel(ACCOUNT_ID);
        let security = security_request(
            &kernel,
            br#"{"ContactInformation":{"FullName":"Private Primary","PhoneNumber":"+1-555-0100","CountryCode":"US"}}"#,
        );
        let AwsAccountContactOutcome::Page(page) = kernel
            .decode(
                &security,
                StatusCode::OK,
                None,
                br#"{"AlternateContact":{"AlternateContactType":"SECURITY","EmailAddress":"security@example.test","Name":"Private Security","PhoneNumber":"+1-555-0101","Title":"Security"}}"#,
            )
            .unwrap()
        else {
            panic!("expected completed page")
        };
        assert_eq!(page.next_cursor, None);
        assert_eq!(page.records.len(), 1);
        let record = &page.records[0];
        let fixture: Value = serde_json::from_slice(GENUINE_READ_FIXTURE).unwrap();
        let expected = &fixture[0];
        assert_eq!(record.provider_id, expected["id"]);
        assert_eq!(record.provider_kind, expected["kind"]);
        assert_eq!(record.schema_ref, expected["schema_ref"]);
        assert_eq!(record.payload, expected["payload"]);
        assert_eq!(
            serde_json::to_value(&record.fields).unwrap(),
            expected["attributes"]
        );
        let serialized = format!("{:?}{}", record.fields, record.payload);
        for private_value in [
            "Private Primary",
            "+1-555-0100",
            "security@example.test",
            "Private Security",
            "+1-555-0101",
        ] {
            assert!(!serialized.contains(private_value));
        }
    }

    #[test]
    fn optional_not_found_is_normalized_for_both_operations() {
        let kernel = kernel(ACCOUNT_ID);
        let primary = kernel.plan().unwrap();
        let AwsAccountContactOutcome::Request(security) = kernel
            .decode(
                &primary,
                StatusCode::NOT_FOUND,
                Some("ResourceNotFoundException:http://internal"),
                br#"{"message":"not configured"}"#,
            )
            .unwrap()
        else {
            panic!("expected security request")
        };
        let AwsAccountContactOutcome::Page(page) = kernel
            .decode(
                &security,
                StatusCode::BAD_REQUEST,
                None,
                br#"{"__type":"com.amazonaws.account#ResourceNotFoundException"}"#,
            )
            .unwrap()
        else {
            panic!("expected completed page")
        };
        let record = &page.records[0];
        for field in [
            "primary_contact_configured",
            "security_alternate_contact_present",
            "security_alternate_contact_complete",
            "security_contact_email_present",
            "security_contact_name_present",
            "security_contact_phone_present",
        ] {
            assert_eq!(record.fields.get(field).map(String::as_str), Some("false"));
        }
    }

    #[test]
    fn null_optional_contacts_are_absent_and_wrong_shapes_fail_closed() {
        let kernel = kernel(ACCOUNT_ID);
        let security = security_request(&kernel, br#"{"ContactInformation":null}"#);
        let AwsAccountContactOutcome::Page(page) = kernel
            .decode(
                &security,
                StatusCode::OK,
                None,
                br#"{"AlternateContact":null}"#,
            )
            .unwrap()
        else {
            panic!("expected completed page")
        };
        assert_eq!(
            page.records[0]
                .fields
                .get("security_alternate_contact_present")
                .map(String::as_str),
            Some("false")
        );

        let primary = kernel.plan().unwrap();
        assert_eq!(
            kernel.decode(
                &primary,
                StatusCode::OK,
                None,
                br#"{"ContactInformation":"invalid"}"#,
            ),
            Err(AwsAccountContactError::InvalidResponse)
        );
        assert_eq!(
            kernel.decode(
                &security,
                StatusCode::OK,
                None,
                br#"{"AlternateContact":[]}"#,
            ),
            Err(AwsAccountContactError::InvalidResponse)
        );
    }

    #[test]
    fn provider_errors_fail_closed_without_messages() {
        let kernel = kernel(ACCOUNT_ID);
        let request = kernel.plan().unwrap();
        let error = kernel
            .decode(
                &request,
                StatusCode::FORBIDDEN,
                Some("AccessDeniedException"),
                br#"{"message":"secret provider detail"}"#,
            )
            .unwrap_err();
        assert_eq!(
            error,
            AwsAccountContactError::Provider {
                status: 403,
                code: Some("AccessDeniedException".to_owned()),
            }
        );
        assert!(!error.to_string().contains("secret provider detail"));
        assert_eq!(
            kernel.decode(&request, StatusCode::OK, None, br#"[]"#),
            Err(AwsAccountContactError::InvalidResponse)
        );
    }

    #[test]
    fn stable_identity_is_account_scoped_and_non_aliasing() {
        let first = kernel("123456789012");
        let second = kernel("210987654321");
        let first_request = security_request(&first, br#"{}"#);
        let second_request = security_request(&second, br#"{}"#);
        let AwsAccountContactOutcome::Page(first_page) = first
            .decode(&first_request, StatusCode::OK, None, br#"{}"#)
            .unwrap()
        else {
            panic!("expected first page")
        };
        let AwsAccountContactOutcome::Page(second_page) = second
            .decode(&second_request, StatusCode::OK, None, br#"{}"#)
            .unwrap()
        else {
            panic!("expected second page")
        };
        assert_eq!(
            first_page.records[0].provider_id,
            "aws-account-contact-123456789012"
        );
        assert_eq!(
            second_page.records[0].provider_id,
            "aws-account-contact-210987654321"
        );
        assert_ne!(
            first_page.records[0].provider_id,
            second_page.records[0].provider_id
        );
    }

    #[test]
    fn rejects_wrong_scope_stage_and_unsafe_configuration() {
        let first = kernel(ACCOUNT_ID);
        let second = kernel("210987654321");
        let request = first.plan().unwrap();
        assert_eq!(
            second.decode(&request, StatusCode::OK, None, br#"{}"#),
            Err(AwsAccountContactError::RequestScopeMismatch)
        );

        let mut invalid_stage = request;
        invalid_stage.primary_contact_configured = Some(false);
        assert_eq!(
            first.decode(&invalid_stage, StatusCode::OK, None, br#"{}"#),
            Err(AwsAccountContactError::RequestStageMismatch)
        );

        assert!(matches!(
            AwsAccountContactKernel::new("http://169.254.169.254", ACCOUNT_ID, "us-east-1"),
            Err(AwsAccountContactError::InvalidBaseUrl)
        ));
        assert!(matches!(
            AwsAccountContactKernel::new(
                "https://account.us-east-1.amazonaws.com/path",
                ACCOUNT_ID,
                "us-east-1"
            ),
            Err(AwsAccountContactError::InvalidBaseUrl)
        ));
        assert!(matches!(
            AwsAccountContactKernel::new(
                "https://account.us-east-1.amazonaws.com",
                "1234",
                "us-east-1"
            ),
            Err(AwsAccountContactError::InvalidAccountId)
        ));
        assert!(matches!(
            AwsAccountContactKernel::new(
                "https://account.us-east-1.amazonaws.com",
                ACCOUNT_ID,
                "US EAST 1"
            ),
            Err(AwsAccountContactError::InvalidSigningRegion)
        ));
    }
}
