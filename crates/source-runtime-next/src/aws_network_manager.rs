//! Portable AWS network-manager request, fanout, and response kernel.
//!
//! The kernel covers the AWS Certificate Manager certificate and Route 53
//! Resolver endpoint/rule families. It plans credential-free AWS JSON
//! requests, preserves the SigV4 service boundary, correlates enrichment
//! fanout, and normalizes provider responses without owning credentials,
//! private endpoints, or deployment topology.

use std::{collections::BTreeMap, error::Error, fmt, net::IpAddr};

use reqwest::{StatusCode, Url};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

const MAX_CURSOR_BYTES: usize = 4_096;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PROVIDER_RECORDS: usize = 1_000;
const AWS_JSON_CONTENT_TYPE: &str = "application/x-amz-json-1.1";
const ACM_STATUSES: &[&str] = &[
    "PENDING_VALIDATION",
    "ISSUED",
    "INACTIVE",
    "EXPIRED",
    "VALIDATION_TIMED_OUT",
    "REVOKED",
    "FAILED",
];

/// AWS network-manager source family implemented by this kernel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AwsNetworkManagerFamily {
    /// AWS Certificate Manager certificates.
    AcmCertificate,
    /// Route 53 Resolver endpoints.
    Route53ResolverEndpoint,
    /// Route 53 Resolver rules.
    Route53ResolverRule,
}

impl AwsNetworkManagerFamily {
    /// Return the Go source-catalog family identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::AcmCertificate => "acm_certificate",
            Self::Route53ResolverEndpoint => "route53_resolver_endpoint",
            Self::Route53ResolverRule => "route53_resolver_rule",
        }
    }

    const fn provider_kind(self) -> &'static str {
        match self {
            Self::AcmCertificate => "aws.acm_certificate",
            Self::Route53ResolverEndpoint => "aws.route53_resolver_endpoint",
            Self::Route53ResolverRule => "aws.route53_resolver_rule",
        }
    }

    const fn schema_ref(self) -> &'static str {
        match self {
            Self::AcmCertificate => "aws/acm_certificate/v1",
            Self::Route53ResolverEndpoint => "aws/route53_resolver_endpoint/v1",
            Self::Route53ResolverRule => "aws/route53_resolver_rule/v1",
        }
    }

    const fn maximum_page_size(self) -> usize {
        match self {
            Self::AcmCertificate => 1_000,
            Self::Route53ResolverEndpoint | Self::Route53ResolverRule => 100,
        }
    }
}

/// Purpose of one AWS provider request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AwsNetworkManagerRequestKind {
    /// List ACM certificate summaries.
    ListCertificates,
    /// Read one complete ACM certificate.
    DescribeCertificate,
    /// Read tags for one ACM certificate.
    ListCertificateTags,
    /// List Route 53 Resolver endpoints.
    ListResolverEndpoints,
    /// Read tags for one Route 53 Resolver endpoint.
    ListResolverEndpointTags,
    /// List Route 53 Resolver rules.
    ListResolverRules,
    /// Read tags for one Route 53 Resolver rule.
    ListResolverRuleTags,
}

impl AwsNetworkManagerRequestKind {
    const fn target(self) -> &'static str {
        match self {
            Self::ListCertificates => "CertificateManager.ListCertificates",
            Self::DescribeCertificate => "CertificateManager.DescribeCertificate",
            Self::ListCertificateTags => "CertificateManager.ListTagsForCertificate",
            Self::ListResolverEndpoints => "Route53Resolver.ListResolverEndpoints",
            Self::ListResolverEndpointTags | Self::ListResolverRuleTags => {
                "Route53Resolver.ListTagsForResource"
            }
            Self::ListResolverRules => "Route53Resolver.ListResolverRules",
        }
    }

    const fn service(self) -> &'static str {
        match self {
            Self::ListCertificates | Self::DescribeCertificate | Self::ListCertificateTags => "acm",
            Self::ListResolverEndpoints
            | Self::ListResolverEndpointTags
            | Self::ListResolverRules
            | Self::ListResolverRuleTags => "route53resolver",
        }
    }
}

/// One credential-free AWS JSON request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsNetworkManagerRequest {
    url: Url,
    family: AwsNetworkManagerFamily,
    kind: AwsNetworkManagerRequestKind,
    account_id: String,
    region: String,
    cursor: Option<String>,
    page_size: usize,
    subject: Option<Value>,
    body: Vec<u8>,
    kernel_fingerprint: [u8; 32],
}

impl AwsNetworkManagerRequest {
    /// Return the exact provider URL. The caller must authorize it before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return the source family correlated with this request.
    pub const fn family(&self) -> AwsNetworkManagerFamily {
        self.family
    }

    /// Return the provider operation represented by this request.
    pub const fn kind(&self) -> AwsNetworkManagerRequestKind {
        self.kind
    }

    /// Return the exact HTTP method.
    pub const fn method(&self) -> &'static str {
        "POST"
    }

    /// Return the AWS JSON request body without authorization material.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Return the required AWS JSON media type.
    pub const fn content_type(&self) -> &'static str {
        AWS_JSON_CONTENT_TYPE
    }

    /// Return the exact `X-Amz-Target` header value.
    pub const fn amz_target(&self) -> &'static str {
        self.kind.target()
    }

    /// Return the AWS Signature Version 4 service name.
    pub const fn signing_service(&self) -> &'static str {
        self.kind.service()
    }

    /// Return the AWS Signature Version 4 region.
    pub fn signing_region(&self) -> &str {
        &self.region
    }
}

/// One normalized AWS network-manager source record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsNetworkManagerRecord {
    /// Source-catalog family identifier.
    pub family: String,
    /// Emitted provider event kind.
    pub provider_kind: String,
    /// Versioned provider schema reference.
    pub schema_ref: String,
    /// Stable Go-compatible source-event identifier.
    pub provider_id: String,
    /// Portable scalar fields consumed by source mapping.
    pub fields: BTreeMap<String, String>,
    /// Normalized provider payload with account and region correlation.
    pub payload: Value,
}

/// Result of decoding one provider operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsNetworkManagerBatch {
    /// Complete normalized records available after this operation.
    pub records: Vec<AwsNetworkManagerRecord>,
    /// Correlated enrichment requests required to complete listed resources.
    pub requests: Vec<AwsNetworkManagerRequest>,
    /// Validated provider cursor from a list operation.
    pub next_cursor: Option<String>,
}

/// Provider-specific AWS network-manager request and response kernel.
#[derive(Clone, Debug)]
pub struct AwsNetworkManagerKernel {
    acm_base_url: Url,
    resolver_base_url: Url,
    account_id: String,
    region: String,
    fingerprint: [u8; 32],
}

impl AwsNetworkManagerKernel {
    /// Build a kernel for one account, region, and pair of AWS service origins.
    ///
    /// The origins and planned requests contain no credential material. The
    /// caller owns egress authorization, operation-scoped credential leasing,
    /// and Signature Version 4 authorization.
    pub fn new(
        acm_base_url: &str,
        resolver_base_url: &str,
        account_id: &str,
        region: &str,
    ) -> Result<Self, AwsNetworkManagerError> {
        let acm_base_url = validate_origin(acm_base_url)?;
        let resolver_base_url = validate_origin(resolver_base_url)?;
        let account_id = account_id.trim();
        if account_id.len() != 12 || !account_id.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(AwsNetworkManagerError::InvalidAccountId);
        }
        let region = region.trim();
        if region.is_empty()
            || region.len() > 63
            || !region
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(AwsNetworkManagerError::InvalidRegion);
        }
        let fingerprint = kernel_fingerprint(
            acm_base_url.as_str(),
            resolver_base_url.as_str(),
            account_id,
            region,
        );
        Ok(Self {
            acm_base_url,
            resolver_base_url,
            account_id: account_id.to_owned(),
            region: region.to_owned(),
            fingerprint,
        })
    }

    /// Plan the first or next list request for one family.
    pub fn plan(
        &self,
        family: AwsNetworkManagerFamily,
        cursor: Option<&str>,
        page_size: usize,
    ) -> Result<AwsNetworkManagerRequest, AwsNetworkManagerError> {
        if page_size == 0 || page_size > family.maximum_page_size() {
            return Err(AwsNetworkManagerError::InvalidPageSize);
        }
        let cursor = cursor.map(validate_cursor).transpose()?.map(str::to_owned);
        let kind = match family {
            AwsNetworkManagerFamily::AcmCertificate => {
                AwsNetworkManagerRequestKind::ListCertificates
            }
            AwsNetworkManagerFamily::Route53ResolverEndpoint => {
                AwsNetworkManagerRequestKind::ListResolverEndpoints
            }
            AwsNetworkManagerFamily::Route53ResolverRule => {
                AwsNetworkManagerRequestKind::ListResolverRules
            }
        };
        self.request(family, kind, cursor, page_size, None)
    }

    /// Decode one response for a request issued by this exact kernel.
    ///
    /// `provider_error_code` is the safe Smithy error identifier, not the
    /// provider message or response body.
    pub fn decode(
        &self,
        request: &AwsNetworkManagerRequest,
        status: StatusCode,
        provider_error_code: Option<&str>,
        body: &[u8],
    ) -> Result<AwsNetworkManagerBatch, AwsNetworkManagerError> {
        self.validate_request(request)?;
        let optional_missing_tags = request.kind
            == AwsNetworkManagerRequestKind::ListCertificateTags
            && !status.is_success()
            && provider_error_code.is_some_and(is_resource_not_found);
        if !status.is_success() && !optional_missing_tags {
            return Err(AwsNetworkManagerError::ProviderFailure {
                status: status.as_u16(),
                code: safe_error_code(provider_error_code),
            });
        }
        let response = if optional_missing_tags {
            json!({"Tags": []})
        } else {
            decode_json(body)?
        };
        match request.kind {
            AwsNetworkManagerRequestKind::ListCertificates => {
                self.decode_certificate_list(request, &response)
            }
            AwsNetworkManagerRequestKind::DescribeCertificate => {
                self.decode_certificate_detail(request, &response)
            }
            AwsNetworkManagerRequestKind::ListCertificateTags => {
                self.decode_certificate_tags(request, &response)
            }
            AwsNetworkManagerRequestKind::ListResolverEndpoints => {
                self.decode_resolver_list(request, &response, true)
            }
            AwsNetworkManagerRequestKind::ListResolverEndpointTags => {
                self.decode_resolver_tags(request, &response, true)
            }
            AwsNetworkManagerRequestKind::ListResolverRules => {
                self.decode_resolver_list(request, &response, false)
            }
            AwsNetworkManagerRequestKind::ListResolverRuleTags => {
                self.decode_resolver_tags(request, &response, false)
            }
        }
    }

    fn decode_certificate_list(
        &self,
        request: &AwsNetworkManagerRequest,
        response: &Value,
    ) -> Result<AwsNetworkManagerBatch, AwsNetworkManagerError> {
        let object = response_object(response)?;
        let summaries = optional_array(object, "CertificateSummaryList")?;
        bounded_records(summaries.len())?;
        let mut requests = Vec::with_capacity(summaries.len());
        for summary in summaries {
            let summary = value_object(summary)?;
            let arn = response_string_member(summary, "CertificateArn")?.unwrap_or_default();
            if arn.is_empty() {
                continue;
            }
            requests.push(self.request(
                request.family,
                AwsNetworkManagerRequestKind::DescribeCertificate,
                None,
                request.page_size,
                Some(json!({"CertificateArn": arn})),
            )?);
        }
        Ok(AwsNetworkManagerBatch {
            records: Vec::new(),
            requests,
            next_cursor: response_cursor(object)?,
        })
    }

    fn decode_certificate_detail(
        &self,
        request: &AwsNetworkManagerRequest,
        response: &Value,
    ) -> Result<AwsNetworkManagerBatch, AwsNetworkManagerError> {
        let object = response_object(response)?;
        let Some(certificate) = object.get("Certificate") else {
            return Ok(empty_batch());
        };
        if certificate.is_null() {
            return Ok(empty_batch());
        }
        let certificate = value_object(certificate)?;
        certificate_identity(certificate)?;
        let tags = self.request(
            request.family,
            AwsNetworkManagerRequestKind::ListCertificateTags,
            None,
            request.page_size,
            Some(Value::Object(certificate.clone())),
        )?;
        Ok(AwsNetworkManagerBatch {
            records: Vec::new(),
            requests: vec![tags],
            next_cursor: None,
        })
    }

    fn decode_certificate_tags(
        &self,
        request: &AwsNetworkManagerRequest,
        response: &Value,
    ) -> Result<AwsNetworkManagerBatch, AwsNetworkManagerError> {
        let subject = request
            .subject
            .as_ref()
            .ok_or(AwsNetworkManagerError::RequestScopeMismatch)?;
        let certificate = value_object(subject)?;
        let tags = decode_tags(response_object(response)?)?;
        Ok(AwsNetworkManagerBatch {
            records: vec![build_certificate_record(
                &self.account_id,
                &self.region,
                certificate,
                tags,
            )?],
            requests: Vec::new(),
            next_cursor: None,
        })
    }

    fn decode_resolver_list(
        &self,
        request: &AwsNetworkManagerRequest,
        response: &Value,
        endpoints: bool,
    ) -> Result<AwsNetworkManagerBatch, AwsNetworkManagerError> {
        let object = response_object(response)?;
        let member = if endpoints {
            "ResolverEndpoints"
        } else {
            "ResolverRules"
        };
        let values = optional_array(object, member)?;
        bounded_records(values.len())?;
        let mut records = Vec::new();
        let mut requests = Vec::new();
        for value in values {
            let item = value_object(value)?;
            resolver_identity(item, endpoints)?;
            let arn = response_string_member(item, "Arn")?.unwrap_or_default();
            if arn.is_empty() {
                records.push(build_resolver_record(
                    &self.account_id,
                    &self.region,
                    item,
                    BTreeMap::new(),
                    endpoints,
                )?);
                continue;
            }
            let kind = if endpoints {
                AwsNetworkManagerRequestKind::ListResolverEndpointTags
            } else {
                AwsNetworkManagerRequestKind::ListResolverRuleTags
            };
            requests.push(self.request(
                request.family,
                kind,
                None,
                request.page_size,
                Some(resolver_tag_subject(item, &BTreeMap::new())),
            )?);
        }
        Ok(AwsNetworkManagerBatch {
            records,
            requests,
            next_cursor: response_cursor(object)?,
        })
    }

    fn decode_resolver_tags(
        &self,
        request: &AwsNetworkManagerRequest,
        response: &Value,
        endpoints: bool,
    ) -> Result<AwsNetworkManagerBatch, AwsNetworkManagerError> {
        let subject = request
            .subject
            .as_ref()
            .ok_or(AwsNetworkManagerError::RequestScopeMismatch)?;
        let state = value_object(subject)?;
        let item = value_object(
            state
                .get("record")
                .ok_or(AwsNetworkManagerError::RequestScopeMismatch)?,
        )?;
        let mut tags = decode_accumulated_tags(
            state
                .get("tags")
                .ok_or(AwsNetworkManagerError::RequestScopeMismatch)?,
        )?;
        let response = response_object(response)?;
        tags.extend(decode_tags(response)?);
        bounded_records(tags.len())?;
        if let Some(cursor) = response_cursor(response)? {
            let next = self.request(
                request.family,
                request.kind,
                Some(cursor),
                request.page_size,
                Some(resolver_tag_subject(item, &tags)),
            )?;
            return Ok(AwsNetworkManagerBatch {
                records: Vec::new(),
                requests: vec![next],
                next_cursor: None,
            });
        }
        Ok(AwsNetworkManagerBatch {
            records: vec![build_resolver_record(
                &self.account_id,
                &self.region,
                item,
                tags,
                endpoints,
            )?],
            requests: Vec::new(),
            next_cursor: None,
        })
    }

    fn request(
        &self,
        family: AwsNetworkManagerFamily,
        kind: AwsNetworkManagerRequestKind,
        cursor: Option<String>,
        page_size: usize,
        subject: Option<Value>,
    ) -> Result<AwsNetworkManagerRequest, AwsNetworkManagerError> {
        validate_kind_family(kind, family)?;
        let url = match kind.service() {
            "acm" => self.acm_base_url.clone(),
            _ => self.resolver_base_url.clone(),
        };
        let body = request_body(kind, cursor.as_deref(), page_size, subject.as_ref())?;
        Ok(AwsNetworkManagerRequest {
            url,
            family,
            kind,
            account_id: self.account_id.clone(),
            region: self.region.clone(),
            cursor,
            page_size,
            subject,
            body,
            kernel_fingerprint: self.fingerprint,
        })
    }

    fn validate_request(
        &self,
        request: &AwsNetworkManagerRequest,
    ) -> Result<(), AwsNetworkManagerError> {
        validate_kind_family(request.kind, request.family)?;
        let expected_url = match request.kind.service() {
            "acm" => &self.acm_base_url,
            _ => &self.resolver_base_url,
        };
        if &request.url != expected_url
            || request.account_id != self.account_id
            || request.region != self.region
            || request.kernel_fingerprint != self.fingerprint
            || request.page_size == 0
            || request.page_size > request.family.maximum_page_size()
        {
            return Err(AwsNetworkManagerError::RequestScopeMismatch);
        }
        let expected = request_body(
            request.kind,
            request.cursor.as_deref(),
            request.page_size,
            request.subject.as_ref(),
        )?;
        if request.body != expected {
            return Err(AwsNetworkManagerError::RequestScopeMismatch);
        }
        Ok(())
    }
}

/// Safe AWS network-manager kernel failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwsNetworkManagerError {
    /// Service base URL is not a secure origin-only URL.
    InvalidBaseUrl,
    /// Account identity is not exactly twelve ASCII digits.
    InvalidAccountId,
    /// AWS region is empty or contains an unsafe character.
    InvalidRegion,
    /// Requested page size is outside the provider family bound.
    InvalidPageSize,
    /// Provider cursor is empty, oversized, or contains a control character.
    InvalidCursor,
    /// Request does not belong to this exact kernel and family stage.
    RequestScopeMismatch,
    /// Provider returned a non-success status and safe error code.
    ProviderFailure {
        /// HTTP status returned by the provider.
        status: u16,
        /// Bounded Smithy error identifier, when safe and present.
        code: Option<String>,
    },
    /// Provider response is oversized, malformed, or violates the operation shape.
    InvalidResponse,
    /// Provider resource lacks the stable identity required by the Go contract.
    MissingIdentity,
}

impl fmt::Display for AwsNetworkManagerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBaseUrl => formatter.write_str("invalid AWS service base URL"),
            Self::InvalidAccountId => formatter.write_str("invalid AWS account ID"),
            Self::InvalidRegion => formatter.write_str("invalid AWS region"),
            Self::InvalidPageSize => formatter.write_str("invalid AWS page size"),
            Self::InvalidCursor => formatter.write_str("invalid AWS provider cursor"),
            Self::RequestScopeMismatch => formatter.write_str("AWS request scope mismatch"),
            Self::ProviderFailure { status, code } => {
                write!(
                    formatter,
                    "AWS provider request failed with status {status}"
                )?;
                if let Some(code) = code {
                    write!(formatter, " ({code})")?;
                }
                Ok(())
            }
            Self::InvalidResponse => formatter.write_str("invalid AWS provider response"),
            Self::MissingIdentity => formatter.write_str("AWS resource identity is missing"),
        }
    }
}

impl Error for AwsNetworkManagerError {}

fn validate_origin(value: &str) -> Result<Url, AwsNetworkManagerError> {
    let url = Url::parse(value).map_err(|_| AwsNetworkManagerError::InvalidBaseUrl)?;
    let host = url
        .host_str()
        .ok_or(AwsNetworkManagerError::InvalidBaseUrl)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
        || host.eq_ignore_ascii_case("localhost")
        || host.ends_with(".local")
        || host.parse::<IpAddr>().is_ok()
    {
        return Err(AwsNetworkManagerError::InvalidBaseUrl);
    }
    Ok(url)
}

fn kernel_fingerprint(acm: &str, resolver: &str, account: &str, region: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    for value in [acm, resolver, account, region] {
        digest.update(value.len().to_be_bytes());
        digest.update(value.as_bytes());
    }
    digest.finalize().into()
}

fn validate_kind_family(
    kind: AwsNetworkManagerRequestKind,
    family: AwsNetworkManagerFamily,
) -> Result<(), AwsNetworkManagerError> {
    let matches = match family {
        AwsNetworkManagerFamily::AcmCertificate => matches!(
            kind,
            AwsNetworkManagerRequestKind::ListCertificates
                | AwsNetworkManagerRequestKind::DescribeCertificate
                | AwsNetworkManagerRequestKind::ListCertificateTags
        ),
        AwsNetworkManagerFamily::Route53ResolverEndpoint => matches!(
            kind,
            AwsNetworkManagerRequestKind::ListResolverEndpoints
                | AwsNetworkManagerRequestKind::ListResolverEndpointTags
        ),
        AwsNetworkManagerFamily::Route53ResolverRule => matches!(
            kind,
            AwsNetworkManagerRequestKind::ListResolverRules
                | AwsNetworkManagerRequestKind::ListResolverRuleTags
        ),
    };
    if matches {
        Ok(())
    } else {
        Err(AwsNetworkManagerError::RequestScopeMismatch)
    }
}

fn request_body(
    kind: AwsNetworkManagerRequestKind,
    cursor: Option<&str>,
    page_size: usize,
    subject: Option<&Value>,
) -> Result<Vec<u8>, AwsNetworkManagerError> {
    let body = match kind {
        AwsNetworkManagerRequestKind::ListCertificates => {
            let mut object = Map::new();
            object.insert("CertificateStatuses".to_owned(), json!(ACM_STATUSES));
            object.insert("MaxItems".to_owned(), json!(page_size));
            if let Some(cursor) = cursor {
                object.insert("NextToken".to_owned(), json!(validate_cursor(cursor)?));
            }
            Value::Object(object)
        }
        AwsNetworkManagerRequestKind::DescribeCertificate
        | AwsNetworkManagerRequestKind::ListCertificateTags => {
            let subject =
                value_object(subject.ok_or(AwsNetworkManagerError::RequestScopeMismatch)?)?;
            let arn = string_member(subject, "CertificateArn")
                .filter(|value| !value.is_empty())
                .ok_or(AwsNetworkManagerError::RequestScopeMismatch)?;
            json!({"CertificateArn": arn})
        }
        AwsNetworkManagerRequestKind::ListResolverEndpoints
        | AwsNetworkManagerRequestKind::ListResolverRules => {
            let mut object = Map::new();
            object.insert("MaxResults".to_owned(), json!(page_size));
            if let Some(cursor) = cursor {
                object.insert("NextToken".to_owned(), json!(validate_cursor(cursor)?));
            }
            Value::Object(object)
        }
        AwsNetworkManagerRequestKind::ListResolverEndpointTags
        | AwsNetworkManagerRequestKind::ListResolverRuleTags => {
            let subject =
                value_object(subject.ok_or(AwsNetworkManagerError::RequestScopeMismatch)?)?;
            let record = value_object(
                subject
                    .get("record")
                    .ok_or(AwsNetworkManagerError::RequestScopeMismatch)?,
            )?;
            let arn = string_member(record, "Arn")
                .filter(|value| !value.is_empty())
                .ok_or(AwsNetworkManagerError::RequestScopeMismatch)?;
            let mut object = Map::new();
            object.insert("MaxResults".to_owned(), json!(100));
            object.insert("ResourceArn".to_owned(), json!(arn));
            if let Some(cursor) = cursor {
                object.insert("NextToken".to_owned(), json!(validate_cursor(cursor)?));
            }
            Value::Object(object)
        }
    };
    serde_json::to_vec(&body).map_err(|_| AwsNetworkManagerError::RequestScopeMismatch)
}

fn decode_json(body: &[u8]) -> Result<Value, AwsNetworkManagerError> {
    if body.is_empty() || body.len() > MAX_RESPONSE_BYTES {
        return Err(AwsNetworkManagerError::InvalidResponse);
    }
    serde_json::from_slice(body).map_err(|_| AwsNetworkManagerError::InvalidResponse)
}

fn response_object(response: &Value) -> Result<&Map<String, Value>, AwsNetworkManagerError> {
    value_object(response)
}

fn value_object(value: &Value) -> Result<&Map<String, Value>, AwsNetworkManagerError> {
    value
        .as_object()
        .ok_or(AwsNetworkManagerError::InvalidResponse)
}

fn optional_array<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a [Value], AwsNetworkManagerError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(values)) => Ok(values),
        Some(_) => Err(AwsNetworkManagerError::InvalidResponse),
    }
}

fn bounded_records(count: usize) -> Result<(), AwsNetworkManagerError> {
    if count > MAX_PROVIDER_RECORDS {
        Err(AwsNetworkManagerError::InvalidResponse)
    } else {
        Ok(())
    }
}

fn response_cursor(object: &Map<String, Value>) -> Result<Option<String>, AwsNetworkManagerError> {
    match object.get("NextToken") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.trim().is_empty() => Ok(None),
        Some(Value::String(value)) => Ok(Some(validate_cursor(value)?.to_owned())),
        Some(_) => Err(AwsNetworkManagerError::InvalidResponse),
    }
}

fn validate_cursor(value: &str) -> Result<&str, AwsNetworkManagerError> {
    if value.is_empty()
        || value.len() > MAX_CURSOR_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(AwsNetworkManagerError::InvalidCursor)
    } else {
        Ok(value)
    }
}

fn safe_error_code(value: Option<&str>) -> Option<String> {
    value.and_then(|value| {
        let value = value.split(':').next().unwrap_or_default().trim();
        (!value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')))
        .then(|| value.to_owned())
    })
}

fn is_resource_not_found(value: &str) -> bool {
    value
        .split(':')
        .next()
        .is_some_and(|value| value.trim() == "ResourceNotFoundException")
}

fn decode_tags(
    object: &Map<String, Value>,
) -> Result<BTreeMap<String, String>, AwsNetworkManagerError> {
    let tags = optional_array(object, "Tags")?;
    bounded_records(tags.len())?;
    let mut result = BTreeMap::new();
    for tag in tags {
        let tag = value_object(tag)?;
        let key = match tag.get("Key") {
            None | Some(Value::Null) => continue,
            Some(Value::String(value)) => value.trim(),
            Some(_) => return Err(AwsNetworkManagerError::InvalidResponse),
        };
        if key.is_empty() {
            continue;
        }
        let value = match tag.get("Value") {
            None | Some(Value::Null) => "",
            Some(Value::String(value)) => value.trim(),
            Some(_) => return Err(AwsNetworkManagerError::InvalidResponse),
        };
        result.insert(key.to_owned(), value.to_owned());
    }
    Ok(result)
}

fn resolver_tag_subject(item: &Map<String, Value>, tags: &BTreeMap<String, String>) -> Value {
    json!({
        "record": Value::Object(item.clone()),
        "tags": tags,
    })
}

fn decode_accumulated_tags(
    value: &Value,
) -> Result<BTreeMap<String, String>, AwsNetworkManagerError> {
    let object = value_object(value)?;
    bounded_records(object.len())?;
    let mut tags = BTreeMap::new();
    for (key, value) in object {
        if key.trim().is_empty() || key.trim() != key {
            return Err(AwsNetworkManagerError::RequestScopeMismatch);
        }
        let value = value
            .as_str()
            .ok_or(AwsNetworkManagerError::RequestScopeMismatch)?;
        tags.insert(key.clone(), value.to_owned());
    }
    Ok(tags)
}

fn string_member<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn response_string_member<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, AwsNetworkManagerError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.trim()).filter(|value| !value.is_empty())),
        Some(_) => Err(AwsNetworkManagerError::InvalidResponse),
    }
}

fn bool_member(object: &Map<String, Value>, key: &str) -> Result<bool, AwsNetworkManagerError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(AwsNetworkManagerError::InvalidResponse),
    }
}

fn number_string(object: &Map<String, Value>, key: &str) -> Result<String, AwsNetworkManagerError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::Number(value)) if value.is_i64() || value.is_u64() => Ok(value.to_string()),
        Some(_) => Err(AwsNetworkManagerError::InvalidResponse),
    }
}

fn string_array(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Vec<String>, AwsNetworkManagerError> {
    let values = optional_array(object, key)?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::trim)
                .map(str::to_owned)
                .ok_or(AwsNetworkManagerError::InvalidResponse)
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|values| {
            values
                .into_iter()
                .filter(|value| !value.is_empty())
                .collect()
        })
}

fn certificate_identity(certificate: &Map<String, Value>) -> Result<&str, AwsNetworkManagerError> {
    response_string_member(certificate, "CertificateArn")?
        .or(response_string_member(certificate, "DomainName")?)
        .ok_or(AwsNetworkManagerError::MissingIdentity)
}

fn resolver_identity(
    item: &Map<String, Value>,
    endpoints: bool,
) -> Result<&str, AwsNetworkManagerError> {
    response_string_member(item, "Arn")?
        .or(response_string_member(item, "Id")?)
        .or(response_string_member(item, "Name")?)
        .ok_or_else(|| {
            let _ = endpoints;
            AwsNetworkManagerError::MissingIdentity
        })
}

fn build_certificate_record(
    account_id: &str,
    region: &str,
    certificate: &Map<String, Value>,
    tags: BTreeMap<String, String>,
) -> Result<AwsNetworkManagerRecord, AwsNetworkManagerError> {
    let identity = certificate_identity(certificate)?;
    let arn = response_string_member(certificate, "CertificateArn")?.unwrap_or_default();
    let domain = response_string_member(certificate, "DomainName")?.unwrap_or_default();
    let mut fields = common_fields(
        account_id,
        region,
        AwsNetworkManagerFamily::AcmCertificate,
        identity,
        if domain.is_empty() { identity } else { domain },
        "acm_certificate",
        &tags,
    );
    insert_string(&mut fields, "arn", arn);
    insert_string(&mut fields, "certificate_arn", arn);
    copy_string_fields(
        &mut fields,
        certificate,
        &[
            ("CertificateAuthorityArn", "certificate_authority_arn"),
            ("DomainName", "domain_name"),
            ("FailureReason", "failure_reason"),
            ("Issuer", "issuer"),
            ("KeyAlgorithm", "key_algorithm"),
            ("ManagedBy", "managed_by"),
            ("RenewalEligibility", "renewal_eligibility"),
            ("RevocationReason", "revocation_reason"),
            ("Serial", "serial"),
            ("SignatureAlgorithm", "signature_algorithm"),
            ("Status", "status"),
            ("Subject", "subject"),
            ("Type", "type"),
        ],
    )?;
    fields.insert(
        "in_use_by".to_owned(),
        string_array(certificate, "InUseBy")?.join(","),
    );
    fields.insert(
        "subject_alternative_names".to_owned(),
        string_array(certificate, "SubjectAlternativeNames")?.join(","),
    );
    fields.insert("public".to_owned(), "false".to_owned());
    fields.insert("internet_exposed".to_owned(), "false".to_owned());
    let payload = json!({
        "account_id": account_id,
        "region": region,
        "certificate": Value::Object(certificate.clone()),
        "tags": tags,
    });
    Ok(record(
        AwsNetworkManagerFamily::AcmCertificate,
        format!("aws-acm-certificate-{identity}"),
        fields,
        payload,
    ))
}

fn build_resolver_record(
    account_id: &str,
    region: &str,
    item: &Map<String, Value>,
    tags: BTreeMap<String, String>,
    endpoints: bool,
) -> Result<AwsNetworkManagerRecord, AwsNetworkManagerError> {
    let identity = resolver_identity(item, endpoints)?;
    let arn = response_string_member(item, "Arn")?.unwrap_or_default();
    let id = response_string_member(item, "Id")?.unwrap_or_default();
    let name = response_string_member(item, "Name")?.unwrap_or(id);
    let family = if endpoints {
        AwsNetworkManagerFamily::Route53ResolverEndpoint
    } else {
        AwsNetworkManagerFamily::Route53ResolverRule
    };
    let resource_type = if endpoints {
        "route53_resolver_endpoint"
    } else {
        "route53_resolver_rule"
    };
    let mut fields = common_fields(
        account_id,
        region,
        family,
        identity,
        name,
        resource_type,
        &tags,
    );
    insert_string(&mut fields, "arn", arn);
    if endpoints {
        copy_string_fields(
            &mut fields,
            item,
            &[
                ("Arn", "endpoint_arn"),
                ("Id", "endpoint_id"),
                ("Name", "endpoint_name"),
                ("Direction", "direction"),
                ("HostVPCId", "host_vpc_id"),
                ("OutpostArn", "outpost_arn"),
                ("PreferredInstanceType", "preferred_instance_type"),
                ("ResolverEndpointType", "resolver_endpoint_type"),
                ("Status", "status"),
                ("StatusMessage", "status_message"),
            ],
        )?;
        fields.insert(
            "dns64_enabled".to_owned(),
            bool_member(item, "Dns64Enabled")?.to_string(),
        );
        fields.insert(
            "ip_address_count".to_owned(),
            number_string(item, "IpAddressCount")?,
        );
        fields.insert(
            "ipv6_internet_access_enabled".to_owned(),
            bool_member(item, "Ipv6InternetAccessEnabled")?.to_string(),
        );
        fields.insert(
            "protocols".to_owned(),
            string_array(item, "Protocols")?.join(","),
        );
        fields.insert(
            "rni_enhanced_metrics_enabled".to_owned(),
            bool_member(item, "RniEnhancedMetricsEnabled")?.to_string(),
        );
        fields.insert(
            "security_group_ids".to_owned(),
            string_array(item, "SecurityGroupIds")?.join(","),
        );
        fields.insert(
            "target_name_server_metrics_enabled".to_owned(),
            bool_member(item, "TargetNameServerMetricsEnabled")?.to_string(),
        );
    } else {
        copy_string_fields(
            &mut fields,
            item,
            &[
                ("Arn", "rule_arn"),
                ("Id", "rule_id"),
                ("Name", "rule_name"),
                ("DelegationRecord", "delegation_record"),
                ("DomainName", "domain_name"),
                ("OwnerId", "owner_id"),
                ("ResolverEndpointId", "resolver_endpoint_id"),
                ("RuleType", "rule_type"),
                ("ShareStatus", "share_status"),
                ("Status", "status"),
                ("StatusMessage", "status_message"),
            ],
        )?;
        let targets = optional_array(item, "TargetIps")?;
        let mut ips = Vec::new();
        let mut ports = Vec::new();
        let mut protocols = Vec::new();
        for target in targets {
            let target = value_object(target)?;
            if let Some(ip) =
                response_string_member(target, "Ip")?.or(response_string_member(target, "Ipv6")?)
            {
                ips.push(ip.to_owned());
            }
            let port = number_string(target, "Port")?;
            if !port.is_empty() {
                ports.push(port);
            }
            if let Some(protocol) = response_string_member(target, "Protocol")? {
                protocols.push(protocol.to_owned());
            }
        }
        fields.insert("target_ips".to_owned(), ips.join(","));
        fields.insert("target_ports".to_owned(), ports.join(","));
        fields.insert("target_protocols".to_owned(), protocols.join(","));
    }
    fields.insert("public".to_owned(), "false".to_owned());
    fields.insert("internet_exposed".to_owned(), "false".to_owned());
    let payload_key = if endpoints { "endpoint" } else { "rule" };
    let mut payload = Map::new();
    payload.insert("account_id".to_owned(), json!(account_id));
    payload.insert("region".to_owned(), json!(region));
    payload.insert(payload_key.to_owned(), Value::Object(item.clone()));
    payload.insert("tags".to_owned(), json!(tags));
    let prefix = if endpoints {
        "aws-route53-resolver-endpoint"
    } else {
        "aws-route53-resolver-rule"
    };
    Ok(record(
        family,
        format!("{prefix}-{identity}"),
        fields,
        Value::Object(payload),
    ))
}

fn common_fields(
    account_id: &str,
    region: &str,
    family: AwsNetworkManagerFamily,
    resource_id: &str,
    resource_name: &str,
    resource_type: &str,
    tags: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("domain".to_owned(), account_id.to_owned()),
        (
            "env".to_owned(),
            tag_lookup(tags, &["environment", "env", "stage"]),
        ),
        (
            "environment".to_owned(),
            tag_lookup(tags, &["environment", "env", "stage"]),
        ),
        ("family".to_owned(), family.id().to_owned()),
        (
            "owner".to_owned(),
            tag_lookup(
                tags,
                &[
                    "owner",
                    "application_owner",
                    "business_owner",
                    "service_owner",
                ],
            ),
        ),
        ("region".to_owned(), region.to_owned()),
        ("resource_id".to_owned(), resource_id.to_owned()),
        ("resource_name".to_owned(), resource_name.to_owned()),
        ("resource_provider".to_owned(), "aws".to_owned()),
        ("resource_type".to_owned(), resource_type.to_owned()),
        ("tags".to_owned(), encode_tags(tags)),
        (
            "team".to_owned(),
            tag_lookup(tags, &["team", "squad", "group"]),
        ),
    ])
}

fn tag_lookup(tags: &BTreeMap<String, String>, keys: &[&str]) -> String {
    let normalized = tags
        .iter()
        .map(|(key, value)| (normalize_tag_key(key), value))
        .collect::<BTreeMap<_, _>>();
    keys.iter()
        .find_map(|key| normalized.get(&normalize_tag_key(key)))
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or_default()
        .to_owned()
}

fn normalize_tag_key(value: &str) -> String {
    let mut normalized = value
        .trim()
        .to_ascii_lowercase()
        .replace(['-', ' ', '.'], "_");
    normalized = normalized.trim_matches('_').to_owned();
    while normalized.contains("__") {
        normalized = normalized.replace("__", "_");
    }
    normalized
}

fn encode_tags(tags: &BTreeMap<String, String>) -> String {
    tags.iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn record(
    family: AwsNetworkManagerFamily,
    provider_id: String,
    fields: BTreeMap<String, String>,
    payload: Value,
) -> AwsNetworkManagerRecord {
    AwsNetworkManagerRecord {
        family: family.id().to_owned(),
        provider_kind: family.provider_kind().to_owned(),
        schema_ref: family.schema_ref().to_owned(),
        provider_id,
        fields,
        payload,
    }
}

fn insert_string(fields: &mut BTreeMap<String, String>, key: &str, value: &str) {
    fields.insert(key.to_owned(), value.to_owned());
}

fn copy_string_fields(
    fields: &mut BTreeMap<String, String>,
    source: &Map<String, Value>,
    mappings: &[(&str, &str)],
) -> Result<(), AwsNetworkManagerError> {
    for (provider_key, field_key) in mappings {
        insert_string(
            fields,
            field_key,
            response_string_member(source, provider_key)?.unwrap_or_default(),
        );
    }
    Ok(())
}

fn empty_batch() -> AwsNetworkManagerBatch {
    AwsNetworkManagerBatch {
        records: Vec::new(),
        requests: Vec::new(),
        next_cursor: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "123456789012";
    const REGION: &str = "us-east-1";
    const CERTIFICATE_ARN: &str = "arn:aws:acm:us-east-1:123456789012:certificate/cert-123";
    const ENDPOINT_ARN: &str =
        "arn:aws:route53resolver:us-east-1:123456789012:resolver-endpoint/rslvr-in-123";
    const RULE_ARN: &str =
        "arn:aws:route53resolver:us-east-1:123456789012:resolver-rule/rslvr-rr-123";

    fn kernel() -> AwsNetworkManagerKernel {
        AwsNetworkManagerKernel::new(
            "https://acm.us-east-1.amazonaws.com",
            "https://route53resolver.us-east-1.amazonaws.com",
            ACCOUNT,
            REGION,
        )
        .expect("kernel")
    }

    fn decode(
        kernel: &AwsNetworkManagerKernel,
        request: &AwsNetworkManagerRequest,
        body: Value,
    ) -> AwsNetworkManagerBatch {
        kernel
            .decode(
                request,
                StatusCode::OK,
                None,
                &serde_json::to_vec(&body).expect("json"),
            )
            .expect("decode")
    }

    #[test]
    fn plans_exact_bounded_list_requests() {
        let kernel = kernel();
        let certificate = kernel
            .plan(AwsNetworkManagerFamily::AcmCertificate, Some("next-1"), 50)
            .expect("certificate request");
        assert_eq!(
            certificate.kind(),
            AwsNetworkManagerRequestKind::ListCertificates
        );
        assert_eq!(certificate.method(), "POST");
        assert_eq!(certificate.signing_service(), "acm");
        assert_eq!(
            certificate.amz_target(),
            "CertificateManager.ListCertificates"
        );
        assert_eq!(certificate.content_type(), AWS_JSON_CONTENT_TYPE);
        let body: Value = serde_json::from_slice(certificate.body()).expect("body");
        assert_eq!(body["MaxItems"], 50);
        assert_eq!(body["NextToken"], "next-1");
        assert_eq!(body["CertificateStatuses"], json!(ACM_STATUSES));

        let endpoint = kernel
            .plan(AwsNetworkManagerFamily::Route53ResolverEndpoint, None, 100)
            .expect("endpoint request");
        assert_eq!(endpoint.signing_service(), "route53resolver");
        assert_eq!(
            endpoint.amz_target(),
            "Route53Resolver.ListResolverEndpoints"
        );
        assert_eq!(
            serde_json::from_slice::<Value>(endpoint.body()).expect("body"),
            json!({"MaxResults": 100})
        );
    }

    #[test]
    fn certificate_fanout_preserves_go_identity_and_fields() {
        let kernel = kernel();
        let list = kernel
            .plan(AwsNetworkManagerFamily::AcmCertificate, None, 25)
            .expect("list");
        let listed = decode(
            &kernel,
            &list,
            json!({
                "CertificateSummaryList": [
                    {"CertificateArn": CERTIFICATE_ARN, "DomainName": "api.writer.com"},
                    {"DomainName": "missing-arn.example"}
                ],
                "NextToken": "page-2"
            }),
        );
        assert_eq!(listed.next_cursor.as_deref(), Some("page-2"));
        assert_eq!(listed.requests.len(), 1);
        let describe = &listed.requests[0];
        assert_eq!(
            describe.kind(),
            AwsNetworkManagerRequestKind::DescribeCertificate
        );
        assert_eq!(
            serde_json::from_slice::<Value>(describe.body()).expect("body"),
            json!({"CertificateArn": CERTIFICATE_ARN})
        );

        let described = decode(
            &kernel,
            describe,
            json!({"Certificate": {
                "CertificateArn": CERTIFICATE_ARN,
                "DomainName": "api.writer.com",
                "Status": "ISSUED",
                "Type": "AMAZON_ISSUED",
                "KeyAlgorithm": "RSA_2048",
                "SubjectAlternativeNames": ["api.writer.com", "www.writer.com"],
                "InUseBy": ["load-balancer-1"]
            }}),
        );
        assert_eq!(described.requests.len(), 1);
        let tags = &described.requests[0];
        assert_eq!(
            tags.kind(),
            AwsNetworkManagerRequestKind::ListCertificateTags
        );
        let tagged = decode(
            &kernel,
            tags,
            json!({"Tags": [{"Key": " Team ", "Value": " edge "}]}),
        );
        let record = &tagged.records[0];
        assert_eq!(
            record.provider_id,
            format!("aws-acm-certificate-{CERTIFICATE_ARN}")
        );
        assert_eq!(record.provider_kind, "aws.acm_certificate");
        assert_eq!(record.fields["status"], "ISSUED");
        assert_eq!(record.fields["domain"], ACCOUNT);
        assert_eq!(record.fields["resource_provider"], "aws");
        assert_eq!(record.fields["tags"], "Team=edge");
        assert_eq!(record.fields["team"], "edge");
        assert_eq!(record.fields["domain_name"], "api.writer.com");
        assert_eq!(
            record.fields["subject_alternative_names"],
            "api.writer.com,www.writer.com"
        );
        assert_eq!(record.payload["tags"]["Team"], "edge");
    }

    #[test]
    fn resolver_endpoint_fanout_normalizes_provider_contract() {
        let kernel = kernel();
        let list = kernel
            .plan(AwsNetworkManagerFamily::Route53ResolverEndpoint, None, 100)
            .expect("list");
        let listed = decode(
            &kernel,
            &list,
            json!({"ResolverEndpoints": [{
                "Arn": ENDPOINT_ARN,
                "Id": "rslvr-in-123",
                "Name": "corp-inbound",
                "Direction": "INBOUND",
                "HostVPCId": "vpc-123",
                "IpAddressCount": 2,
                "Protocols": ["Do53"],
                "SecurityGroupIds": ["sg-53"],
                "Status": "OPERATIONAL",
                "RniEnhancedMetricsEnabled": true
            }]}),
        );
        assert_eq!(listed.requests.len(), 1);
        let first_tags = decode(
            &kernel,
            &listed.requests[0],
            json!({
                "Tags": [{"Key": "Team", "Value": "network"}],
                "NextToken": "tag-page-2"
            }),
        );
        assert!(first_tags.records.is_empty());
        assert_eq!(first_tags.requests.len(), 1);
        assert_eq!(
            serde_json::from_slice::<Value>(first_tags.requests[0].body()).expect("body"),
            json!({
                "MaxResults": 100,
                "NextToken": "tag-page-2",
                "ResourceArn": ENDPOINT_ARN
            })
        );
        let tagged = decode(
            &kernel,
            &first_tags.requests[0],
            json!({"Tags": [{"Key": "Environment", "Value": "production"}]}),
        );
        let record = &tagged.records[0];
        assert_eq!(
            record.provider_id,
            format!("aws-route53-resolver-endpoint-{ENDPOINT_ARN}")
        );
        assert_eq!(record.fields["host_vpc_id"], "vpc-123");
        assert_eq!(record.fields["protocols"], "Do53");
        assert_eq!(record.fields["rni_enhanced_metrics_enabled"], "true");
        assert_eq!(record.fields["environment"], "production");
        assert_eq!(record.fields["env"], "production");
        assert_eq!(record.payload["tags"]["Team"], "network");
        assert_eq!(record.payload["tags"]["Environment"], "production");
    }

    #[test]
    fn resolver_rule_fanout_normalizes_targets() {
        let kernel = kernel();
        let list = kernel
            .plan(AwsNetworkManagerFamily::Route53ResolverRule, None, 100)
            .expect("list");
        let listed = decode(
            &kernel,
            &list,
            json!({"ResolverRules": [{
                "Arn": RULE_ARN,
                "Id": "rslvr-rr-123",
                "Name": "corp-example",
                "DomainName": "corp.example.com.",
                "ResolverEndpointId": "rslvr-out-123",
                "RuleType": "FORWARD",
                "Status": "COMPLETE",
                "TargetIps": [
                    {"Ip": "10.0.0.10", "Port": 53, "Protocol": "Do53"},
                    {"Ipv6": "2001:db8::53", "Port": 853, "Protocol": "DoT"}
                ]
            }], "NextToken": "rules-2"}),
        );
        assert_eq!(listed.next_cursor.as_deref(), Some("rules-2"));
        let tagged = decode(&kernel, &listed.requests[0], json!({"Tags": []}));
        let record = &tagged.records[0];
        assert_eq!(
            record.provider_id,
            format!("aws-route53-resolver-rule-{RULE_ARN}")
        );
        assert_eq!(record.fields["target_ips"], "10.0.0.10,2001:db8::53");
        assert_eq!(record.fields["target_ports"], "53,853");
        assert_eq!(record.fields["target_protocols"], "Do53,DoT");
    }

    #[test]
    fn untaggable_resolver_item_emits_without_fanout() {
        let kernel = kernel();
        let list = kernel
            .plan(AwsNetworkManagerFamily::Route53ResolverEndpoint, None, 10)
            .expect("list");
        let batch = decode(
            &kernel,
            &list,
            json!({"ResolverEndpoints": [{"Id": "rslvr-in-123", "Name": "local"}]}),
        );
        assert!(batch.requests.is_empty());
        assert_eq!(
            batch.records[0].provider_id,
            "aws-route53-resolver-endpoint-rslvr-in-123"
        );
    }

    #[test]
    fn optional_missing_certificate_tags_emit_empty_tags() {
        let kernel = kernel();
        let list = kernel
            .plan(AwsNetworkManagerFamily::AcmCertificate, None, 10)
            .expect("list");
        let described = decode(
            &kernel,
            &decode(
                &kernel,
                &list,
                json!({"CertificateSummaryList": [{"CertificateArn": CERTIFICATE_ARN}]}),
            )
            .requests[0],
            json!({"Certificate": {"CertificateArn": CERTIFICATE_ARN}}),
        );
        let batch = kernel
            .decode(
                &described.requests[0],
                StatusCode::BAD_REQUEST,
                Some("ResourceNotFoundException:detail"),
                b"not-json",
            )
            .expect("optional tags");
        assert_eq!(batch.records.len(), 1);
        assert_eq!(batch.records[0].payload["tags"], json!({}));
    }

    #[test]
    fn rejects_cross_kernel_requests_and_unsafe_inputs() {
        let request = kernel()
            .plan(AwsNetworkManagerFamily::AcmCertificate, None, 10)
            .expect("request");
        let other = AwsNetworkManagerKernel::new(
            "https://acm.us-west-2.amazonaws.com",
            "https://route53resolver.us-west-2.amazonaws.com",
            ACCOUNT,
            "us-west-2",
        )
        .expect("other");
        assert_eq!(
            other.decode(&request, StatusCode::OK, None, b"{}"),
            Err(AwsNetworkManagerError::RequestScopeMismatch)
        );
        assert_eq!(
            kernel().plan(
                AwsNetworkManagerFamily::Route53ResolverRule,
                Some("bad\ncursor"),
                10,
            ),
            Err(AwsNetworkManagerError::InvalidCursor)
        );
        assert_eq!(
            kernel().plan(AwsNetworkManagerFamily::Route53ResolverEndpoint, None, 101),
            Err(AwsNetworkManagerError::InvalidPageSize)
        );
        assert!(matches!(
            AwsNetworkManagerKernel::new(
                "http://acm.example.com",
                "https://resolver.example.com",
                ACCOUNT,
                REGION,
            ),
            Err(AwsNetworkManagerError::InvalidBaseUrl),
        ));
    }

    #[test]
    fn fails_closed_on_provider_errors_malformed_shapes_and_cursors() {
        let kernel = kernel();
        let request = kernel
            .plan(AwsNetworkManagerFamily::Route53ResolverRule, None, 10)
            .expect("request");
        assert_eq!(
            kernel.decode(
                &request,
                StatusCode::FORBIDDEN,
                Some("AccessDeniedException"),
                br#"{"message":"secret detail"}"#,
            ),
            Err(AwsNetworkManagerError::ProviderFailure {
                status: 403,
                code: Some("AccessDeniedException".to_owned()),
            })
        );
        assert_eq!(
            kernel.decode(&request, StatusCode::OK, None, br#"{"ResolverRules":{}}"#),
            Err(AwsNetworkManagerError::InvalidResponse)
        );
        let oversized_cursor = "x".repeat(MAX_CURSOR_BYTES + 1);
        let response = json!({"ResolverRules": [], "NextToken": oversized_cursor});
        assert_eq!(
            kernel.decode(
                &request,
                StatusCode::OK,
                None,
                &serde_json::to_vec(&response).expect("json"),
            ),
            Err(AwsNetworkManagerError::InvalidCursor)
        );
    }

    #[test]
    fn malformed_tag_members_fail_closed() {
        let kernel = kernel();
        let list = kernel
            .plan(AwsNetworkManagerFamily::Route53ResolverEndpoint, None, 10)
            .expect("list");
        let listed = decode(
            &kernel,
            &list,
            json!({"ResolverEndpoints": [{
                "Arn": ENDPOINT_ARN,
                "Id": "rslvr-in-123"
            }]}),
        );
        assert_eq!(
            kernel.decode(
                &listed.requests[0],
                StatusCode::OK,
                None,
                br#"{"Tags":[{"Key":"Team","Value":7}]}"#,
            ),
            Err(AwsNetworkManagerError::InvalidResponse)
        );
    }

    #[test]
    fn malformed_resolver_record_members_fail_closed() {
        let kernel = kernel();
        let endpoint_list = kernel
            .plan(AwsNetworkManagerFamily::Route53ResolverEndpoint, None, 10)
            .expect("endpoint list");
        let invalid_bool = decode(
            &kernel,
            &endpoint_list,
            json!({"ResolverEndpoints": [{
                "Arn": ENDPOINT_ARN,
                "Dns64Enabled": "false"
            }]}),
        );
        assert_eq!(
            kernel.decode(
                &invalid_bool.requests[0],
                StatusCode::OK,
                None,
                br#"{"Tags":[]}"#,
            ),
            Err(AwsNetworkManagerError::InvalidResponse)
        );

        let invalid_string = decode(
            &kernel,
            &endpoint_list,
            json!({"ResolverEndpoints": [{
                "Arn": ENDPOINT_ARN,
                "Status": 7
            }]}),
        );
        assert_eq!(
            kernel.decode(
                &invalid_string.requests[0],
                StatusCode::OK,
                None,
                br#"{"Tags":[]}"#,
            ),
            Err(AwsNetworkManagerError::InvalidResponse)
        );

        let rule_list = kernel
            .plan(AwsNetworkManagerFamily::Route53ResolverRule, None, 10)
            .expect("rule list");
        let invalid_targets = decode(
            &kernel,
            &rule_list,
            json!({"ResolverRules": [{
                "Arn": RULE_ARN,
                "TargetIps": {}
            }]}),
        );
        assert_eq!(
            kernel.decode(
                &invalid_targets.requests[0],
                StatusCode::OK,
                None,
                br#"{"Tags":[]}"#,
            ),
            Err(AwsNetworkManagerError::InvalidResponse)
        );
    }

    #[test]
    fn fails_closed_when_provider_identity_is_missing() {
        let kernel = kernel();
        let request = kernel
            .plan(AwsNetworkManagerFamily::Route53ResolverEndpoint, None, 10)
            .expect("request");
        assert_eq!(
            kernel.decode(
                &request,
                StatusCode::OK,
                None,
                br#"{"ResolverEndpoints":[{"Status":"OPERATIONAL"}]}"#,
            ),
            Err(AwsNetworkManagerError::MissingIdentity)
        );
    }
}
