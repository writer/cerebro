//! EvidenceCAS request, readiness, contract, response, and correlation kernel.
//!
//! The kernel models the portable public contract for EvidenceCAS without
//! embedding environment routes, credential values, deployment topology, or
//! authorization decisions. Callers must authorize the planned URL and obtain
//! an operation-scoped credential before issuing an object request.

use std::{collections::BTreeMap, error::Error, fmt, net::IpAddr, str::FromStr};

use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;

const DEFAULT_BUCKET: &str = "cases";
const MAX_BUCKET_LENGTH: usize = 128;

/// Portable configuration accepted by the EvidenceCAS object family.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvidenceCasConfig {
    /// EvidenceCAS bucket. Empty values use the portable `cases` default.
    pub bucket: Option<String>,
    /// Optional object-key prefix filter.
    pub prefix: Option<String>,
    /// Optional object tag filter.
    pub tag: Option<String>,
}

/// Purpose of one credential-free EvidenceCAS request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceCasRequestKind {
    /// Service readiness probe.
    Readiness,
    /// Portable route-contract probe.
    Contract,
    /// Evidence object reference collection.
    Objects,
}

/// One credential-free HTTP request planned by the EvidenceCAS kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceCasRequest {
    url: Url,
    kind: EvidenceCasRequestKind,
}

impl EvidenceCasRequest {
    /// Return the exact request URL. The caller must authorize it before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return the portable request purpose.
    pub const fn kind(&self) -> EvidenceCasRequestKind {
        self.kind
    }

    /// Return the authorization scheme required by this request.
    ///
    /// Control routes are unauthenticated in the portable contract. Object
    /// collection requires a bearer credential supplied by the caller.
    pub const fn authorization_scheme(&self) -> Option<&'static str> {
        match self.kind {
            EvidenceCasRequestKind::Objects => Some("Bearer"),
            EvidenceCasRequestKind::Readiness | EvidenceCasRequestKind::Contract => None,
        }
    }

    /// Return the required response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }
}

/// Validated EvidenceCAS route contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceCasContract {
    /// Portable service identity returned by EvidenceCAS.
    pub service: String,
    /// Positive version of the portable route contract.
    pub route_contract_version: u64,
}

/// One normalized EvidenceCAS object reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceCasRecord {
    /// Source-catalog family identifier.
    pub family: String,
    /// Emitted provider kind.
    pub provider_kind: String,
    /// Stable provider identity, preferring URI and falling back to digest.
    pub provider_id: String,
    /// Canonical occurrence timestamp selected by the Go-compatible precedence.
    pub occurred_at: Option<String>,
    /// Portable scalar attributes used by source mapping and correlation.
    pub fields: BTreeMap<String, String>,
    /// Original provider object, including unrecognized metadata.
    pub payload: Value,
}

/// A complete, non-paginated EvidenceCAS object response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceCasPage {
    /// Normalized object references in provider order.
    pub records: Vec<EvidenceCasRecord>,
    /// EvidenceCAS exposes no cursor in the current portable object contract.
    pub next_cursor: Option<String>,
}

/// Provider-specific EvidenceCAS request and response kernel.
#[derive(Clone, Debug)]
pub struct EvidenceCasKernel {
    base_url: Url,
    bucket: String,
    prefix: Option<String>,
    tag: Option<String>,
}

impl EvidenceCasKernel {
    /// Build a kernel for one EvidenceCAS origin and portable configuration.
    ///
    /// The returned plans still require shared live-egress authorization. This
    /// type never accepts or stores a credential value.
    pub fn new(base_url: &str, config: EvidenceCasConfig) -> Result<Self, EvidenceCasError> {
        let base_url = validate_origin(base_url)?;
        let bucket = nonblank(config.bucket.as_deref())
            .unwrap_or(DEFAULT_BUCKET)
            .to_owned();
        validate_bucket(&bucket)?;
        Ok(Self {
            base_url,
            bucket,
            prefix: nonblank(config.prefix.as_deref()).map(str::to_owned),
            tag: nonblank(config.tag.as_deref()).map(str::to_owned),
        })
    }

    /// Plan the service readiness request.
    pub fn plan_readiness(&self) -> Result<EvidenceCasRequest, EvidenceCasError> {
        self.request("/readyz", EvidenceCasRequestKind::Readiness)
    }

    /// Plan the portable route-contract request.
    pub fn plan_contract(&self) -> Result<EvidenceCasRequest, EvidenceCasError> {
        self.request("/v1/contract", EvidenceCasRequestKind::Contract)
    }

    /// Plan the object reference read, including portable bucket and filters.
    pub fn plan_objects(&self) -> Result<EvidenceCasRequest, EvidenceCasError> {
        let path = format!("/v1/b/{}/refs", self.bucket);
        let mut request = self.request(&path, EvidenceCasRequestKind::Objects)?;
        if self.prefix.is_some() || self.tag.is_some() {
            let mut query = request.url.query_pairs_mut();
            if let Some(prefix) = self.prefix.as_deref() {
                query.append_pair("prefix", prefix);
            }
            if let Some(tag) = self.tag.as_deref() {
                query.append_pair("tag", tag);
            }
        }
        Ok(request)
    }

    /// Validate the body returned for a planned readiness request.
    pub fn decode_readiness(
        &self,
        request: &EvidenceCasRequest,
        body: &[u8],
    ) -> Result<(), EvidenceCasError> {
        self.validate_request(request, EvidenceCasRequestKind::Readiness)?;
        let response: ReadinessResponse =
            serde_json::from_slice(body).map_err(|_| EvidenceCasError::InvalidResponse)?;
        if !response.ok {
            return Err(EvidenceCasError::NotReady);
        }
        Ok(())
    }

    /// Validate and return the portable route contract.
    pub fn decode_contract(
        &self,
        request: &EvidenceCasRequest,
        body: &[u8],
    ) -> Result<EvidenceCasContract, EvidenceCasError> {
        self.validate_request(request, EvidenceCasRequestKind::Contract)?;
        let response: ContractResponse =
            serde_json::from_slice(body).map_err(|_| EvidenceCasError::InvalidResponse)?;
        if response.service != "evidence-cas" {
            return Err(EvidenceCasError::ContractServiceMismatch);
        }
        if response.route_contract_version < 1 {
            return Err(EvidenceCasError::ContractVersionUnsupported);
        }
        Ok(EvidenceCasContract {
            service: response.service,
            route_contract_version: response.route_contract_version,
        })
    }

    /// Decode the portable `objects` envelope and its correlation attributes.
    pub fn decode_objects(
        &self,
        request: &EvidenceCasRequest,
        body: &[u8],
    ) -> Result<EvidenceCasPage, EvidenceCasError> {
        self.validate_request(request, EvidenceCasRequestKind::Objects)?;
        let root: Value =
            serde_json::from_slice(body).map_err(|_| EvidenceCasError::InvalidResponse)?;
        let objects = root
            .as_object()
            .and_then(|root| root.get("objects"))
            .and_then(Value::as_array)
            .ok_or(EvidenceCasError::InvalidResponse)?;
        let records = objects
            .iter()
            .cloned()
            .map(normalize_record)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(EvidenceCasPage {
            records,
            next_cursor: None,
        })
    }

    fn request(
        &self,
        path: &str,
        kind: EvidenceCasRequestKind,
    ) -> Result<EvidenceCasRequest, EvidenceCasError> {
        let url = self
            .base_url
            .join(path.trim_start_matches('/'))
            .map_err(|_| EvidenceCasError::InvalidBaseUrl)?;
        Ok(EvidenceCasRequest { url, kind })
    }

    fn validate_request(
        &self,
        request: &EvidenceCasRequest,
        kind: EvidenceCasRequestKind,
    ) -> Result<(), EvidenceCasError> {
        if request.kind != kind || request.url.origin() != self.base_url.origin() {
            return Err(EvidenceCasError::RequestScopeMismatch);
        }
        Ok(())
    }
}

/// Safe EvidenceCAS kernel failures. Messages never include credential values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceCasError {
    /// Base URL is not a secure provider origin.
    InvalidBaseUrl,
    /// Bucket is empty, too long, or contains a path-unsafe character.
    InvalidBucket,
    /// Response JSON does not match the selected portable contract.
    InvalidResponse,
    /// The service reports that it is not ready.
    NotReady,
    /// The control response names a service other than EvidenceCAS.
    ContractServiceMismatch,
    /// The control response does not advertise a positive route-contract version.
    ContractVersionUnsupported,
    /// An object omitted both portable stable identity fields.
    MissingRecordIdentity,
    /// A response was decoded against a request from another origin or stage.
    RequestScopeMismatch,
}

impl fmt::Display for EvidenceCasError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidBaseUrl => "evidence_cas base URL must be a secure origin",
            Self::InvalidBucket => "evidence_cas bucket is invalid",
            Self::InvalidResponse => "evidence_cas response does not match the portable contract",
            Self::NotReady => "evidence_cas readiness check failed",
            Self::ContractServiceMismatch => "evidence_cas contract service is invalid",
            Self::ContractVersionUnsupported => {
                "evidence_cas route contract version must be positive"
            }
            Self::MissingRecordIdentity => "evidence_cas object identity is missing",
            Self::RequestScopeMismatch => {
                "evidence_cas request origin or purpose does not match the kernel"
            }
        })
    }
}

impl Error for EvidenceCasError {}

#[derive(Deserialize)]
struct ReadinessResponse {
    ok: bool,
}

#[derive(Deserialize)]
struct ContractResponse {
    service: String,
    route_contract_version: u64,
}

fn validate_origin(raw: &str) -> Result<Url, EvidenceCasError> {
    let mut url = Url::parse(raw.trim()).map_err(|_| EvidenceCasError::InvalidBaseUrl)?;
    let host = url.host_str().ok_or(EvidenceCasError::InvalidBaseUrl)?;
    let loopback =
        host == "localhost" || IpAddr::from_str(host).is_ok_and(|address| address.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(EvidenceCasError::InvalidBaseUrl);
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(EvidenceCasError::InvalidBaseUrl);
    }
    if IpAddr::from_str(host).is_ok_and(|address| unsafe_ip_literal(address, loopback)) {
        return Err(EvidenceCasError::InvalidBaseUrl);
    }
    if url.port().is_some_and(|port| port != 443) && !loopback {
        return Err(EvidenceCasError::InvalidBaseUrl);
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

fn validate_bucket(bucket: &str) -> Result<(), EvidenceCasError> {
    if bucket.is_empty() || bucket.len() > MAX_BUCKET_LENGTH {
        return Err(EvidenceCasError::InvalidBucket);
    }
    for (index, byte) in bucket.bytes().enumerate() {
        if (index == 0 && !byte.is_ascii_alphanumeric())
            || !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(EvidenceCasError::InvalidBucket);
        }
    }
    Ok(())
}

fn normalize_record(payload: Value) -> Result<EvidenceCasRecord, EvidenceCasError> {
    if !payload.is_object() {
        return Err(EvidenceCasError::InvalidResponse);
    }
    let provider_id = first_scalar(&payload, &["uri", "digest"])
        .ok_or(EvidenceCasError::MissingRecordIdentity)?;
    let occurred_at = first_scalar(
        &payload,
        &[
            "metadata.occurred_at",
            "occurred_at",
            "metadata.observed_at",
            "observed_at",
            "updated_at",
        ],
    );
    let mut fields = BTreeMap::new();
    for (attribute, paths) in attribute_paths() {
        if let Some(value) = first_scalar(&payload, paths) {
            fields.insert((*attribute).to_owned(), value);
        }
    }
    fields.insert("source_product".to_owned(), "evidence_cas".to_owned());
    fields.insert(
        "evidence_type".to_owned(),
        "evidence_cas.artifact".to_owned(),
    );
    Ok(EvidenceCasRecord {
        family: "object".to_owned(),
        provider_kind: "evidence_cas.object".to_owned(),
        provider_id,
        occurred_at,
        fields,
        payload,
    })
}

fn attribute_paths() -> &'static [(&'static str, &'static [&'static str])] {
    &[
        ("tenant_id", &["metadata.tenant_id", "tenant_id"]),
        ("evidence_id", &["metadata.evidence_id", "uri", "key"]),
        ("resource_urn", &["metadata.resource_urn"]),
        (
            "source_runtime_id",
            &["metadata.source_runtime_id", "source_runtime_id"],
        ),
        (
            "source_event_id",
            &[
                "metadata.source_event_id",
                "source_event_id",
                "metadata.event_id",
                "event_id",
            ],
        ),
        ("request_id", &["metadata.request_id", "request_id"]),
        ("trace_id", &["metadata.trace_id", "trace_id"]),
        ("traceparent", &["metadata.traceparent", "traceparent"]),
        ("occurred_at", &["metadata.occurred_at", "occurred_at"]),
        (
            "observed_at",
            &["metadata.observed_at", "observed_at", "updated_at"],
        ),
        ("case_id", &["metadata.case_id"]),
        ("case_urn", &["metadata.case_urn"]),
        ("case_link_status", &["metadata.case_link_status"]),
        ("resource_entity_type", &["metadata.resource_entity_type"]),
        ("resource_id", &["metadata.resource_id"]),
        ("resource_link_status", &["metadata.resource_link_status"]),
        (
            "resource_name",
            &["metadata.resource_name", "metadata.filename"],
        ),
        ("resource_type", &["metadata.resource_type"]),
        ("source_system", &["metadata.source_system"]),
        (
            "unresolved_case_context",
            &["metadata.unresolved_case_context"],
        ),
        (
            "unresolved_resource_context",
            &["metadata.unresolved_resource_context"],
        ),
        ("evidence_cas_uri", &["uri"]),
        ("evidence_cas_digest", &["digest"]),
        ("evidence_cas_manifest_version", &["manifest_version"]),
        ("evidence_cas_merkle_root", &["merkle_root"]),
        ("evidence_cas_commit_id", &["commit_id"]),
        ("evidence_cas_content_type", &["content_type"]),
        ("evidence_cas_size_bytes", &["size"]),
        ("evidence_cas_blocks_count", &["blocks_count"]),
        ("evidence_cas_ref_type", &["ref_type"]),
    ]
}

fn first_scalar(root: &Value, paths: &[&str]) -> Option<String> {
    paths
        .iter()
        .find_map(|path| value_at_path(root, path).and_then(scalar_string))
}

fn value_at_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.')
        .try_fold(root, |value, segment| value.as_object()?.get(segment))
}

fn scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => nonblank(Some(value)).map(str::to_owned),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn nonblank(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel() -> EvidenceCasKernel {
        EvidenceCasKernel::new(
            "https://evidence-cas.example.test",
            EvidenceCasConfig::default(),
        )
        .unwrap()
    }

    #[test]
    fn plans_control_and_default_object_contract_without_credentials() {
        let kernel = kernel();
        let readiness = kernel.plan_readiness().unwrap();
        assert_eq!(
            readiness.url().as_str(),
            "https://evidence-cas.example.test/readyz"
        );
        assert_eq!(readiness.kind(), EvidenceCasRequestKind::Readiness);
        assert_eq!(readiness.authorization_scheme(), None);

        let contract = kernel.plan_contract().unwrap();
        assert_eq!(contract.url().path(), "/v1/contract");
        assert_eq!(contract.authorization_scheme(), None);

        let objects = kernel.plan_objects().unwrap();
        assert_eq!(objects.url().path(), "/v1/b/cases/refs");
        assert_eq!(objects.url().query(), None);
        assert_eq!(objects.authorization_scheme(), Some("Bearer"));
        assert_eq!(objects.accept(), "application/json");
    }

    #[test]
    fn custom_bucket_and_filters_match_the_go_request_contract() {
        let kernel = EvidenceCasKernel::new(
            "https://evidence-cas.example.test",
            EvidenceCasConfig {
                bucket: Some("trusted-endpoint".to_owned()),
                prefix: Some("agents/".to_owned()),
                tag: Some("endpoint".to_owned()),
            },
        )
        .unwrap();
        let request = kernel.plan_objects().unwrap();
        assert_eq!(request.url().path(), "/v1/b/trusted-endpoint/refs");
        assert_eq!(request.url().query(), Some("prefix=agents%2F&tag=endpoint"));
    }

    #[test]
    fn bucket_validation_is_fail_closed() {
        for bucket in ["../cases", "-cases", "cases/path", "cases space", "cáses"] {
            assert_eq!(
                EvidenceCasKernel::new(
                    "https://evidence-cas.example.test",
                    EvidenceCasConfig {
                        bucket: Some(bucket.to_owned()),
                        ..EvidenceCasConfig::default()
                    },
                )
                .unwrap_err(),
                EvidenceCasError::InvalidBucket
            );
        }
        assert_eq!(
            EvidenceCasKernel::new(
                "https://evidence-cas.example.test",
                EvidenceCasConfig {
                    bucket: Some("a".repeat(129)),
                    ..EvidenceCasConfig::default()
                },
            )
            .unwrap_err(),
            EvidenceCasError::InvalidBucket
        );
    }

    #[test]
    fn origin_validation_rejects_embedded_authority_and_paths() {
        for origin in [
            "http://evidence-cas.example.test",
            "https://token@evidence-cas.example.test",
            "https://evidence-cas.example.test/private",
            "https://10.0.0.1",
        ] {
            assert_eq!(
                EvidenceCasKernel::new(origin, EvidenceCasConfig::default()).unwrap_err(),
                EvidenceCasError::InvalidBaseUrl
            );
        }
        EvidenceCasKernel::new("http://127.0.0.1:8080", EvidenceCasConfig::default()).unwrap();
    }

    #[test]
    fn readiness_and_contract_are_strict_and_request_bound() {
        let kernel = kernel();
        let readiness = kernel.plan_readiness().unwrap();
        kernel
            .decode_readiness(&readiness, br#"{"ok":true}"#)
            .unwrap();
        assert_eq!(
            kernel.decode_readiness(&readiness, br#"{"ok":false}"#),
            Err(EvidenceCasError::NotReady)
        );
        let contract = kernel.plan_contract().unwrap();
        assert_eq!(
            kernel
                .decode_contract(
                    &contract,
                    br#"{"service":"evidence-cas","route_contract_version":2}"#,
                )
                .unwrap(),
            EvidenceCasContract {
                service: "evidence-cas".to_owned(),
                route_contract_version: 2,
            }
        );
        assert_eq!(
            kernel.decode_contract(
                &contract,
                br#"{"service":"other","route_contract_version":1}"#,
            ),
            Err(EvidenceCasError::ContractServiceMismatch)
        );
        assert_eq!(
            kernel.decode_contract(
                &contract,
                br#"{"service":"evidence-cas","route_contract_version":0}"#,
            ),
            Err(EvidenceCasError::ContractVersionUnsupported)
        );
        assert_eq!(
            kernel.decode_readiness(&contract, br#"{"ok":true}"#),
            Err(EvidenceCasError::RequestScopeMismatch)
        );
    }

    #[test]
    fn object_response_preserves_identity_correlation_and_payload() {
        let kernel = kernel();
        let request = kernel.plan_objects().unwrap();
        let body = br#"{
            "objects": [{
                "ref_type": "evidencecas.manifest.v2",
                "uri": "evidencecas://cases/case-123/evidence/evidence-456",
                "key": "case-123/evidence/evidence-456",
                "digest": "sha256canonical",
                "size": 42,
                "content_type": "application/json",
                "manifest_version": 2,
                "merkle_root": "merkle-root",
                "commit_id": "commit-123",
                "blocks_count": 3,
                "updated_at": "2026-06-06T00:05:00Z",
                "metadata": {
                    "tenant_id": "tenant-123",
                    "source_system": "iris",
                    "source_runtime_id": "iris-evidencecas-runtime",
                    "source_event_id": "iris-event-123",
                    "case_id": "case-123",
                    "case_urn": "urn:cerebro:tenant-123:case:case-123",
                    "evidence_id": "evidence-456",
                    "resource_urn": "urn:cerebro:tenant-123:case:case-123",
                    "resource_entity_type": "case",
                    "filename": "evidence.json",
                    "resource_link_status": "missing",
                    "case_link_status": "linked",
                    "unresolved_resource_context": true,
                    "unresolved_case_context": false,
                    "request_id": "request-123",
                    "trace_id": "trace-123",
                    "traceparent": "00-00000000000000000000000000000123-0000000000000123-01",
                    "occurred_at": "2026-06-06T00:00:00Z",
                    "observed_at": "2026-06-06T00:03:00Z",
                    "legacy_case_key": "legacy-case-123"
                }
            }]
        }"#;
        let page = kernel.decode_objects(&request, body).unwrap();
        assert_eq!(page.next_cursor, None);
        assert_eq!(page.records.len(), 1);
        let record = &page.records[0];
        assert_eq!(record.family, "object");
        assert_eq!(record.provider_kind, "evidence_cas.object");
        assert_eq!(
            record.provider_id,
            "evidencecas://cases/case-123/evidence/evidence-456"
        );
        assert_eq!(record.occurred_at.as_deref(), Some("2026-06-06T00:00:00Z"));
        for (key, expected) in [
            ("tenant_id", "tenant-123"),
            ("source_system", "iris"),
            ("source_runtime_id", "iris-evidencecas-runtime"),
            ("source_event_id", "iris-event-123"),
            ("case_id", "case-123"),
            ("case_urn", "urn:cerebro:tenant-123:case:case-123"),
            ("evidence_id", "evidence-456"),
            ("resource_name", "evidence.json"),
            ("resource_link_status", "missing"),
            ("case_link_status", "linked"),
            ("unresolved_resource_context", "true"),
            ("unresolved_case_context", "false"),
            ("evidence_cas_digest", "sha256canonical"),
            ("evidence_cas_manifest_version", "2"),
            ("evidence_cas_size_bytes", "42"),
            ("evidence_cas_blocks_count", "3"),
            ("source_product", "evidence_cas"),
            ("evidence_type", "evidence_cas.artifact"),
        ] {
            assert_eq!(record.fields.get(key).map(String::as_str), Some(expected));
        }
        assert_eq!(
            record.payload["metadata"]["legacy_case_key"],
            "legacy-case-123"
        );
    }

    #[test]
    fn timestamp_precedence_and_identity_fallback_match_the_go_contract() {
        let kernel = kernel();
        let request = kernel.plan_objects().unwrap();
        let page = kernel
            .decode_objects(
                &request,
                br#"{"objects":[
                    {"digest":"sha256first","updated_at":"2026-06-06T00:05:00Z","observed_at":"2026-06-06T00:04:00Z","metadata":{"observed_at":"2026-06-06T00:03:00Z"}},
                    {"uri":"evidencecas://cases/second","digest":"sha256second","occurred_at":"2026-06-06T00:02:00Z"}
                ]}"#,
            )
            .unwrap();
        assert_eq!(page.records[0].provider_id, "sha256first");
        assert_eq!(
            page.records[0].occurred_at.as_deref(),
            Some("2026-06-06T00:03:00Z")
        );
        assert_eq!(page.records[1].provider_id, "evidencecas://cases/second");
        assert_eq!(
            page.records[1].occurred_at.as_deref(),
            Some("2026-06-06T00:02:00Z")
        );
    }

    #[test]
    fn malformed_envelopes_and_missing_identity_fail_closed() {
        let kernel = kernel();
        let request = kernel.plan_objects().unwrap();
        assert_eq!(
            kernel.decode_objects(&request, br#"{"items":[]}"#),
            Err(EvidenceCasError::InvalidResponse)
        );
        assert_eq!(
            kernel.decode_objects(&request, br#"{"objects":[{"key":"only-key"}]}"#),
            Err(EvidenceCasError::MissingRecordIdentity)
        );
    }
}
