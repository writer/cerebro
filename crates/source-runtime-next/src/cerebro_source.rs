//! Credential-free Cerebro access-telemetry decoding and normalization kernel.
//!
//! The Go source collects tenant-scoped S3 NDJSON archives through the shared
//! S3 adapter. Callers retain ownership of S3 access, role authorization,
//! decompression, pagination, and cursor state; this module accepts one bounded
//! archive record and reproduces the provider-local access-event contract.

use std::{
    collections::BTreeMap,
    error::Error,
    fmt::{self, Write as _},
    str::FromStr,
};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const MAX_RECORD_BYTES: usize = 1 << 20;
const ACCESS_EVENT_NAME: &str = "cerebro.api.access";
const ACCESS_PROVIDER_KIND: &str = "cerebro.api_access";
const ACCESS_ID_PREFIX: &str = "cerebro-api-access-";

const COPIED_ATTRIBUTES: [&str; 28] = [
    "auth_mode",
    "client_id",
    "connect_code",
    "connect_procedure",
    "credential_id",
    "denial_reason",
    "device_id",
    "duration_ms",
    "effective_status_code",
    "effective_tenant_id",
    "matched_scope",
    "missing_scopes",
    "operation_family",
    "operation_type",
    "principal",
    "principal_tenant_id",
    "remote_ip",
    "request_id",
    "requested_tenant_id",
    "required_scopes",
    "risk_level",
    "risk_score",
    "scopes",
    "sensitive_action",
    "status",
    "status_code",
    "tenant_id",
    "tenant_mismatch",
];

/// One portable Cerebro source family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CerebroSourceFamily {
    /// Cerebro API access-audit telemetry.
    Access,
}

impl CerebroSourceFamily {
    /// Return the source-catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Access => "access",
        }
    }

    /// Return the emitted provider kind.
    pub const fn provider_kind(self) -> &'static str {
        match self {
            Self::Access => ACCESS_PROVIDER_KIND,
        }
    }
}

impl FromStr for CerebroSourceFamily {
    type Err = CerebroSourceError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "access" => Ok(Self::Access),
            _ => Err(CerebroSourceError::InvalidFamily),
        }
    }
}

/// One normalized Cerebro access-telemetry record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CerebroSourceRecord {
    /// Source-catalog family identifier.
    pub family: String,
    /// Emitted provider kind.
    pub provider_kind: String,
    /// Stable Go-compatible event identity.
    pub provider_id: String,
    /// Validated provider occurrence timestamp.
    pub occurred_at: String,
    /// Go-compatible scalar attributes used by source mapping.
    pub fields: BTreeMap<String, String>,
    /// Original telemetry payload with no credentials added.
    pub payload: Value,
}

/// One decoded Cerebro archive record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CerebroSourcePage {
    /// The single normalized access event from the archive record.
    pub records: Vec<CerebroSourceRecord>,
    /// Archive pagination remains owned by the shared S3 NDJSON adapter.
    pub next_cursor: Option<String>,
}

/// Tenant-fenced decoder for one Cerebro access-telemetry archive record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CerebroSourceKernel {
    tenant_id: String,
}

impl CerebroSourceKernel {
    /// Build a credential-free decoder for one runtime tenant.
    pub fn new(tenant_id: &str) -> Result<Self, CerebroSourceError> {
        let tenant_id = tenant_id.trim();
        if tenant_id.is_empty() {
            return Err(CerebroSourceError::InvalidTenant);
        }
        Ok(Self {
            tenant_id: tenant_id.to_owned(),
        })
    }

    /// Return whether this provider-local decoder requires credential material.
    pub const fn requires_credentials(&self) -> bool {
        false
    }

    /// Decode one bounded NDJSON record and enforce the runtime tenant fence.
    pub fn decode(&self, body: &[u8]) -> Result<CerebroSourcePage, CerebroSourceError> {
        let body = trim_ascii_whitespace(body);
        if body.is_empty() {
            return Err(CerebroSourceError::InvalidTelemetry);
        }
        if body.len() > MAX_RECORD_BYTES {
            return Err(CerebroSourceError::RecordTooLarge);
        }
        let payload: Value =
            serde_json::from_slice(body).map_err(|_| CerebroSourceError::InvalidTelemetry)?;
        let object = payload
            .as_object()
            .ok_or(CerebroSourceError::InvalidTelemetry)?;
        if string_field(object, "name") != ACCESS_EVENT_NAME {
            return Err(CerebroSourceError::UnsupportedTelemetry);
        }

        let occurred_at = string_field(object, "ts");
        if occurred_at.is_empty() {
            return Err(CerebroSourceError::MissingTimestamp);
        }
        OffsetDateTime::parse(&occurred_at, &Rfc3339)
            .map_err(|_| CerebroSourceError::InvalidTimestamp)?;

        let fields = access_attributes(object);
        let event_tenant = fields
            .get("tenant_id")
            .map(String::as_str)
            .unwrap_or(&self.tenant_id);
        if event_tenant != self.tenant_id {
            return Err(CerebroSourceError::TenantScope);
        }

        let provider_id = access_event_id(object, body);
        Ok(CerebroSourcePage {
            records: vec![CerebroSourceRecord {
                family: CerebroSourceFamily::Access.as_str().to_owned(),
                provider_kind: ACCESS_PROVIDER_KIND.to_owned(),
                provider_id,
                occurred_at,
                fields,
                payload,
            }],
            next_cursor: None,
        })
    }
}

/// Safe Cerebro access-telemetry decoding failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CerebroSourceError {
    /// Family identifier is not the supported access contract.
    InvalidFamily,
    /// The runtime tenant is blank.
    InvalidTenant,
    /// The record is empty, malformed JSON, or not a JSON object.
    InvalidTelemetry,
    /// The record exceeds the shared S3 NDJSON line limit.
    RecordTooLarge,
    /// The record is not a Cerebro API access event.
    UnsupportedTelemetry,
    /// The record has no occurrence timestamp.
    MissingTimestamp,
    /// The occurrence timestamp is not RFC 3339.
    InvalidTimestamp,
    /// The record tenant differs from the source runtime tenant.
    TenantScope,
}

impl fmt::Display for CerebroSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "cerebro source family is invalid",
            Self::InvalidTenant => "cerebro source runtime tenant is invalid",
            Self::InvalidTelemetry => "cerebro access telemetry JSON is invalid",
            Self::RecordTooLarge => "cerebro access telemetry exceeds the shared NDJSON line limit",
            Self::UnsupportedTelemetry => "record is not cerebro API access telemetry",
            Self::MissingTimestamp => "cerebro access telemetry timestamp is required",
            Self::InvalidTimestamp => "cerebro access telemetry timestamp is invalid",
            Self::TenantScope => "cerebro access telemetry is outside the runtime tenant",
        })
    }
}

impl Error for CerebroSourceError {}

fn access_attributes(object: &Map<String, Value>) -> BTreeMap<String, String> {
    let route = string_field(object, "route");
    let connect_procedure = string_field(object, "connect_procedure");
    let client_ip = string_field(object, "client_ip");
    let remote_ip = string_field(object, "remote_ip");
    let mut fields = BTreeMap::from([
        (
            "event_type".to_owned(),
            first_nonblank(&[&route, &connect_procedure, "api_access"]),
        ),
        ("outcome_result".to_owned(), string_field(object, "outcome")),
        ("route".to_owned(), route),
        ("method".to_owned(), string_field(object, "method")),
        (
            "source_ip".to_owned(),
            first_nonblank(&[&client_ip, &remote_ip]),
        ),
        ("actor_user".to_owned(), string_field(object, "principal")),
        ("resource_type".to_owned(), "cerebro_api_route".to_owned()),
    ]);
    for key in COPIED_ATTRIBUTES {
        let value = string_field(object, key);
        if !value.is_empty() {
            fields.insert(key.to_owned(), value);
        }
    }
    if !fields.contains_key("tenant_mismatch") && tenant_mismatch(&fields) {
        fields.insert("tenant_mismatch".to_owned(), "true".to_owned());
    }
    fields
}

fn tenant_mismatch(fields: &BTreeMap<String, String>) -> bool {
    let effective = first_field(fields, &["effective_tenant_id", "tenant_id"]);
    let requested = first_field(fields, &["requested_tenant_id", "principal_tenant_id"]);
    effective.is_some() && requested.is_some() && requested != effective
}

fn access_event_id(object: &Map<String, Value>, raw: &[u8]) -> String {
    let request_id = string_field(object, "request_id");
    let suffix = if request_id.is_empty() {
        let digest = Sha256::digest(raw);
        let mut encoded = String::with_capacity(16);
        for byte in digest.iter().take(8) {
            write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
        }
        encoded
    } else {
        request_id
    };
    format!("{ACCESS_ID_PREFIX}{suffix}")
}

fn string_field(object: &Map<String, Value>, key: &str) -> String {
    scalar_string(object.get(key)).unwrap_or_default()
}

fn scalar_string(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(value) => nonblank(value).map(str::to_owned),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Array(values) => {
            let values = values
                .iter()
                .filter_map(|value| match value {
                    Value::String(value) => nonblank(value).map(str::to_owned),
                    Value::Number(value) => Some(value.to_string()),
                    Value::Bool(value) => Some(value.to_string()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join(",");
            (!values.is_empty()).then_some(values)
        }
        Value::Null | Value::Object(_) => None,
    }
}

fn first_nonblank(values: &[&str]) -> String {
    values
        .iter()
        .find_map(|value| nonblank(value))
        .unwrap_or_default()
        .to_owned()
}

fn first_field<'a>(fields: &'a BTreeMap<String, String>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| fields.get(*key).and_then(|value| nonblank(value)))
}

fn nonblank(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn trim_ascii_whitespace(mut body: &[u8]) -> &[u8] {
    while body.first().is_some_and(u8::is_ascii_whitespace) {
        body = &body[1..];
    }
    while body.last().is_some_and(u8::is_ascii_whitespace) {
        body = &body[..body.len() - 1];
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCESS_RECORD: &[u8] = br#"{
      "kind":"event",
      "name":"cerebro.api.access",
      "ts":"2026-06-09T12:00:00Z",
      "outcome":"allowed",
      "status":200,
      "method":"GET",
      "route":"GET /sources",
      "tenant_id":"writer",
      "effective_tenant_id":"writer",
      "requested_tenant_id":"writer",
      "principal":"ci@example.com",
      "client_ip":"198.51.100.7",
      "request_id":"audit-request-1",
      "required_scopes":["cerebro.cosmo.security.read"],
      "scopes":["cerebro.cosmo.security.read","cerebro.findings.write"],
      "sensitive_action":false
    }"#;

    fn decode(body: &[u8]) -> CerebroSourcePage {
        CerebroSourceKernel::new("writer")
            .unwrap()
            .decode(body)
            .unwrap()
    }

    #[test]
    fn access_record_matches_go_identity_scope_and_contract() {
        let page = decode(ACCESS_RECORD);
        assert_eq!(page.next_cursor, None);
        assert_eq!(page.records.len(), 1);
        let record = &page.records[0];
        assert_eq!(record.family, "access");
        assert_eq!(record.provider_kind, "cerebro.api_access");
        assert_eq!(record.provider_id, "cerebro-api-access-audit-request-1");
        assert_eq!(record.occurred_at, "2026-06-09T12:00:00Z");
        for (key, expected) in [
            ("event_type", "GET /sources"),
            ("outcome_result", "allowed"),
            ("method", "GET"),
            ("source_ip", "198.51.100.7"),
            ("actor_user", "ci@example.com"),
            ("resource_type", "cerebro_api_route"),
            (
                "scopes",
                "cerebro.cosmo.security.read,cerebro.findings.write",
            ),
            ("sensitive_action", "false"),
            ("status", "200"),
        ] {
            assert_eq!(record.fields.get(key).map(String::as_str), Some(expected));
        }
        assert_eq!(record.payload["request_id"], "audit-request-1");
        assert!(
            !CerebroSourceKernel::new("writer")
                .unwrap()
                .requires_credentials()
        );
    }

    #[test]
    fn scalar_projection_and_fallbacks_match_the_go_source() {
        let page = decode(
            br#"{
          "name":"cerebro.api.access",
          "ts":"2026-06-09T12:00:00.123456789Z",
          "outcome":true,
          "connect_procedure":"findings.list",
          "tenant_id":"writer",
          "principal":false,
          "remote_ip":"203.0.113.9",
          "required_scopes":["read",7,true,null,{"ignored":true},"  "]
        }"#,
        );
        let fields = &page.records[0].fields;
        assert_eq!(
            fields.get("event_type").map(String::as_str),
            Some("findings.list")
        );
        assert_eq!(
            fields.get("outcome_result").map(String::as_str),
            Some("true")
        );
        assert_eq!(fields.get("actor_user").map(String::as_str), Some("false"));
        assert_eq!(
            fields.get("source_ip").map(String::as_str),
            Some("203.0.113.9")
        );
        assert_eq!(
            fields.get("required_scopes").map(String::as_str),
            Some("read,7,true")
        );
    }

    #[test]
    fn tenant_mismatch_is_derived_but_an_explicit_value_is_preserved() {
        let derived = decode(
            br#"{
          "name":"cerebro.api.access",
          "ts":"2026-06-09T12:00:00Z",
          "tenant_id":"writer",
          "requested_tenant_id":"other"
        }"#,
        );
        assert_eq!(
            derived.records[0]
                .fields
                .get("tenant_mismatch")
                .map(String::as_str),
            Some("true")
        );

        let explicit = decode(
            br#"{
          "name":"cerebro.api.access",
          "ts":"2026-06-09T12:00:00Z",
          "tenant_id":"writer",
          "requested_tenant_id":"other",
          "tenant_mismatch":false
        }"#,
        );
        assert_eq!(
            explicit.records[0]
                .fields
                .get("tenant_mismatch")
                .map(String::as_str),
            Some("false")
        );
    }

    #[test]
    fn runtime_tenant_is_used_when_the_record_omits_tenant_id() {
        let record = decode(br#"{"name":"cerebro.api.access","ts":"2026-06-09T12:00:00Z"}"#)
            .records
            .remove(0);
        assert_eq!(record.fields.get("tenant_id"), None);
    }

    #[test]
    fn records_outside_the_runtime_tenant_fail_closed() {
        assert_eq!(
            CerebroSourceKernel::new("writer").unwrap().decode(
                br#"{"name":"cerebro.api.access","ts":"2026-06-09T12:00:00Z","tenant_id":"other"}"#
            ),
            Err(CerebroSourceError::TenantScope)
        );
        assert_eq!(
            CerebroSourceKernel::new("  "),
            Err(CerebroSourceError::InvalidTenant)
        );
    }

    #[test]
    fn unsupported_or_malformed_telemetry_fails_closed() {
        let kernel = CerebroSourceKernel::new("writer").unwrap();
        assert_eq!(
            kernel.decode(b"not-json"),
            Err(CerebroSourceError::InvalidTelemetry)
        );
        assert_eq!(
            kernel.decode(b"[]"),
            Err(CerebroSourceError::InvalidTelemetry)
        );
        assert_eq!(
            kernel.decode(br#"{"name":"other","ts":"2026-06-09T12:00:00Z"}"#),
            Err(CerebroSourceError::UnsupportedTelemetry)
        );
        assert_eq!(
            kernel.decode(br#"{"name":"cerebro.api.access"}"#),
            Err(CerebroSourceError::MissingTimestamp)
        );
        assert_eq!(
            kernel.decode(br#"{"name":"cerebro.api.access","ts":"yesterday"}"#),
            Err(CerebroSourceError::InvalidTimestamp)
        );
        assert_eq!(
            kernel.decode(&vec![b'x'; MAX_RECORD_BYTES + 1]),
            Err(CerebroSourceError::RecordTooLarge)
        );
    }

    #[test]
    fn fallback_identity_hashes_the_trimmed_ndjson_record() {
        let page =
            decode(b" \n{\"name\":\"cerebro.api.access\",\"ts\":\"2026-06-09T12:00:00Z\"}\t ");
        assert_eq!(
            page.records[0].provider_id,
            "cerebro-api-access-92eaff618dc72dac"
        );
    }

    #[test]
    fn family_parser_accepts_only_the_catalog_family() {
        assert_eq!("access".parse(), Ok(CerebroSourceFamily::Access));
        assert_eq!(
            "api_access".parse::<CerebroSourceFamily>(),
            Err(CerebroSourceError::InvalidFamily)
        );
    }
}
