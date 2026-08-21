//! Security Tooling Map request planning, decoding, and normalization kernel.
//!
//! The provider exposes two non-paginated JSON collections. This module keeps
//! provider-owned paths, envelopes, identities, and coverage vocabulary out of
//! the generic HTTP runtime. Callers still own live-egress decisions and
//! operation-scoped bearer credential handling.

use std::{collections::BTreeMap, error::Error, fmt, net::IpAddr, str::FromStr};

use reqwest::Url;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const SOURCE_ID: &str = "security_tooling_map";

/// One portable Security Tooling Map collection family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityToolingMapFamily {
    /// Security and GRC tool inventory.
    Tool,
    /// Relationships between tools and security controls.
    ControlMapping,
}

impl SecurityToolingMapFamily {
    /// Return the source-catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tool => "tool",
            Self::ControlMapping => "control_mapping",
        }
    }

    /// Return the emitted provider kind.
    pub const fn provider_kind(self) -> &'static str {
        match self {
            Self::Tool => "security_tooling_map.tool",
            Self::ControlMapping => "security_tooling_map.control_mapping",
        }
    }

    const fn path(self) -> &'static str {
        match self {
            Self::Tool => "/tools",
            Self::ControlMapping => "/control-mappings",
        }
    }

    const fn envelope_keys(self) -> &'static [&'static str] {
        match self {
            Self::Tool => &["tool", "tools"],
            Self::ControlMapping => &[
                "control_mapping",
                "control_mappings",
                "controlmapping",
                "controlmappings",
            ],
        }
    }
}

impl FromStr for SecurityToolingMapFamily {
    type Err = SecurityToolingMapError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "tool" => Ok(Self::Tool),
            "control_mapping" => Ok(Self::ControlMapping),
            _ => Err(SecurityToolingMapError::InvalidFamily),
        }
    }
}

/// One credential-free HTTP request planned by the provider kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityToolingMapRequest {
    url: Url,
    family: SecurityToolingMapFamily,
}

impl SecurityToolingMapRequest {
    /// Return the exact provider URL. The caller must authorize it before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return the required authorization scheme without credential material.
    pub const fn authorization_scheme(&self) -> &'static str {
        "Bearer"
    }

    /// Return the required response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }
}

/// One normalized Security Tooling Map provider record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityToolingMapRecord {
    /// Source-catalog family identifier.
    pub family: String,
    /// Emitted provider kind.
    pub provider_kind: String,
    /// Stable provider identity or deterministic fallback digest.
    pub provider_id: String,
    /// Portable scalar attributes selected by the Go source contract.
    pub fields: BTreeMap<String, String>,
    /// Original provider record without credential material.
    pub payload: Value,
}

/// One complete, non-paginated provider result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityToolingMapPage {
    /// Normalized records in provider order.
    pub records: Vec<SecurityToolingMapRecord>,
    /// This provider contract has no continuation cursor.
    pub next_cursor: Option<String>,
}

/// Provider-specific Security Tooling Map request and response kernel.
#[derive(Clone, Debug)]
pub struct SecurityToolingMapKernel {
    base_url: Url,
    family: SecurityToolingMapFamily,
}

impl SecurityToolingMapKernel {
    /// Build a kernel for one configured provider origin and family.
    ///
    /// The returned request still requires the shared live-egress decision and
    /// an operation-scoped bearer credential lease before network access.
    pub fn new(
        base_url: &str,
        family: SecurityToolingMapFamily,
    ) -> Result<Self, SecurityToolingMapError> {
        Ok(Self {
            base_url: validate_origin(base_url)?,
            family,
        })
    }

    /// Plan the family's only credential-free collection request.
    pub fn plan(
        &self,
        cursor: Option<&str>,
    ) -> Result<SecurityToolingMapRequest, SecurityToolingMapError> {
        if cursor.is_some_and(|value| !value.trim().is_empty()) {
            return Err(SecurityToolingMapError::UnsupportedCursor);
        }
        let url = self
            .base_url
            .join(self.family.path().trim_start_matches('/'))
            .map_err(|_| SecurityToolingMapError::InvalidBaseUrl)?;
        Ok(SecurityToolingMapRequest {
            url,
            family: self.family,
        })
    }

    /// Decode a response for a request produced by this kernel.
    pub fn decode(
        &self,
        request: &SecurityToolingMapRequest,
        body: &[u8],
    ) -> Result<SecurityToolingMapPage, SecurityToolingMapError> {
        let expected = self.plan(None)?;
        if request.family != self.family || request.url != expected.url {
            return Err(SecurityToolingMapError::RequestScopeMismatch);
        }
        let records = decode_records(self.family, body)?
            .into_iter()
            .filter_map(|payload| normalize_record(self.family, payload))
            .collect();
        Ok(SecurityToolingMapPage {
            records,
            next_cursor: None,
        })
    }
}

/// Safe provider-kernel failures. Messages never contain credential values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecurityToolingMapError {
    /// Family identifier is not one of the two supported contracts.
    InvalidFamily,
    /// Configured base URL is not a secure provider origin.
    InvalidBaseUrl,
    /// The Go source contract does not define provider pagination.
    UnsupportedCursor,
    /// Response JSON does not contain a supported record list.
    InvalidResponse,
    /// A request was decoded by a kernel for another family or origin.
    RequestScopeMismatch,
}

impl fmt::Display for SecurityToolingMapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "security tooling map family is invalid",
            Self::InvalidBaseUrl => "security tooling map base URL must be a secure origin",
            Self::UnsupportedCursor => "security tooling map does not support cursors",
            Self::InvalidResponse => "security tooling map response JSON is invalid",
            Self::RequestScopeMismatch => {
                "security tooling map request does not match the configured kernel"
            }
        })
    }
}

impl Error for SecurityToolingMapError {}

fn validate_origin(raw: &str) -> Result<Url, SecurityToolingMapError> {
    let mut url = Url::parse(raw.trim()).map_err(|_| SecurityToolingMapError::InvalidBaseUrl)?;
    let host = url
        .host_str()
        .ok_or(SecurityToolingMapError::InvalidBaseUrl)?;
    let loopback =
        host == "localhost" || IpAddr::from_str(host).is_ok_and(|address| address.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(SecurityToolingMapError::InvalidBaseUrl);
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(SecurityToolingMapError::InvalidBaseUrl);
    }
    if IpAddr::from_str(host).is_ok_and(|address| unsafe_ip_literal(address, loopback)) {
        return Err(SecurityToolingMapError::InvalidBaseUrl);
    }
    if url.port().is_some_and(|port| port != 443) && !loopback {
        return Err(SecurityToolingMapError::InvalidBaseUrl);
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

fn decode_records(
    family: SecurityToolingMapFamily,
    body: &[u8],
) -> Result<Vec<Value>, SecurityToolingMapError> {
    let root: Value =
        serde_json::from_slice(body).map_err(|_| SecurityToolingMapError::InvalidResponse)?;
    if let Value::Array(records) = root {
        return validate_records(records);
    }
    let object = root
        .as_object()
        .ok_or(SecurityToolingMapError::InvalidResponse)?;
    for key in ["data", "items", "results", "records"]
        .into_iter()
        .chain(family.envelope_keys().iter().copied())
    {
        match object.get(key) {
            Some(Value::Array(records)) => return validate_records(records.clone()),
            Some(Value::Null) => return Ok(Vec::new()),
            Some(_) | None => {}
        }
    }
    Err(SecurityToolingMapError::InvalidResponse)
}

fn validate_records(records: Vec<Value>) -> Result<Vec<Value>, SecurityToolingMapError> {
    if records.iter().all(Value::is_object) {
        Ok(records)
    } else {
        Err(SecurityToolingMapError::InvalidResponse)
    }
}

fn normalize_record(
    family: SecurityToolingMapFamily,
    payload: Value,
) -> Option<SecurityToolingMapRecord> {
    let object = payload.as_object()?;
    let (provider_id, fields) = match family {
        SecurityToolingMapFamily::Tool => normalize_tool(object)?,
        SecurityToolingMapFamily::ControlMapping => normalize_control_mapping(object, &payload)?,
    };
    Some(SecurityToolingMapRecord {
        family: family.as_str().to_owned(),
        provider_kind: family.provider_kind().to_owned(),
        provider_id,
        fields,
        payload,
    })
}

fn normalize_tool(object: &Map<String, Value>) -> Option<(String, BTreeMap<String, String>)> {
    let provider_id = first_nonempty(object, &["id", "name"])?;
    let mut fields = selected_fields(
        object,
        &[
            "name",
            "org",
            "repo",
            "repository",
            "url",
            "status",
            "lifecycle_owner",
            "owners",
            "primary_language",
            "categories",
            "capabilities",
            "surfaces",
            "depends_on",
            "consumed_by",
            "overlaps_with",
            "agent_role",
            "last_pushed",
        ],
    );
    fields.insert("tool_id".to_owned(), provider_id.clone());
    fields.insert("source_product".to_owned(), SOURCE_ID.to_owned());
    Some((provider_id, fields))
}

fn normalize_control_mapping(
    object: &Map<String, Value>,
    payload: &Value,
) -> Option<(String, BTreeMap<String, String>)> {
    let tool_id = first_nonempty(object, &["tool_id", "tool_name"])?;
    let control_id = value_string(object.get("control_id")?).filter(|value| !value.is_empty())?;
    let provider_id = value_string(object.get("id").unwrap_or(&Value::Null))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| stable_id(payload));
    let mut fields = selected_fields(
        object,
        &[
            "tool_name",
            "control_id",
            "control_name",
            "framework",
            "coverage",
            "control_status",
            "attack_tactic",
            "attack_tactics",
            "attack_technique",
            "attack_techniques",
            "mitre_attack_tactic",
            "mitre_attack_tactics",
            "mitre_attack_technique",
            "mitre_attack_techniques",
            "d3fend_tactic",
            "d3fend_tactics",
            "d3fend_technique",
            "d3fend_techniques",
            "d3fend_artifact",
            "d3fend_artifacts",
            "defend_tactic",
            "defend_tactics",
            "defend_technique",
            "defend_techniques",
            "defend_artifact",
            "defend_artifacts",
            "mitre_defend_tactic",
            "mitre_defend_tactics",
            "mitre_defend_technique",
            "mitre_defend_techniques",
            "mitre_defend_artifact",
            "mitre_defend_artifacts",
            "evidence_surface",
            "gap_reason",
            "owner",
            "last_assessed_at",
        ],
    );
    if let Some(mapping_id) = object.get("id").and_then(value_string)
        && !mapping_id.is_empty()
    {
        fields.insert("mapping_id".to_owned(), mapping_id);
    }
    fields.insert("tool_id".to_owned(), tool_id);
    fields.insert("control_id".to_owned(), control_id);
    fields.insert("source_product".to_owned(), SOURCE_ID.to_owned());
    if let Some(status) = fields
        .get("coverage")
        .and_then(|value| coverage_status(value))
    {
        fields.insert("coverage_status".to_owned(), status.to_owned());
    }
    Some((provider_id, fields))
}

fn selected_fields(object: &Map<String, Value>, keys: &[&str]) -> BTreeMap<String, String> {
    keys.iter()
        .filter_map(|key| {
            object
                .get(*key)
                .and_then(value_string)
                .filter(|value| !value.is_empty())
                .map(|value| ((*key).to_owned(), value))
        })
        .collect()
}

fn first_nonempty(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        object
            .get(*key)
            .and_then(value_string)
            .filter(|value| !value.is_empty())
    })
}

fn value_string(value: &Value) -> Option<String> {
    let value = match value {
        Value::Null => return None,
        Value::String(value) => value.trim().to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::Array(values) => values
            .iter()
            .filter_map(value_string)
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => serde_json::to_string(value).ok()?,
    };
    Some(value)
}

fn coverage_status(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" => None,
        "full" | "covered" | "complete" | "implemented" | "operating" | "met" | "yes" | "true" => {
            Some("covered")
        }
        "none" | "gap" | "missing" | "partial" | "planned" | "not_covered" | "uncovered"
        | "in_progress" | "todo" | "unmet" | "no" | "false" => Some("gap"),
        _ => None,
    }
}

fn stable_id(payload: &Value) -> String {
    let encoded = serde_json::to_vec(payload).unwrap_or_default();
    let digest = Sha256::digest(encoded);
    digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel(family: SecurityToolingMapFamily) -> SecurityToolingMapKernel {
        SecurityToolingMapKernel::new("https://security-map.example.test", family).unwrap()
    }

    #[test]
    fn families_preserve_paths_kinds_and_bearer_contract() {
        for (family, path, kind) in [
            (
                SecurityToolingMapFamily::Tool,
                "/tools",
                "security_tooling_map.tool",
            ),
            (
                SecurityToolingMapFamily::ControlMapping,
                "/control-mappings",
                "security_tooling_map.control_mapping",
            ),
        ] {
            let request = kernel(family).plan(None).unwrap();
            assert_eq!(request.url().path(), path);
            assert_eq!(request.authorization_scheme(), "Bearer");
            assert_eq!(request.accept(), "application/json");
            assert_eq!(family.provider_kind(), kind);
        }
    }

    #[test]
    fn tool_decode_preserves_go_fields_and_drops_missing_identity() {
        let kernel = kernel(SecurityToolingMapFamily::Tool);
        let request = kernel.plan(None).unwrap();
        let page = kernel
            .decode(
                &request,
                br#"{"tools":[{"id":"agent-gateway","name":"Agent Gateway","repository":"WriterInternal/agent-gateway","owners":["Security","Platform"],"categories":["ai_security","dlp"]},{"name":"fallback-name","status":"ga"},{"status":"unknown"}]}"#,
            )
            .unwrap();
        assert_eq!(page.next_cursor, None);
        assert_eq!(page.records.len(), 2);
        assert_eq!(page.records[0].provider_id, "agent-gateway");
        assert_eq!(page.records[0].provider_kind, "security_tooling_map.tool");
        assert_eq!(page.records[0].fields["tool_id"], "agent-gateway");
        assert_eq!(page.records[0].fields["owners"], "Security,Platform");
        assert_eq!(page.records[0].fields["categories"], "ai_security,dlp");
        assert_eq!(page.records[1].provider_id, "fallback-name");
    }

    #[test]
    fn control_mapping_decode_normalizes_coverage_and_filters_malformed_rows() {
        let kernel = kernel(SecurityToolingMapFamily::ControlMapping);
        let request = kernel.plan(None).unwrap();
        let page = kernel
            .decode(
                &request,
                br#"{"control_mappings":[{"id":"agent-gateway-soc2-cc6","tool_id":"agent-gateway","control_id":"SOC2-CC6","coverage":"partial","attack_techniques":["T1190","T1552"],"owner":"Security"},{"id":"covered","tool_name":"fallback-tool","control_id":"SOC2-CC7","coverage":"Operating"},{"id":"missing-control","tool_id":"agent-gateway"},{"id":"missing-tool","control_id":"SOC2-CC8"}]}"#,
            )
            .unwrap();
        assert_eq!(page.records.len(), 2);
        assert_eq!(
            page.records[0].fields["mapping_id"],
            "agent-gateway-soc2-cc6"
        );
        assert_eq!(page.records[0].fields["coverage_status"], "gap");
        assert_eq!(page.records[0].fields["attack_techniques"], "T1190,T1552");
        assert_eq!(page.records[1].fields["tool_id"], "fallback-tool");
        assert_eq!(page.records[1].fields["coverage_status"], "covered");
    }

    #[test]
    fn idless_control_mappings_keep_distinct_stable_identities() {
        let kernel = kernel(SecurityToolingMapFamily::ControlMapping);
        let request = kernel.plan(None).unwrap();
        let page = kernel
            .decode(
                &request,
                br#"[{"tool_id":"agent-gateway","control_id":"SOC2-CC6"},{"tool_id":"agent-gateway","control_id":"SOC2-CC7"}]"#,
            )
            .unwrap();
        assert_eq!(page.records.len(), 2);
        assert_eq!(page.records[0].provider_id.len(), 24);
        assert_ne!(page.records[0].provider_id, page.records[1].provider_id);
        assert!(!page.records[0].fields.contains_key("mapping_id"));
    }

    #[test]
    fn kernel_fails_closed_on_origins_cursors_envelopes_and_request_scope() {
        assert!(matches!(
            SecurityToolingMapKernel::new("http://169.254.169.254", SecurityToolingMapFamily::Tool),
            Err(SecurityToolingMapError::InvalidBaseUrl)
        ));
        assert!(matches!(
            kernel(SecurityToolingMapFamily::Tool).plan(Some("next")),
            Err(SecurityToolingMapError::UnsupportedCursor)
        ));
        let tool_kernel = kernel(SecurityToolingMapFamily::Tool);
        let tool_request = tool_kernel.plan(None).unwrap();
        assert!(matches!(
            tool_kernel.decode(&tool_request, br#"{"tools":{}}"#),
            Err(SecurityToolingMapError::InvalidResponse)
        ));
        assert!(matches!(
            kernel(SecurityToolingMapFamily::ControlMapping)
                .decode(&tool_request, br#"{"control_mappings":[]}"#),
            Err(SecurityToolingMapError::RequestScopeMismatch)
        ));
    }
}
