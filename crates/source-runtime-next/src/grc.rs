//! Credential-free Vanta GRC request and page decoding kernel.
//!
//! OAuth, hardened HTTP transport, and runtime wiring remain outside this
//! provider-local module. The kernel only selects a family, bounds page
//! requests, decodes provider cursors, and derives stable record identity.

use std::{collections::BTreeMap, error::Error, fmt, str::FromStr};

use serde::Deserialize;
use serde_json::Value;

macro_rules! grc_families {
    ($($(#[$doc:meta])* $variant:ident => ($id:literal, $path:literal, [$($key:literal),+])),+ $(,)?) => {
        /// One supported Vanta-backed GRC source family.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum GrcFamily {
            $($(#[$doc])* $variant,)+
        }

        impl GrcFamily {
            /// Every family implemented by the Go pull source at the pinned base.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            /// Return the canonical source-family identifier.
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $id,)+ }
            }

            /// Return the exact provider collection path used by the Go source.
            pub const fn endpoint(self) -> &'static str {
                match self { $(Self::$variant => $path,)+ }
            }

            const fn id_paths(self) -> &'static [&'static str] {
                match self { $(Self::$variant => &[$($key),+],)+ }
            }
        }
    };
}

grc_families! {
    /// Compliance frameworks.
    Framework => ("framework", "/v1/frameworks", ["id", "externalId", "name"]),
    /// Framework controls.
    Control => ("control", "/v1/controls", ["id", "externalId", "name"]),
    /// Automated and manual control tests.
    ControlTest => ("control_test", "/v1/tests", ["id", "externalId", "name"]),
    /// Policies.
    Policy => ("policy", "/v1/policies", ["id", "externalId", "name"]),
    /// Uploaded evidence documents.
    Document => ("document", "/v1/documents", ["id", "externalId", "name"]),
    /// Third-party contracts.
    Contract => ("contract", "/v1/contracts", ["id", "externalId", "name"]),
    /// Regulatory notifications.
    RegulatoryNotification => ("regulatory_notification", "/v1/regulatory-notifications", ["id", "notificationId", "externalId"]),
    /// Recovery-time and recovery-point objectives.
    RecoveryObjective => ("recovery_objective", "/v1/recovery-objectives", ["id", "objectiveId", "biaId", "externalId", "name"]),
    /// Authorization and ATO packages.
    AuthorizationPackage => ("authorization_package", "/v1/authorization-packages", ["id", "packageId", "atoId", "sspId", "externalId", "name"]),
    /// Plan-of-action and milestone items.
    PoamItem => ("poam_item", "/v1/poam-items", ["id", "poamItemId", "weaknessId", "findingId", "externalId", "title"]),
    /// Security training attestations.
    TrainingAttestation => ("training_attestation", "/v1/training-attestations", ["id", "attestationId", "trainingAttestationId", "externalId"]),
    /// Discovered third parties.
    DiscoveredVendor => ("discovered_vendor", "/v1/discovered-vendors", ["id", "externalId", "name"]),
    /// Provider audit events.
    EventLog => ("event_log", "/v1/event-logs", ["id", "externalId", "name"]),
    /// Identity groups.
    Group => ("group", "/v1/groups", ["id", "externalId", "name"]),
    /// Vendor-risk attributes.
    VendorRiskAttribute => ("vendor_risk_attribute", "/v1/vendor-risk-attributes", ["id", "externalId", "name"]),
    /// Third-party vendors.
    Vendor => ("vendor", "/v1/vendors", ["id", "externalId", "name"]),
    /// Vulnerabilities.
    Vulnerability => ("vulnerability", "/v1/vulnerabilities", ["id", "externalId", "name"]),
    /// Vulnerability remediation state.
    VulnerabilityRemediation => ("vulnerability_remediation", "/v1/vulnerability-remediations", ["id", "externalId", "name"]),
    /// Assets affected by vulnerabilities.
    VulnerableAsset => ("vulnerable_asset", "/v1/vulnerable-assets", ["id", "assetId", "targetId", "externalId", "name"]),
    /// Monitored endpoint posture.
    MonitoredComputer => ("monitored_computer", "/v1/monitored-computers", ["id", "serialNumber", "udid"]),
    /// Risk-register scenarios.
    RiskScenario => ("risk_scenario", "/v1/risk-scenarios", ["riskId", "id"]),
    /// Workforce people.
    Person => ("person", "/v1/people", ["id", "userId", "emailAddress"]),
    /// Provider users.
    User => ("user", "/v1/users", ["id", "email"]),
    /// Provider integrations.
    Integration => ("integration", "/v1/integrations", ["integrationId", "id"]),
}

impl FromStr for GrcFamily {
    type Err = GrcError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|family| family.as_str() == value.trim())
            .ok_or(GrcError::InvalidFamily)
    }
}

/// Credential-free request metadata for one Vanta page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrcRequest {
    /// Provider-relative endpoint.
    pub path: String,
    /// Provider page-size query value.
    pub page_size: usize,
    /// Opaque continuation cursor, absent on the first page.
    pub cursor: Option<String>,
}

/// One decoded provider record with stable portable identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrcRecord {
    /// Canonical source-family identifier.
    pub family: String,
    /// Canonical emitted provider kind.
    pub provider_kind: String,
    /// Go-compatible provider-owned record identifier.
    pub provider_id: String,
    /// Identity fields safe to pass into the shared mapper.
    pub fields: BTreeMap<String, String>,
    /// Original decoded provider object for later family-specific projection.
    pub payload: Value,
}

/// One bounded provider page and its continuation cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrcPage {
    /// Provider records in response order.
    pub records: Vec<GrcRecord>,
    /// Opaque cursor for the next page, absent when the page is terminal.
    pub next_cursor: Option<String>,
}

/// Credential-free Vanta GRC request and response kernel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrcKernel {
    family: GrcFamily,
}

impl GrcKernel {
    /// Build a kernel for one supported family.
    pub const fn new(family: GrcFamily) -> Self {
        Self { family }
    }

    /// Return whether the provider poller requires credential material.
    pub const fn requires_credentials(&self) -> bool {
        true
    }

    /// Build bounded provider request metadata without resolving credentials.
    pub fn request(&self, cursor: Option<&str>, page_size: usize) -> Result<GrcRequest, GrcError> {
        if !(1..=100).contains(&page_size) {
            return Err(GrcError::InvalidPageSize);
        }
        Ok(GrcRequest {
            path: self.family.endpoint().to_owned(),
            page_size,
            cursor: cursor.and_then(nonblank).map(str::to_owned),
        })
    }

    /// Decode one provider response without performing network I/O.
    pub fn decode_page(&self, body: &[u8]) -> Result<GrcPage, GrcError> {
        let envelope: PageEnvelope =
            serde_json::from_slice(body).map_err(|_| GrcError::InvalidPage)?;
        let mut records = Vec::with_capacity(envelope.results.data.len());
        for payload in envelope.results.data {
            let object = payload.as_object().ok_or(GrcError::RecordNotObject)?;
            let provider_id = self
                .family
                .id_paths()
                .iter()
                .find_map(|path| field_string(object, path))
                .map(normalize_id)
                .filter(|value| !value.is_empty())
                .ok_or(GrcError::MissingRecordId)?;
            let fields = BTreeMap::from([
                ("external_id".to_owned(), provider_id.clone()),
                ("provider".to_owned(), "vanta".to_owned()),
                ("source_provider".to_owned(), "vanta".to_owned()),
            ]);
            records.push(GrcRecord {
                family: self.family.as_str().to_owned(),
                provider_kind: format!("grc.{}", self.family.as_str()),
                provider_id,
                fields,
                payload,
            });
        }
        let next_cursor = if envelope.results.page_info.has_next_page {
            Some(
                nonblank(&envelope.results.page_info.end_cursor)
                    .ok_or(GrcError::MissingContinuationCursor)?
                    .to_owned(),
            )
        } else {
            None
        };
        Ok(GrcPage {
            records,
            next_cursor,
        })
    }
}

/// Safe provider-local GRC contract failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GrcError {
    /// Family identifier is not supported by the pinned Go source.
    InvalidFamily,
    /// Vanta permits page sizes from one through one hundred.
    InvalidPageSize,
    /// Response bytes do not match the provider page envelope.
    InvalidPage,
    /// A page item is not a JSON object.
    RecordNotObject,
    /// A record lacks every provider identity field for its family.
    MissingRecordId,
    /// The provider claims another page but omits its cursor.
    MissingContinuationCursor,
}

impl fmt::Display for GrcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "grc family is invalid",
            Self::InvalidPageSize => "grc page size must be between 1 and 100",
            Self::InvalidPage => "grc provider page JSON is invalid",
            Self::RecordNotObject => "grc provider record must be an object",
            Self::MissingRecordId => "grc provider record identity is missing",
            Self::MissingContinuationCursor => "grc provider continuation cursor is missing",
        })
    }
}

impl Error for GrcError {}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PageEnvelope {
    results: PageResults,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PageResults {
    #[serde(rename = "pageInfo")]
    page_info: PageInfo,
    data: Vec<Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PageInfo {
    #[serde(rename = "endCursor")]
    end_cursor: String,
    #[serde(rename = "hasNextPage")]
    has_next_page: bool,
}

fn field_string(object: &serde_json::Map<String, Value>, path: &str) -> Option<String> {
    let mut current = object.get(path.split('.').next()?)?;
    for part in path.split('.').skip(1) {
        current = current.as_object()?.get(part)?;
    }
    source_string(current)
}

fn source_string(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(value) => nonblank(value).map(str::to_owned),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::Array(values) => {
            let joined = values
                .iter()
                .filter_map(source_string)
                .collect::<Vec<_>>()
                .join(",");
            nonblank(&joined).map(str::to_owned)
        }
        Value::Object(object) => ["displayName", "name", "id", "email"]
            .into_iter()
            .find_map(|key| object.get(key).and_then(source_string)),
    }
}

fn normalize_id(value: String) -> String {
    value.trim().replace(['/', ' '], "_")
}

fn nonblank(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_go_family_has_a_bounded_provider_request() {
        assert_eq!(GrcFamily::ALL.len(), 24);
        for &family in GrcFamily::ALL {
            assert_eq!(family.as_str().parse(), Ok(family));
            let request = GrcKernel::new(family)
                .request(Some(" cursor "), 100)
                .unwrap();
            assert!(request.path.starts_with("/v1/"));
            assert_eq!(request.page_size, 100);
            assert_eq!(request.cursor.as_deref(), Some("cursor"));
            assert!(GrcKernel::new(family).requires_credentials());
        }
    }

    #[test]
    fn control_test_page_preserves_payload_identity_and_cursor() {
        let body = br#"{
          "results": {
            "pageInfo": {"endCursor": "next-2", "hasNextPage": true},
            "data": [{
              "id": "test / one",
              "controls": [{"id": "control-1", "externalId": "AC-2"}]
            }]
          }
        }"#;
        let page = GrcKernel::new(GrcFamily::ControlTest)
            .decode_page(body)
            .unwrap();
        assert_eq!(page.next_cursor.as_deref(), Some("next-2"));
        let record = &page.records[0];
        assert_eq!(record.family, "control_test");
        assert_eq!(record.provider_kind, "grc.control_test");
        assert_eq!(record.provider_id, "test___one");
        assert_eq!(record.fields["provider"], "vanta");
        assert_eq!(record.payload["controls"][0]["externalId"], "AC-2");
    }

    #[test]
    fn family_specific_identity_precedence_matches_go_contract() {
        let risk = GrcKernel::new(GrcFamily::RiskScenario)
            .decode_page(br#"{"results":{"data":[{"riskId":"risk/7","id":"ignored"}]}}"#)
            .unwrap();
        assert_eq!(risk.records[0].provider_id, "risk_7");
        let integration = GrcKernel::new(GrcFamily::Integration)
            .decode_page(br#"{"results":{"data":[{"integrationId":"int 4","id":"ignored"}]}}"#)
            .unwrap();
        assert_eq!(integration.records[0].provider_id, "int_4");
    }

    #[test]
    fn terminal_page_discards_stale_cursor_value() {
        let page = GrcKernel::new(GrcFamily::Vendor)
            .decode_page(br#"{"results":{"pageInfo":{"endCursor":"stale","hasNextPage":false},"data":[{"id":"vendor-1"}]}}"#)
            .unwrap();
        assert_eq!(page.next_cursor, None);
    }

    #[test]
    fn malformed_shapes_missing_identity_and_cursor_fail_closed() {
        let kernel = GrcKernel::new(GrcFamily::Control);
        assert_eq!(kernel.decode_page(b"not-json"), Err(GrcError::InvalidPage));
        assert_eq!(
            kernel.decode_page(br#"{"results":{"data":["not-an-object"]}}"#),
            Err(GrcError::RecordNotObject)
        );
        assert_eq!(
            kernel.decode_page(br#"{"results":{"data":[{"description":"no identity"}]}}"#),
            Err(GrcError::MissingRecordId)
        );
        assert_eq!(
            kernel.decode_page(br#"{"results":{"pageInfo":{"hasNextPage":true},"data":[]}}"#),
            Err(GrcError::MissingContinuationCursor)
        );
        assert_eq!(kernel.request(None, 0), Err(GrcError::InvalidPageSize));
        assert_eq!(kernel.request(None, 101), Err(GrcError::InvalidPageSize));
    }
}
