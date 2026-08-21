//! SDK push telemetry normalization kernel.
//!
//! The SDK source is a push adapter rather than a provider collector. This
//! module keeps its deterministic validation, tenant fence, posture
//! canonicalization, and append-log identity portable while leaving transport,
//! authentication, persistence, and graph projection to their owning layers.

use std::{collections::BTreeMap, error::Error, fmt};

use prost_types::Timestamp;
use sha2::{Digest, Sha256};

const SOURCE_ID: &str = "sdk";
const INTEGRATION_POSTURE_KIND: &str = "sdk.integration_posture";
const INTEGRATION_POSTURE_SCHEMA_REF: &str = "sdk/integration_posture/v1";
const POSTURE_STATUS_AT_RISK: &str = "at_risk";
const POSTURE_STATUS_SECURE: &str = "secure";

/// One raw integration-posture payload received through the SDK push surface.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SdkPushedTelemetry {
    /// Tenant declared by the authenticated SDK runtime.
    pub tenant_id: String,
    /// Source-runtime instance that submitted the posture observation.
    pub runtime_id: String,
    /// SDK integration name, such as `jira`.
    pub integration: String,
    /// Canonical Cerebro URN for the observed resource.
    pub resource_urn: String,
    /// Optional resource kind carried into event attributes.
    pub resource_type: String,
    /// Optional operator-facing resource label.
    pub resource_label: String,
    /// Integration-specific control identifier.
    pub control: String,
    /// Raw secure or at-risk posture value.
    pub posture_status: String,
    /// Optional reason for an at-risk posture.
    pub risk_reason: String,
    /// Provider occurrence time, when supplied by the SDK runtime.
    pub occurred_at: Option<Timestamp>,
    /// Additional scalar attributes supplied by the integration.
    pub attributes: BTreeMap<String, String>,
}

/// One validated `sdk.integration_posture` append-log event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdkIntegrationPostureEvent {
    /// Deterministic identity used for append-log deduplication.
    pub id: String,
    /// Validated tenant authority.
    pub tenant_id: String,
    /// Static SDK source identifier.
    pub source_id: String,
    /// Static SDK posture event kind.
    pub kind: String,
    /// Provider occurrence time, when supplied.
    pub occurred_at: Option<Timestamp>,
    /// Static SDK posture schema reference.
    pub schema_ref: String,
    /// Normalized posture and integration attributes.
    pub attributes: BTreeMap<String, String>,
}

/// Safe SDK telemetry validation failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SdkTelemetryError {
    /// A required tenant, integration, control, resource URN, or posture field is absent.
    Missing(&'static str),
    /// A token contains a reserved colon delimiter.
    ReservedDelimiter(&'static str),
    /// A field contains a C0 control character or DEL.
    UnsafeCharacters(&'static str),
    /// The resource name is not a canonical Cerebro URN.
    InvalidResourceUrn,
    /// The resource URN belongs to a tenant other than the event tenant.
    CrossTenantResourceUrn,
    /// The posture value cannot be canonicalized to secure or at-risk.
    UnknownPostureStatus,
}

impl fmt::Display for SdkTelemetryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(field) => write!(formatter, "sdk telemetry {field} is required"),
            Self::ReservedDelimiter(field) => {
                write!(
                    formatter,
                    "sdk telemetry {field} contains reserved ':' character"
                )
            }
            Self::UnsafeCharacters(field) => {
                write!(
                    formatter,
                    "sdk telemetry {field} contains unsafe characters"
                )
            }
            Self::InvalidResourceUrn => {
                formatter.write_str("sdk telemetry resource urn is malformed")
            }
            Self::CrossTenantResourceUrn => {
                formatter.write_str("sdk telemetry resource urn belongs to another tenant")
            }
            Self::UnknownPostureStatus => {
                formatter.write_str("sdk telemetry posture status is not recognized")
            }
        }
    }
}

impl Error for SdkTelemetryError {}

/// Validate and normalize one SDK push payload without performing I/O.
///
/// Identical reports retain one event ID for append-log deduplication. A
/// secure/at-risk transition receives a distinct ID so the new posture cannot
/// be dropped as a retry of the old state.
pub fn normalize_sdk_pushed_telemetry(
    payload: SdkPushedTelemetry,
) -> Result<SdkIntegrationPostureEvent, SdkTelemetryError> {
    let tenant_id = safe_required_token("tenant id", &payload.tenant_id)?;
    let integration = safe_required_token("integration", &payload.integration)?;
    let control = safe_required_token("control", &payload.control)?;

    let resource_urn = payload.resource_urn.trim().to_owned();
    if resource_urn.is_empty() {
        return Err(SdkTelemetryError::Missing("resource urn"));
    }
    if unsafe_characters(&resource_urn) {
        return Err(SdkTelemetryError::UnsafeCharacters("resource urn"));
    }
    let resource_tenant =
        cerebro_urn_tenant(&resource_urn).ok_or(SdkTelemetryError::InvalidResourceUrn)?;
    if resource_tenant != tenant_id {
        return Err(SdkTelemetryError::CrossTenantResourceUrn);
    }

    let raw_posture_status = payload.posture_status.trim();
    if raw_posture_status.is_empty() {
        return Err(SdkTelemetryError::Missing("posture status"));
    }
    let posture_status = normalize_posture_status(raw_posture_status)
        .ok_or(SdkTelemetryError::UnknownPostureStatus)?;

    let mut attributes = BTreeMap::new();
    for (key, value) in payload.attributes {
        let key = key.trim().to_owned();
        let value = value.trim().to_owned();
        if key.is_empty() || value.is_empty() {
            continue;
        }
        if unsafe_characters(&key) || unsafe_characters(&value) {
            return Err(SdkTelemetryError::UnsafeCharacters("attribute"));
        }
        attributes.insert(key, value);
    }

    let resource_type = safe_optional_field("resource type", &payload.resource_type)?;
    let resource_label = safe_optional_field("resource label", &payload.resource_label)?;
    let risk_reason = safe_optional_field("risk reason", &payload.risk_reason)?;
    let runtime_id = safe_optional_field("runtime id", &payload.runtime_id)?;

    set_typed_attribute(&mut attributes, "integration", &integration);
    set_typed_attribute(&mut attributes, "resource_urn", &resource_urn);
    set_typed_attribute(&mut attributes, "resource_type", &resource_type);
    set_typed_attribute(&mut attributes, "resource_label", &resource_label);
    set_typed_attribute(&mut attributes, "control", &control);
    set_typed_attribute(&mut attributes, "posture_status", posture_status);
    set_typed_attribute(&mut attributes, "risk_reason", &risk_reason);
    set_typed_attribute(&mut attributes, "source_runtime_id", &runtime_id);

    Ok(SdkIntegrationPostureEvent {
        id: integration_posture_event_id(
            &tenant_id,
            &integration,
            &control,
            &resource_urn,
            posture_status,
        ),
        tenant_id,
        source_id: SOURCE_ID.to_owned(),
        kind: INTEGRATION_POSTURE_KIND.to_owned(),
        occurred_at: payload.occurred_at,
        schema_ref: INTEGRATION_POSTURE_SCHEMA_REF.to_owned(),
        attributes,
    })
}

fn safe_required_token(field: &'static str, value: &str) -> Result<String, SdkTelemetryError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(SdkTelemetryError::Missing(field));
    }
    if unsafe_characters(value) {
        return Err(SdkTelemetryError::UnsafeCharacters(field));
    }
    if value.contains(':') {
        return Err(SdkTelemetryError::ReservedDelimiter(field));
    }
    Ok(value.to_owned())
}

fn safe_optional_field(field: &'static str, value: &str) -> Result<String, SdkTelemetryError> {
    let value = value.trim();
    if unsafe_characters(value) {
        return Err(SdkTelemetryError::UnsafeCharacters(field));
    }
    Ok(value.to_owned())
}

fn unsafe_characters(value: &str) -> bool {
    value
        .chars()
        .any(|character| character <= '\u{1f}' || character == '\u{7f}')
}

fn cerebro_urn_tenant(value: &str) -> Option<&str> {
    if value.trim() != value || !value.starts_with("urn:cerebro:") {
        return None;
    }
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() < 4 || parts[0] != "urn" || parts[1] != "cerebro" {
        return None;
    }
    if parts.last().is_some_and(|part| part.is_empty()) {
        return None;
    }
    if parts[3] == "runtime" && (parts.len() < 7 || parts[5].is_empty()) {
        return None;
    }
    for (index, part) in parts[2..].iter().enumerate() {
        if part.trim() != *part || (index < 3 && part.is_empty()) {
            return None;
        }
    }
    Some(parts[2])
}

fn normalize_posture_status(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "at_risk" | "atrisk" | "risk" | "at-risk" | "insecure" | "failing" | "fail" | "failed"
        | "noncompliant" | "non_compliant" | "non-compliant" | "violation" | "open"
        | "high_risk" | "high-risk" => Some(POSTURE_STATUS_AT_RISK),
        "secure" | "ok" | "pass" | "passing" | "passed" | "compliant" | "resolved" | "healthy"
        | "remediated" | "closed" => Some(POSTURE_STATUS_SECURE),
        _ => None,
    }
}

fn set_typed_attribute(attributes: &mut BTreeMap<String, String>, key: &str, value: &str) {
    if value.trim().is_empty() {
        attributes.remove(key);
    } else {
        attributes.insert(key.to_owned(), value.to_owned());
    }
}

fn integration_posture_event_id(
    tenant_id: &str,
    integration: &str,
    control: &str,
    resource_urn: &str,
    posture_status: &str,
) -> String {
    let mut hasher = Sha256::new();
    for (index, value) in [
        tenant_id,
        integration,
        control,
        resource_urn,
        posture_status,
    ]
    .into_iter()
    .enumerate()
    {
        if index > 0 {
            hasher.update([0]);
        }
        hasher.update(value.as_bytes());
    }
    let digest = hasher.finalize();
    let suffix = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sdk-integration-posture-{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    type PayloadMutation = fn(&mut SdkPushedTelemetry);

    fn valid_payload() -> SdkPushedTelemetry {
        SdkPushedTelemetry {
            tenant_id: "writer".to_owned(),
            runtime_id: "writer-sdk-jira-posture".to_owned(),
            integration: "jira".to_owned(),
            resource_urn: "urn:cerebro:writer:runtime:writer-sdk-jira-posture:workspace:writer"
                .to_owned(),
            resource_type: "workspace".to_owned(),
            resource_label: "Writer Jira".to_owned(),
            control: "sso_enforced".to_owned(),
            posture_status: "at_risk".to_owned(),
            risk_reason: "workspace allows password-only sign-in".to_owned(),
            occurred_at: Some(Timestamp {
                seconds: 1_777_636_800,
                nanos: 0,
            }),
            attributes: BTreeMap::from([("owner".to_owned(), "Security".to_owned())]),
        }
    }

    #[test]
    fn normalizes_valid_posture_and_preserves_occurrence_time() {
        let payload = valid_payload();
        let occurred_at = payload.occurred_at;
        let event = normalize_sdk_pushed_telemetry(payload).unwrap();

        assert_eq!(event.tenant_id, "writer");
        assert_eq!(event.source_id, "sdk");
        assert_eq!(event.kind, "sdk.integration_posture");
        assert_eq!(event.schema_ref, "sdk/integration_posture/v1");
        assert_eq!(event.occurred_at, occurred_at);
        assert_eq!(event.attributes["integration"], "jira");
        assert_eq!(event.attributes["control"], "sso_enforced");
        assert_eq!(event.attributes["posture_status"], "at_risk");
        assert_eq!(event.attributes["owner"], "Security");
        assert_eq!(
            event.attributes["source_runtime_id"],
            "writer-sdk-jira-posture"
        );
        assert!(event.id.starts_with("sdk-integration-posture-"));
        assert_eq!(event.id.len(), "sdk-integration-posture-".len() + 24);
    }

    #[test]
    fn typed_fields_override_or_remove_untrusted_attribute_values() {
        let mut payload = valid_payload();
        payload.runtime_id.clear();
        payload.resource_type.clear();
        payload.resource_label.clear();
        payload.risk_reason.clear();
        payload.attributes.extend([
            ("integration".to_owned(), "attacker-integration".to_owned()),
            ("resource_type".to_owned(), "attacker-type".to_owned()),
            ("resource_label".to_owned(), "attacker-label".to_owned()),
            ("control".to_owned(), "attacker-control".to_owned()),
            ("posture_status".to_owned(), "secure".to_owned()),
            ("risk_reason".to_owned(), "attacker-risk".to_owned()),
            (
                "source_runtime_id".to_owned(),
                "attacker-runtime".to_owned(),
            ),
        ]);

        let event = normalize_sdk_pushed_telemetry(payload).unwrap();
        assert_eq!(event.attributes["integration"], "jira");
        assert_eq!(event.attributes["control"], "sso_enforced");
        assert_eq!(event.attributes["posture_status"], "at_risk");
        for key in [
            "resource_type",
            "resource_label",
            "risk_reason",
            "source_runtime_id",
        ] {
            assert!(!event.attributes.contains_key(key), "unexpected {key}");
        }
        assert_eq!(event.attributes["owner"], "Security");
    }

    #[test]
    fn posture_identity_is_stable_for_retries_and_changes_for_transitions() {
        let first = normalize_sdk_pushed_telemetry(valid_payload()).unwrap();
        let mut retry = valid_payload();
        retry.occurred_at = Some(Timestamp {
            seconds: 1_777_658_400,
            nanos: 0,
        });
        let retry = normalize_sdk_pushed_telemetry(retry).unwrap();
        let mut secure = valid_payload();
        secure.posture_status = "secure".to_owned();
        let secure = normalize_sdk_pushed_telemetry(secure).unwrap();

        assert_eq!(first.id, retry.id);
        assert_ne!(first.id, secure.id);
    }

    #[test]
    fn rejects_missing_required_fields() {
        let cases: [(&str, PayloadMutation); 5] = [
            ("tenant id", |payload: &mut SdkPushedTelemetry| {
                payload.tenant_id = "  ".to_owned()
            }),
            ("integration", |payload: &mut SdkPushedTelemetry| {
                payload.integration.clear()
            }),
            ("control", |payload: &mut SdkPushedTelemetry| {
                payload.control.clear()
            }),
            ("resource urn", |payload: &mut SdkPushedTelemetry| {
                payload.resource_urn.clear()
            }),
            ("posture status", |payload: &mut SdkPushedTelemetry| {
                payload.posture_status.clear()
            }),
        ];
        for (field, mutate) in cases {
            let mut payload = valid_payload();
            mutate(&mut payload);
            assert_eq!(
                normalize_sdk_pushed_telemetry(payload),
                Err(SdkTelemetryError::Missing(field))
            );
        }
    }

    #[test]
    fn rejects_malformed_or_cross_tenant_resource_urns() {
        let invalid = [
            "not-a-urn",
            "urn:cerebro:",
            "urn:cerebro:writer",
            "urn:cerebro::workspace:writer",
            "urn:cerebro:writer::writer",
            "urn:cerebro:writer:runtime:runtime-id::entity-id",
            "urn:cerebro:writer:workspace:",
        ];
        for resource_urn in invalid {
            let mut payload = valid_payload();
            payload.resource_urn = resource_urn.to_owned();
            assert_eq!(
                normalize_sdk_pushed_telemetry(payload),
                Err(SdkTelemetryError::InvalidResourceUrn),
                "{resource_urn}"
            );
        }

        let mut payload = valid_payload();
        payload.resource_urn = "urn:cerebro:acme:workspace:acme".to_owned();
        assert_eq!(
            normalize_sdk_pushed_telemetry(payload),
            Err(SdkTelemetryError::CrossTenantResourceUrn)
        );
    }

    #[test]
    fn preserves_colon_delimited_resource_ids() {
        let mut payload = valid_payload();
        payload.resource_urn =
            "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/AdminRole".to_owned();
        let event = normalize_sdk_pushed_telemetry(payload).unwrap();
        assert_eq!(
            event.attributes["resource_urn"],
            "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/AdminRole"
        );
    }

    #[test]
    fn rejects_unsafe_characters_and_reserved_token_delimiters() {
        let unsafe_cases: [(&str, PayloadMutation); 5] = [
            ("tenant id", |payload: &mut SdkPushedTelemetry| {
                payload.tenant_id = "writer\njira".to_owned()
            }),
            ("integration", |payload: &mut SdkPushedTelemetry| {
                payload.integration = "jira\ncommand".to_owned()
            }),
            ("control", |payload: &mut SdkPushedTelemetry| {
                payload.control = "sso\tenforced".to_owned()
            }),
            ("runtime id", |payload: &mut SdkPushedTelemetry| {
                payload.runtime_id = "writer-sdk\njira".to_owned()
            }),
            ("resource urn", |payload: &mut SdkPushedTelemetry| {
                payload.resource_urn = "urn:cerebro:writer:workspace:name\u{1}".to_owned()
            }),
        ];
        for (field, mutate) in unsafe_cases {
            let mut payload = valid_payload();
            mutate(&mut payload);
            assert_eq!(
                normalize_sdk_pushed_telemetry(payload),
                Err(SdkTelemetryError::UnsafeCharacters(field))
            );
        }

        let mut payload = valid_payload();
        payload
            .attributes
            .insert("owner".to_owned(), "sec\0urity".to_owned());
        assert_eq!(
            normalize_sdk_pushed_telemetry(payload),
            Err(SdkTelemetryError::UnsafeCharacters("attribute"))
        );

        let delimiter_cases: [(&str, PayloadMutation); 3] = [
            ("tenant id", |payload: &mut SdkPushedTelemetry| {
                payload.tenant_id = "writer:prod".to_owned()
            }),
            ("integration", |payload: &mut SdkPushedTelemetry| {
                payload.integration = "jira:prod".to_owned()
            }),
            ("control", |payload: &mut SdkPushedTelemetry| {
                payload.control = "sso:enforced".to_owned()
            }),
        ];
        for (field, mutate) in delimiter_cases {
            let mut payload = valid_payload();
            mutate(&mut payload);
            assert_eq!(
                normalize_sdk_pushed_telemetry(payload),
                Err(SdkTelemetryError::ReservedDelimiter(field))
            );
        }
    }

    #[test]
    fn normalizes_posture_synonyms_and_rejects_unknown_values() {
        for (input, expected) in [
            ("failing", "at_risk"),
            ("violation", "at_risk"),
            ("compliant", "secure"),
            ("resolved", "secure"),
        ] {
            let mut payload = valid_payload();
            payload.posture_status = input.to_owned();
            let event = normalize_sdk_pushed_telemetry(payload).unwrap();
            assert_eq!(event.attributes["posture_status"], expected);
        }

        let mut payload = valid_payload();
        payload.posture_status = "purple".to_owned();
        assert_eq!(
            normalize_sdk_pushed_telemetry(payload),
            Err(SdkTelemetryError::UnknownPostureStatus)
        );
    }
}
