use std::collections::BTreeMap;

use serde::Deserialize;
#[cfg(test)]
use serde_json::Value;

use super::model::{
    CanonicalScalar, ControlRef, Decision, KernelError, Operation, RuleFindingDecision,
    RuleRequest, attribute, decode_payload, finding_hash, first_non_empty, identity_anchor,
    normalized_observation_time, scalar, stable_external_id, trim_empty, valid_identity_component,
    validate_scope,
};

pub(super) const RULE_ID: &str = "cosmo-coordination-active-risk";
pub(super) const DEFINITION_DIGEST: &str =
    "1367f20b5cfe85e3f901760f27d8540d15227712b86e5ca3da41122e296225a4";
const SOURCE_ID: &str = "cosmo";
const EVENT_KIND: &str = "cosmo.fact";
const SCHEMA_REF: &str = "cosmo/fact/v1";
const TITLE: &str = "Cosmo Agent Memory Coordination Risk Active";
const CHECK_ID: &str = "cosmo-coordination-active-risk-current";
const CHECK_NAME: &str = "Cosmo Agent Memory Coordination Risk Active (current state)";

/// Closed projection of a real Cosmo fact payload. `confidence`, `value`,
/// `reason`, and `summary` are explicitly tolerated because the source may
/// carry them, but they never become risk evidence. Tenant, workspace,
/// runtime, and time fields are deliberately absent and therefore rejected.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Payload {
    #[serde(rename = "key")]
    _key: Option<CanonicalScalar>,
    category: Option<CanonicalScalar>,
    source: Option<CanonicalScalar>,
    risk_state: Option<CanonicalScalar>,
    state: Option<CanonicalScalar>,
    status: Option<CanonicalScalar>,
    resolved: Option<CanonicalScalar>,
    risk_reason: Option<CanonicalScalar>,
    risk_severity: Option<CanonicalScalar>,
    severity: Option<CanonicalScalar>,
    #[serde(rename = "confidence")]
    _confidence: Option<CanonicalScalar>,
    #[serde(rename = "value")]
    _value: Option<CanonicalScalar>,
    #[serde(rename = "reason")]
    _reason: Option<CanonicalScalar>,
    #[serde(rename = "summary")]
    _summary: Option<CanonicalScalar>,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ProjectionReceipt {
    pub(super) input_digest: String,
    pub(super) output_digest: String,
    pub(super) dropped_fields: usize,
}

/// Projects arbitrary bounded provider fact data into the closed rule DTO.
/// Trusted context fields are never projected from provider-controlled bytes.
#[cfg(test)]
pub(super) fn project_source_payload(
    raw: &[u8],
) -> Result<(Vec<u8>, ProjectionReceipt), KernelError> {
    let decoded: Value = decode_payload(raw)?;
    let object = decoded.as_object().ok_or(KernelError::MalformedPayload)?;
    const TRUSTED: &[&str] = &[
        "tenant_id",
        "workspace_id",
        "runtime_id",
        "source_runtime_id",
        "occurred_at",
        "observed_at",
    ];
    const ALLOWED: &[&str] = &[
        "key",
        "category",
        "source",
        "risk_state",
        "state",
        "status",
        "resolved",
        "risk_reason",
        "risk_severity",
        "severity",
        "confidence",
        "value",
        "reason",
        "summary",
    ];
    let mut projected = BTreeMap::new();
    let mut dropped_fields = 0;
    for (key, value) in object {
        if TRUSTED.contains(&key.as_str()) {
            return Err(KernelError::ScopeMismatch);
        }
        if !ALLOWED.contains(&key.as_str()) {
            dropped_fields += 1;
            continue;
        }
        if !matches!(value, Value::String(_) | Value::Bool(_) | Value::Number(_)) {
            return Err(KernelError::MalformedPayload);
        }
        projected.insert(key.clone(), value.clone());
    }
    let output = serde_json::to_vec(&projected).map_err(|_| KernelError::MalformedPayload)?;
    let receipt = ProjectionReceipt {
        input_digest: super::model::byte_digest(raw),
        output_digest: super::model::byte_digest(&output),
        dropped_fields,
    };
    Ok((output, receipt))
}

pub(super) fn evaluate(request: &RuleRequest) -> Result<Decision, KernelError> {
    validate_scope(request, SOURCE_ID, SCHEMA_REF)?;
    if !request.event.kind.trim().eq_ignore_ascii_case(EVENT_KIND) {
        return Ok(Decision::none());
    }
    if request.operation != Operation::Evaluate && !request.event.payload.is_empty() {
        return Err(KernelError::ActionPayloadNotEmpty);
    }
    if request.operation == Operation::OpenAnchor {
        return Ok(Decision::anchor(identity_anchor(
            &request.event.attributes,
            &["cosmo_risk_urn"],
        )));
    }
    // Cosmo memory is never allowed to close a finding. Match the Go
    // CounterEventRule without inspecting payload bytes or observation time.
    if request.operation == Operation::Close {
        return Ok(Decision::none());
    }
    let payload: Payload = decode_payload(&request.event.payload)?;
    normalized_observation_time(&request.event.observed_at)?;
    match request.operation {
        Operation::Evaluate => evaluate_open(request, &payload),
        Operation::OpenAnchor => Err(KernelError::UnsupportedOperation),
        Operation::Close => Err(KernelError::UnsupportedOperation),
    }
}

fn evaluate_open(request: &RuleRequest, payload: &Payload) -> Result<Decision, KernelError> {
    // The source promotes the stable fact key into event attributes. The Go
    // oracle rejects a payload-only key through `hasRequiredAttributes`.
    let fact_key = attribute(&request.event, "key");
    if fact_key.is_empty() {
        return Ok(Decision::none());
    }
    let category = first_non_empty(&[
        attribute(&request.event, "category"),
        scalar(&payload.category),
    ]);
    if !is_coordination_risk_category(category) || risk_state(request, payload) != "active" {
        return Ok(Decision::none());
    }
    let source = first_non_empty(&[attribute(&request.event, "source"), scalar(&payload.source)]);
    let session_id = source.strip_prefix("session:").map_or("", str::trim);
    let tenant_id = request.runtime.tenant_id.trim();
    let runtime_id = request.runtime.runtime_id.trim();
    let risk_urn = risk_urn(tenant_id, runtime_id, session_id, fact_key);
    if risk_urn.is_empty() {
        return Ok(Decision::none());
    }
    let fact_urn = format!(
        "urn:cerebro:{tenant_id}:cosmo_fact:{}",
        stable_external_id(fact_key)
    );
    let mut resource_urns = vec![fact_urn.clone()];
    if !session_id.is_empty() {
        resource_urns.push(format!(
            "urn:cerebro:{tenant_id}:cosmo_session:{}",
            stable_external_id(session_id)
        ));
    }
    let (risk_reason, risk_reason_source) = evidence(
        attribute(&request.event, "risk_reason"),
        scalar(&payload.risk_reason),
    );
    let (risk_severity, risk_severity_source) = evidence(
        attribute(&request.event, "risk_severity"),
        first_non_empty(&[scalar(&payload.risk_severity), scalar(&payload.severity)]),
    );
    let mut attributes = BTreeMap::from([
        ("cosmo_risk_urn".into(), risk_urn.clone()),
        ("fact_key".into(), fact_key.into()),
        ("session_id".into(), session_id.into()),
        ("category".into(), category.into()),
        ("risk_state".into(), "active".into()),
        ("risk_reason".into(), risk_reason.into()),
        ("risk_reason_source".into(), risk_reason_source.into()),
        ("risk_severity".into(), risk_severity.into()),
        ("risk_severity_source".into(), risk_severity_source.into()),
        ("event_id".into(), request.event.id.trim().into()),
        ("source_runtime_id".into(), runtime_id.into()),
        ("primary_resource_urn".into(), fact_urn),
    ]);
    if risk_reason_source == "agent_memory_payload" && !risk_reason.is_empty() {
        attributes.insert("risk_reason_operator_validation".into(), "required".into());
    }
    if risk_severity_source == "agent_memory_payload" && !risk_severity.is_empty() {
        attributes.insert(
            "risk_severity_operator_validation".into(),
            "required".into(),
        );
    }
    insert_rule_attributes(&mut attributes);
    trim_empty(&mut attributes);
    let fingerprint = finding_hash(&[RULE_ID, &risk_urn]);
    let observed_at = normalized_observation_time(&request.event.observed_at)?;
    Ok(Decision::open(RuleFindingDecision {
        id: fingerprint.clone(),
        fingerprint,
        tenant_id: tenant_id.into(),
        runtime_id: runtime_id.into(),
        rule_id: RULE_ID.into(),
        title: TITLE.into(),
        severity: "HIGH".into(),
        status: "open".into(),
        summary: "Cosmo agent memory records active coordination risk".into(),
        resource_urns,
        event_ids: vec![request.event.id.trim().into()],
        observed_policy_ids: None,
        policy_id: String::new(),
        policy_name: String::new(),
        check_id: CHECK_ID.into(),
        check_name: CHECK_NAME.into(),
        control_refs: vec![
            ControlRef {
                framework_name: "SOC 2".into(),
                control_id: "CC7.1".into(),
            },
            ControlRef {
                framework_name: "ISO 27001:2022".into(),
                control_id: "A.5.7".into(),
            },
        ],
        attributes,
        first_observed_at: observed_at.clone(),
        last_observed_at: observed_at,
    }))
}

fn risk_state(request: &RuleRequest, payload: &Payload) -> &'static str {
    let explicit = first_non_empty(&[
        attribute(&request.event, "risk_state"),
        scalar(&payload.risk_state),
        scalar(&payload.state),
        scalar(&payload.status),
    ]);
    match explicit.to_ascii_lowercase().as_str() {
        "resolved" | "closed" | "mitigated" | "inactive" | "remediated" => "resolved",
        "active" | "open" | "ongoing" | "current" => "active",
        _ => {
            let resolved = first_non_empty(&[
                attribute(&request.event, "resolved"),
                scalar(&payload.resolved),
            ]);
            match parse_bool(resolved) {
                Some(true) => "resolved",
                Some(false) => "active",
                None => "",
            }
        }
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim() {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Some(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Some(false),
        _ => None,
    }
}

fn is_coordination_risk_category(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "coordination_risk" | "coordination-risk" | "security_risk" | "security-risk"
    )
}

fn evidence<'a>(attribute_value: &'a str, payload_value: &'a str) -> (&'a str, &'static str) {
    if !attribute_value.trim().is_empty() {
        (attribute_value.trim(), "event_attribute")
    } else if !payload_value.trim().is_empty() {
        (payload_value.trim(), "agent_memory_payload")
    } else {
        ("", "")
    }
}

fn risk_urn(tenant_id: &str, runtime_id: &str, session_id: &str, fact_key: &str) -> String {
    if [tenant_id, runtime_id, fact_key, session_id]
        .iter()
        .filter(|value| !value.trim().is_empty())
        .any(|value| !valid_identity_component(value))
        || [tenant_id, runtime_id, fact_key]
            .iter()
            .any(|value| value.trim().is_empty())
    {
        return String::new();
    }
    let session_scope = if session_id.trim().is_empty() {
        "sessionless".to_owned()
    } else {
        format!("session:{}", session_id.trim())
    };
    let key = finding_hash(&[
        "cosmo_coordination_risk",
        tenant_id,
        runtime_id,
        &session_scope,
        fact_key,
    ]);
    format!(
        "urn:cerebro:{}:cosmo_coordination_risk:{key}",
        tenant_id.trim()
    )
}

fn insert_rule_attributes(attributes: &mut BTreeMap<String, String>) {
    attributes.extend([
        ("rule_maturity".into(), "test".into()),
        ("rule_severity".into(), "HIGH".into()),
        ("rule_source_id".into(), SOURCE_ID.into()),
        ("rule_status".into(), "open".into()),
        ("rule_event_kinds".into(), EVENT_KIND.into()),
        ("rule_fingerprint_fields".into(), "cosmo_risk_urn".into()),
        (
            "rule_false_positives".into(),
            "Memory facts that record a historical coordination-risk pattern that has already been remediated but still require operator review before the finding is resolved.,Resolved Cosmo memory facts do not close a matching finding by themselves; prompt-injected or otherwise agent-written resolution state must be operator-verified against session and runtime evidence.,risk_reason and risk_severity are evidence hints from Cosmo memory when their source attributes are agent_memory_payload; validate them before treating the text as authoritative.".into(),
        ),
        (
            "rule_references".into(),
            "https://github.com/writer/cerebro/blob/main/docs/domains/source-runtime-guide.md".into(),
        ),
        ("rule_required_attributes".into(), "key".into()),
        (
            "rule_tags".into(),
            "cosmo,agent-memory,coordination,posture".into(),
        ),
        (
            "rule_runbook".into(),
            "Review the coordination-risk pattern recorded for the affected session and remediate the underlying risky coordination. Treat risk_reason and risk_severity as agent-written evidence hints when their source is agent_memory_payload, verify resolved memory facts against session and runtime evidence, and resolve the finding through the reviewed finding workflow rather than Cosmo memory alone.".into(),
        ),
    ]);
}
