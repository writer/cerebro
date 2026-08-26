use std::collections::BTreeMap;
use std::fmt::Write as _;

use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::model::{
    Action, ControlRef, EvaluationEnvelope, EvaluationResponse, FindingRecord, KernelError,
    Operation, RuleRequest, SCHEMA_VERSION, TAILSCALE_DEFINITION_DIGEST, TAILSCALE_RULE_ID,
};

/// Wasm host/guest ABI version.
pub const ABI_VERSION: u32 = 1;
/// Maximum accepted JSON request size.
pub const MAX_INPUT_BYTES: usize = 1 << 20;
/// Maximum emitted JSON response size.
pub const MAX_OUTPUT_BYTES: usize = 1 << 20;

const TITLE: &str = "Tailscale Tailnet Device Approval Disabled";
const CHECK_ID: &str = "tailscale-tailnet-device-approval-disabled-current";
const CHECK_NAME: &str = "Tailscale Tailnet Device Approval Disabled (current state)";
const WORKSPACE_ATTRIBUTE: &str = "cerebro_application_workspace_id";

/// Evaluates one content-bound request without network, clock, graph, or store access.
pub fn evaluate(envelope: EvaluationEnvelope) -> Result<EvaluationResponse, KernelError> {
    if envelope.schema_version != SCHEMA_VERSION {
        return Err(KernelError::UnsupportedSchema);
    }
    if envelope.request.rule_id.trim() != TAILSCALE_RULE_ID {
        return Err(KernelError::UnsupportedRule);
    }
    let request_bytes =
        serde_json::to_vec(&envelope.request).map_err(|_| KernelError::InvalidInput)?;
    if envelope.input_digest != prefixed_digest(&request_bytes) {
        return Err(KernelError::InputDigestMismatch);
    }
    let (action, anchor, finding) = match envelope.request.operation {
        Operation::Evaluate => evaluate_open(&envelope.request)?,
        Operation::OpenAnchor => evaluate_open_anchor(&envelope.request),
        Operation::Close => evaluate_close(&envelope.request)?,
    };
    let fingerprint = finding
        .as_ref()
        .map_or("", |record| record.fingerprint.as_str());
    let decision_digest = decision_digest(action, &anchor, fingerprint);
    Ok(EvaluationResponse {
        schema_version: SCHEMA_VERSION,
        rule_id: TAILSCALE_RULE_ID,
        definition_digest: TAILSCALE_DEFINITION_DIGEST,
        input_digest: envelope.input_digest,
        decision_digest,
        action,
        anchor,
        finding,
    })
}

fn evaluate_open(
    request: &RuleRequest,
) -> Result<(Action, String, Option<FindingRecord>), KernelError> {
    validate_evaluation_scope(request)?;
    if !request
        .event_kind
        .trim()
        .eq_ignore_ascii_case("tailscale.tailnet")
    {
        return Ok((Action::None, String::new(), None));
    }
    let tailnet = attribute(request, "tailnet");
    if tailnet.is_empty()
        || parse_optional_bool(attribute(request, "devices_approval_on")) != Some(false)
    {
        return Ok((Action::None, String::new(), None));
    }
    let occurred_at = normalized_timestamp(&request.occurred_at)?;
    let tenant_id = request.runtime_tenant_id.trim();
    let runtime_id = request.runtime_id.trim();
    let tailnet_urn = format!("urn:cerebro:{tenant_id}:tailscale_tailnet:{tailnet}");
    let fingerprint = fingerprint(TAILSCALE_RULE_ID, &tailnet_urn);
    let mut attributes = BTreeMap::from([
        ("tailscale_tailnet_urn".into(), tailnet_urn.clone()),
        ("tailnet".into(), tailnet.into()),
        ("devices_approval_on".into(), attribute(request, "devices_approval_on").into()),
        ("users_approval_on".into(), attribute(request, "users_approval_on").into()),
        ("network_flow_logging_on".into(), attribute(request, "network_flow_logging_on").into()),
        ("event_id".into(), request.event_id.trim().into()),
        ("source_runtime_id".into(), attribute(request, "source_runtime_id").into()),
        ("primary_resource_urn".into(), tailnet_urn.clone()),
        ("rule_maturity".into(), "test".into()),
        ("rule_severity".into(), "MEDIUM".into()),
        ("rule_source_id".into(), "tailscale".into()),
        ("rule_status".into(), "open".into()),
        ("rule_event_kinds".into(), "tailscale.tailnet".into()),
        ("rule_fingerprint_fields".into(), "tailscale_tailnet_urn".into()),
        ("rule_false_positives".into(), "Tailnets that intentionally rely on tag/ACL-based authorization instead of manual device approval.".into()),
        ("rule_references".into(), "https://tailscale.com/kb/1099/device-approval".into()),
        ("rule_required_attributes".into(), "tailnet".into()),
        ("rule_tags".into(), "tailscale,tailnet,device-approval,access-control".into()),
        ("rule_runbook".into(), "Confirm whether device approval should be enforced for this tailnet; if so, enable device approval so new devices require administrator review before joining.".into()),
    ]);
    attributes.retain(|_, value| !value.trim().is_empty());
    let finding = FindingRecord {
        id: fingerprint.clone(),
        fingerprint,
        tenant_id: tenant_id.into(),
        runtime_id: runtime_id.into(),
        rule_id: TAILSCALE_RULE_ID,
        title: TITLE,
        severity: "MEDIUM",
        status: "open",
        summary: format!("Tailscale tailnet {tailnet} has device approval disabled"),
        resource_urns: vec![tailnet_urn.clone()],
        event_ids: vec![request.event_id.trim().into()],
        check_id: CHECK_ID,
        check_name: CHECK_NAME,
        control_refs: vec![
            ControlRef {
                framework_name: "SOC 2",
                control_id: "CC6.1",
            },
            ControlRef {
                framework_name: "ISO 27001:2022",
                control_id: "A.8.2",
            },
        ],
        attributes,
        first_observed_at: occurred_at.clone(),
        last_observed_at: occurred_at,
    };
    Ok((Action::Open, String::new(), Some(finding)))
}

fn evaluate_open_anchor(request: &RuleRequest) -> (Action, String, Option<FindingRecord>) {
    let urn = attribute(request, "tailscale_tailnet_urn");
    let anchor = if urn.is_empty() {
        String::new()
    } else {
        format!("tailscale_tailnet_urn={urn}")
    };
    (Action::OpenAnchor, anchor, None)
}

fn evaluate_close(
    request: &RuleRequest,
) -> Result<(Action, String, Option<FindingRecord>), KernelError> {
    if request.event_tenant_id.trim().is_empty()
        || !request
            .event_source_id
            .trim()
            .eq_ignore_ascii_case("tailscale")
    {
        return Err(KernelError::ScopeMismatch);
    }
    if !request
        .event_kind
        .trim()
        .eq_ignore_ascii_case("tailscale.tailnet")
    {
        return Ok((Action::None, String::new(), None));
    }
    let tailnet = attribute(request, "tailnet");
    if tailnet.is_empty()
        || parse_optional_bool(attribute(request, "devices_approval_on")) != Some(true)
    {
        return Ok((Action::None, String::new(), None));
    }
    let urn = format!(
        "urn:cerebro:{}:tailscale_tailnet:{tailnet}",
        request.event_tenant_id.trim()
    );
    Ok((Action::Close, format!("tailscale_tailnet_urn={urn}"), None))
}

fn validate_evaluation_scope(request: &RuleRequest) -> Result<(), KernelError> {
    if request.runtime_id.trim().is_empty()
        || request.runtime_tenant_id.trim().is_empty()
        || request.event_tenant_id.trim().is_empty()
        || request.runtime_tenant_id.trim() != request.event_tenant_id.trim()
        || !request
            .runtime_source_id
            .trim()
            .eq_ignore_ascii_case("tailscale")
        || !request
            .event_source_id
            .trim()
            .eq_ignore_ascii_case("tailscale")
    {
        return Err(KernelError::ScopeMismatch);
    }
    let event_workspace = attribute(request, WORKSPACE_ATTRIBUTE);
    let runtime_workspace = request.runtime_workspace_id.trim();
    if !runtime_workspace.is_empty()
        && !event_workspace.is_empty()
        && runtime_workspace != event_workspace
    {
        return Err(KernelError::ScopeMismatch);
    }
    Ok(())
}

fn normalized_timestamp(value: &str) -> Result<String, KernelError> {
    let parsed =
        OffsetDateTime::parse(value.trim(), &Rfc3339).map_err(|_| KernelError::InvalidInput)?;
    parsed
        .format(&Rfc3339)
        .map_err(|_| KernelError::InvalidInput)
}

fn attribute<'a>(request: &'a RuleRequest, key: &str) -> &'a str {
    request.attributes.get(key).map_or("", |value| value.trim())
}

fn parse_optional_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "t" | "true" | "yes" | "y" | "enabled" | "on" | "active" => Some(true),
        "0" | "f" | "false" | "no" | "n" | "disabled" | "off" | "inactive" => Some(false),
        _ => None,
    }
}

fn fingerprint(parts: &str, anchor: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(parts.trim().as_bytes());
    digest.update([0]);
    digest.update(anchor.trim().as_bytes());
    digest.update([0]);
    hex_digest(&digest.finalize())
}

fn decision_digest(action: Action, anchor: &str, fingerprint: &str) -> String {
    let action = serde_json::to_value(action)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default();
    let mut digest = Sha256::new();
    for value in [action.as_str(), anchor, fingerprint] {
        digest.update(value.trim().as_bytes());
        digest.update([0]);
    }
    format!("sha256:{}", hex_digest(&digest.finalize()))
}

fn prefixed_digest(value: &[u8]) -> String {
    format!("sha256:{}", hex_digest(&Sha256::digest(value)))
}

fn hex_digest(value: &[u8]) -> String {
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EvaluationEnvelope;

    fn request(operation: Operation, approval: &str) -> EvaluationEnvelope {
        let request = RuleRequest {
            operation,
            rule_id: TAILSCALE_RULE_ID.into(),
            runtime_id: "runtime-1".into(),
            runtime_source_id: "tailscale".into(),
            runtime_tenant_id: "tenant-a".into(),
            runtime_workspace_id: "workspace-a".into(),
            event_id: "event-1".into(),
            event_tenant_id: "tenant-a".into(),
            event_source_id: "tailscale".into(),
            event_kind: "tailscale.tailnet".into(),
            occurred_at: "2026-04-23T12:05:00Z".into(),
            attributes: BTreeMap::from([
                ("tailnet".into(), "example.com".into()),
                ("devices_approval_on".into(), approval.into()),
                (WORKSPACE_ATTRIBUTE.into(), "workspace-a".into()),
            ]),
        };
        let input_digest = prefixed_digest(&serde_json::to_vec(&request).unwrap());
        EvaluationEnvelope {
            schema_version: SCHEMA_VERSION.into(),
            input_digest,
            request,
        }
    }

    #[test]
    fn generated_catalog_digest_is_exact() {
        let definition = cerebro_policy_catalog::lookup_detection(TAILSCALE_RULE_ID).unwrap();
        assert_eq!(definition.definition_digest, TAILSCALE_DEFINITION_DIGEST);
    }

    #[test]
    fn opens_and_closes_on_the_same_tenant_scoped_anchor() {
        let opened = evaluate(request(Operation::Evaluate, "false")).unwrap();
        assert_eq!(opened.action, Action::Open);
        let finding = opened.finding.unwrap();
        assert_eq!(finding.tenant_id, "tenant-a");
        assert_eq!(
            finding.resource_urns,
            ["urn:cerebro:tenant-a:tailscale_tailnet:example.com"]
        );
        let closed = evaluate(request(Operation::Close, "true")).unwrap();
        assert_eq!(closed.action, Action::Close);
        assert_eq!(
            closed.anchor,
            "tailscale_tailnet_urn=urn:cerebro:tenant-a:tailscale_tailnet:example.com"
        );
    }

    #[test]
    fn rejects_cross_tenant_and_cross_workspace_inputs() {
        let mut tenant = request(Operation::Evaluate, "false");
        tenant.request.event_tenant_id = "tenant-b".into();
        tenant.input_digest = prefixed_digest(&serde_json::to_vec(&tenant.request).unwrap());
        assert_eq!(evaluate(tenant), Err(KernelError::ScopeMismatch));

        let mut workspace = request(Operation::Evaluate, "false");
        workspace.request.runtime_workspace_id = "workspace-b".into();
        workspace.input_digest = prefixed_digest(&serde_json::to_vec(&workspace.request).unwrap());
        assert_eq!(evaluate(workspace), Err(KernelError::ScopeMismatch));
    }
}
