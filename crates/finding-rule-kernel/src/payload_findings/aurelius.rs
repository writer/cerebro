//! Aurelius rule for unresolved high-severity vulnerabilities in promoted images.
//!
//! Stable vulnerability identity is derived from image digest, CVE, and package
//! under the authenticated tenant. Provider payload can supplement lifecycle
//! presentation fields, but trusted event attributes own required identity and
//! source scope.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::model::{
    CanonicalScalar, ControlRef, Decision, KernelError, Operation, RuleFindingDecision,
    RuleRequest, attribute, decode_payload, finding_hash, first_non_empty, identity_anchor,
    normalized_observation_time, scalar, trim_empty, valid_identity_component, validate_scope,
};

/// Closed catalog identifier for this rule.
pub(super) const RULE_ID: &str = "aurelius-promoted-vulnerability-active";
/// Generated catalog commitment for the exact rule definition.
pub(super) const DEFINITION_DIGEST: &str =
    "5ec15d147ab34294d8214a19f519a7f52fce6bb2a59dfed9b408c3028695aab9";
/// Required source family on runtime and event scope.
const SOURCE_ID: &str = "aurelius";
/// Only event kind eligible for matching.
const EVENT_KIND: &str = "aurelius.finding";
/// Exact provider payload schema admitted by the host.
const SCHEMA_REF: &str = "aurelius/finding/v1";
/// Stable finding title.
const TITLE: &str = "Aurelius Promoted Image Unresolved High Vulnerability";
/// Stable current-state check identifier.
const CHECK_ID: &str = "aurelius-promoted-vulnerability-active-current";
/// Operator-facing check name.
const CHECK_NAME: &str = "Aurelius Promoted Image Unresolved High Vulnerability (current state)";

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
/// Closed projection of an Aurelius finding payload.
///
/// Underscored fields are admitted for schema parity but cannot supply required
/// identity or severity evidence; those values must come from trusted attributes.
struct Payload {
    #[serde(rename = "image_digest")]
    _image_digest: Option<CanonicalScalar>,
    image_uri: Option<CanonicalScalar>,
    #[serde(rename = "cve_id")]
    _cve_id: Option<CanonicalScalar>,
    #[serde(rename = "package")]
    _package: Option<CanonicalScalar>,
    #[serde(rename = "severity")]
    _severity: Option<CanonicalScalar>,
    #[serde(rename = "installed_version")]
    _installed_version: Option<CanonicalScalar>,
    #[serde(rename = "fixed_version")]
    _fixed_version: Option<CanonicalScalar>,
    state: Option<CanonicalScalar>,
    promoted: Option<CanonicalScalar>,
    exception_status: Option<CanonicalScalar>,
    track: Option<CanonicalScalar>,
}

pub(super) fn evaluate(request: &RuleRequest) -> Result<Decision, KernelError> {
    validate_scope(request, SOURCE_ID, SCHEMA_REF)?;
    // A valid Aurelius event outside the rule kind is a non-match.
    if !request.event.kind.trim().eq_ignore_ascii_case(EVENT_KIND) {
        return Ok(Decision::none());
    }
    // Action operations consume trusted lifecycle attributes only. Carrying raw
    // provider bytes across that boundary is rejected rather than ignored.
    if request.operation != Operation::Evaluate && !request.event.payload.is_empty() {
        return Err(KernelError::ActionPayloadNotEmpty);
    }
    if request.operation == Operation::OpenAnchor {
        return Ok(Decision::anchor(identity_anchor(
            &request.event.attributes,
            &["aurelius_vulnerability_urn"],
        )));
    }
    // The trusted adapter promotes close lifecycle fields into attributes and
    // admits action requests without payload bytes.
    if request.operation == Operation::Close {
        return evaluate_close(request);
    }
    // Evaluate is the only path that decodes provider JSON. Validate authority
    // time independently even if the final predicate is a non-match.
    let payload: Payload = decode_payload(&request.event.payload)?;
    normalized_observation_time(&request.event.observed_at)?;
    match request.operation {
        Operation::Evaluate => evaluate_open(request, &payload),
        Operation::OpenAnchor => Err(KernelError::UnsupportedOperation),
        Operation::Close => Err(KernelError::UnsupportedOperation),
    }
}

fn evaluate_open(request: &RuleRequest, payload: &Payload) -> Result<Decision, KernelError> {
    // Required fingerprint and predicate inputs must be promoted by the trusted
    // adapter; payload-only copies cannot open a finding.
    let image_digest = attribute(&request.event, "image_digest");
    let cve_id = attribute(&request.event, "cve_id");
    let package = attribute(&request.event, "package");
    let severity = attribute(&request.event, "severity");
    if [image_digest, cve_id, package, severity]
        .iter()
        .any(|value| value.is_empty())
    {
        return Ok(Decision::none());
    }
    let lifecycle = LifecycleAttributes::from_request(request, payload);
    // Open only for high/critical, unresolved, promoted vulnerabilities without
    // an active approved exception.
    if !lifecycle.risky(severity) {
        return Ok(Decision::none());
    }
    let tenant_id = request.runtime.tenant_id.trim();
    let vulnerability_urn = vulnerability_urn(tenant_id, image_digest, cve_id, package);
    if vulnerability_urn.is_empty() {
        return Ok(Decision::none());
    }
    let image_urn = format!("urn:cerebro:{tenant_id}:container_image_digest:{image_digest}");
    // Recurrence follows the tenant-scoped vulnerability URN, independent of
    // mutable severity, lifecycle, image URI, or observation time.
    let fingerprint = finding_hash(&[RULE_ID, &vulnerability_urn]);
    let observed_at = normalized_observation_time(&request.event.observed_at)?;
    let mut attributes = BTreeMap::from([
        (
            "aurelius_vulnerability_urn".into(),
            vulnerability_urn.clone(),
        ),
        ("aurelius_image_urn".into(), image_urn.clone()),
        ("container_image_urn".into(), image_urn.clone()),
        ("image_digest".into(), image_digest.into()),
        ("image_uri".into(), lifecycle.image_uri.into()),
        ("cve_id".into(), cve_id.into()),
        ("package".into(), package.into()),
        (
            "installed_version".into(),
            attribute(&request.event, "installed_version").into(),
        ),
        (
            "fixed_version".into(),
            attribute(&request.event, "fixed_version").into(),
        ),
        ("severity".into(), severity.into()),
        ("state".into(), lifecycle.state.into()),
        ("promoted".into(), lifecycle.promoted.into()),
        ("track".into(), lifecycle.track.into()),
        ("exception_status".into(), lifecycle.exception_status.into()),
        ("event_id".into(), request.event.id.trim().into()),
        (
            "source_runtime_id".into(),
            attribute(&request.event, "source_runtime_id").into(),
        ),
        ("primary_resource_urn".into(), vulnerability_urn.clone()),
    ]);
    insert_rule_attributes(&mut attributes);
    trim_empty(&mut attributes);
    Ok(Decision::open(RuleFindingDecision {
        id: fingerprint.clone(),
        fingerprint,
        tenant_id: tenant_id.into(),
        runtime_id: request.runtime.runtime_id.trim().into(),
        rule_id: RULE_ID.into(),
        title: TITLE.into(),
        severity: normalized_severity(severity).into(),
        status: "open".into(),
        summary: summary(&lifecycle, severity, cve_id, package, image_digest),
        resource_urns: vec![vulnerability_urn, image_urn],
        event_ids: vec![request.event.id.trim().into()],
        observed_policy_ids: None,
        policy_id: cve_id.into(),
        policy_name: cve_id.into(),
        check_id: CHECK_ID.into(),
        check_name: CHECK_NAME.into(),
        control_refs: vec![
            ControlRef {
                framework_name: "SOC 2".into(),
                control_id: "CC7.1".into(),
            },
            ControlRef {
                framework_name: "ISO 27001:2022".into(),
                control_id: "A.8.8".into(),
            },
        ],
        attributes,
        first_observed_at: observed_at.clone(),
        last_observed_at: observed_at,
    }))
}

fn evaluate_close(request: &RuleRequest) -> Result<Decision, KernelError> {
    // Close uses the same trusted identity tuple as open, but all lifecycle
    // signals must be in host attributes because action payloads are forbidden.
    let image_digest = attribute(&request.event, "image_digest");
    let cve_id = attribute(&request.event, "cve_id");
    let package = attribute(&request.event, "package");
    if [image_digest, cve_id, package]
        .iter()
        .any(|value| value.is_empty())
    {
        return Ok(Decision::none());
    }
    let lifecycle = LifecycleAttributes::from_attributes(request);
    if !lifecycle.remediated(attribute(&request.event, "severity")) {
        return Ok(Decision::none());
    }
    close_decision(request, image_digest, cve_id, package)
}

fn close_decision(
    request: &RuleRequest,
    image_digest: &str,
    cve_id: &str,
    package: &str,
) -> Result<Decision, KernelError> {
    // Rebuild the open path's exact URN, then express it through the standard
    // `field=value` identity anchor consumed by finding lifecycle storage.
    let vulnerability_urn = vulnerability_urn(
        request.runtime.tenant_id.trim(),
        image_digest,
        cve_id,
        package,
    );
    let anchor = identity_anchor(
        &BTreeMap::from([("aurelius_vulnerability_urn".into(), vulnerability_urn)]),
        &["aurelius_vulnerability_urn"],
    );
    if anchor.is_empty() {
        Ok(Decision::none())
    } else {
        Ok(Decision::close(anchor))
    }
}

struct LifecycleAttributes<'a> {
    /// Display identity for summaries, never stable recurrence identity.
    image_uri: &'a str,
    /// Provider remediation state.
    state: &'a str,
    /// Whether the image is in a promoted track.
    promoted: &'a str,
    /// Optional release track presentation field.
    track: &'a str,
    /// Provider policy-exception state.
    exception_status: &'a str,
}

impl<'a> LifecycleAttributes<'a> {
    /// Resolves trusted attributes before payload fallbacks.
    fn from_request(request: &'a RuleRequest, payload: &'a Payload) -> Self {
        Self {
            image_uri: first_non_empty(&[
                attribute(&request.event, "image_uri"),
                scalar(&payload.image_uri),
            ]),
            state: first_non_empty(&[attribute(&request.event, "state"), scalar(&payload.state)]),
            promoted: first_non_empty(&[
                attribute(&request.event, "promoted"),
                scalar(&payload.promoted),
            ]),
            track: first_non_empty(&[attribute(&request.event, "track"), scalar(&payload.track)]),
            exception_status: first_non_empty(&[
                attribute(&request.event, "exception_status"),
                scalar(&payload.exception_status),
            ]),
        }
    }

    /// Reads close lifecycle state exclusively from trusted attributes.
    fn from_attributes(request: &'a RuleRequest) -> Self {
        Self {
            image_uri: attribute(&request.event, "image_uri"),
            state: attribute(&request.event, "state"),
            promoted: attribute(&request.event, "promoted"),
            track: attribute(&request.event, "track"),
            exception_status: attribute(&request.event, "exception_status"),
        }
    }

    /// Returns whether all open predicates are simultaneously satisfied.
    fn risky(&self, severity: &str) -> bool {
        is_actionable_severity(severity)
            && !is_resolved(self.state)
            && is_promoted(self.promoted)
            && !has_active_exception(self.exception_status)
    }

    /// Returns whether any closed remediation predicate is explicitly satisfied.
    fn remediated(&self, severity: &str) -> bool {
        is_resolved(self.state)
            || is_unpromoted(self.promoted)
            || has_active_exception(self.exception_status)
            || is_below_actionable_severity(severity)
    }
}

fn vulnerability_urn(tenant_id: &str, image_digest: &str, cve_id: &str, package: &str) -> String {
    // Reject control-bearing or empty identity parts before hashing the provider
    // tuple into a compact tenant-scoped URN.
    if [tenant_id, image_digest, cve_id, package]
        .iter()
        .any(|value| !valid_identity_component(value))
    {
        return String::new();
    }
    let key = finding_hash(&[
        "aurelius-promoted-vulnerability",
        image_digest,
        cve_id,
        package,
    ]);
    format!(
        "urn:cerebro:{}:aurelius_vulnerability:{key}",
        tenant_id.trim()
    )
}

fn is_actionable_severity(value: &str) -> bool {
    // Unknown values never satisfy the open predicate.
    matches!(
        value.trim().to_ascii_uppercase().as_str(),
        "CRITICAL" | "HIGH"
    )
}

fn is_below_actionable_severity(value: &str) -> bool {
    // Only recognized lower severities are affirmative close evidence.
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "medium" | "moderate" | "low" | "info" | "informational" | "negligible"
    )
}

fn is_resolved(value: &str) -> bool {
    // Closed provider spellings are an explicit vocabulary, not substring tests.
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "fixed"
            | "resolved"
            | "remediated"
            | "downgraded"
            | "not_affected"
            | "notaffected"
            | "closed"
    )
}

fn is_promoted(value: &str) -> bool {
    // Recognize provider Boolean and lifecycle spellings for promotion.
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "yes" | "1" | "promoted"
    )
}

fn is_unpromoted(value: &str) -> bool {
    // Unpromotion is independent affirmative remediation evidence.
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "false" | "no" | "0" | "unpromoted" | "not_promoted"
    )
}

fn has_active_exception(value: &str) -> bool {
    // Only active/approved/granted exceptions suppress or close this rule.
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "active" | "approved" | "granted"
    )
}

fn normalized_severity(value: &str) -> &'static str {
    // Output uses the lifecycle severity vocabulary; an unexpected input falls
    // back to MEDIUM but cannot reach open because it is not actionable above.
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => "CRITICAL",
        "high" => "HIGH",
        "medium" | "moderate" => "MEDIUM",
        "low" => "LOW",
        "info" | "informational" => "INFO",
        _ => "MEDIUM",
    }
}

fn summary(
    lifecycle: &LifecycleAttributes<'_>,
    severity: &str,
    cve_id: &str,
    package: &str,
    image_digest: &str,
) -> String {
    // Prefer provider display identity, then the stable digest, with explicit
    // placeholders only for fields not required by the open predicate.
    let image = first_non_empty(&[lifecycle.image_uri, image_digest, "unknown image"]);
    format!(
        "{} Aurelius vulnerability {} affects promoted {} in image {}",
        normalized_severity(severity),
        first_non_empty(&[cve_id, "vulnerability"]),
        first_non_empty(&[package, "unknown package"]),
        image
    )
}

fn insert_rule_attributes(attributes: &mut BTreeMap<String, String>) {
    // Fixed catalog metadata travels with every finding for operator explanation
    // and parity with the existing lifecycle record.
    attributes.extend([
        ("rule_maturity".into(), "test".into()),
        ("rule_severity".into(), "dynamic".into()),
        ("rule_source_id".into(), SOURCE_ID.into()),
        ("rule_status".into(), "open".into()),
        ("rule_event_kinds".into(), EVENT_KIND.into()),
        (
            "rule_fingerprint_fields".into(),
            "aurelius_vulnerability_urn".into(),
        ),
        (
            "rule_false_positives".into(),
            "Vulnerability covered by an active, approved Aurelius policy exception, already downgraded below high severity, or remediated by a newer promoted image build.".into(),
        ),
        (
            "rule_references".into(),
            "https://kubernetes.io/docs/concepts/security/supply-chain-security/".into(),
        ),
        (
            "rule_required_attributes".into(),
            "image_digest,cve_id,package,severity".into(),
        ),
        (
            "rule_tags".into(),
            "aurelius,container,vulnerability,image,promotion,attack.initial-access".into(),
        ),
        (
            "rule_runbook".into(),
            "Confirm the promoted image still carries the unresolved vulnerability; rebuild and re-promote a fixed image or grant an approved policy exception, then re-scan to clear the finding.".into(),
        ),
    ]);
}
