use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

use super::model::{CanonicalScalar, decode_payload, finding_hash, scalar};
use super::*;

const OBSERVED_AT: &str = "2026-05-22T12:00:00Z";

fn aurelius_request(operation: Operation) -> RuleRequest {
    RuleRequest {
        operation,
        rule_id: aurelius::RULE_ID.into(),
        runtime: TrustedRuntime {
            runtime_id: "writer-aurelius-finding".into(),
            source_id: "aurelius".into(),
            tenant_id: "writer".into(),
            workspace_id: "workspace-a".into(),
        },
        event: EventInput {
            id: "aurelius-vuln-open".into(),
            tenant_id: "writer".into(),
            source_id: "aurelius".into(),
            kind: "aurelius.finding".into(),
            schema_ref: "aurelius/finding/v1".into(),
            observed_at: OBSERVED_AT.into(),
            replay_sequence: 7,
            attributes: BTreeMap::from([
                ("image_digest".into(), "sha256:c6b86af5b3d40000".into()),
                (
                    "image_uri".into(),
                    "us-docker.pkg.dev/writer/prod/api@sha256:c6b86af5b3d40000".into(),
                ),
                ("cve_id".into(), "CVE-2026-1111".into()),
                ("package".into(), "openssl".into()),
                ("installed_version".into(), "3.0.0".into()),
                ("fixed_version".into(), "3.0.12".into()),
                ("severity".into(), "high".into()),
                ("state".into(), "promoted".into()),
                ("promoted".into(), "true".into()),
                ("track".into(), "prod".into()),
                ("exception_status".into(), "none".into()),
                ("source_runtime_id".into(), "writer-aurelius-finding".into()),
            ]),
            payload: if operation == Operation::Evaluate {
                br#"{"image_digest":"sha256:c6b86af5b3d40000","image_uri":"us-docker.pkg.dev/writer/prod/api@sha256:c6b86af5b3d40000","cve_id":"CVE-2026-1111","package":"openssl","severity":"high","installed_version":"3.0.0","fixed_version":"3.0.12","state":"promoted","promoted":true,"exception_status":"none","track":"prod"}"#.to_vec()
            } else {
                Vec::new()
            },
        },
    }
}

fn cosmo_request(operation: Operation) -> RuleRequest {
    RuleRequest {
        operation,
        rule_id: cosmo::RULE_ID.into(),
        runtime: TrustedRuntime {
            runtime_id: "writer-cosmo-fact".into(),
            source_id: "cosmo".into(),
            tenant_id: "writer".into(),
            workspace_id: "workspace-a".into(),
        },
        event: EventInput {
            id: "cosmo-risk-1".into(),
            tenant_id: "writer".into(),
            source_id: "cosmo".into(),
            kind: "cosmo.fact".into(),
            schema_ref: "cosmo/fact/v1".into(),
            observed_at: "2026-05-01T12:00:00Z".into(),
            replay_sequence: 11,
            attributes: BTreeMap::from([
                ("key".into(), "coordination:risk:thread-7".into()),
                ("category".into(), "coordination_risk".into()),
                ("source".into(), "session:thread-7".into()),
                ("risk_state".into(), "active".into()),
                (
                    "risk_reason".into(),
                    "agent coordinated a privileged change across multiple sessions without approval"
                        .into(),
                ),
                ("risk_severity".into(), "high".into()),
                ("source_runtime_id".into(), "writer-cosmo-fact".into()),
            ]),
            payload: if operation == Operation::Evaluate {
                br#"{"key":"coordination:risk:thread-7","category":"coordination_risk","source":"session:thread-7","risk_state":"active","risk_reason":"payload reason is lower precedence","risk_severity":"critical","confidence":0.9}"#.to_vec()
            } else {
                Vec::new()
            },
        },
    }
}

fn opened(request: &RuleRequest) -> RuleFindingDecision {
    let decision = evaluate(request).expect("evaluation succeeds");
    assert_eq!(decision.action, Action::Open);
    decision.finding.expect("open finding")
}

#[test]
fn generated_definition_and_public_catalog_contracts_are_exact() {
    for (rule_id, digest) in [
        (aurelius::RULE_ID, aurelius::DEFINITION_DIGEST),
        (cosmo::RULE_ID, cosmo::DEFINITION_DIGEST),
    ] {
        let definition = cerebro_policy_catalog::lookup_detection(rule_id).unwrap();
        assert_eq!(definition.definition_digest, digest);
        assert_eq!(definition.computed_digest().unwrap(), digest);
    }

    let catalog: Value = serde_json::from_str(include_str!(
        "../../../../internal/findings/public_detection_catalog.json"
    ))
    .unwrap();
    let detections = catalog["detections"].as_array().unwrap();
    let get = |rule_id: &str| {
        detections
            .iter()
            .find(|entry| entry["id"] == rule_id)
            .unwrap()
    };
    let aurelius = get(aurelius::RULE_ID);
    assert_eq!(aurelius["evidence_type"], "vulnerability_management");
    assert_eq!(
        aurelius["assessment_methods"],
        serde_json::json!(["examine", "test"])
    );
    assert_eq!(
        aurelius["risk_statement"],
        "A promoted container image may carry active vulnerabilities into a trusted environment."
    );
    assert_eq!(
        aurelius["remediation_intent"],
        "Rebuild or patch the image, re-attest the promotion, and retain promotion and scan evidence."
    );
    assert!(
        aurelius["auditor_guidance"]
            .as_str()
            .unwrap()
            .contains("correlated graph path")
    );

    let cosmo = get(cosmo::RULE_ID);
    assert_eq!(cosmo["evidence_type"], "ai_agent_governance");
    assert_eq!(
        cosmo["assessment_methods"],
        serde_json::json!(["examine", "test"])
    );
    assert_eq!(
        cosmo["risk_statement"],
        "Active agent-memory coordination risk may allow unsafe automated actions or data exposure."
    );
    assert_eq!(
        cosmo["remediation_intent"],
        "Constrain the agent coordination path, validate guardrails, and retain agent evidence."
    );
    assert!(
        cosmo["auditor_guidance"]
            .as_str()
            .unwrap()
            .contains("source-state snapshot")
    );
}

#[derive(Deserialize)]
struct GoRuleFixture {
    rule_id: String,
    runtime: GoRuntimeFixture,
    events: Vec<GoEventFixture>,
    expected_findings: Vec<GoFindingFixture>,
    expected_no_match: Vec<GoNoMatchFixture>,
}

#[derive(Deserialize)]
struct GoRuntimeFixture {
    id: String,
    source_id: String,
    tenant_id: String,
}

#[derive(Deserialize)]
struct GoEventFixture {
    id: String,
    tenant_id: String,
    source_id: String,
    kind: String,
    occurred_at: String,
    attributes: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct GoFindingFixture {
    rule_id: String,
    severity: String,
    status: String,
    summary: String,
    event_ids: Vec<String>,
    attributes: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct GoNoMatchFixture {
    event_id: String,
}

#[test]
fn rust_consumes_the_same_checked_go_oracle_fixtures() {
    for raw in [
        include_str!(
            "../../../../internal/findings/testdata/rules/aurelius-promoted-vulnerability-active.json"
        ),
        include_str!(
            "../../../../internal/findings/testdata/rules/cosmo-coordination-active-risk.json"
        ),
    ] {
        let fixture: GoRuleFixture = serde_json::from_str(raw).unwrap();
        for (sequence, event) in fixture.events.into_iter().enumerate() {
            let request = RuleRequest {
                operation: Operation::Evaluate,
                rule_id: fixture.rule_id.clone(),
                runtime: TrustedRuntime {
                    runtime_id: fixture.runtime.id.clone(),
                    source_id: fixture.runtime.source_id.clone(),
                    tenant_id: fixture.runtime.tenant_id.clone(),
                    workspace_id: "fixture-workspace".into(),
                },
                event: EventInput {
                    id: event.id.clone(),
                    tenant_id: event.tenant_id,
                    source_id: event.source_id,
                    kind: event.kind,
                    schema_ref: if fixture.rule_id == aurelius::RULE_ID {
                        "aurelius/finding/v1".into()
                    } else {
                        "cosmo/fact/v1".into()
                    },
                    observed_at: event.occurred_at,
                    replay_sequence: sequence as u64,
                    attributes: event.attributes,
                    payload: Vec::new(),
                },
            };
            let decision = evaluate(&request).unwrap();
            if let Some(expected) = fixture
                .expected_findings
                .iter()
                .find(|finding| finding.event_ids == [event.id.as_str()])
            {
                let finding = decision.finding.expect("Go fixture expects a finding");
                assert_eq!(decision.action, Action::Open);
                assert_eq!(finding.rule_id, expected.rule_id);
                assert_eq!(finding.severity, expected.severity);
                assert_eq!(finding.status, expected.status);
                assert_eq!(finding.summary, expected.summary);
                assert_eq!(finding.event_ids, expected.event_ids);
                for (key, value) in &expected.attributes {
                    assert_eq!(finding.attributes.get(key), Some(value), "{key}");
                }
            } else {
                assert!(
                    fixture
                        .expected_no_match
                        .iter()
                        .any(|expected| expected.event_id == event.id)
                );
                assert_eq!(decision, Decision::none());
            }
        }
    }
}

#[test]
fn aurelius_open_matches_the_historical_go_record_subset() {
    let finding = opened(&aurelius_request(Operation::Evaluate));
    let vulnerability_urn = "urn:cerebro:writer:aurelius_vulnerability:493b1e0218d8db17a8481054b3563db15481ac666ba6c3d8245ec6a6a79a00bf";
    assert_eq!(
        finding.id,
        "2080b506af7b41ad7aaa86c99656cc7aa57ad1af58973086b24ff3a26f8ce402"
    );
    assert_eq!(finding.fingerprint, finding.id);
    assert_eq!(finding.tenant_id, "writer");
    assert_eq!(finding.runtime_id, "writer-aurelius-finding");
    assert_eq!(finding.rule_id, aurelius::RULE_ID);
    assert_eq!(
        finding.title,
        "Aurelius Promoted Image Unresolved High Vulnerability"
    );
    assert_eq!(finding.severity, "HIGH");
    assert_eq!(finding.status, "open");
    assert_eq!(
        finding.summary,
        "HIGH Aurelius vulnerability CVE-2026-1111 affects promoted openssl in image us-docker.pkg.dev/writer/prod/api@sha256:c6b86af5b3d40000"
    );
    assert_eq!(
        finding.resource_urns,
        [
            vulnerability_urn,
            "urn:cerebro:writer:container_image_digest:sha256:c6b86af5b3d40000"
        ]
    );
    assert_eq!(finding.event_ids, ["aurelius-vuln-open"]);
    assert_eq!(finding.policy_id, "CVE-2026-1111");
    assert_eq!(finding.policy_name, "CVE-2026-1111");
    assert_eq!(
        finding.check_id,
        "aurelius-promoted-vulnerability-active-current"
    );
    assert_eq!(finding.control_refs[0].control_id, "CC7.1");
    assert_eq!(finding.control_refs[1].control_id, "A.8.8");
    assert_eq!(finding.first_observed_at, OBSERVED_AT);
    assert_eq!(finding.last_observed_at, OBSERVED_AT);
    assert_eq!(
        finding.attributes["aurelius_vulnerability_urn"],
        vulnerability_urn
    );
    assert_eq!(
        finding.attributes["source_runtime_id"],
        "writer-aurelius-finding"
    );
    assert!(
        !finding
            .attributes
            .contains_key("cerebro_application_workspace_id")
    );
}

#[test]
fn aurelius_uses_attribute_precedence_and_real_severity() {
    let mut precedence = aurelius_request(Operation::Evaluate);
    precedence.event.payload = br#"{"image_digest":"payload-only","cve_id":"payload-cve","package":"payload-package","severity":"low","state":"fixed","promoted":false,"exception_status":"active","image_uri":"payload-image"}"#.to_vec();
    let finding = opened(&precedence);
    assert_eq!(
        finding.attributes["image_digest"],
        "sha256:c6b86af5b3d40000"
    );
    assert_eq!(finding.attributes["state"], "promoted");
    assert_eq!(finding.attributes["promoted"], "true");
    assert_eq!(finding.attributes["exception_status"], "none");

    for severity in ["low", "medium", "unknown"] {
        let mut request = aurelius_request(Operation::Evaluate);
        request
            .event
            .attributes
            .insert("severity".into(), severity.into());
        let decision = evaluate(&request).unwrap();
        assert_eq!(decision, Decision::none(), "severity {severity}");
    }
}

#[test]
fn aurelius_close_and_recurrence_preserve_the_exact_anchor_and_identity() {
    let open = opened(&aurelius_request(Operation::Evaluate));
    let mut anchor_request = aurelius_request(Operation::OpenAnchor);
    anchor_request.event.attributes = open.attributes.clone();
    let open_anchor = evaluate(&anchor_request).unwrap().anchor;
    assert_eq!(
        open_anchor,
        format!(
            "aurelius_vulnerability_urn={}",
            open.attributes["aurelius_vulnerability_urn"]
        )
    );

    for (field, value) in [
        ("state", "fixed"),
        ("promoted", "false"),
        ("exception_status", "active"),
        ("severity", "medium"),
    ] {
        let mut close = aurelius_request(Operation::Close);
        close.event.attributes.insert(field.into(), value.into());
        let decision = evaluate(&close).unwrap();
        assert_eq!(decision.action, Action::Close, "{field}={value}");
        assert_eq!(decision.anchor, open_anchor);
    }

    let mut unrelated = aurelius_request(Operation::Close);
    unrelated
        .event
        .attributes
        .insert("cve_id".into(), "CVE-OTHER".into());
    unrelated
        .event
        .attributes
        .insert("state".into(), "fixed".into());
    assert_ne!(evaluate(&unrelated).unwrap().anchor, open_anchor);

    let mut recurrence = aurelius_request(Operation::Evaluate);
    recurrence.event.id = "aurelius-vuln-recurrence".into();
    recurrence.event.observed_at = "2026-05-22T14:00:00Z".into();
    let reopened = opened(&recurrence);
    assert_eq!(reopened.id, open.id);
    assert_eq!(reopened.fingerprint, open.fingerprint);
}

#[test]
fn aurelius_requires_normalized_stable_identity_attributes() {
    for field in ["image_digest", "cve_id", "package", "severity"] {
        let mut request = aurelius_request(Operation::Evaluate);
        request.event.attributes.remove(field);
        assert_eq!(
            evaluate(&request).unwrap(),
            Decision::none(),
            "missing {field}"
        );
    }
}

#[test]
fn cosmo_open_matches_the_historical_go_record_subset() {
    let finding = opened(&cosmo_request(Operation::Evaluate));
    let risk_urn = "urn:cerebro:writer:cosmo_coordination_risk:081433b50564f6901a823d298c60b79fdb574d24b7e8a3e987e9693c5f614971";
    assert_eq!(
        finding.id,
        "9545935c7c0c44ef2592599d8dbb125ab14696d8b4380ce0a2efc5c202014fda"
    );
    assert_eq!(finding.fingerprint, finding.id);
    assert_eq!(finding.runtime_id, "writer-cosmo-fact");
    assert_eq!(finding.severity, "HIGH");
    assert_eq!(finding.status, "open");
    assert_eq!(
        finding.summary,
        "Cosmo agent memory records active coordination risk"
    );
    assert_eq!(
        finding.resource_urns,
        [
            "urn:cerebro:writer:cosmo_fact:id-873b69e0e168001720199af9fbf1b7a6",
            "urn:cerebro:writer:cosmo_session:id-7369a510fb91d7dbab5074391bb95b5d"
        ]
    );
    assert_eq!(finding.attributes["cosmo_risk_urn"], risk_urn);
    assert_eq!(finding.attributes["risk_reason_source"], "event_attribute");
    assert_eq!(finding.attributes["risk_severity"], "high");
    assert_eq!(
        finding.attributes["risk_severity_source"],
        "event_attribute"
    );
    assert!(finding.policy_id.is_empty());
    assert!(finding.policy_name.is_empty());
    assert_eq!(finding.control_refs[0].control_id, "CC7.1");
    assert_eq!(finding.control_refs[1].control_id, "A.5.7");
    assert!(
        !finding
            .attributes
            .contains_key("cerebro_application_workspace_id")
    );
}

#[test]
fn cosmo_payload_evidence_and_ignored_source_fields_are_explicit() {
    for field in ["confidence", "value", "reason", "summary"] {
        let mut request = cosmo_request(Operation::Evaluate);
        request.event.attributes.remove("risk_reason");
        request.event.attributes.remove("risk_severity");
        request.event.payload = format!(
            "{{\"key\":\"coordination:risk:thread-7\",\"category\":\"coordination_risk\",\"source\":\"session:thread-7\",\"status\":\"active\",\"risk_reason\":\"payload evidence\",\"severity\":\"high\",\"{field}\":\"ignored scalar\"}}"
        )
        .into_bytes();
        let finding = opened(&request);
        assert_eq!(finding.attributes["risk_reason"], "payload evidence");
        assert_eq!(
            finding.attributes["risk_reason_source"],
            "agent_memory_payload"
        );
        assert_eq!(
            finding.attributes["risk_reason_operator_validation"],
            "required"
        );
        assert_eq!(finding.attributes["risk_severity"], "high");
        assert!(!finding.attributes.contains_key(field));
    }
}

#[test]
fn cosmo_provider_projection_is_bounded_closed_and_receipted() {
    let raw = br#"{
        "record_id":"fact-7",
        "key":"coordination:risk:thread-7",
        "category":"coordination_risk",
        "source":"session:thread-7",
        "status":"active",
        "risk_reason":"provider-shaped evidence",
        "severity":"high",
        "confidence":0.875,
        "metadata":{"agent":"writer","turns":[1,2,3]}
    }"#;
    let (payload, receipt) = cosmo::project_source_payload(raw).unwrap();
    assert_eq!(receipt.input_digest.len(), 64);
    assert_eq!(receipt.output_digest.len(), 64);
    assert_ne!(receipt.input_digest, receipt.output_digest);
    assert_eq!(receipt.dropped_fields, 2);

    let mut request = cosmo_request(Operation::Evaluate);
    request.event.attributes.remove("risk_reason");
    request.event.attributes.remove("risk_severity");
    request.event.payload = payload;
    let finding = opened(&request);
    assert_eq!(
        finding.attributes["risk_reason"],
        "provider-shaped evidence"
    );
    assert_eq!(finding.attributes["risk_severity"], "high");

    for trusted in ["tenant_id", "workspace_id", "runtime_id", "occurred_at"] {
        let forged = format!("{{\"{trusted}\":\"forged\"}}");
        assert_eq!(
            cosmo::project_source_payload(forged.as_bytes()),
            Err(KernelError::ScopeMismatch)
        );
    }
    assert_eq!(
        cosmo::project_source_payload(&vec![b'x'; MAX_PAYLOAD_BYTES + 1]),
        Err(KernelError::PayloadTooLarge)
    );
}

#[test]
fn cosmo_rejects_missing_or_payload_only_required_key() {
    let mut missing = cosmo_request(Operation::Evaluate);
    missing.event.attributes.remove("key");
    missing.event.payload =
        br#"{"category":"coordination_risk","source":"session:thread-7","status":"active"}"#
            .to_vec();
    assert_eq!(evaluate(&missing).unwrap(), Decision::none());

    let mut payload_only = missing;
    payload_only.event.payload = br#"{"key":"coordination:risk:thread-7","category":"coordination_risk","source":"session:thread-7","status":"active"}"#.to_vec();
    assert_eq!(evaluate(&payload_only).unwrap(), Decision::none());
}

#[test]
fn cosmo_never_auto_closes_and_preserves_identity_on_recurrence() {
    let open = opened(&cosmo_request(Operation::Evaluate));
    let mut close = cosmo_request(Operation::Close);
    close
        .event
        .attributes
        .insert("risk_state".into(), "resolved".into());
    assert_eq!(evaluate(&close).unwrap(), Decision::none());

    let mut recurrence = cosmo_request(Operation::Evaluate);
    recurrence.event.id = "cosmo-risk-2".into();
    recurrence.event.observed_at = "2026-05-01T14:00:00Z".into();
    let reopened = opened(&recurrence);
    assert_eq!(reopened.id, open.id);
    assert_eq!(reopened.fingerprint, open.fingerprint);
}

#[test]
fn cosmo_session_and_delimiter_identities_do_not_collide() {
    let mut uppercase = cosmo_request(Operation::Evaluate);
    uppercase
        .event
        .attributes
        .insert("source".into(), "SESSION:thread-7".into());
    let uppercase = opened(&uppercase);
    assert_eq!(uppercase.resource_urns.len(), 1);

    let mut sessionless = cosmo_request(Operation::Evaluate);
    sessionless.event.attributes.remove("source");
    sessionless.event.payload = br#"{"key":"coordination:risk:thread-7","category":"coordination_risk","risk_state":"active"}"#.to_vec();
    let sessionless = opened(&sessionless);
    assert_eq!(sessionless.resource_urns.len(), 1);

    let mut literal = cosmo_request(Operation::Evaluate);
    literal
        .event
        .attributes
        .insert("source".into(), "session:sessionless".into());
    let literal = opened(&literal);
    assert_ne!(sessionless.id, literal.id);

    let mut colon = cosmo_request(Operation::Evaluate);
    colon
        .event
        .attributes
        .insert("key".into(), "coordination:risk".into());
    let colon = opened(&colon);
    let mut slash = cosmo_request(Operation::Evaluate);
    slash
        .event
        .attributes
        .insert("key".into(), "coordination/risk".into());
    let slash = opened(&slash);
    assert_ne!(colon.resource_urns[0], slash.resource_urns[0]);
    assert_ne!(colon.id, slash.id);
}

#[test]
fn trusted_scope_fails_closed_without_using_payload_or_workspace_attributes() {
    for mutation in ["tenant", "source", "runtime"] {
        let mut request = cosmo_request(Operation::Evaluate);
        match mutation {
            "tenant" => request.event.tenant_id = "other".into(),
            "source" => request.event.source_id = "aurelius".into(),
            "runtime" => {
                request
                    .event
                    .attributes
                    .insert("source_runtime_id".into(), "shadow".into());
            }
            _ => unreachable!(),
        };
        assert_eq!(evaluate(&request), Err(KernelError::ScopeMismatch));
    }

    let first = opened(&cosmo_request(Operation::Evaluate));
    let mut other_workspace = cosmo_request(Operation::Evaluate);
    other_workspace.runtime.workspace_id = "workspace-b".into();
    other_workspace.event.attributes.insert(
        "cerebro_application_workspace_id".into(),
        "provider-controlled".into(),
    );
    assert_eq!(
        evaluate(&other_workspace),
        Err(KernelError::WorkspaceMismatch)
    );

    other_workspace.event.attributes.insert(
        "cerebro_application_workspace_id".into(),
        "workspace-b".into(),
    );
    let second = opened(&other_workspace);
    assert_eq!(first.id, second.id);
    assert_eq!(first.fingerprint, second.fingerprint);
    assert!(
        !second
            .attributes
            .contains_key("cerebro_application_workspace_id")
    );
}

#[test]
fn exact_schema_and_utc_observation_are_host_contracts() {
    for make in [
        aurelius_request as fn(Operation) -> RuleRequest,
        cosmo_request as fn(Operation) -> RuleRequest,
    ] {
        for schema in ["", "wrong/schema/v1"] {
            let mut request = make(Operation::Evaluate);
            request.event.schema_ref = schema.into();
            assert_eq!(evaluate(&request), Err(KernelError::SchemaMismatch));
        }

        let mut offset = make(Operation::Evaluate);
        offset.event.observed_at = "2026-05-22T05:00:00-07:00".into();
        let offset = evaluate_scoped(&offset).unwrap();
        assert_eq!(offset.observed_at, "2026-05-22T12:00:00Z");
        assert_eq!(
            offset.decision.finding.as_ref().unwrap().first_observed_at,
            "2026-05-22T12:00:00Z"
        );

        let mut fractional = make(Operation::Evaluate);
        fractional.event.observed_at = "2026-05-22T12:00:00.120000000Z".into();
        let fractional = evaluate_scoped(&fractional).unwrap();
        assert_eq!(fractional.observed_at, "2026-05-22T12:00:00.12Z");

        let mut zero_fraction = make(Operation::Evaluate);
        zero_fraction.event.observed_at = "2026-05-22T12:00:00.000000000Z".into();
        let zero_fraction = evaluate_scoped(&zero_fraction).unwrap();
        assert_eq!(zero_fraction.observed_at, "2026-05-22T12:00:00Z");

        let mut over_precision = make(Operation::Evaluate);
        over_precision.event.observed_at = "2026-05-22T12:00:00.1234567890Z".into();
        assert_eq!(
            evaluate_scoped(&over_precision),
            Err(KernelError::InvalidObservationTime)
        );
    }
}

#[test]
fn unrelated_kind_returns_none_before_payload_decode() {
    for mut request in [
        aurelius_request(Operation::Evaluate),
        cosmo_request(Operation::Evaluate),
    ] {
        request.event.kind = "unrelated.kind".into();
        request.event.payload = br#"{"truncated":"#.to_vec();
        assert_eq!(evaluate(&request).unwrap(), Decision::none());
    }
}

#[test]
fn action_dispatch_requires_trusted_kind_and_payload_free_requests() {
    let mut aurelius = aurelius_request(Operation::Close);
    aurelius
        .event
        .attributes
        .insert("state".into(), "fixed".into());
    aurelius.event.payload = br#"{"truncated":"#.to_vec();
    assert_eq!(evaluate(&aurelius), Err(KernelError::ActionPayloadNotEmpty));

    let mut cosmo = cosmo_request(Operation::Close);
    cosmo.event.payload = br#"{"truncated":"#.to_vec();
    assert_eq!(evaluate(&cosmo), Err(KernelError::ActionPayloadNotEmpty));

    for make in [
        aurelius_request as fn(Operation) -> RuleRequest,
        cosmo_request as fn(Operation) -> RuleRequest,
    ] {
        for operation in [Operation::OpenAnchor, Operation::Close] {
            let mut wrong_kind = make(operation);
            wrong_kind.event.kind = "unrelated.kind".into();
            wrong_kind.event.payload = br#"{"unknown":true}"#.to_vec();
            assert_eq!(evaluate(&wrong_kind).unwrap(), Decision::none());

            for payload in [
                br#"{"unknown":true}"#.to_vec(),
                br#"{"state":"open","state":"fixed"}"#.to_vec(),
                vec![b'x'; MAX_PAYLOAD_BYTES + 1],
                format!(
                    "{}0{}",
                    "[".repeat(MAX_PAYLOAD_DEPTH),
                    "]".repeat(MAX_PAYLOAD_DEPTH)
                )
                .into_bytes(),
            ] {
                let mut request = make(operation);
                request.event.payload = payload;
                assert_eq!(evaluate(&request), Err(KernelError::ActionPayloadNotEmpty));
            }
        }
    }
}

#[test]
fn missing_or_blank_open_anchor_is_no_action() {
    for make in [
        aurelius_request as fn(Operation) -> RuleRequest,
        cosmo_request as fn(Operation) -> RuleRequest,
    ] {
        let mut request = make(Operation::OpenAnchor);
        request.event.attributes.clear();
        let missing = evaluate_scoped(&request).unwrap();
        assert_eq!(missing.decision, Decision::none());
        assert_ne!(missing.decision.action, Action::Close);
        assert!(missing.decision.anchor.is_empty());
        request
            .event
            .attributes
            .insert("aurelius_vulnerability_urn".into(), "  ".into());
        request
            .event
            .attributes
            .insert("cosmo_risk_urn".into(), "  ".into());
        let blank = evaluate_scoped(&request).unwrap();
        assert_eq!(blank.decision, Decision::none());
        assert_ne!(blank.decision.action, Action::Close);
        assert!(blank.decision.anchor.is_empty());
    }
}

#[test]
fn scoped_host_boundary_fails_closed_without_fallback_or_write() {
    for expected in [
        KernelError::EvaluatorFailure,
        KernelError::MalformedEvaluatorResponse,
        KernelError::InvalidEvaluatorReceipt,
    ] {
        let request = aurelius_request(Operation::Evaluate);
        let mut invocations = 0;
        let result = evaluate_scoped_with(&request, |_| {
            invocations += 1;
            Err(expected.clone())
        });
        assert_eq!(result, Err(expected));
        assert_eq!(invocations, 1, "the host must not invoke a Go fallback");

        let writes = result
            .ok()
            .into_iter()
            .filter(|scoped| matches!(scoped.decision.action, Action::Open | Action::Close));
        assert_eq!(writes.count(), 0, "evaluator failure must not write");
    }
}

#[test]
fn evaluator_response_and_receipt_are_closed_and_context_bound() {
    let request = aurelius_request(Operation::Evaluate);
    let decision = evaluate(&request).unwrap();
    let receipt = expected_receipt(&request, &decision).unwrap();

    for field in [
        "workspace",
        "tenant",
        "runtime",
        "source",
        "rule",
        "definition",
        "input_digest",
        "output_digest",
        "action",
    ] {
        let mut forged = receipt.clone();
        match field {
            "workspace" => forged.workspace_id = "forged".into(),
            "tenant" => forged.tenant_id = "forged".into(),
            "runtime" => forged.runtime_id = "forged".into(),
            "source" => forged.source_id = "forged".into(),
            "rule" => forged.rule_id = "forged".into(),
            "definition" => forged.definition_digest = "forged".into(),
            "input_digest" => forged.input_digest = "forged".into(),
            "output_digest" => forged.output_digest = "forged".into(),
            "action" => forged.action = Action::Close,
            _ => unreachable!(),
        }
        assert_eq!(
            evaluate_scoped_output_with(&request, |_| {
                Ok(EvaluatorOutput {
                    decision: decision.clone(),
                    receipt: forged,
                })
            }),
            Err(KernelError::InvalidEvaluatorReceipt),
            "{field}"
        );
    }

    for mutate in ["tenant", "runtime", "rule"] {
        let mut forged = decision.clone();
        let finding = forged.finding.as_mut().unwrap();
        match mutate {
            "tenant" => finding.tenant_id = "forged".into(),
            "runtime" => finding.runtime_id = "forged".into(),
            "rule" => finding.rule_id = "forged".into(),
            _ => unreachable!(),
        }
        let forged_receipt = expected_receipt(&request, &forged).unwrap();
        assert_eq!(
            evaluate_scoped_output_with(&request, |_| {
                Ok(EvaluatorOutput {
                    decision: forged,
                    receipt: forged_receipt,
                })
            }),
            Err(KernelError::InvalidEvaluatorReceipt),
            "{mutate}"
        );
    }

    let malformed = Decision {
        action: Action::Close,
        anchor: String::new(),
        finding: decision.finding,
    };
    let malformed_receipt = expected_receipt(&request, &malformed).unwrap();
    assert_eq!(
        evaluate_scoped_output_with(&request, |_| {
            Ok(EvaluatorOutput {
                decision: malformed,
                receipt: malformed_receipt,
            })
        }),
        Err(KernelError::MalformedEvaluatorResponse)
    );
}

#[test]
fn source_runtime_attribute_contract_is_explicit_for_both_rules() {
    let mut aurelius_absent = aurelius_request(Operation::Evaluate);
    aurelius_absent.event.attributes.remove("source_runtime_id");
    let aurelius_finding = opened(&aurelius_absent);
    assert_eq!(aurelius_finding.runtime_id, "writer-aurelius-finding");
    assert!(
        !aurelius_finding
            .attributes
            .contains_key("source_runtime_id")
    );

    let aurelius_present = opened(&aurelius_request(Operation::Evaluate));
    assert_eq!(
        aurelius_present.attributes["source_runtime_id"],
        "writer-aurelius-finding"
    );

    let mut cosmo_absent = cosmo_request(Operation::Evaluate);
    cosmo_absent.event.attributes.remove("source_runtime_id");
    let cosmo_finding = opened(&cosmo_absent);
    assert_eq!(cosmo_finding.runtime_id, "writer-cosmo-fact");
    assert_eq!(
        cosmo_finding.attributes["source_runtime_id"], "writer-cosmo-fact",
        "Cosmo output uses only the trusted host runtime"
    );

    for mut conflicting in [
        aurelius_request(Operation::Evaluate),
        cosmo_request(Operation::Evaluate),
    ] {
        conflicting
            .event
            .attributes
            .insert("source_runtime_id".into(), "forged-runtime".into());
        assert_eq!(evaluate(&conflicting), Err(KernelError::ScopeMismatch));
    }
}

#[test]
fn open_anchor_raw_rule_ignores_time_but_host_envelope_requires_trusted_time() {
    for make in [
        aurelius_request as fn(Operation) -> RuleRequest,
        cosmo_request as fn(Operation) -> RuleRequest,
    ] {
        let mut request = make(Operation::OpenAnchor);
        let opened_finding = opened(&make(Operation::Evaluate));
        request.event.attributes = opened_finding.attributes;
        request.event.observed_at = "provider-controlled-invalid-time".into();
        let raw = evaluate(&request).unwrap();
        assert_eq!(raw.action, Action::OpenAnchor);
        assert!(!raw.anchor.is_empty());
        assert_eq!(
            evaluate_scoped(&request),
            Err(KernelError::InvalidObservationTime),
            "the adapter must supply trusted synthetic event time"
        );
    }
}

#[test]
fn scoped_envelope_preserves_workspace_without_changing_public_identity() {
    for make in [
        aurelius_request as fn(Operation) -> RuleRequest,
        cosmo_request as fn(Operation) -> RuleRequest,
    ] {
        let request = make(Operation::Evaluate);
        let scoped = evaluate_scoped(&request).unwrap();
        assert_eq!(scoped.workspace_id, "workspace-a");
        assert_eq!(
            scoped.require_workspace("workspace-b"),
            Err(KernelError::WorkspaceMismatch)
        );
        let finding = scoped
            .require_workspace("workspace-a")
            .unwrap()
            .finding
            .as_ref()
            .unwrap();
        assert!(!finding.id.contains("workspace-a"));
        assert!(!finding.fingerprint.contains("workspace-a"));
        assert!(
            finding
                .resource_urns
                .iter()
                .all(|urn| !urn.contains("workspace-a"))
        );
        assert!(scoped.decision.anchor.is_empty());
    }

    let mut missing = aurelius_request(Operation::Evaluate);
    missing.runtime.workspace_id = "  ".into();
    assert_eq!(
        evaluate_scoped(&missing),
        Err(KernelError::MissingTrustedContext)
    );
}

#[test]
fn full_record_conversion_has_exact_go_defaults_and_preserves_host_state() {
    let raw = opened(&aurelius_request(Operation::Evaluate));
    let converted = CompleteFindingRecord::from(raw.clone());
    assert_eq!(converted.host, HostFindingFields::default());
    let wire = serde_json::to_value(&converted).unwrap();
    assert!(wire["GraphEvidenceRows"].is_null());
    assert!(wire["RiskReasons"].is_null());
    assert!(wire["RiskFactors"].is_null());
    assert!(wire["Notes"].is_null());
    assert!(wire["Tickets"].is_null());
    assert!(wire["ExternalRefs"].is_null());
    assert_eq!(wire["DueAt"], "0001-01-01T00:00:00Z");
    assert_eq!(wire["StatusUpdatedAt"], "0001-01-01T00:00:00Z");
    assert_eq!(wire["TombstonedAt"], "0001-01-01T00:00:00Z");

    let mut persisted = converted;
    persisted.rule.status = "suppressed".into();
    persisted.host.graph_evidence_rows = Some(Vec::new());
    persisted.host.risk_score = 87;
    persisted.host.risk_reasons = Some(vec!["analyst-confirmed".into()]);
    persisted.host.notes = Some(vec![serde_json::json!({"id":"note-1"})]);
    persisted.host.assignee = "operator-1".into();
    persisted.host.status_reason = "manual review".into();
    persisted.host.tombstoned = true;
    persisted.host.tombstone_generation = 2;

    let overlaid = persisted.overlay_preserving_host_state(raw);
    assert_eq!(overlaid.rule.status, "suppressed");
    assert_eq!(overlaid.host, persisted.host);
    assert_eq!(
        serde_json::to_value(&overlaid).unwrap()["GraphEvidenceRows"],
        serde_json::json!([])
    );

    let mut manually_resolved = persisted.clone();
    manually_resolved.rule.status = "resolved".into();
    manually_resolved.host.status_reason.clear();
    let reemit = opened(&aurelius_request(Operation::Evaluate));
    let preserved = manually_resolved.overlay_preserving_host_state(reemit);
    assert_eq!(preserved.rule.status, "resolved");
    assert!(preserved.host.status_reason.is_empty());
}

#[test]
fn converted_full_records_equal_the_checked_go_oracle_byte_shape() {
    let oracle: Value = serde_json::from_str(include_str!(
        "../../../../internal/findings/testdata/rules/payload-findings-full-go-oracle.json"
    ))
    .unwrap();
    for (name, request) in [
        ("aurelius", aurelius_request(Operation::Evaluate)),
        ("cosmo", cosmo_request(Operation::Evaluate)),
    ] {
        let rust = serde_json::to_value(CompleteFindingRecord::from(opened(&request))).unwrap();
        assert_eq!(rust, oracle[name], "{name} full FindingRecord drift");
    }
}

#[test]
fn candidate_production_and_closeout_keep_the_same_workspace_envelope() {
    let open = evaluate_scoped(&aurelius_request(Operation::Evaluate)).unwrap();
    let candidate = open.for_path(PersistencePath::Candidate);
    let production = open.for_path(PersistencePath::ProductionUpsert);
    assert_eq!(candidate.workspace_id, production.workspace_id);
    assert_eq!(candidate.decision, production.decision);
    assert_eq!(candidate.observed_at, production.observed_at);
    assert_eq!(candidate.replay_sequence, production.replay_sequence);

    let mut close_request = aurelius_request(Operation::Close);
    close_request
        .event
        .attributes
        .insert("state".into(), "fixed".into());
    let closeout = evaluate_scoped(&close_request)
        .unwrap()
        .for_path(PersistencePath::Closeout);
    assert_eq!(closeout.workspace_id, production.workspace_id);
    assert_eq!(closeout.tenant_id, "writer");
    assert_eq!(closeout.runtime_id, "writer-aurelius-finding");
    assert_eq!(closeout.source_id, "aurelius");
    assert_eq!(closeout.rule_id, aurelius::RULE_ID);
    assert_eq!(closeout.event_id, "aurelius-vuln-open");
    assert_eq!(closeout.decision.action, Action::Close);
    assert!(!closeout.decision.anchor.is_empty());
}

#[test]
fn scoped_chronology_orders_timestamp_then_replay_sequence() {
    #[derive(Debug, Eq, PartialEq)]
    struct Stored {
        first: String,
        last: String,
        latest_sequence: u64,
        status: &'static str,
    }

    fn apply(stored: &mut Stored, action: &ScopedPersistenceAction) {
        if action.observed_at < stored.first {
            stored.first.clone_from(&action.observed_at);
        }
        let newer = action.observed_at > stored.last
            || (action.observed_at == stored.last
                && action.replay_sequence > stored.latest_sequence);
        if !newer {
            return;
        }
        stored.last.clone_from(&action.observed_at);
        stored.latest_sequence = action.replay_sequence;
        stored.status = match action.decision.action {
            Action::Open => "open",
            Action::Close => "resolved",
            Action::None | Action::OpenAnchor => stored.status,
        };
    }

    let mut open_t2_request = aurelius_request(Operation::Evaluate);
    open_t2_request.event.observed_at = "2026-05-22T14:00:00Z".into();
    open_t2_request.event.replay_sequence = 5;
    let open_t2 = evaluate_scoped(&open_t2_request)
        .unwrap()
        .for_path(PersistencePath::ProductionUpsert);
    let mut stored = Stored {
        first: open_t2.observed_at.clone(),
        last: open_t2.observed_at.clone(),
        latest_sequence: open_t2.replay_sequence,
        status: "open",
    };

    let mut older_open_request = aurelius_request(Operation::Evaluate);
    older_open_request.event.observed_at = "2026-05-22T13:00:00Z".into();
    older_open_request.event.replay_sequence = 99;
    apply(
        &mut stored,
        &evaluate_scoped(&older_open_request)
            .unwrap()
            .for_path(PersistencePath::ProductionUpsert),
    );
    assert_eq!(stored.first, "2026-05-22T13:00:00Z");
    assert_eq!(stored.last, "2026-05-22T14:00:00Z");
    assert_eq!(stored.status, "open");

    let mut older_close_request = aurelius_request(Operation::Close);
    older_close_request.event.observed_at = "2026-05-22T13:30:00Z".into();
    older_close_request.event.replay_sequence = 100;
    older_close_request
        .event
        .attributes
        .insert("state".into(), "fixed".into());
    apply(
        &mut stored,
        &evaluate_scoped(&older_close_request)
            .unwrap()
            .for_path(PersistencePath::Closeout),
    );
    assert_eq!(stored.status, "open", "an older close cannot close t2");
    assert_eq!(stored.last, "2026-05-22T14:00:00Z");

    let mut tied_close_request = older_close_request;
    tied_close_request.event.observed_at = "2026-05-22T14:00:00Z".into();
    tied_close_request.event.replay_sequence = 6;
    apply(
        &mut stored,
        &evaluate_scoped(&tied_close_request)
            .unwrap()
            .for_path(PersistencePath::Closeout),
    );
    assert_eq!(stored.status, "resolved");
    assert_eq!(stored.latest_sequence, 6);

    let mut stale_reopen_request = aurelius_request(Operation::Evaluate);
    stale_reopen_request.event.observed_at = "2026-05-22T14:00:00Z".into();
    stale_reopen_request.event.replay_sequence = 5;
    apply(
        &mut stored,
        &evaluate_scoped(&stale_reopen_request)
            .unwrap()
            .for_path(PersistencePath::ProductionUpsert),
    );
    assert_eq!(stored.status, "resolved", "a stale tie cannot reopen");
}

#[test]
fn strict_payload_rejections_cover_both_rules_and_all_limits() {
    for mut request in [
        aurelius_request(Operation::Evaluate),
        cosmo_request(Operation::Evaluate),
    ] {
        for malformed in [
            br#"{"#.as_slice(),
            br#"{"state":"active"} trailing"#.as_slice(),
        ] {
            request.event.payload = malformed.to_vec();
            assert_eq!(evaluate(&request), Err(KernelError::MalformedPayload));
        }

        request.event.payload = vec![b' '; MAX_PAYLOAD_BYTES + 1];
        assert_eq!(evaluate(&request), Err(KernelError::PayloadTooLarge));

        request.event.payload = format!(
            "{}0{}",
            "[".repeat(MAX_PAYLOAD_DEPTH),
            "]".repeat(MAX_PAYLOAD_DEPTH)
        )
        .into_bytes();
        assert_eq!(evaluate(&request), Err(KernelError::PayloadTooDeep));

        request.event.payload = format!(
            "[{}]",
            std::iter::repeat_n("0", MAX_PAYLOAD_ARRAY_ITEMS + 1)
                .collect::<Vec<_>>()
                .join(",")
        )
        .into_bytes();
        assert_eq!(evaluate(&request), Err(KernelError::PayloadArrayTooLarge));

        request.event.payload = format!(
            "{{{}}}",
            (0..=MAX_PAYLOAD_OBJECT_FIELDS)
                .map(|index| format!("\"field_{index}\":0"))
                .collect::<Vec<_>>()
                .join(",")
        )
        .into_bytes();
        assert_eq!(evaluate(&request), Err(KernelError::PayloadObjectTooLarge));

        request.event.payload = format!(
            "{{\"state\":\"{}\"}}",
            "x".repeat(MAX_PAYLOAD_STRING_BYTES + 1)
        )
        .into_bytes();
        assert_eq!(evaluate(&request), Err(KernelError::PayloadStringTooLarge));

        request.event.payload = br#"{"state":"active","state":"resolved"}"#.to_vec();
        assert_eq!(evaluate(&request), Err(KernelError::DuplicatePayloadField));

        request.event.payload = br#"{"value":{"nested":true}}"#.to_vec();
        assert_eq!(evaluate(&request), Err(KernelError::MalformedPayload));

        for trusted in ["tenant_id", "workspace_id", "runtime_id", "occurred_at"] {
            request.event.payload =
                format!("{{\"{trusted}\":\"attacker-controlled\"}}").into_bytes();
            assert_eq!(evaluate(&request), Err(KernelError::MalformedPayload));
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScalarFixture {
    value: Option<CanonicalScalar>,
}

#[test]
fn canonical_scalars_match_go_format_float_fixed_vectors() {
    for (raw, expected) in [
        ("1e3", "1000"),
        ("1e-7", "0.0000001"),
        ("1e20", "100000000000000000000"),
        (
            "1e100",
            "10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        ("1e-20", "0.00000000000000000001"),
        ("9007199254740993", "9007199254740992"),
        ("1.2300", "1.23"),
        ("-0", "-0"),
        ("1.25", "1.25"),
        ("true", "true"),
        ("\"  text  \"", "text"),
    ] {
        let payload = format!("{{\"value\":{raw}}}");
        let fixture: ScalarFixture = decode_payload(payload.as_bytes()).unwrap();
        assert_eq!(scalar(&fixture.value), expected, "{raw}");
    }
}

#[test]
fn host_workspace_is_a_conversion_boundary_not_a_public_identity_input() {
    for make in [
        aurelius_request as fn(Operation) -> RuleRequest,
        cosmo_request as fn(Operation) -> RuleRequest,
    ] {
        let mut workspace_a = make(Operation::Evaluate);
        let first = opened(&workspace_a);
        workspace_a.runtime.workspace_id = "workspace-b".into();
        let second = opened(&workspace_a);
        assert_eq!(first.id, second.id);
        assert_eq!(first.fingerprint, second.fingerprint);
        assert_eq!(first.attributes, second.attributes);
    }
}

#[test]
fn unsupported_rule_is_an_error_and_has_no_fallback() {
    let mut request = aurelius_request(Operation::Evaluate);
    request.rule_id = "unsupported".into();
    assert_eq!(evaluate(&request), Err(KernelError::UnsupportedRule));
    assert_eq!(
        finding_hash(&["a", "b"]),
        "8fb20ef63ced4145fc2e983ffe597d1dcff39154c3bf21f0fa9dde6a0c50fdc9"
    );
}

#[test]
fn identity_components_reject_nul_and_control_delimiter_collisions() {
    for field in ["image_digest", "cve_id", "package"] {
        let mut request = aurelius_request(Operation::Evaluate);
        request
            .event
            .attributes
            .insert(field.into(), "part\0crafted".into());
        assert_eq!(evaluate(&request).unwrap(), Decision::none(), "{field}");
    }

    for value in ["fact\0key", "fact\nkey"] {
        let mut request = cosmo_request(Operation::Evaluate);
        request.event.attributes.insert("key".into(), value.into());
        assert_eq!(evaluate(&request).unwrap(), Decision::none(), "{value:?}");
    }

    for make in [
        aurelius_request as fn(Operation) -> RuleRequest,
        cosmo_request as fn(Operation) -> RuleRequest,
    ] {
        let mut request = make(Operation::OpenAnchor);
        request
            .event
            .attributes
            .insert("aurelius_vulnerability_urn".into(), "urn\0crafted".into());
        request
            .event
            .attributes
            .insert("cosmo_risk_urn".into(), "urn\0crafted".into());
        assert_eq!(evaluate(&request).unwrap(), Decision::none());
    }
}
