//! Native REST parity for the Go `GET /platform/graph/provenance` derivation.
//!
//! The Rust product surface serves the same provenance envelope at
//! `GET /v1/graph/provenance`, derived from one exact-key entity read plus the
//! pure string derivation ported from `internal/graphprovenance/provenance.go`
//! and `internal/projectionmeta/classification.go`.
//!
//! NOTE on vocabulary: the projection classes emitted here (`durable_state`,
//! `evidence`, `lifecycle_state`, `ephemeral_event`) mirror the Go
//! `internal/projectionmeta` classification and are intentionally DIFFERENT
//! from the source catalog's `ProjectionClass` enum
//! (`crates/source-catalog`). The catalog vocabulary describes how a source
//! stream is projected; this vocabulary classifies a projected graph entity
//! for provenance display. Do not unify them.

use std::collections::BTreeMap;

use cerebro_agent_context::ContextEntity;
use serde::Serialize;

const ATTRIBUTE_PROJECTION_CLASS: &str = "projection_class";
const ATTRIBUTE_PROJECTION_REASON: &str = "projection_reason";

const CLASS_DURABLE_STATE: &str = "durable_state";
const CLASS_EVIDENCE: &str = "evidence";
const CLASS_LIFECYCLE_STATE: &str = "lifecycle_state";
const CLASS_EPHEMERAL_EVENT: &str = "ephemeral_event";

/// Attribute keys surfaced as freshness signals, in emission order.
const FRESHNESS_KEYS: [&str; 4] = ["observed_at", "last_observed_at", "at", "updated_at"];

/// JSON contract mirroring the Go route's `graphprovenance.Response`.
#[derive(Debug, Eq, PartialEq, Serialize)]
pub(crate) struct GraphProvenanceResponse {
    urn: String,
    tenant_id: String,
    entity_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    label: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    source_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    runtime_id: String,
    projection_class: String,
    projection_reason: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    attributes: BTreeMap<String, String>,
    provenance: ProvenanceEnvelope,
}

/// JSON contract mirroring the Go route's `graphprovenance.Provenance`.
#[derive(Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ProvenanceEnvelope {
    surface: String,
    scope: String,
    source_urns: Vec<String>,
    citation_status: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    freshness_signals: Vec<String>,
}

/// Provenance classification of one projected entity.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Classification {
    pub(crate) class: &'static str,
    pub(crate) reason: &'static str,
}

/// Ports `projectionmeta.ClassifyEntity` unchanged (see module note on the
/// deliberate vocabulary divergence from the catalog's `ProjectionClass`).
pub(crate) fn classify_entity(
    entity_type: &str,
    attributes: &BTreeMap<String, String>,
) -> Classification {
    let entity_type = entity_type.trim().to_lowercase();
    match entity_type.as_str() {
        "sentinelone.activity" => {
            return Classification {
                class: CLASS_EPHEMERAL_EVENT,
                reason: "source_activity_event",
            };
        }
        "runtime.evidence" | "evidence" => {
            return Classification {
                class: CLASS_EVIDENCE,
                reason: "evidence_reference",
            };
        }
        "finding" | "ticket" | "external_ref" | "decision" | "action" | "outcome"
        | "annotation" => {
            return Classification {
                class: CLASS_LIFECYCLE_STATE,
                reason: "workflow_lifecycle_state",
            };
        }
        _ => {}
    }
    if entity_type == "github.runner" && attribute(attributes, "action").starts_with("workflows.") {
        return Classification {
            class: CLASS_EPHEMERAL_EVENT,
            reason: "hosted_workflow_job_runner_event",
        };
    }
    if entity_type.contains("evidence")
        || entity_type.ends_with(".scan")
        || entity_type.ends_with(".verdict")
    {
        return Classification {
            class: CLASS_EVIDENCE,
            reason: "evidence_shaped_entity",
        };
    }
    Classification {
        class: CLASS_DURABLE_STATE,
        reason: "projected_current_state",
    }
}

/// Returns the tenant segment of a tenant-scoped Cerebro URN, mirroring the Go
/// `graphprovenance.TenantIDFromURN` acceptance rules (`urn.Parse` plus at
/// least one part after the kind segment).
pub(crate) fn tenant_id_from_urn(urn: &str) -> Option<&str> {
    let value = urn.trim();
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() < 5 || parts[0] != "urn" || parts[1] != "cerebro" {
        return None;
    }
    if parts[3] == "runtime" && (parts.len() < 7 || parts[5].is_empty()) {
        return None;
    }
    if parts.last().is_none_or(|part| part.is_empty()) {
        return None;
    }
    for (index, part) in parts[2..].iter().enumerate() {
        if part.trim() != *part || (index < 3 && part.is_empty()) {
            return None;
        }
    }
    Some(parts[2])
}

/// Builds the provenance envelope for one exact-key catalog entity, mirroring
/// the Go `graphprovenance` `fromRow` derivation.
pub(crate) fn provenance_response(
    tenant_id: &str,
    entity: &ContextEntity,
) -> GraphProvenanceResponse {
    let urn = entity.agent_key.trim().to_owned();
    let attributes = entity.properties.clone();
    let entity_type = entity.entity_kind.trim().to_owned();
    let classification = classify_entity(&entity_type, &attributes);
    let tenant_id = tenant_id.trim().to_owned();

    let mut source_urns = vec![urn.clone()];
    let source_event_id = first_non_empty(&[
        attribute(&attributes, "source_event_id"),
        attribute(&attributes, "event_id"),
    ]);
    if !source_event_id.is_empty() {
        source_urns.push(format!("event:{source_event_id}"));
    }

    let scope = first_non_empty(&[&tenant_id, tenant_id_from_urn(&urn).unwrap_or_default()]);
    let freshness_signals = freshness_signals(&attributes);
    GraphProvenanceResponse {
        urn,
        tenant_id,
        entity_type,
        label: entity.label.trim().to_owned(),
        source_id: attribute(&attributes, "source_id").to_owned(),
        runtime_id: runtime_id(entity),
        projection_class: first_non_empty(&[
            attribute(&attributes, ATTRIBUTE_PROJECTION_CLASS),
            classification.class,
        ]),
        projection_reason: first_non_empty(&[
            attribute(&attributes, ATTRIBUTE_PROJECTION_REASON),
            classification.reason,
        ]),
        attributes,
        provenance: ProvenanceEnvelope {
            surface: "graph-provenance".to_owned(),
            scope,
            source_urns,
            citation_status: "valid".to_owned(),
            freshness_signals,
        },
    }
}

/// Emits `key=value` freshness signals for the known timestamp attributes.
pub(crate) fn freshness_signals(attributes: &BTreeMap<String, String>) -> Vec<String> {
    FRESHNESS_KEYS
        .iter()
        .filter_map(|key| {
            let value = attribute(attributes, key);
            (!value.is_empty()).then(|| format!("{key}={value}"))
        })
        .collect()
}

/// Resolves the entity's runtime ID the same way the Rust catalog filter does:
/// the `runtime_id` property first, then the authority's `source_runtime_id`.
fn runtime_id(entity: &ContextEntity) -> String {
    let from_properties = attribute(&entity.properties, "runtime_id");
    if !from_properties.is_empty() {
        return from_properties.to_owned();
    }
    entity
        .authority
        .get("source_runtime_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn attribute<'a>(attributes: &'a BTreeMap<String, String>, key: &str) -> &'a str {
    attributes.get(key).map_or("", |value| value.trim())
}

fn first_non_empty(values: &[&str]) -> String {
    values
        .iter()
        .map(|value| value.trim())
        .find(|value| !value.is_empty())
        .unwrap_or_default()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use cerebro_organizational_model::EntityId;
    use serde_json::json;

    use super::*;

    fn entity(
        agent_key: &str,
        entity_kind: &str,
        label: &str,
        properties: BTreeMap<String, String>,
    ) -> ContextEntity {
        ContextEntity {
            entity_id: EntityId::parse("entity-a").unwrap(),
            agent_key: agent_key.to_owned(),
            entity_kind: entity_kind.to_owned(),
            authority: json!({}),
            label: label.to_owned(),
            properties,
        }
    }

    #[test]
    fn classification_matches_the_go_projectionmeta_vocabulary() {
        let empty = BTreeMap::new();
        for (entity_type, class, reason) in [
            (
                "sentinelone.activity",
                CLASS_EPHEMERAL_EVENT,
                "source_activity_event",
            ),
            (
                " SentinelOne.Activity ",
                CLASS_EPHEMERAL_EVENT,
                "source_activity_event",
            ),
            ("runtime.evidence", CLASS_EVIDENCE, "evidence_reference"),
            ("evidence", CLASS_EVIDENCE, "evidence_reference"),
            ("finding", CLASS_LIFECYCLE_STATE, "workflow_lifecycle_state"),
            ("ticket", CLASS_LIFECYCLE_STATE, "workflow_lifecycle_state"),
            (
                "external_ref",
                CLASS_LIFECYCLE_STATE,
                "workflow_lifecycle_state",
            ),
            (
                "decision",
                CLASS_LIFECYCLE_STATE,
                "workflow_lifecycle_state",
            ),
            ("action", CLASS_LIFECYCLE_STATE, "workflow_lifecycle_state"),
            ("outcome", CLASS_LIFECYCLE_STATE, "workflow_lifecycle_state"),
            (
                "annotation",
                CLASS_LIFECYCLE_STATE,
                "workflow_lifecycle_state",
            ),
            (
                "wiz.evidence-item",
                CLASS_EVIDENCE,
                "evidence_shaped_entity",
            ),
            ("qualys.scan", CLASS_EVIDENCE, "evidence_shaped_entity"),
            (
                "crowdstrike.verdict",
                CLASS_EVIDENCE,
                "evidence_shaped_entity",
            ),
            ("okta.user", CLASS_DURABLE_STATE, "projected_current_state"),
            ("", CLASS_DURABLE_STATE, "projected_current_state"),
        ] {
            let classification = classify_entity(entity_type, &empty);
            assert_eq!(classification.class, class, "class for {entity_type:?}");
            assert_eq!(classification.reason, reason, "reason for {entity_type:?}");
        }
    }

    #[test]
    fn github_runner_classification_depends_on_the_workflow_action_attribute() {
        let workflow = BTreeMap::from([("action".to_owned(), " workflows.completed ".to_owned())]);
        assert_eq!(
            classify_entity("github.runner", &workflow),
            Classification {
                class: CLASS_EPHEMERAL_EVENT,
                reason: "hosted_workflow_job_runner_event",
            }
        );
        for attributes in [
            BTreeMap::new(),
            BTreeMap::from([("action".to_owned(), "runners.registered".to_owned())]),
        ] {
            assert_eq!(
                classify_entity("github.runner", &attributes),
                Classification {
                    class: CLASS_DURABLE_STATE,
                    reason: "projected_current_state",
                }
            );
        }
    }

    #[test]
    fn freshness_signals_keep_the_go_key_order_and_skip_blank_values() {
        let attributes = BTreeMap::from([
            ("updated_at".to_owned(), "2026-08-25T02:00:00Z".to_owned()),
            (
                "observed_at".to_owned(),
                " 2026-08-25T01:00:00Z ".to_owned(),
            ),
            ("last_observed_at".to_owned(), "  ".to_owned()),
            ("created_at".to_owned(), "2026-08-24T00:00:00Z".to_owned()),
        ]);
        assert_eq!(
            freshness_signals(&attributes),
            vec![
                "observed_at=2026-08-25T01:00:00Z".to_owned(),
                "updated_at=2026-08-25T02:00:00Z".to_owned(),
            ]
        );
        assert!(freshness_signals(&BTreeMap::new()).is_empty());
    }

    #[test]
    fn tenant_derivation_mirrors_the_go_urn_parser() {
        assert_eq!(
            tenant_id_from_urn(" urn:cerebro:tenant-a:okta.user:00u-demo "),
            Some("tenant-a")
        );
        assert_eq!(
            tenant_id_from_urn("urn:cerebro:tenant-a:runtime:okta-prod:okta.user:00u-demo"),
            Some("tenant-a")
        );
        for invalid in [
            "",
            "   ",
            "urn:cerebro:tenant-a:asset",
            "urn:other:tenant-a:asset:one",
            "arn:cerebro:tenant-a:asset:one",
            "urn:cerebro::asset:one",
            "urn:cerebro:tenant-a::one",
            "urn:cerebro:tenant-a:asset:",
            "urn:cerebro:tenant a:asset: one",
            "urn:cerebro:tenant-a:runtime::okta.user:00u-demo",
            "urn:cerebro:tenant-a:runtime:okta-prod",
        ] {
            assert_eq!(tenant_id_from_urn(invalid), None, "accepted {invalid:?}");
        }
    }

    #[test]
    fn tenant_mismatch_between_urn_and_authenticated_tenant_is_detectable() {
        let urn = "urn:cerebro:tenant-a:okta.user:00u-demo";
        let urn_tenant = tenant_id_from_urn(urn).unwrap();
        assert_eq!(urn_tenant, "tenant-a");
        assert_ne!(urn_tenant, "tenant-b");
    }

    #[test]
    fn envelope_uses_stored_projection_metadata_and_event_source_urns() {
        let properties = BTreeMap::from([
            ("projection_class".to_owned(), " stored_class ".to_owned()),
            ("projection_reason".to_owned(), "stored_reason".to_owned()),
            ("source_event_id".to_owned(), " event-a ".to_owned()),
            ("event_id".to_owned(), "event-b".to_owned()),
            ("source_id".to_owned(), " okta ".to_owned()),
            ("runtime_id".to_owned(), " okta-prod ".to_owned()),
            ("observed_at".to_owned(), "2026-08-25T01:00:00Z".to_owned()),
        ]);
        let entity = entity(
            " urn:cerebro:tenant-a:okta.user:00u-demo ",
            " okta.user ",
            " Demo user ",
            properties.clone(),
        );
        let response = provenance_response("tenant-a", &entity);
        assert_eq!(response.urn, "urn:cerebro:tenant-a:okta.user:00u-demo");
        assert_eq!(response.tenant_id, "tenant-a");
        assert_eq!(response.entity_type, "okta.user");
        assert_eq!(response.label, "Demo user");
        assert_eq!(response.source_id, "okta");
        assert_eq!(response.runtime_id, "okta-prod");
        assert_eq!(response.projection_class, "stored_class");
        assert_eq!(response.projection_reason, "stored_reason");
        assert_eq!(response.attributes, properties);
        assert_eq!(response.provenance.surface, "graph-provenance");
        assert_eq!(response.provenance.scope, "tenant-a");
        assert_eq!(response.provenance.citation_status, "valid");
        assert_eq!(
            response.provenance.source_urns,
            vec![
                "urn:cerebro:tenant-a:okta.user:00u-demo".to_owned(),
                "event:event-a".to_owned(),
            ]
        );
        assert_eq!(
            response.provenance.freshness_signals,
            vec!["observed_at=2026-08-25T01:00:00Z".to_owned()]
        );
    }

    #[test]
    fn envelope_derives_classification_and_falls_back_to_secondary_signals() {
        let mut entity = entity(
            "urn:cerebro:tenant-a:qualys.scan:scan-1",
            "qualys.scan",
            "",
            BTreeMap::from([("event_id".to_owned(), "event-b".to_owned())]),
        );
        entity.authority = json!({"source_runtime_id": " qualys-prod "});
        let response = provenance_response("  ", &entity);
        assert_eq!(response.tenant_id, "");
        assert_eq!(response.label, "");
        assert_eq!(response.source_id, "");
        assert_eq!(response.runtime_id, "qualys-prod");
        assert_eq!(response.projection_class, CLASS_EVIDENCE);
        assert_eq!(response.projection_reason, "evidence_shaped_entity");
        // The scope falls back to the URN tenant when no tenant row value exists.
        assert_eq!(response.provenance.scope, "tenant-a");
        assert_eq!(
            response.provenance.source_urns,
            vec![
                "urn:cerebro:tenant-a:qualys.scan:scan-1".to_owned(),
                "event:event-b".to_owned(),
            ]
        );
        assert!(response.provenance.freshness_signals.is_empty());
    }

    #[test]
    fn envelope_serializes_the_go_json_contract_with_omitted_empties() {
        let entity = entity(
            "urn:cerebro:tenant-a:group:security",
            "group",
            "",
            BTreeMap::new(),
        );
        let response = provenance_response("tenant-a", &entity);
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(
            json,
            json!({
                "urn": "urn:cerebro:tenant-a:group:security",
                "tenant_id": "tenant-a",
                "entity_type": "group",
                "projection_class": "durable_state",
                "projection_reason": "projected_current_state",
                "provenance": {
                    "surface": "graph-provenance",
                    "scope": "tenant-a",
                    "source_urns": ["urn:cerebro:tenant-a:group:security"],
                    "citation_status": "valid",
                },
            })
        );
    }
}
