//! PagerDuty responder-topology semantic projection facts.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::{PagerDutyFamily, PagerDutyRecord};

/// One tenant-scoped semantic entity emitted by PagerDuty projection.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PagerDutyEntityFact {
    /// Stable tenant-scoped URN.
    pub urn: String,
    /// Go-compatible entity type.
    pub entity_type: String,
    /// Human-readable label.
    pub label: String,
    /// Stable semantic attributes.
    pub attributes: BTreeMap<String, String>,
}

/// One semantic PagerDuty responder-topology relation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PagerDutyRelationFact {
    /// Source entity URN.
    pub from_urn: String,
    /// Closed Go-compatible relation.
    pub relation: String,
    /// Target entity URN.
    pub to_urn: String,
}

/// Deterministic PagerDuty projection facts used for Go/Rust parity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PagerDutyProjectionFacts {
    /// Deduplicated entities sorted by semantic identity.
    pub entities: Vec<PagerDutyEntityFact>,
    /// Deduplicated relations sorted by semantic identity.
    pub relations: Vec<PagerDutyRelationFact>,
}

/// Project normalized records into responder identity and escalation-coverage facts.
pub fn project_pagerduty_records(records: &[PagerDutyRecord]) -> PagerDutyProjectionFacts {
    let mut entities = BTreeMap::new();
    let mut relations = BTreeSet::new();
    for record in records {
        project_record(record, &mut entities, &mut relations);
    }
    PagerDutyProjectionFacts {
        entities: entities.into_values().collect(),
        relations: relations.into_iter().collect(),
    }
}

fn project_record(
    record: &PagerDutyRecord,
    entities: &mut BTreeMap<String, PagerDutyEntityFact>,
    relations: &mut BTreeSet<PagerDutyRelationFact>,
) {
    let primary_urn = provider_urn(
        &record.tenant_id,
        record.family.urn_kind(),
        &record.provider_id,
    );
    let mut attributes = record.attributes.clone();
    if record.family == PagerDutyFamily::Service {
        let has_escalation = attributes
            .get("escalation_policy_id")
            .is_some_and(|value| !value.is_empty());
        attributes.insert(
            "has_escalation_policy".to_owned(),
            has_escalation.to_string(),
        );
        let active = !matches!(
            attributes.get("status").map(|value| value.to_ascii_lowercase()),
            Some(value) if matches!(value.as_str(), "disabled" | "deleted" | "inactive" | "removed")
        );
        attributes.insert("active".to_owned(), active.to_string());
    }
    add_entity(
        entities,
        PagerDutyEntityFact {
            urn: primary_urn.clone(),
            entity_type: record.event_kind.clone(),
            label: label(&record.attributes, &record.provider_id),
            attributes,
        },
    );

    match record.family {
        PagerDutyFamily::User => {
            if let Some(email) = record
                .attributes
                .get("email")
                .filter(|value| !value.is_empty())
            {
                let normalized = email.trim().to_ascii_lowercase();
                let identifier_urn = format!(
                    "urn:cerebro:{}:identifier:email:{}",
                    record.tenant_id, normalized
                );
                let identity_urn = format!(
                    "urn:cerebro:{}:identity:email:{}",
                    record.tenant_id, normalized
                );
                add_entity(
                    entities,
                    context_entity(
                        identifier_urn.clone(),
                        "identifier.email",
                        &normalized,
                        "value",
                        &normalized,
                    ),
                );
                add_entity(
                    entities,
                    context_entity(
                        identity_urn.clone(),
                        "identity.email",
                        &normalized,
                        "value",
                        &normalized,
                    ),
                );
                add_relation(relations, &primary_urn, "has_identifier", &identifier_urn);
                add_relation(
                    relations,
                    &primary_urn,
                    "represents_identity",
                    &identity_urn,
                );
                add_relation(relations, &identity_urn, "has_identifier", &identifier_urn);
                add_relation(
                    relations,
                    &identifier_urn,
                    "represents_identity",
                    &identity_urn,
                );
            }
        }
        PagerDutyFamily::Service => {
            if let Some(policy_id) = record
                .attributes
                .get("escalation_policy_id")
                .filter(|value| !value.is_empty())
            {
                let policy_urn = provider_urn(
                    &record.tenant_id,
                    PagerDutyFamily::EscalationPolicy.urn_kind(),
                    policy_id,
                );
                let policy_label = record
                    .attributes
                    .get("escalation_policy_name")
                    .map(String::as_str)
                    .unwrap_or(policy_id);
                add_entity(
                    entities,
                    context_entity(
                        policy_urn.clone(),
                        PagerDutyFamily::EscalationPolicy.event_kind(),
                        policy_label,
                        "escalation_policy_id",
                        policy_id,
                    ),
                );
                add_relation(relations, &primary_urn, "depends_on", &policy_urn);
                add_relation(relations, &policy_urn, "supports", &primary_urn);
            }
        }
        PagerDutyFamily::EscalationPolicy => {
            project_policy_context(record, &primary_urn, entities, relations);
        }
        PagerDutyFamily::Integration => {
            if let Some(service_id) = record
                .attributes
                .get("service_id")
                .filter(|value| !value.is_empty())
            {
                let service_urn = provider_urn(
                    &record.tenant_id,
                    PagerDutyFamily::Service.urn_kind(),
                    service_id,
                );
                let service_label = record
                    .attributes
                    .get("service_name")
                    .map(String::as_str)
                    .unwrap_or(service_id);
                add_entity(
                    entities,
                    context_entity(
                        service_urn.clone(),
                        PagerDutyFamily::Service.event_kind(),
                        service_label,
                        "service_id",
                        service_id,
                    ),
                );
                add_relation(relations, &primary_urn, "belongs_to", &service_urn);
                add_relation(relations, &service_urn, "contains", &primary_urn);
            }
            if let Some(vendor_id) = record
                .attributes
                .get("vendor_id")
                .filter(|value| !value.is_empty())
            {
                let vendor_urn = provider_urn(
                    &record.tenant_id,
                    PagerDutyFamily::Vendor.urn_kind(),
                    vendor_id,
                );
                let vendor_label = record
                    .attributes
                    .get("vendor_name")
                    .map(String::as_str)
                    .unwrap_or(vendor_id);
                add_entity(
                    entities,
                    context_entity(
                        vendor_urn.clone(),
                        PagerDutyFamily::Vendor.event_kind(),
                        vendor_label,
                        "vendor_id",
                        vendor_id,
                    ),
                );
                add_relation(relations, &primary_urn, "depends_on", &vendor_urn);
            }
        }
        PagerDutyFamily::Team | PagerDutyFamily::Schedule | PagerDutyFamily::Vendor => {}
    }
}

fn project_policy_context(
    record: &PagerDutyRecord,
    primary_urn: &str,
    entities: &mut BTreeMap<String, PagerDutyEntityFact>,
    relations: &mut BTreeSet<PagerDutyRelationFact>,
) {
    if let Some(teams) = record.payload.get("teams").and_then(Value::as_array) {
        for team in teams {
            let Some(id) = string_at(team, "id") else {
                continue;
            };
            let urn = provider_urn(&record.tenant_id, PagerDutyFamily::Team.urn_kind(), id);
            let label = string_at(team, "summary")
                .or_else(|| string_at(team, "name"))
                .unwrap_or(id);
            add_entity(
                entities,
                context_entity(
                    urn.clone(),
                    PagerDutyFamily::Team.event_kind(),
                    label,
                    "team_id",
                    id,
                ),
            );
            add_relation(relations, primary_urn, "belongs_to", &urn);
            add_relation(relations, &urn, "contains", primary_urn);
        }
    }
    let Some(rules) = record
        .payload
        .get("escalation_rules")
        .and_then(Value::as_array)
    else {
        return;
    };
    for rule in rules {
        let Some(targets) = rule.get("targets").and_then(Value::as_array) else {
            continue;
        };
        for target in targets {
            let (family, attribute) = match string_at(target, "type") {
                Some("schedule_reference") => (PagerDutyFamily::Schedule, "schedule_id"),
                Some("user_reference") => (PagerDutyFamily::User, "user_id"),
                _ => continue,
            };
            let Some(id) = string_at(target, "id") else {
                continue;
            };
            let urn = provider_urn(&record.tenant_id, family.urn_kind(), id);
            let label = string_at(target, "summary")
                .or_else(|| string_at(target, "name"))
                .unwrap_or(id);
            add_entity(
                entities,
                context_entity(urn.clone(), family.event_kind(), label, attribute, id),
            );
            add_relation(relations, primary_urn, "depends_on", &urn);
        }
    }
}

fn context_entity(
    urn: String,
    entity_type: &str,
    label: &str,
    attribute: &str,
    attribute_value: &str,
) -> PagerDutyEntityFact {
    PagerDutyEntityFact {
        urn,
        entity_type: entity_type.to_owned(),
        label: label.to_owned(),
        attributes: BTreeMap::from([(attribute.to_owned(), attribute_value.to_owned())]),
    }
}

fn add_entity(entities: &mut BTreeMap<String, PagerDutyEntityFact>, incoming: PagerDutyEntityFact) {
    if let Some(existing) = entities.get_mut(&incoming.urn) {
        if incoming.attributes.len() > existing.attributes.len() {
            existing.entity_type = incoming.entity_type.clone();
            existing.label = incoming.label.clone();
        }
        existing.attributes.extend(incoming.attributes);
    } else {
        entities.insert(incoming.urn.clone(), incoming);
    }
}

fn add_relation(
    relations: &mut BTreeSet<PagerDutyRelationFact>,
    from_urn: &str,
    relation: &str,
    to_urn: &str,
) {
    relations.insert(PagerDutyRelationFact {
        from_urn: from_urn.to_owned(),
        relation: relation.to_owned(),
        to_urn: to_urn.to_owned(),
    });
}

fn provider_urn(tenant_id: &str, kind: &str, provider_id: &str) -> String {
    format!("urn:cerebro:{tenant_id}:{kind}:{provider_id}")
}

fn label(attributes: &BTreeMap<String, String>, fallback: &str) -> String {
    attributes
        .get("name")
        .or_else(|| attributes.get("summary"))
        .filter(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| fallback.to_owned())
}

fn string_at<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)?
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}
