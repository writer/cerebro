use std::collections::BTreeMap;

use super::{AirbrakeFamily, AirbrakeRecord};

/// One deterministic tenant-scoped Airbrake projection entity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AirbrakeEntityFact {
    /// Canonical entity URN.
    pub urn: String,
    /// Closed entity type.
    pub entity_type: String,
    /// Human-readable label.
    pub label: String,
}

/// Provider-local projection facts used for Go/Rust parity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AirbrakeProjectionFacts {
    /// Deduplicated entities in canonical order.
    pub entities: Vec<AirbrakeEntityFact>,
}

/// Project normalized records with the same asset, finding, and audit semantics as Go.
pub fn project_airbrake_records(records: &[AirbrakeRecord]) -> AirbrakeProjectionFacts {
    let mut entities = BTreeMap::<String, AirbrakeEntityFact>::new();
    for record in records {
        match record.family {
            AirbrakeFamily::Deploys | AirbrakeFamily::Projects | AirbrakeFamily::SourceMaps => {
                project_asset(&mut entities, record)
            }
            AirbrakeFamily::Groups => project_finding(&mut entities, record),
            AirbrakeFamily::ProjectActivities => project_audit(&mut entities, record),
        }
    }
    AirbrakeProjectionFacts {
        entities: entities.into_values().collect(),
    }
}

fn project_asset(entities: &mut BTreeMap<String, AirbrakeEntityFact>, record: &AirbrakeRecord) {
    let Some(urn) = record.attributes.get("resource_urn") else {
        return;
    };
    let resource_type = record
        .attributes
        .get("resource_type")
        .map(String::as_str)
        .unwrap_or("asset");
    insert(
        entities,
        urn.clone(),
        format!("runtime.{}", resource_type.replace('_', ".")),
        attribute(record, "resource_name"),
    );
}

fn project_finding(entities: &mut BTreeMap<String, AirbrakeEntityFact>, record: &AirbrakeRecord) {
    let finding_id = attribute(record, "finding_id");
    insert(
        entities,
        format!(
            "urn:cerebro:{}:finding:{}",
            encode_segment(&record.tenant_id),
            encode_segment(&finding_id)
        ),
        "finding".to_owned(),
        attribute(record, "title"),
    );
}

fn project_audit(entities: &mut BTreeMap<String, AirbrakeEntityFact>, record: &AirbrakeRecord) {
    let actor_id = attribute(record, "actor_id");
    insert(
        entities,
        format!(
            "urn:cerebro:{}:airbrake_user:{}",
            encode_segment(&record.tenant_id),
            encode_segment(&actor_id)
        ),
        "airbrake.user".to_owned(),
        record
            .attributes
            .get("actor_name")
            .cloned()
            .unwrap_or(actor_id),
    );

    let resource_id = attribute(record, "resource_id");
    let resource_type = record
        .attributes
        .get("resource_type")
        .map(String::as_str)
        .unwrap_or("resource");
    insert(
        entities,
        format!(
            "urn:cerebro:{}:airbrake_{}:{}",
            encode_segment(&record.tenant_id),
            encode_segment(&resource_type.to_ascii_lowercase()),
            encode_segment(&resource_id)
        ),
        format!("airbrake.{}", resource_type.to_ascii_lowercase()),
        attribute(record, "resource_name"),
    );
}

fn insert(
    entities: &mut BTreeMap<String, AirbrakeEntityFact>,
    urn: String,
    entity_type: String,
    label: String,
) {
    entities.insert(
        urn.clone(),
        AirbrakeEntityFact {
            urn,
            entity_type,
            label,
        },
    );
}

fn attribute(record: &AirbrakeRecord, key: &str) -> String {
    record
        .attributes
        .get(key)
        .cloned()
        .unwrap_or_else(|| record.provider_id.clone())
}

fn encode_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.trim().bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}
