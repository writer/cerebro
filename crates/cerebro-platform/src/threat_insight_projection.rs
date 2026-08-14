use std::collections::BTreeSet;

use cerebro_organizational_model::{
    AssertionProvenance, Entity, EntityKind, GraphAssertion, GraphDelta, ObservationRef,
    ProviderKind, RelationKind, RelationshipAssertion,
};
use cerebro_source_runtime_next::{CollectedBatch, CommittedSourceEvent};

const SOURCE_ID: &str = "okta";
const FAMILY_ID: &str = "threat_insight";
const EVENT_KIND: &str = "okta.threat_insight";
const SCHEMA_REF: &str = "okta/threat_insight/v1";
const RESOURCE_ID: &str = "threat_insight_config";
const RESOURCE_TYPE: &str = "ThreatInsightConfiguration";

pub(crate) fn matches(event: &CommittedSourceEvent) -> bool {
    event.source_id() == SOURCE_ID
        && event.family_id() == FAMILY_ID
        && event.event_kind() == EVENT_KIND
        && event.schema_ref() == SCHEMA_REF
}

pub(crate) fn project(event: CommittedSourceEvent) -> Result<(CollectedBatch, GraphDelta), String> {
    if !matches(&event) {
        return Err("event is not the exact Okta ThreatInsight v1 contract".to_owned());
    }
    let tenant_id = event.tenant_id().clone();
    let source_runtime_id = event.source_runtime_id().clone();
    let observation_id = event.observation_id().clone();
    let observed_at_unix_ms = event.observed_at_unix_ms();
    let payload = event
        .payload()
        .as_object()
        .ok_or("Okta ThreatInsight payload must be an object")?;
    let domain = required_payload_string(payload, "domain")?.to_owned();
    let action = required_payload_string(payload, "action")?.to_owned();
    let zones = payload
        .get("exclude_zones")
        .and_then(serde_json::Value::as_array)
        .ok_or("Okta ThreatInsight exclude_zones must be an array")?;
    let mut unique_zones = BTreeSet::new();
    for zone in zones {
        let zone = zone
            .as_str()
            .ok_or("Okta ThreatInsight exclude_zones must contain only strings")?;
        if zone.trim().is_empty() || zone.trim() != zone || zone.chars().any(char::is_control) {
            return Err("Okta ThreatInsight network zone ID is invalid".to_owned());
        }
        unique_zones.insert(zone.to_owned());
    }

    require_attribute(&event, "family", FAMILY_ID)?;
    require_attribute(&event, "domain", &domain)?;
    require_attribute(&event, "action", &action)?;
    require_attribute(&event, "resource_id", RESOURCE_ID)?;
    require_attribute(&event, "resource_type", RESOURCE_TYPE)?;
    if domain != tenant_id.as_str() {
        return Err("Okta ThreatInsight domain does not match the event tenant".to_owned());
    }
    let exclude_zone_count = event
        .attributes()
        .get("exclude_zone_count")
        .ok_or("Okta ThreatInsight event is missing exclude_zone_count")?
        .parse::<usize>()
        .map_err(|_| "Okta ThreatInsight exclude_zone_count is invalid")?;
    if exclude_zone_count != zones.len() {
        return Err("Okta ThreatInsight exclude_zone_count does not match the payload".to_owned());
    }

    let batch = event
        .into_batch(EVENT_KIND.to_owned(), RESOURCE_ID.to_owned())
        .map_err(|error| error.to_string())?;
    let receipt = batch.scope.receipt().clone();
    let organization = Entity::provider(
        tenant_id.clone(),
        source_runtime_id.clone(),
        ProviderKind::parse("okta.org").map_err(|error| error.to_string())?,
        domain.clone(),
        EntityKind::Organization,
        domain.clone(),
    )
    .and_then(|entity| entity.with_property("domain", domain.clone()))
    .map_err(|error| error.to_string())?;
    let threat_insight = Entity::provider(
        tenant_id.clone(),
        source_runtime_id.clone(),
        ProviderKind::parse(EVENT_KIND).map_err(|error| error.to_string())?,
        RESOURCE_ID,
        EntityKind::Resource,
        "ThreatInsight",
    )
    .and_then(|entity| entity.with_property("action", action))
    .and_then(|entity| entity.with_property("domain", domain))
    .and_then(|entity| entity.with_property("exclude_zone_count", exclude_zone_count.to_string()))
    .and_then(|entity| entity.with_property("resource_type", RESOURCE_TYPE))
    .map_err(|error| error.to_string())?;
    let provenance = AssertionProvenance::direct(
        vec![
            ObservationRef::new(&receipt, observation_id, RESOURCE_ID)
                .map_err(|error| error.to_string())?,
        ],
        "cerebro-okta-threat-insight",
        env!("CARGO_PKG_VERSION"),
    )
    .map_err(|error| error.to_string())?;

    let mut builder = receipt.begin_delta();
    builder
        .add_entity(organization.clone())
        .map_err(|error| error.to_string())?;
    builder
        .add_entity(threat_insight.clone())
        .map_err(|error| error.to_string())?;
    builder
        .add_assertion(GraphAssertion::Relationship(
            RelationshipAssertion::new(
                &organization,
                RelationKind::Contains,
                &threat_insight,
                provenance.clone(),
                observed_at_unix_ms,
            )
            .map_err(|error| error.to_string())?,
        ))
        .map_err(|error| error.to_string())?;

    for zone in unique_zones {
        let zone_entity = Entity::provider(
            tenant_id.clone(),
            source_runtime_id.clone(),
            ProviderKind::parse("okta.network_zone").map_err(|error| error.to_string())?,
            zone.clone(),
            EntityKind::Resource,
            zone.clone(),
        )
        .and_then(|entity| entity.with_property("network_zone_id", zone.clone()))
        .and_then(|entity| entity.with_property("zone_id", zone))
        .map_err(|error| error.to_string())?;
        builder
            .add_entity(zone_entity.clone())
            .map_err(|error| error.to_string())?;
        for (from, relation, to) in [
            (&threat_insight, RelationKind::DependsOn, &zone_entity),
            (&organization, RelationKind::Contains, &zone_entity),
        ] {
            builder
                .add_assertion(GraphAssertion::Relationship(
                    RelationshipAssertion::new(
                        from,
                        relation,
                        to,
                        provenance.clone(),
                        observed_at_unix_ms,
                    )
                    .map_err(|error| error.to_string())?,
                ))
                .map_err(|error| error.to_string())?;
        }
    }
    Ok((batch, builder.build()))
}

fn required_payload_string<'a>(
    payload: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<&'a str, String> {
    payload
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| {
            !value.trim().is_empty()
                && value.trim() == *value
                && !value.chars().any(char::is_control)
        })
        .ok_or_else(|| format!("Okta ThreatInsight {field} is invalid"))
}

fn require_attribute(
    event: &CommittedSourceEvent,
    key: &str,
    expected: &str,
) -> Result<(), String> {
    match event.attributes().get(key).map(String::as_str) {
        Some(actual) if actual == expected => Ok(()),
        _ => Err(format!(
            "Okta ThreatInsight {key} does not match the event contract"
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use cerebro_organizational_model::{ObservationId, SourceRuntimeId, TenantId};
    use cerebro_source_runtime_next::{CommittedSourceEvent, CommittedSourceInput};

    use super::*;

    fn event(zones: serde_json::Value) -> CommittedSourceEvent {
        event_with("example.okta.test", "block", "example.okta.test", zones)
    }

    fn event_with(
        tenant: &str,
        attribute_action: &str,
        payload_domain: &str,
        zones: serde_json::Value,
    ) -> CommittedSourceEvent {
        let count = zones.as_array().map_or(0, Vec::len);
        CommittedSourceEvent::from_input(CommittedSourceInput {
            tenant_id: TenantId::parse(tenant).unwrap(),
            source_runtime_id: SourceRuntimeId::parse("okta-runtime").unwrap(),
            observation_id: ObservationId::parse("compat:v1:threat-insight").unwrap(),
            source_id: SOURCE_ID.to_owned(),
            family_id: FAMILY_ID.to_owned(),
            event_kind: EVENT_KIND.to_owned(),
            schema_ref: SCHEMA_REF.to_owned(),
            observed_at_unix_ms: 1_720_000_000_123,
            attributes: BTreeMap::from([
                ("action".to_owned(), attribute_action.to_owned()),
                ("domain".to_owned(), tenant.to_owned()),
                ("exclude_zone_count".to_owned(), count.to_string()),
                ("family".to_owned(), FAMILY_ID.to_owned()),
                ("resource_id".to_owned(), RESOURCE_ID.to_owned()),
                ("resource_type".to_owned(), RESOURCE_TYPE.to_owned()),
                ("source_runtime_id".to_owned(), "okta-runtime".to_owned()),
            ]),
            payload: serde_json::json!({
                "action": "block",
                "domain": payload_domain,
                "exclude_zones": zones,
            }),
        })
        .unwrap()
    }

    #[test]
    fn valid_legacy_contract_projects_entities_and_provenance() {
        let (batch, delta) = project(event(serde_json::json!(["zone-b", "zone-a"]))).unwrap();

        assert_eq!(batch.records.len(), 1);
        assert_eq!(delta.entities().len(), 4);
        assert_eq!(delta.assertions().len(), 5);
        assert!(delta.assertions().iter().all(|assertion| {
            assertion.provenance().observations()[0]
                .observation_id()
                .as_str()
                == "compat:v1:threat-insight"
        }));
    }

    #[test]
    fn zone_order_is_projection_idempotent() {
        let (_, first) = project(event(serde_json::json!(["zone-b", "zone-a"]))).unwrap();
        let (_, second) = project(event(serde_json::json!(["zone-a", "zone-b"]))).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn tenant_and_provenance_mismatches_fail_closed() {
        let wrong_domain = event_with(
            "example.okta.test",
            "block",
            "other.okta.test",
            serde_json::json!(["zone-a"]),
        );
        assert!(project(wrong_domain).unwrap_err().contains("domain"));

        let wrong_action = event_with(
            "example.okta.test",
            "audit",
            "example.okta.test",
            serde_json::json!(["zone-a"]),
        );
        assert!(project(wrong_action).unwrap_err().contains("action"));
    }
}
