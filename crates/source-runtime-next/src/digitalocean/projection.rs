use std::collections::BTreeMap;

use super::{DigitalOceanFamily, DigitalOceanRecord};

/// One deterministic tenant-scoped DigitalOcean projection entity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DigitalOceanEntityFact {
    /// Canonical entity URN.
    pub urn: String,
    /// Legacy Go entity type.
    pub entity_type: String,
    /// Human-readable label.
    pub label: String,
    /// Exact semantic projection attributes.
    pub attributes: BTreeMap<String, String>,
}

/// One deterministic DigitalOcean relationship fact.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DigitalOceanLinkFact {
    /// Source entity URN.
    pub from_urn: String,
    /// Legacy Go relationship name.
    pub relation: String,
    /// Target entity URN.
    pub to_urn: String,
    /// Relationship attributes.
    pub attributes: BTreeMap<String, String>,
}

/// Provider-local semantic projection result used only for parity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DigitalOceanProjectionFacts {
    /// Deduplicated entities in canonical order.
    pub entities: Vec<DigitalOceanEntityFact>,
    /// Deduplicated relationships in canonical order.
    pub links: Vec<DigitalOceanLinkFact>,
}

/// Project normalized records using the current Go projector semantics.
pub fn project_digitalocean_records(records: &[DigitalOceanRecord]) -> DigitalOceanProjectionFacts {
    let mut entities = BTreeMap::<String, DigitalOceanEntityFact>::new();
    let mut links = BTreeMap::<(String, String, String), DigitalOceanLinkFact>::new();
    for record in records {
        let urn = attribute(record, "resource_urn");
        let resource_id = attribute(record, "resource_id");
        let label = record
            .attributes
            .get("resource_name")
            .filter(|value| !value.is_empty())
            .cloned()
            .unwrap_or_else(|| resource_id.clone());
        let (entity_type, entity_attributes) = match record.family {
            DigitalOceanFamily::Droplets => (
                "runtime.compute.droplet",
                BTreeMap::from([
                    ("region".to_owned(), attribute(record, "region")),
                    ("resource_id".to_owned(), resource_id),
                    ("resource_type".to_owned(), "droplet".to_owned()),
                ]),
            ),
            DigitalOceanFamily::Vpcs => (
                "runtime.network.vpc",
                BTreeMap::from([
                    ("region".to_owned(), attribute(record, "region")),
                    ("resource_id".to_owned(), resource_id),
                    ("resource_type".to_owned(), "vpc".to_owned()),
                ]),
            ),
            DigitalOceanFamily::Firewalls => (
                "runtime.network.firewall",
                BTreeMap::from([
                    (
                        "public_ingress".to_owned(),
                        attribute(record, "public_ingress"),
                    ),
                    ("resource_id".to_owned(), resource_id),
                    ("resource_type".to_owned(), "firewall".to_owned()),
                ]),
            ),
        };
        entities.insert(
            urn.clone(),
            DigitalOceanEntityFact {
                urn: urn.clone(),
                entity_type: entity_type.to_owned(),
                label,
                attributes: entity_attributes,
            },
        );
        match record.family {
            DigitalOceanFamily::Droplets => {
                if let Some(vpc) = record.attributes.get("vpc_uuid") {
                    insert_link(
                        &mut links,
                        &urn,
                        "belongs_to",
                        &scoped_urn(&record.tenant_id, "digitalocean_vpcs", vpc),
                        &record.event_id,
                        None,
                    );
                }
            }
            DigitalOceanFamily::Firewalls => {
                let public = record
                    .attributes
                    .get("public_ingress")
                    .is_some_and(|value| value.eq_ignore_ascii_case("true"));
                for droplet_id in record
                    .attributes
                    .get("droplet_ids")
                    .into_iter()
                    .flat_map(|ids| ids.split(','))
                    .map(str::trim)
                    .filter(|id| !id.is_empty())
                {
                    let droplet =
                        scoped_urn(&record.tenant_id, "digitalocean_droplets", droplet_id);
                    insert_link(
                        &mut links,
                        &urn,
                        "attached_to",
                        &droplet,
                        &record.event_id,
                        None,
                    );
                    if public {
                        insert_link(
                            &mut links,
                            &urn,
                            "can_reach",
                            &droplet,
                            &record.event_id,
                            Some(("exposure", "public")),
                        );
                    }
                }
            }
            DigitalOceanFamily::Vpcs => {}
        }
    }
    DigitalOceanProjectionFacts {
        entities: entities.into_values().collect(),
        links: links.into_values().collect(),
    }
}

fn insert_link(
    links: &mut BTreeMap<(String, String, String), DigitalOceanLinkFact>,
    from_urn: &str,
    relation: &str,
    to_urn: &str,
    event_id: &str,
    extra: Option<(&str, &str)>,
) {
    let mut attributes = BTreeMap::from([("event_id".to_owned(), event_id.to_owned())]);
    if let Some((key, value)) = extra {
        attributes.insert(key.to_owned(), value.to_owned());
    }
    let fact = DigitalOceanLinkFact {
        from_urn: from_urn.to_owned(),
        relation: relation.to_owned(),
        to_urn: to_urn.to_owned(),
        attributes,
    };
    links.insert(
        (
            fact.from_urn.clone(),
            fact.relation.clone(),
            fact.to_urn.clone(),
        ),
        fact,
    );
}

fn scoped_urn(tenant: &str, kind: &str, id: &str) -> String {
    format!("urn:cerebro:{tenant}:{kind}:{id}")
}

fn attribute(record: &DigitalOceanRecord, key: &str) -> String {
    record.attributes.get(key).cloned().unwrap_or_default()
}
