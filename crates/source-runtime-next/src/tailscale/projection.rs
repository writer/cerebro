use std::collections::{BTreeMap, BTreeSet};

use super::{TailscaleError, TailscaleFamily, TailscaleRecord};

/// Deterministic tenant-scoped Tailscale projection entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleEntityFact {
    /// Entity URN.
    pub urn: String,
    /// Provider-specific entity type.
    pub entity_type: String,
    /// Human-readable label.
    pub label: String,
    /// Provider attributes safe for graph persistence.
    pub attributes: BTreeMap<String, String>,
}

/// Deterministic tenant-scoped Tailscale projection relation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleRelationFact {
    /// Source entity URN.
    pub from: String,
    /// Stable relation kind.
    pub relation: String,
    /// Target entity URN.
    pub to: String,
    /// Relation evidence attributes.
    pub attributes: BTreeMap<String, String>,
}

/// Projection facts emitted from normalized Tailscale records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TailscaleProjectionFacts {
    /// Deterministically ordered entities.
    pub entities: Vec<TailscaleEntityFact>,
    /// Deterministically ordered relations.
    pub relations: Vec<TailscaleRelationFact>,
}

/// Project exact provider semantics without using the narrower generic catalog.
pub fn project_tailscale_records(
    records: &[TailscaleRecord],
) -> Result<TailscaleProjectionFacts, TailscaleError> {
    let mut entities = BTreeMap::<String, TailscaleEntityFact>::new();
    let mut relations = BTreeMap::<(String, String, String), TailscaleRelationFact>::new();
    for record in records {
        let id = record
            .attributes
            .get(record.family.required_attribute())
            .filter(|value| !value.trim().is_empty())
            .ok_or(TailscaleError::ProjectionFailure)?;
        let primary = urn(&record.tenant_id, record.family.urn_kind(), id);
        add_entity(
            &mut entities,
            &primary,
            record.family.event_kind(),
            record
                .attributes
                .get("resource_name")
                .map_or(id.as_str(), String::as_str),
            record.attributes.clone(),
        );
        match record.family {
            TailscaleFamily::Tailnet | TailscaleFamily::User => {}
            TailscaleFamily::Device => {
                project_device(record, &primary, &mut entities, &mut relations)
            }
            TailscaleFamily::Group => {
                project_group(record, &primary, &mut entities, &mut relations)
            }
            TailscaleFamily::Tag => project_tag(record, &primary, &mut entities, &mut relations),
            TailscaleFamily::Service => {
                project_service(record, &primary, &mut entities, &mut relations)
            }
            TailscaleFamily::Grant => {
                project_grant(record, &primary, &mut entities, &mut relations)
            }
        }
    }
    Ok(TailscaleProjectionFacts {
        entities: entities.into_values().collect(),
        relations: relations.into_values().collect(),
    })
}

fn project_device(
    record: &TailscaleRecord,
    device: &str,
    entities: &mut BTreeMap<String, TailscaleEntityFact>,
    relations: &mut BTreeMap<(String, String, String), TailscaleRelationFact>,
) {
    if let Some(owner) = first(record, &["user_id", "owner_email"]) {
        let owner_urn = urn(&record.tenant_id, "tailscale_user", owner);
        add_entity(
            entities,
            &owner_urn,
            "tailscale.user",
            owner,
            BTreeMap::from([("login_name".to_owned(), owner.to_owned())]),
        );
        add_relation(record, relations, device, "owned_by", &owner_urn, None);
        if truthy(record.attributes.get("authorized"))
            && !truthy(record.attributes.get("blocks_incoming_connections"))
        {
            add_relation(record, relations, &owner_urn, "can_reach", device, None);
        }
    }
    for tag in list(record.attributes.get("tags")) {
        let tag_urn = urn(&record.tenant_id, "tailscale_tag", tag);
        add_entity(
            entities,
            &tag_urn,
            "tailscale.tag",
            tag,
            BTreeMap::from([("tag_id".to_owned(), tag.to_owned())]),
        );
        add_relation(record, relations, device, "tagged_as", &tag_urn, None);
    }
}

fn project_group(
    record: &TailscaleRecord,
    group: &str,
    entities: &mut BTreeMap<String, TailscaleEntityFact>,
    relations: &mut BTreeMap<(String, String, String), TailscaleRelationFact>,
) {
    for member in list(record.attributes.get("members")) {
        let (kind, entity_type) = principal_kind(member);
        let member_urn = urn(&record.tenant_id, kind, member);
        add_entity(
            entities,
            &member_urn,
            entity_type,
            member,
            BTreeMap::from([("login_name".to_owned(), member.to_owned())]),
        );
        add_relation(record, relations, group, "contains", &member_urn, None);
        add_relation(record, relations, &member_urn, "member_of", group, None);
    }
}

fn project_tag(
    record: &TailscaleRecord,
    tag: &str,
    entities: &mut BTreeMap<String, TailscaleEntityFact>,
    relations: &mut BTreeMap<(String, String, String), TailscaleRelationFact>,
) {
    for owner in list(record.attributes.get("owners")) {
        let (kind, entity_type) = principal_kind(owner);
        let owner_urn = urn(&record.tenant_id, kind, owner);
        add_entity(entities, &owner_urn, entity_type, owner, BTreeMap::new());
        add_relation(record, relations, tag, "owned_by", &owner_urn, None);
    }
}

fn project_service(
    record: &TailscaleRecord,
    service: &str,
    entities: &mut BTreeMap<String, TailscaleEntityFact>,
    relations: &mut BTreeMap<(String, String, String), TailscaleRelationFact>,
) {
    for tag in list(record.attributes.get("tags")) {
        let tag_urn = urn(&record.tenant_id, "tailscale_tag", tag);
        add_entity(entities, &tag_urn, "tailscale.tag", tag, BTreeMap::new());
        add_relation(record, relations, service, "tagged_as", &tag_urn, None);
    }
}

fn project_grant(
    record: &TailscaleRecord,
    grant: &str,
    entities: &mut BTreeMap<String, TailscaleEntityFact>,
    relations: &mut BTreeMap<(String, String, String), TailscaleRelationFact>,
) {
    let disabled = truthy(record.attributes.get("disabled"));
    for source in list(record.attributes.get("sources")) {
        let (kind, entity_type) = principal_kind(source);
        let source_urn = urn(&record.tenant_id, kind, source);
        add_entity(entities, &source_urn, entity_type, source, BTreeMap::new());
        add_relation(
            record,
            relations,
            grant,
            "grants_entitlement",
            &source_urn,
            disabled.then_some("tailscale_grant_disabled"),
        );
    }
    for destination in list(record.attributes.get("destinations")) {
        let destination_urn = urn(&record.tenant_id, "tailscale_destination", destination);
        add_entity(
            entities,
            &destination_urn,
            "tailscale.destination",
            destination,
            BTreeMap::new(),
        );
        add_relation(
            record,
            relations,
            grant,
            "can_reach",
            &destination_urn,
            disabled.then_some("tailscale_grant_disabled"),
        );
    }
}

fn add_entity(
    entities: &mut BTreeMap<String, TailscaleEntityFact>,
    urn: &str,
    entity_type: &str,
    label: &str,
    attributes: BTreeMap<String, String>,
) {
    entities
        .entry(urn.to_owned())
        .and_modify(|entity| entity.attributes.extend(attributes.clone()))
        .or_insert_with(|| TailscaleEntityFact {
            urn: urn.to_owned(),
            entity_type: entity_type.to_owned(),
            label: label.to_owned(),
            attributes,
        });
}

fn add_relation(
    record: &TailscaleRecord,
    relations: &mut BTreeMap<(String, String, String), TailscaleRelationFact>,
    from: &str,
    relation: &str,
    to: &str,
    retraction: Option<&str>,
) {
    let mut attributes = BTreeMap::from([
        ("event_id".to_owned(), record.event_id.clone()),
        ("at".to_owned(), record.occurred_at.clone()),
    ]);
    if let Some(retraction) = retraction {
        attributes.insert("retraction".to_owned(), retraction.to_owned());
    }
    let key = (from.to_owned(), relation.to_owned(), to.to_owned());
    relations.insert(
        key,
        TailscaleRelationFact {
            from: from.to_owned(),
            relation: relation.to_owned(),
            to: to.to_owned(),
            attributes,
        },
    );
}

fn first<'a>(record: &'a TailscaleRecord, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| {
        record
            .attributes
            .get(*key)
            .map(String::as_str)
            .filter(|value| !value.trim().is_empty())
    })
}

fn list(value: Option<&String>) -> Vec<&str> {
    let mut seen = BTreeSet::new();
    value
        .into_iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty() && seen.insert((*value).to_owned()))
        .collect()
}

fn principal_kind(value: &str) -> (&'static str, &'static str) {
    if value.starts_with("group:") {
        ("tailscale_group", "tailscale.group")
    } else if value.starts_with("tag:") {
        ("tailscale_tag", "tailscale.tag")
    } else {
        ("tailscale_user", "tailscale.user")
    }
}

fn truthy(value: Option<&String>) -> bool {
    value.is_some_and(|value| value.eq_ignore_ascii_case("true"))
}

fn urn(tenant: &str, kind: &str, id: &str) -> String {
    format!("urn:cerebro:{tenant}:{kind}:{}", id.trim())
}
