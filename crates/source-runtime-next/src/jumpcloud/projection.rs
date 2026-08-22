use std::collections::{BTreeMap, BTreeSet};

use super::{JumpCloudFamily, JumpCloudRecord};

/// One deterministic tenant-scoped JumpCloud projection entity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct JumpCloudEntityFact {
    /// Canonical entity URN.
    pub urn: String,
    /// Closed entity type.
    pub entity_type: String,
    /// Human-readable label.
    pub label: String,
}

/// One deterministic JumpCloud projection relation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct JumpCloudRelationFact {
    /// Source entity URN.
    pub from_urn: String,
    /// Closed semantic relation.
    pub relation: String,
    /// Target entity URN.
    pub to_urn: String,
}

/// Provider-local projection facts used for Go/Rust parity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct JumpCloudProjectionFacts {
    /// Deduplicated entities in canonical order.
    pub entities: Vec<JumpCloudEntityFact>,
    /// Deduplicated relations in canonical order.
    pub relations: Vec<JumpCloudRelationFact>,
}

/// Project normalized JumpCloud records into identity, system, and access context.
pub fn project_jumpcloud_records(records: &[JumpCloudRecord]) -> JumpCloudProjectionFacts {
    let mut entities = BTreeMap::<String, JumpCloudEntityFact>::new();
    let mut relations = BTreeSet::<JumpCloudRelationFact>::new();
    for record in records {
        match record.family {
            JumpCloudFamily::Users => add_entity(
                &mut entities,
                record,
                "jumpcloud_users",
                "identity_user",
                "display_name",
            ),
            JumpCloudFamily::Groups => add_entity(
                &mut entities,
                record,
                "jumpcloud_groups",
                "user_group",
                "group_name",
            ),
            JumpCloudFamily::Systems => add_entity(
                &mut entities,
                record,
                "jumpcloud_systems",
                "system",
                "resource_name",
            ),
            JumpCloudFamily::Applications => add_entity(
                &mut entities,
                record,
                "jumpcloud_applications",
                "application",
                "app_name",
            ),
            JumpCloudFamily::SystemGroups => add_entity(
                &mut entities,
                record,
                "jumpcloud_system_groups",
                "system_group",
                "group_name",
            ),
            JumpCloudFamily::GroupMembers => {
                let group_id = &record.attributes["group_id"];
                let member_id = &record.attributes["member_id"];
                let group_urn = format!(
                    "urn:cerebro:{}:jumpcloud_groups:{group_id}",
                    record.tenant_id
                );
                let member_urn = format!(
                    "urn:cerebro:{}:jumpcloud_users:{member_id}",
                    record.tenant_id
                );
                entities
                    .entry(group_urn.clone())
                    .or_insert(JumpCloudEntityFact {
                        urn: group_urn.clone(),
                        entity_type: "user_group".to_owned(),
                        label: group_id.clone(),
                    });
                entities
                    .entry(member_urn.clone())
                    .or_insert(JumpCloudEntityFact {
                        urn: member_urn.clone(),
                        entity_type: "identity_user".to_owned(),
                        label: member_id.clone(),
                    });
                relations.insert(JumpCloudRelationFact {
                    from_urn: member_urn,
                    relation: "member_of".to_owned(),
                    to_urn: group_urn,
                });
            }
            JumpCloudFamily::AuditEvents => {}
        }
    }
    JumpCloudProjectionFacts {
        entities: entities.into_values().collect(),
        relations: relations.into_iter().collect(),
    }
}

fn add_entity(
    entities: &mut BTreeMap<String, JumpCloudEntityFact>,
    record: &JumpCloudRecord,
    kind: &str,
    entity_type: &str,
    label_key: &str,
) {
    let urn = record
        .attributes
        .get("resource_urn")
        .cloned()
        .unwrap_or_else(|| {
            format!(
                "urn:cerebro:{}:{kind}:{}",
                record.tenant_id, record.provider_id
            )
        });
    entities.insert(
        urn.clone(),
        JumpCloudEntityFact {
            urn,
            entity_type: entity_type.to_owned(),
            label: record
                .attributes
                .get(label_key)
                .cloned()
                .unwrap_or_else(|| record.provider_id.clone()),
        },
    );
}
