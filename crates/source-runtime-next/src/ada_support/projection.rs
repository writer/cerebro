use std::collections::BTreeMap;

use super::{AdaSupportFamily, AdaSupportRecord};

/// One deterministic tenant-scoped Ada Support projection entity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AdaSupportEntityFact {
    /// Canonical entity URN.
    pub urn: String,
    /// Closed entity type.
    pub entity_type: String,
    /// Human-readable label.
    pub label: String,
}

/// Provider-local projection facts used for Go/Rust parity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AdaSupportProjectionFacts {
    /// Deduplicated entities in canonical order.
    pub entities: Vec<AdaSupportEntityFact>,
}

/// Project normalized Ada Support records into identities and provider resources.
pub fn project_ada_support_records(records: &[AdaSupportRecord]) -> AdaSupportProjectionFacts {
    let mut entities = BTreeMap::<String, AdaSupportEntityFact>::new();
    for record in records {
        let (urn, entity_type, label) = if record.family == AdaSupportFamily::EndUsers {
            (
                format!(
                    "urn:cerebro:{}:ada_support_user:{}",
                    encode_segment(&record.tenant_id),
                    encode_segment(&record.provider_id)
                ),
                "ada_support.user".to_owned(),
                record
                    .attributes
                    .get("display_name")
                    .or_else(|| record.attributes.get("email"))
                    .cloned()
                    .unwrap_or_else(|| record.provider_id.clone()),
            )
        } else {
            let Some(urn) = record.attributes.get("resource_urn") else {
                continue;
            };
            let (entity_type, label_key) = match record.family {
                AdaSupportFamily::AuditEvents => ("ada_support.audit_resource", "resource_name"),
                AdaSupportFamily::Conversations => ("ada_support.conversation", "resource_name"),
                AdaSupportFamily::KnowledgeArticles => {
                    ("ada_support.knowledge_article", "policy_name")
                }
                AdaSupportFamily::PlatformIntegrations => {
                    ("ada_support.platform_integration", "resource_name")
                }
                AdaSupportFamily::EndUsers => continue,
            };
            (
                urn.clone(),
                entity_type.to_owned(),
                record
                    .attributes
                    .get(label_key)
                    .cloned()
                    .unwrap_or_else(|| record.provider_id.clone()),
            )
        };
        entities.insert(
            urn.clone(),
            AdaSupportEntityFact {
                urn,
                entity_type,
                label,
            },
        );
    }
    AdaSupportProjectionFacts {
        entities: entities.into_values().collect(),
    }
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
