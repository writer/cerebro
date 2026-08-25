use std::{cmp::Ordering, collections::BTreeMap};

use cerebro_organizational_store::EntityCatalogPage;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub(crate) struct Query {
    pub source_status: String,
    pub limit: usize,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Row {
    pub urn: String,
    pub discovery_id: String,
    pub name: String,
    pub normalized_name: String,
    pub source_id: String,
    pub runtime_id: String,
    pub provider: String,
    pub source_status: String,
    pub decision_state: String,
    pub category: String,
    pub website_url: String,
    pub linked_vendor_urn: String,
    pub decision_reason: String,
    pub decision_updated_by: String,
    pub decision_updated_at: String,
    pub attributes: BTreeMap<String, String>,
    pub source_ids: Vec<String>,
    pub confidence_score: f64,
    pub discovery_reason: String,
    pub first_observed_at: String,
    pub last_observed_at: String,
    pub signals: Vec<Signal>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Signal {
    pub id: String,
    pub label: String,
    pub source_id: String,
    pub runtime_id: String,
    pub entity_type: String,
    pub entity_urn: String,
    pub confidence_score: f64,
    pub observed_at: String,
    pub reason: String,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Summary {
    pub total_discoveries: u64,
    pub discovered: u64,
    pub approved: u64,
    pub rejected: u64,
    pub ignored: u64,
    pub linked: u64,
    pub source_count: u64,
    pub evidence_signals: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SourceSummary {
    pub source_id: String,
    pub provider: String,
    pub runtime_id: String,
    pub status: String,
    pub freshness: String,
    pub total: u64,
    pub discovered: u64,
    pub approved: u64,
    pub rejected: u64,
    pub ignored: u64,
    pub linked: u64,
    pub failed: u64,
    pub stale: u64,
    pub cursor_pending: u64,
    pub sync_lag_seconds: u64,
    pub last_error: String,
    pub last_synced_at: String,
}

pub(crate) struct Register {
    pub tenant_id: String,
    pub graph_revision: u64,
    pub generated_at: String,
    pub discoveries: Vec<Row>,
    pub summary: Summary,
    pub source_summaries: Vec<SourceSummary>,
}

pub(crate) fn build(page: EntityCatalogPage, query: &Query, now: OffsetDateTime) -> Register {
    let expected_status = if query.source_status.trim().is_empty() {
        String::new()
    } else {
        normalize_state(&query.source_status)
    };
    let mut discoveries = page
        .entities
        .into_iter()
        .map(|entity| {
            let name = if entity.label.trim().is_empty() {
                first(
                    &entity.properties,
                    &["name", "display_name", "normalized_name"],
                )
                .unwrap_or_else(|| urn_tail(&entity.agent_key))
            } else {
                entity.label.clone()
            };
            let source_status = normalize_state(
                &first(&entity.properties, &["status", "source_status"])
                    .unwrap_or_else(|| "discovered".to_owned()),
            );
            let runtime_id = first(&entity.properties, &["runtime_id", "source_runtime_id"])
                .or_else(|| {
                    entity
                        .authority
                        .get("source_runtime_id")
                        .and_then(serde_json::Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .unwrap_or_default();
            let source_id = first(&entity.properties, &["source_id"])
                .or_else(|| {
                    entity
                        .authority
                        .get("provider_kind")
                        .and_then(serde_json::Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .unwrap_or_default();
            let provider = first(
                &entity.properties,
                &["source_system", "provider", "source_id"],
            )
            .or_else(|| (!source_id.is_empty()).then(|| source_id.clone()))
            .unwrap_or_default();
            let source_ids = string_list(&entity.properties, "source_ids", &source_id);
            let signals = parse_signals(&entity.properties);
            Row {
                urn: entity.agent_key.clone(),
                discovery_id: first(
                    &entity.properties,
                    &["discovered_vendor_id", "vendor_id", "external_id"],
                )
                .unwrap_or_else(|| urn_tail(&entity.agent_key)),
                normalized_name: first(&entity.properties, &["normalized_name"])
                    .unwrap_or_else(|| name.to_lowercase()),
                source_id,
                runtime_id,
                provider,
                source_status: source_status.clone(),
                decision_state: source_status,
                category: value(&entity.properties, "category"),
                website_url: first(
                    &entity.properties,
                    &["website_url", "website", "url", "domain"],
                )
                .unwrap_or_default(),
                linked_vendor_urn: value(&entity.properties, "linked_vendor_urn"),
                decision_reason: value(&entity.properties, "decision_reason"),
                decision_updated_by: value(&entity.properties, "decision_updated_by"),
                decision_updated_at: value(&entity.properties, "decision_updated_at"),
                confidence_score: number(&entity.properties, "confidence_score"),
                discovery_reason: first(
                    &entity.properties,
                    &["discovery_reason", "reason", "description"],
                )
                .unwrap_or_default(),
                first_observed_at: first(
                    &entity.properties,
                    &["first_observed_at", "discovered_at", "created_at"],
                )
                .unwrap_or_default(),
                last_observed_at: first(
                    &entity.properties,
                    &["last_observed_at", "updated_at", "discovered_at"],
                )
                .unwrap_or_default(),
                source_ids,
                signals,
                name,
                attributes: entity.properties,
            }
        })
        .filter(|row| {
            expected_status.is_empty()
                || expected_status == "all"
                || row.source_status == expected_status
        })
        .collect::<Vec<_>>();
    discoveries.sort_by(compare_rows);
    discoveries.truncate(query.limit);
    let summary = summarize(&discoveries);
    let source_summaries = summarize_sources(&discoveries);
    Register {
        tenant_id: page.tenant_id,
        graph_revision: page.graph_revision,
        generated_at: now.format(&Rfc3339).unwrap_or_default(),
        discoveries,
        summary,
        source_summaries,
    }
}

fn number(properties: &BTreeMap<String, String>, key: &str) -> f64 {
    value(properties, key).parse::<f64>().unwrap_or_default()
}

fn string_list(properties: &BTreeMap<String, String>, key: &str, fallback: &str) -> Vec<String> {
    let mut values = value(properties, key)
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if values.is_empty() && !fallback.is_empty() {
        values.push(fallback.to_owned());
    }
    values.sort();
    values.dedup();
    values
}

fn parse_signals(properties: &BTreeMap<String, String>) -> Vec<Signal> {
    let Some(raw) = properties.get("signals") else {
        return Vec::new();
    };
    serde_json::from_str::<Vec<serde_json::Value>>(raw)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| {
            let object = value.as_object()?;
            let text = |key: &str| {
                object
                    .get(key)
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .trim()
                    .to_owned()
            };
            let id = text("id");
            let label = text("label");
            if id.is_empty() || label.is_empty() {
                return None;
            }
            let attributes = object
                .get("attributes")
                .and_then(serde_json::Value::as_object)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|(key, value)| {
                            value.as_str().map(|value| (key.clone(), value.to_owned()))
                        })
                        .collect()
                })
                .unwrap_or_default();
            Some(Signal {
                id,
                label,
                source_id: text("source_id"),
                runtime_id: text("runtime_id"),
                entity_type: text("entity_type"),
                entity_urn: text("entity_urn"),
                confidence_score: object
                    .get("confidence_score")
                    .and_then(serde_json::Value::as_f64)
                    .unwrap_or_default(),
                observed_at: text("observed_at"),
                reason: text("reason"),
                attributes,
            })
        })
        .collect()
}

fn value(properties: &BTreeMap<String, String>, key: &str) -> String {
    properties
        .get(key)
        .map(|value| value.trim().to_owned())
        .unwrap_or_default()
}

fn first(properties: &BTreeMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        let value = value(properties, key);
        (!value.is_empty()).then_some(value)
    })
}

fn urn_tail(urn: &str) -> String {
    urn.rsplit(':').next().unwrap_or_default().trim().to_owned()
}

fn normalize_state(value: &str) -> String {
    match value.trim().to_lowercase().as_str() {
        "" | "new" | "pending" | "needs_review" => "discovered".to_owned(),
        "approve" | "approved" => "approved".to_owned(),
        "reject" | "rejected" => "rejected".to_owned(),
        "ignore" | "ignored" => "ignored".to_owned(),
        "link" | "linked" => "linked".to_owned(),
        other => other.to_owned(),
    }
}

fn rank(value: &str) -> u8 {
    match value {
        "discovered" => 4,
        "approved" => 3,
        "linked" => 2,
        "rejected" | "ignored" => 1,
        _ => 0,
    }
}

fn compare_rows(left: &Row, right: &Row) -> Ordering {
    rank(&right.decision_state)
        .cmp(&rank(&left.decision_state))
        .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
}

fn summarize(rows: &[Row]) -> Summary {
    let mut summary = Summary {
        total_discoveries: rows.len() as u64,
        ..Summary::default()
    };
    for row in rows {
        summary.evidence_signals += row.signals.len() as u64;
        match row.decision_state.as_str() {
            "approved" => summary.approved += 1,
            "rejected" => summary.rejected += 1,
            "ignored" => summary.ignored += 1,
            "linked" => summary.linked += 1,
            _ => summary.discovered += 1,
        }
    }
    summary.source_count = rows
        .iter()
        .flat_map(|row| row.source_ids.iter())
        .filter(|value| !value.is_empty())
        .collect::<std::collections::BTreeSet<_>>()
        .len() as u64;
    summary
}

fn summarize_sources(rows: &[Row]) -> Vec<SourceSummary> {
    let mut sources = BTreeMap::<String, SourceSummary>::new();
    for row in rows {
        let source_ids = if row.source_ids.is_empty() {
            vec![row.source_id.clone()]
        } else {
            row.source_ids.clone()
        };
        for source_id in source_ids.into_iter().filter(|value| !value.is_empty()) {
            let summary = sources
                .entry(source_id.clone())
                .or_insert_with(|| SourceSummary {
                    source_id,
                    provider: row.provider.clone(),
                    runtime_id: row.runtime_id.clone(),
                    status: "ready".to_owned(),
                    freshness: value(&row.attributes, "freshness"),
                    last_error: value(&row.attributes, "last_error"),
                    last_synced_at: first(
                        &row.attributes,
                        &["last_synced_at", "last_observed_at", "updated_at"],
                    )
                    .unwrap_or_default(),
                    ..SourceSummary::default()
                });
            summary.total += 1;
            match row.decision_state.as_str() {
                "approved" => summary.approved += 1,
                "rejected" => summary.rejected += 1,
                "ignored" => summary.ignored += 1,
                "linked" => summary.linked += 1,
                _ => summary.discovered += 1,
            }
            if row.source_status == "failed" {
                summary.failed += 1;
                summary.status = "failed".to_owned();
            }
            if summary.freshness == "stale" {
                summary.stale += 1;
            }
        }
    }
    sources.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerebro_agent_context::ContextEntity;
    use cerebro_organizational_model::EntityId;

    #[test]
    fn builds_filtered_source_backed_discoveries() {
        let page = EntityCatalogPage {
            tenant_id: "writer".to_owned(),
            graph_revision: 17,
            entities: vec![ContextEntity {
                entity_id: EntityId::parse("vendor-discovery-acme").unwrap(),
                agent_key: "urn:cerebro:writer:vendor_discovery:grc:acme".to_owned(),
                entity_kind: "vendor.discovery".to_owned(),
                authority: serde_json::Value::Null,
                label: "Acme".to_owned(),
                properties: BTreeMap::from([
                    ("status".to_owned(), "pending".to_owned()),
                    ("provider".to_owned(), "cloudflare".to_owned()),
                    ("source_id".to_owned(), "grc".to_owned()),
                    ("runtime_id".to_owned(), "grc-prod".to_owned()),
                    ("confidence_score".to_owned(), "0.91".to_owned()),
                    (
                        "signals".to_owned(),
                        r#"[{"id":"signal-1","label":"Provider account","source_id":"grc","entity_urn":"urn:cerebro:writer:vendor_discovery:grc:acme","confidence_score":0.91}]"#.to_owned(),
                    ),
                    ("website_url".to_owned(), "https://acme.example".to_owned()),
                ]),
            }],
            truncated: false,
            next_after_agent_key: String::new(),
            relation_counts: Vec::new(),
        };
        let register = build(
            page,
            &Query {
                source_status: "discovered".to_owned(),
                limit: 10,
            },
            OffsetDateTime::from_unix_timestamp(0).unwrap(),
        );
        assert_eq!(register.graph_revision, 17);
        assert_eq!(register.discoveries.len(), 1);
        assert_eq!(register.discoveries[0].discovery_id, "acme");
        assert_eq!(register.discoveries[0].source_status, "discovered");
        assert_eq!(register.discoveries[0].runtime_id, "grc-prod");
        assert_eq!(register.discoveries[0].signals.len(), 1);
        assert_eq!(register.summary.discovered, 1);
        assert_eq!(register.summary.source_count, 1);
        assert_eq!(register.summary.evidence_signals, 1);
        assert_eq!(register.source_summaries[0].source_id, "grc");
    }

    #[test]
    fn empty_status_filter_keeps_non_discovered_rows() {
        let page = EntityCatalogPage {
            tenant_id: "writer".to_owned(),
            graph_revision: 18,
            entities: vec![ContextEntity {
                entity_id: EntityId::parse("vendor-discovery-ignored").unwrap(),
                agent_key: "urn:cerebro:writer:vendor_discovery:grc:ignored".to_owned(),
                entity_kind: "vendor.discovery".to_owned(),
                authority: serde_json::Value::Null,
                label: "Ignored vendor".to_owned(),
                properties: BTreeMap::from([("status".to_owned(), "ignored".to_owned())]),
            }],
            truncated: false,
            next_after_agent_key: String::new(),
            relation_counts: Vec::new(),
        };
        let register = build(
            page,
            &Query {
                source_status: String::new(),
                limit: 10,
            },
            OffsetDateTime::from_unix_timestamp(0).unwrap(),
        );
        assert_eq!(register.discoveries.len(), 1);
        assert_eq!(register.discoveries[0].source_status, "ignored");
    }
}
