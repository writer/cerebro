use std::{cmp::Ordering, collections::BTreeMap};

use cerebro_organizational_store::{
    EntityCatalogDirection, EntityCatalogPage, EntityCatalogRelationCount,
};
use time::{Date, Duration, OffsetDateTime, format_description::well_known::Rfc3339};

const DUE_SOON_DAYS: i64 = 30;

pub(crate) struct Query {
    pub risk_level: String,
    pub review_state: String,
    pub owner_state: String,
    pub lifecycle_state: String,
    pub queue_only: bool,
    pub limit: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Row {
    pub urn: String,
    pub vendor_id: String,
    pub name: String,
    pub source_id: String,
    pub runtime_id: String,
    pub provider: String,
    pub status: String,
    pub category: String,
    pub website_url: String,
    pub services_provided: String,
    pub lifecycle_state: String,
    pub owner: String,
    pub owner_state: String,
    pub risk_level: String,
    pub risk_score: i32,
    pub risk_score_level: String,
    pub review_state: String,
    pub review_due_at: String,
    pub evidence_freshness_state: String,
    pub packet_state: String,
    pub contract_count: u64,
    pub security_review_count: u64,
    pub questionnaire_count: u64,
    pub assurance_document_count: u64,
    pub open_findings: u64,
    pub critical_findings: u64,
    pub high_findings: u64,
    pub evidence_items: u64,
    pub risk_queue_rank: i32,
    pub queue_reasons: Vec<String>,
    pub next_action_id: String,
    pub next_action_label: String,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Summary {
    pub total_vendors: u64,
    pub active_vendors: u64,
    pub high_risk_vendors: u64,
    pub owner_missing_vendors: u64,
    pub review_overdue_vendors: u64,
    pub review_due_soon_vendors: u64,
    pub review_not_scheduled: u64,
    pub risk_queue_vendors: u64,
    pub stale_evidence_vendors: u64,
    pub open_findings: u64,
    pub critical_findings: u64,
    pub high_findings: u64,
    pub evidence_items: u64,
}

pub(crate) struct Register {
    pub tenant_id: String,
    pub graph_revision: u64,
    pub generated_at: String,
    pub vendors: Vec<Row>,
    pub summary: Summary,
}

pub(crate) fn build(page: EntityCatalogPage, query: &Query, now: OffsetDateTime) -> Register {
    let counts = page
        .relation_counts
        .iter()
        .map(|count| (relation_count_key(count), count.count))
        .collect::<BTreeMap<_, _>>();
    let mut vendors = page
        .entities
        .into_iter()
        .map(|entity| {
            let mut row = Row {
                urn: entity.agent_key.clone(),
                vendor_id: first(&entity.properties, &["vendor_id", "external_id"])
                    .unwrap_or_else(|| urn_tail(&entity.agent_key)),
                name: if entity.label.trim().is_empty() {
                    first(&entity.properties, &["name", "vendor_id"])
                        .unwrap_or_else(|| urn_tail(&entity.agent_key))
                } else {
                    entity.label.clone()
                },
                source_id: entity
                    .properties
                    .get("source_id")
                    .cloned()
                    .unwrap_or_default(),
                runtime_id: entity
                    .properties
                    .get("runtime_id")
                    .cloned()
                    .or_else(|| {
                        entity
                            .authority
                            .get("source_runtime_id")
                            .and_then(serde_json::Value::as_str)
                            .map(ToOwned::to_owned)
                    })
                    .unwrap_or_default(),
                provider: first(
                    &entity.properties,
                    &["source_system", "provider", "source_id"],
                )
                .unwrap_or_default(),
                status: first(&entity.properties, &["status", "vendor_status"]).unwrap_or_default(),
                category: value(&entity.properties, "category"),
                website_url: first(
                    &entity.properties,
                    &["website_url", "website", "url", "domain"],
                )
                .unwrap_or_default(),
                services_provided: value(&entity.properties, "services_provided"),
                lifecycle_state: normalize_lifecycle(
                    &first(
                        &entity.properties,
                        &[
                            "lifecycle_state",
                            "vendor_lifecycle_state",
                            "status",
                            "vendor_status",
                        ],
                    )
                    .unwrap_or_default(),
                ),
                owner: first(
                    &entity.properties,
                    &["security_owner_user_id", "business_owner_user_id"],
                )
                .unwrap_or_default(),
                risk_level: normalize_risk(
                    &first(
                        &entity.properties,
                        &["residual_risk_level", "inherent_risk_level", "risk_level"],
                    )
                    .unwrap_or_else(|| "unknown".to_owned()),
                ),
                review_due_at: value(&entity.properties, "next_security_review_due_date"),
                evidence_freshness_state: first(
                    &entity.properties,
                    &["evidence_freshness_state", "evidence_status"],
                )
                .unwrap_or_else(|| "missing".to_owned()),
                packet_state: first(&entity.properties, &["packet_state", "audit_packet_state"])
                    .unwrap_or_default(),
                contract_count: related_count(&counts, &entity.agent_key, "contract")
                    .max(number(&entity.properties, "contract_count")),
                security_review_count: related_count(&counts, &entity.agent_key, "security.review")
                    .max(number(&entity.properties, "security_review_count")),
                questionnaire_count: related_count(
                    &counts,
                    &entity.agent_key,
                    "security.questionnaire",
                )
                .max(number(&entity.properties, "questionnaire_count")),
                assurance_document_count: related_count(
                    &counts,
                    &entity.agent_key,
                    "assurance.document",
                )
                .max(number(&entity.properties, "assurance_document_count")),
                open_findings: number(&entity.properties, "open_findings"),
                critical_findings: number(&entity.properties, "critical_findings"),
                high_findings: number(&entity.properties, "high_findings"),
                evidence_items: number(&entity.properties, "evidence_items"),
                attributes: entity.properties,
                ..Row::default()
            };
            row.owner_state = if row.owner.is_empty() {
                "missing"
            } else {
                "assigned"
            }
            .to_owned();
            row.review_state = review_state(&row.review_due_at, now);
            row.risk_score = number_i32(&row.attributes, "risk_score")
                .unwrap_or_else(|| score_for_risk(&row.risk_level));
            row.risk_score_level = normalize_risk(
                &first(&row.attributes, &["risk_score_level"])
                    .unwrap_or_else(|| score_level(row.risk_score).to_owned()),
            );
            populate_queue(&mut row);
            row
        })
        .filter(|row| matches(row, query))
        .collect::<Vec<_>>();
    vendors.sort_by(compare_rows);
    vendors.truncate(query.limit);
    let summary = summarize(&vendors);
    Register {
        tenant_id: page.tenant_id,
        graph_revision: page.graph_revision,
        generated_at: now.format(&Rfc3339).unwrap_or_default(),
        vendors,
        summary,
    }
}

fn relation_count_key(count: &EntityCatalogRelationCount) -> (String, String) {
    let kind = if count.direction == EntityCatalogDirection::Incoming
        && count.relation == "associated_with"
    {
        count.neighbor_kind.clone()
    } else {
        String::new()
    };
    (count.agent_key.clone(), kind)
}

fn related_count(counts: &BTreeMap<(String, String), u64>, urn: &str, kind: &str) -> u64 {
    counts
        .get(&(urn.to_owned(), kind.to_owned()))
        .copied()
        .unwrap_or_default()
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

fn number(properties: &BTreeMap<String, String>, key: &str) -> u64 {
    value(properties, key).parse().unwrap_or_default()
}

fn number_i32(properties: &BTreeMap<String, String>, key: &str) -> Option<i32> {
    value(properties, key).parse().ok()
}

fn urn_tail(urn: &str) -> String {
    urn.rsplit(':').next().unwrap_or_default().trim().to_owned()
}

fn normalize(value: &str) -> String {
    value.trim().to_lowercase().replace([' ', '-'], "_")
}

fn normalize_risk(value: &str) -> String {
    let normalized = normalize(value);
    for level in ["critical", "high", "medium", "low"] {
        if normalized.contains(level) {
            return level.to_owned();
        }
    }
    if matches!(normalized.as_str(), "none" | "no_risk") {
        return "low".to_owned();
    }
    if normalized.is_empty() {
        "unknown".to_owned()
    } else {
        normalized
    }
}

fn normalize_lifecycle(value: &str) -> String {
    let normalized = normalize(value);
    match normalized.as_str() {
        "" => "unknown".to_owned(),
        "enabled" | "live" | "production" => "active".to_owned(),
        "pending" | "pending_review" | "review" => "in_review".to_owned(),
        "conditional" => "conditionally_approved".to_owned(),
        "disabled" | "archived" | "deleted" | "terminated" => "retired".to_owned(),
        other => other.to_owned(),
    }
}

fn parse_date(value: &str) -> Option<Date> {
    if let Ok(timestamp) = OffsetDateTime::parse(value, &Rfc3339) {
        return Some(timestamp.date());
    }
    Date::parse(
        value.get(..10).unwrap_or(value),
        time::macros::format_description!("[year]-[month]-[day]"),
    )
    .ok()
}

fn review_state(due_at: &str, now: OffsetDateTime) -> String {
    let Some(due) = parse_date(due_at) else {
        return "not_scheduled".to_owned();
    };
    if due < now.date() {
        "overdue".to_owned()
    } else if due <= now.date() + Duration::days(DUE_SOON_DAYS) {
        "due_soon".to_owned()
    } else {
        "current".to_owned()
    }
}

fn score_for_risk(risk: &str) -> i32 {
    match risk {
        "critical" => 95,
        "high" => 78,
        "medium" => 52,
        "low" => 22,
        _ => 38,
    }
}

fn score_level(score: i32) -> &'static str {
    match score {
        85.. => "critical",
        65..=84 => "high",
        35..=64 => "medium",
        _ => "low",
    }
}

fn populate_queue(row: &mut Row) {
    let mut reasons = Vec::new();
    if row.owner_state == "missing" {
        reasons.push("Assign an owner".to_owned());
    }
    if row.review_state == "overdue" {
        reasons.push("Complete the overdue review".to_owned());
    } else if row.review_state == "due_soon" {
        reasons.push("Schedule the upcoming review".to_owned());
    } else if row.review_state == "not_scheduled" {
        reasons.push("Schedule a security review".to_owned());
    }
    if matches!(row.risk_level.as_str(), "critical" | "high") {
        reasons.push("Review the risk rating".to_owned());
    }
    if row.open_findings > 0 {
        reasons.push("Resolve open findings".to_owned());
    }
    if matches!(
        row.evidence_freshness_state.as_str(),
        "stale" | "expired" | "missing"
    ) {
        reasons.push("Refresh assurance evidence".to_owned());
    }
    row.risk_queue_rank = (row.critical_findings.saturating_mul(100)
        + row.high_findings.saturating_mul(25)
        + row.open_findings.saturating_mul(5)
        + u64::try_from(reasons.len()).unwrap_or_default())
    .min(i32::MAX as u64) as i32;
    if let Some(label) = reasons.first() {
        row.next_action_id = normalize(label);
        row.next_action_label = label.clone();
    }
    row.queue_reasons = reasons;
}

fn matches(row: &Row, query: &Query) -> bool {
    let matches_value = |expected: &str, actual: &str| {
        let expected = normalize(expected);
        expected.is_empty() || expected == "all" || expected == actual
    };
    matches_value(&query.risk_level, &row.risk_level)
        && matches_value(&query.review_state, &row.review_state)
        && matches_value(&query.owner_state, &row.owner_state)
        && matches_value(&query.lifecycle_state, &row.lifecycle_state)
        && (!query.queue_only || !row.queue_reasons.is_empty())
}

fn compare_rows(left: &Row, right: &Row) -> Ordering {
    right
        .risk_queue_rank
        .cmp(&left.risk_queue_rank)
        .then_with(|| risk_rank(&right.risk_level).cmp(&risk_rank(&left.risk_level)))
        .then_with(|| review_rank(&right.review_state).cmp(&review_rank(&left.review_state)))
        .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
}

fn risk_rank(value: &str) -> u8 {
    match value {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn review_rank(value: &str) -> u8 {
    match value {
        "overdue" => 3,
        "due_soon" => 2,
        "not_scheduled" => 1,
        _ => 0,
    }
}

fn summarize(rows: &[Row]) -> Summary {
    let mut summary = Summary {
        total_vendors: rows.len() as u64,
        ..Summary::default()
    };
    for row in rows {
        if !matches!(
            row.lifecycle_state.as_str(),
            "offboarding" | "retired" | "rejected" | "ignored"
        ) {
            summary.active_vendors += 1;
        }
        if matches!(row.risk_level.as_str(), "critical" | "high") {
            summary.high_risk_vendors += 1;
        }
        if row.owner_state == "missing" {
            summary.owner_missing_vendors += 1;
        }
        match row.review_state.as_str() {
            "overdue" => summary.review_overdue_vendors += 1,
            "due_soon" => summary.review_due_soon_vendors += 1,
            "not_scheduled" => summary.review_not_scheduled += 1,
            _ => {}
        }
        if !row.queue_reasons.is_empty() {
            summary.risk_queue_vendors += 1;
        }
        if matches!(row.evidence_freshness_state.as_str(), "stale" | "expired") {
            summary.stale_evidence_vendors += 1;
        }
        summary.open_findings += row.open_findings;
        summary.critical_findings += row.critical_findings;
        summary.high_findings += row.high_findings;
        summary.evidence_items += row.evidence_items;
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerebro_agent_context::ContextEntity;
    use cerebro_organizational_model::EntityId;

    #[test]
    fn builds_filtered_product_rows_and_summary_from_one_revision() {
        let now = OffsetDateTime::parse("2026-08-24T12:00:00Z", &Rfc3339).unwrap();
        let entity = ContextEntity {
            entity_id: EntityId::parse("vendor-acme").unwrap(),
            agent_key: "urn:cerebro:writer:vendor:acme".to_owned(),
            entity_kind: "vendor".to_owned(),
            authority: serde_json::Value::Null,
            label: "Acme".to_owned(),
            properties: BTreeMap::from([
                ("risk_level".to_owned(), "high".to_owned()),
                (
                    "next_security_review_due_date".to_owned(),
                    "2026-08-01".to_owned(),
                ),
                ("open_findings".to_owned(), "3".to_owned()),
                ("high_findings".to_owned(), "1".to_owned()),
                ("evidence_items".to_owned(), "8".to_owned()),
            ]),
        };
        let page = EntityCatalogPage {
            tenant_id: "writer".to_owned(),
            graph_revision: 42,
            entities: vec![entity],
            relation_counts: vec![EntityCatalogRelationCount {
                agent_key: "urn:cerebro:writer:vendor:acme".to_owned(),
                direction: EntityCatalogDirection::Incoming,
                relation: "associated_with".to_owned(),
                neighbor_kind: "contract".to_owned(),
                count: 2,
            }],
            truncated: false,
            next_after_agent_key: String::new(),
        };
        let register = build(
            page,
            &Query {
                risk_level: "high".to_owned(),
                review_state: String::new(),
                owner_state: String::new(),
                lifecycle_state: String::new(),
                queue_only: true,
                limit: 100,
            },
            now,
        );
        assert_eq!(register.graph_revision, 42);
        assert_eq!(register.vendors.len(), 1);
        assert_eq!(register.vendors[0].contract_count, 2);
        assert_eq!(register.vendors[0].review_state, "overdue");
        assert_eq!(register.summary.high_risk_vendors, 1);
        assert_eq!(register.summary.open_findings, 3);
    }
}
