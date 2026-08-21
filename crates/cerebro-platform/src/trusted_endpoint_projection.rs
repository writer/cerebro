use std::collections::BTreeMap;

use cerebro_organizational_model::{
    AssertionProvenance, Entity, EntityKind, GraphAssertion, GraphDelta, ObservationRef,
    ProviderKind, RelationKind, RelationshipAssertion,
};
use cerebro_source_catalog::CompiledPushFamily;
use cerebro_source_runtime_next::{CollectedBatch, CommittedSourceEvent};

const SOURCE_ID: &str = "trusted_endpoint";
const MAPPER_ID: &str = "cerebro-trusted-endpoint";

pub(crate) fn matches(event: &CommittedSourceEvent) -> bool {
    event.source_id() == SOURCE_ID
}

pub(crate) fn project(
    event: CommittedSourceEvent,
    contract: &CompiledPushFamily,
) -> Result<(CollectedBatch, GraphDelta), String> {
    validate_contract(&event, contract)?;
    let payload = event
        .payload()
        .as_object()
        .ok_or("Trusted Endpoint payload must be a JSON object")?;
    let agent_id = first_nonempty([
        event.attributes().get("agent_id").map(String::as_str),
        payload_string(payload, "agent_id"),
        event.attributes().get("device_id").map(String::as_str),
        payload_string(payload, "device_id"),
    ])
    .ok_or("Trusted Endpoint event is missing agent_id")?
    .to_owned();
    let hostname = first_nonempty([
        event.attributes().get("hostname").map(String::as_str),
        payload_string(payload, "hostname"),
        Some(agent_id.as_str()),
    ])
    .expect("agent ID is non-empty")
    .to_owned();
    let tenant_id = event.tenant_id().clone();
    let runtime_id = event.source_runtime_id().clone();
    let observation_id = event.observation_id().clone();
    let observed_at_unix_ms = event.observed_at_unix_ms();
    let event_kind = event.event_kind().to_owned();
    let event_label = event_label(&event).to_owned();
    let event_provider_id = observation_id.as_str().to_owned();

    let batch = event
        .clone()
        .into_batch(event_kind.clone(), event_provider_id.clone())
        .map_err(|error| error.to_string())?;
    let receipt = batch.scope.receipt().clone();
    let agent_kind =
        ProviderKind::parse("trusted_endpoint.agent").map_err(|error| error.to_string())?;
    let mut agent = Entity::provider(
        tenant_id.clone(),
        runtime_id.clone(),
        agent_kind,
        agent_id.clone(),
        EntityKind::Resource,
        hostname,
    )
    .map_err(|error| error.to_string())?;
    agent = add_properties(
        agent,
        event.attributes(),
        &[
            "agent_status",
            "agent_id",
            "device_id",
            "hardware_key",
            "hostname",
            "managed",
        ],
    )?;
    agent = agent
        .with_property("source_product", SOURCE_ID)
        .map_err(|error| error.to_string())?;

    let event_entity_kind =
        ProviderKind::parse(event_entity_type(&event_kind)).map_err(|error| error.to_string())?;
    let mut event_entity = Entity::provider(
        tenant_id.clone(),
        runtime_id.clone(),
        event_entity_kind.clone(),
        event_provider_id.clone(),
        EntityKind::Provider(event_entity_kind),
        event_label,
    )
    .map_err(|error| error.to_string())?;
    event_entity = add_properties(
        event_entity,
        event.attributes(),
        &[
            "action",
            "control_id",
            "decision",
            "finding_id",
            "agent_status",
            "managed",
            "observation_table",
            "outcome_result",
            "reason",
            "severity",
            "status",
        ],
    )?;
    for (key, value) in normalized_event_properties(&event_kind, event.attributes()) {
        event_entity = event_entity
            .with_property(key, value)
            .map_err(|error| error.to_string())?;
    }
    if event_kind == "trusted_endpoint.agent_execution_receipt" {
        event_entity = add_properties(event_entity, event.attributes(), RECEIPT_ATTRIBUTES)?;
    }
    event_entity = event_entity
        .with_property("event_id", observation_id.as_str())
        .and_then(|entity| entity.with_property("kind", &event_kind))
        .and_then(|entity| entity.with_property("source_product", SOURCE_ID))
        .and_then(|entity| {
            entity.with_property("observed_at_unix_ms", observed_at_unix_ms.to_string())
        })
        .map_err(|error| error.to_string())?;

    let provenance = AssertionProvenance::direct(
        vec![
            ObservationRef::new(
                &receipt,
                observation_id,
                format!("{event_kind}:{event_provider_id}"),
            )
            .map_err(|error| error.to_string())?,
        ],
        MAPPER_ID,
        env!("CARGO_PKG_VERSION"),
    )
    .map_err(|error| error.to_string())?;
    let mut builder = receipt.begin_delta();
    builder
        .add_entity(agent.clone())
        .map_err(|error| error.to_string())?;
    builder
        .add_entity(event_entity.clone())
        .map_err(|error| error.to_string())?;
    add_relationship(
        &mut builder,
        &agent,
        RelationKind::TrackedBy,
        &event_entity,
        &provenance,
        observed_at_unix_ms,
    )?;

    if event_kind == "trusted_endpoint.agent_execution_receipt" {
        let product = required_attribute(event_entity.properties(), "agent_product")?;
        let session_id = required_attribute(event_entity.properties(), "session_id")?;
        let receipt_id = required_attribute(event_entity.properties(), "receipt_id")?;
        let session = receipt_entity(
            &tenant_id,
            &runtime_id,
            "trusted_endpoint.agent_session",
            format!("{agent_id}:{product}:{session_id}"),
            format!("{product} {session_id}"),
            event.attributes(),
            &["agent_product", "device_id", "model", "session_id"],
        )?;
        let receipt_entity = receipt_entity(
            &tenant_id,
            &runtime_id,
            "trusted_endpoint.agent_execution_receipt",
            format!("{agent_id}:{receipt_id}"),
            receipt_id.to_owned(),
            event.attributes(),
            &["device_id", "receipt_id", "receipt_key"],
        )?;
        builder
            .add_entity(session.clone())
            .map_err(|error| error.to_string())?;
        builder
            .add_entity(receipt_entity.clone())
            .map_err(|error| error.to_string())?;
        add_relationship(
            &mut builder,
            &agent,
            RelationKind::TrackedBy,
            &session,
            &provenance,
            observed_at_unix_ms,
        )?;
        add_relationship(
            &mut builder,
            &session,
            RelationKind::DependsOn,
            &receipt_entity,
            &provenance,
            observed_at_unix_ms,
        )?;
        add_relationship(
            &mut builder,
            &receipt_entity,
            RelationKind::DependsOn,
            &event_entity,
            &provenance,
            observed_at_unix_ms,
        )?;
    }
    Ok((batch, builder.build()))
}

const RECEIPT_ATTRIBUTES: &[&str] = &[
    "agent_product",
    "captured_at",
    "claimed_evidence_integrity",
    "claimed_provider_binding",
    "claimed_provider_event_id",
    "evidence_integrity",
    "local_user_claim",
    "local_user_claim_source",
    "model",
    "permission_mode",
    "phase",
    "previous_receipt_digest",
    "provider_binding",
    "normalized_receipt_digest",
    "receipt_digest",
    "receipt_id",
    "receipt_key",
    "sequence",
    "session_id",
    "tool_call_id",
    "tool_name",
    "turn_id",
];

fn validate_contract(
    event: &CommittedSourceEvent,
    contract: &CompiledPushFamily,
) -> Result<(), String> {
    if event.source_id() != SOURCE_ID
        || event.family_id() != contract.id()
        || event.event_kind() != contract.event_kind()
        || event.schema_ref() != contract.schema_ref()
    {
        return Err("event does not match the exact Trusted Endpoint push contract".to_owned());
    }
    for field in contract.required_attributes() {
        if event
            .attributes()
            .get(field)
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(format!(
                "Trusted Endpoint event is missing attribute {field}"
            ));
        }
    }
    let payload = event
        .payload()
        .as_object()
        .ok_or("Trusted Endpoint payload must be a JSON object")?;
    for field in contract.required_payload_fields() {
        if payload.get(field).is_none_or(serde_json::Value::is_null) {
            return Err(format!("Trusted Endpoint payload is missing field {field}"));
        }
    }
    Ok(())
}

fn add_properties(
    mut entity: Entity,
    attributes: &BTreeMap<String, String>,
    keys: &[&str],
) -> Result<Entity, String> {
    for key in keys {
        if let Some(value) = attributes.get(*key).map(String::as_str)
            && !value.trim().is_empty()
        {
            entity = entity
                .with_property(*key, value.trim())
                .map_err(|error| error.to_string())?;
        }
    }
    Ok(entity)
}

fn receipt_entity(
    tenant_id: &cerebro_organizational_model::TenantId,
    runtime_id: &cerebro_organizational_model::SourceRuntimeId,
    provider_kind: &str,
    provider_id: String,
    label: String,
    attributes: &BTreeMap<String, String>,
    keys: &[&str],
) -> Result<Entity, String> {
    let kind = ProviderKind::parse(provider_kind).map_err(|error| error.to_string())?;
    let entity = Entity::provider(
        tenant_id.clone(),
        runtime_id.clone(),
        kind.clone(),
        provider_id,
        EntityKind::Provider(kind),
        label,
    )
    .map_err(|error| error.to_string())?;
    let entity = add_properties(entity, attributes, keys)?;
    entity
        .with_property("source_product", SOURCE_ID)
        .map_err(|error| error.to_string())
}

fn add_relationship<Mode>(
    builder: &mut cerebro_organizational_model::GraphDeltaBuilder<Mode>,
    from: &Entity,
    relation: RelationKind,
    to: &Entity,
    provenance: &AssertionProvenance,
    observed_at_unix_ms: i64,
) -> Result<(), String> {
    builder
        .add_assertion(GraphAssertion::Relationship(
            RelationshipAssertion::new(from, relation, to, provenance.clone(), observed_at_unix_ms)
                .map_err(|error| error.to_string())?,
        ))
        .map_err(|error| error.to_string())
}

fn payload_string<'a>(
    payload: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<&'a str> {
    payload.get(key).and_then(serde_json::Value::as_str)
}

fn first_nonempty<'a>(values: impl IntoIterator<Item = Option<&'a str>>) -> Option<&'a str> {
    values
        .into_iter()
        .flatten()
        .find(|value| !value.trim().is_empty())
        .map(str::trim)
}

fn event_entity_type(kind: &str) -> &str {
    match kind {
        "trusted_endpoint.security_finding" => "trusted_endpoint.security_finding",
        "trusted_endpoint.grc_evidence" => "trusted_endpoint.grc_evidence",
        "trusted_endpoint.trust_gate_decision" => "trusted_endpoint.trust_gate_decision",
        "trusted_endpoint.action_outcome" => "trusted_endpoint.action_outcome",
        "trusted_endpoint.agent_execution_receipt" => {
            "trusted_endpoint.agent_execution_receipt_observation"
        }
        _ => "trusted_endpoint.observation",
    }
}

fn event_label(event: &CommittedSourceEvent) -> &str {
    first_nonempty(
        [
            "receipt_id",
            "finding_id",
            "control_id",
            "action",
            "observation_table",
        ]
        .map(|key| event.attributes().get(key).map(String::as_str)),
    )
    .unwrap_or_else(|| event.event_kind())
}

fn normalized_event_properties(
    kind: &str,
    attributes: &BTreeMap<String, String>,
) -> BTreeMap<&'static str, String> {
    let decision = normalize_decision(attributes.get("decision").map_or("", String::as_str));
    BTreeMap::from([
        ("decision_normalized", decision.clone()),
        (
            "severity_normalized",
            normalize_severity(attributes.get("severity").map_or("", String::as_str)),
        ),
        (
            "status_normalized",
            normalize_status(kind, attributes, &decision),
        ),
    ])
    .into_iter()
    .filter(|(_, value)| !value.is_empty())
    .collect()
}

fn normalize_decision(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "deny" | "denied" | "block" | "blocked" | "fail" | "failed" | "reject" | "rejected" => {
            "deny".to_owned()
        }
        "allow" | "allowed" | "pass" | "passed" | "ok" | "permit" | "permitted" | "approved" => {
            "allow".to_owned()
        }
        "error" | "errored" => "error".to_owned(),
        value => value.to_owned(),
    }
}

fn normalize_severity(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" | "crit" | "p0" | "sev0" => "CRITICAL".to_owned(),
        "high" | "p1" | "sev1" => "HIGH".to_owned(),
        "medium" | "med" | "moderate" | "p2" | "sev2" => "MEDIUM".to_owned(),
        "low" | "p3" | "sev3" => "LOW".to_owned(),
        "info" | "informational" | "none" | "p4" | "sev4" => "INFO".to_owned(),
        "" => "UNKNOWN".to_owned(),
        value => value.to_ascii_uppercase(),
    }
}

fn normalize_status(kind: &str, attributes: &BTreeMap<String, String>, decision: &str) -> String {
    match (kind, decision) {
        ("trusted_endpoint.trust_gate_decision", "deny" | "error") => {
            return "failing".to_owned();
        }
        ("trusted_endpoint.trust_gate_decision", "allow") => return "passing".to_owned(),
        _ => {}
    }
    if kind == "trusted_endpoint.security_finding" {
        let status = attributes
            .get("status")
            .map_or("", String::as_str)
            .trim()
            .to_ascii_lowercase();
        if matches!(
            status.as_str(),
            "resolved" | "closed" | "remediated" | "fixed"
        ) || attributes
            .get("resolved_at")
            .is_some_and(|value| !value.trim().is_empty())
        {
            return "passing".to_owned();
        }
        return "failing".to_owned();
    }
    let status = first_nonempty([
        attributes.get("status").map(String::as_str),
        attributes.get("outcome_result").map(String::as_str),
    ])
    .unwrap_or("")
    .to_ascii_lowercase();
    match status.as_str() {
        "fail" | "failed" | "failing" | "non_compliant" | "noncompliant" | "violation" | "open" => {
            "failing".to_owned()
        }
        "pass" | "passed" | "passing" | "compliant" | "ok" | "success" | "resolved" | "closed" => {
            "passing".to_owned()
        }
        "" => "unknown".to_owned(),
        value => value.to_owned(),
    }
}

fn required_attribute<'a>(
    properties: &'a BTreeMap<String, String>,
    key: &str,
) -> Result<&'a str, String> {
    properties
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("Trusted Endpoint receipt is missing {key}"))
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::Path};

    use cerebro_organizational_model::{ObservationId, SourceRuntimeId, TenantId};
    use cerebro_source_catalog::{CompiledPushFamily, SourceCatalog};
    use cerebro_source_runtime_next::{CommittedSourceEvent, CommittedSourceInput};

    use super::*;

    fn catalog() -> SourceCatalog {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap()
    }

    fn event(contract: &CompiledPushFamily) -> CommittedSourceEvent {
        let mut attributes = BTreeMap::from([(
            "source_runtime_id".to_owned(),
            "trusted-endpoint-runtime".to_owned(),
        )]);
        for field in contract.required_attributes() {
            attributes.insert(field.clone(), field_value(field).to_owned());
        }
        attributes.insert("hostname".to_owned(), "endpoint.example.test".to_owned());
        attributes.insert("decision".to_owned(), "blocked".to_owned());
        attributes.insert("severity".to_owned(), "high".to_owned());
        let mut payload = serde_json::Map::new();
        for field in contract.required_payload_fields() {
            payload.insert(
                field.clone(),
                serde_json::Value::String(field_value(field).to_owned()),
            );
        }
        CommittedSourceEvent::from_input(CommittedSourceInput {
            tenant_id: TenantId::parse("tenant-a").unwrap(),
            source_runtime_id: SourceRuntimeId::parse("trusted-endpoint-runtime").unwrap(),
            observation_id: ObservationId::parse(format!("compat:v1:{}", contract.id())).unwrap(),
            source_id: SOURCE_ID.to_owned(),
            family_id: contract.id().to_owned(),
            event_kind: contract.event_kind().to_owned(),
            schema_ref: contract.schema_ref().to_owned(),
            observed_at_unix_ms: 1_720_000_000_123,
            attributes,
            payload: serde_json::Value::Object(payload),
        })
        .unwrap()
    }

    fn field_value(field: &str) -> &str {
        match field {
            "agent_id" => "device-1",
            "device_id" => "device-1",
            "hostname" => "endpoint.example.test",
            "hardware_key" => "hardware-key-1",
            "observation_table" => "host_posture",
            "repo_path_hash" => {
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
            "session_surface" => "codex",
            "risk_score" => "75",
            "finding_id" => "finding-1",
            "severity" => "high",
            "control_id" => "control-1",
            "status" => "open",
            "action" => "git_push",
            "decision" => "deny",
            "outcome" | "outcome_result" => "blocked",
            "receipt_id" => "receipt-1",
            "captured_at" => "2026-08-21T00:00:00Z",
            "agent_product" => "codex",
            "session_id" => "session-1",
            "phase" => "completed",
            "evidence_integrity" => "verified",
            _ => "value",
        }
    }

    #[test]
    fn all_ten_push_families_project_without_an_http_collector() {
        let catalog = catalog();
        let source = catalog.push_source(SOURCE_ID).unwrap();
        let mut projected = Vec::new();
        for contract in source.families() {
            let (batch, delta) = project(event(contract), contract).unwrap();
            assert_eq!(batch.records.len(), 1, "family={}", contract.id());
            assert!(delta.entities().len() >= 2, "family={}", contract.id());
            assert!(!delta.assertions().is_empty(), "family={}", contract.id());
            assert!(
                delta.entities().iter().any(|entity| entity
                    .properties()
                    .get("source_product")
                    .map(String::as_str)
                    == Some(SOURCE_ID)),
                "family={}",
                contract.id()
            );
            projected.push(contract.id());
        }
        assert_eq!(projected.len(), 10);
    }

    #[test]
    fn schema_and_required_fields_fail_closed() {
        let catalog = catalog();
        let contract = catalog
            .push_source(SOURCE_ID)
            .unwrap()
            .family("host_posture")
            .unwrap();
        let mut wrong_schema = event(contract);
        wrong_schema = CommittedSourceEvent::from_input(CommittedSourceInput {
            tenant_id: wrong_schema.tenant_id().clone(),
            source_runtime_id: wrong_schema.source_runtime_id().clone(),
            observation_id: wrong_schema.observation_id().clone(),
            source_id: wrong_schema.source_id().to_owned(),
            family_id: wrong_schema.family_id().to_owned(),
            event_kind: wrong_schema.event_kind().to_owned(),
            schema_ref: "trusted_endpoint/host_posture/v2".to_owned(),
            observed_at_unix_ms: wrong_schema.observed_at_unix_ms(),
            attributes: wrong_schema.attributes().clone(),
            payload: wrong_schema.payload().clone(),
        })
        .unwrap();
        assert!(project(wrong_schema, contract).is_err());

        let mut missing = event(contract);
        let mut attributes = missing.attributes().clone();
        attributes.remove("agent_id");
        missing = CommittedSourceEvent::from_input(CommittedSourceInput {
            tenant_id: missing.tenant_id().clone(),
            source_runtime_id: missing.source_runtime_id().clone(),
            observation_id: missing.observation_id().clone(),
            source_id: missing.source_id().to_owned(),
            family_id: missing.family_id().to_owned(),
            event_kind: missing.event_kind().to_owned(),
            schema_ref: missing.schema_ref().to_owned(),
            observed_at_unix_ms: missing.observed_at_unix_ms(),
            attributes,
            payload: missing.payload().clone(),
        })
        .unwrap();
        assert!(project(missing, contract).is_err());
    }
}
