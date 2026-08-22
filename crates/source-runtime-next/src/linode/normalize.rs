//! Go-compatible Linode issue normalization helpers.

use std::collections::BTreeMap;

use serde_json::Value;
use time::OffsetDateTime;

use super::{
    LinodeError, LinodeRecord,
    identity::{event_id, provider_identity, record_identity, require_event_identity},
    time::occurred_at,
    wire::{IssueWire, WireScalar},
};

pub(super) fn normalize_issue(
    payload: Value,
    tenant_id: &str,
    scope_base: &str,
    observed_at: OffsetDateTime,
) -> Result<LinodeRecord, LinodeError> {
    let issue: IssueWire =
        serde_json::from_value(payload.clone()).map_err(|_| LinodeError::InvalidResponse)?;
    let metadata = issue.metadata.as_ref();
    let evidence = issue.evidence_cas.as_ref();
    let record_id = provider_identity([
        scalar(&issue.id),
        scalar(&issue.created),
        scalar(&issue.finding_id),
        scalar(&issue.resource_urn),
    ])?;
    require_payload_id(&issue.id)?;
    let provider_id = record_identity(&record_id, &issue.identity)?;
    let mut fields = base_fields(tenant_id, &record_id);
    let entity = issue.entity.as_ref().map(value_text).unwrap_or_default();
    for (name, value) in [
        (
            "description",
            first([scalar(&issue.description), scalar(&issue.summary)]),
        ),
        (
            "evidence_cas_digest",
            first([
                scalar(&evidence.and_then(|value| value.digest.clone())),
                scalar(&issue.evidence_cas_digest),
            ]),
        ),
        (
            "evidence_cas_uri",
            first([
                scalar(&evidence.and_then(|value| value.uri.clone())),
                scalar(&issue.evidence_cas_uri),
            ]),
        ),
        ("finding_id", scalar(&issue.id)),
        ("id", scalar(&issue.id)),
        (
            "name",
            first([
                entity.clone(),
                scalar(&issue.summary),
                scalar(&issue.description),
            ]),
        ),
        (
            "observed_at",
            first([
                scalar(&issue.observed_at),
                scalar(&issue.updated_at),
                scalar(&issue.last_seen_at),
            ]),
        ),
        (
            "resource_id",
            first([
                scalar(&issue.resource_id),
                scalar(&issue.id),
                scalar(&metadata.and_then(|value| value.resource_id.clone())),
            ]),
        ),
        (
            "resource_name",
            first([
                scalar(&issue.name),
                scalar(&issue.display_name),
                scalar(&issue.hostname),
                scalar(&metadata.and_then(|value| value.resource_name.clone())),
            ]),
        ),
        (
            "resource_type",
            first([
                scalar(&issue.resource_type),
                scalar(&metadata.and_then(|value| value.resource_type.clone())),
            ]),
        ),
        (
            "resource_urn",
            first([
                scalar(&issue.resource_urn),
                scalar(&issue.urn),
                scalar(&metadata.and_then(|value| value.resource_urn.clone())),
            ]),
        ),
        (
            "severity",
            first([
                scalar(&issue.severity),
                scalar(&issue.risk),
                scalar(&issue.priority),
            ]),
        ),
        (
            "source_event_id",
            first([
                scalar(&issue.event_id),
                scalar(&issue.id),
                scalar(&metadata.and_then(|value| value.event_id.clone())),
            ]),
        ),
        (
            "status",
            first([scalar(&issue.status), scalar(&issue.state)]),
        ),
        (
            "title",
            first([entity, scalar(&issue.summary), scalar(&issue.description)]),
        ),
    ] {
        insert(&mut fields, name, value);
    }
    // Provider tenant fields are deliberately ignored; authenticated context owns tenancy.
    let _untrusted_tenant = (
        &issue.tenant_id,
        metadata.and_then(|value| value.tenant_id.as_ref()),
    );
    for required in [
        "tenant_id",
        "source_event_id",
        "finding_id",
        "resource_urn",
        "severity",
        "status",
    ] {
        require_field(&fields, required)?;
    }
    let occurred_at = occurred_at(
        [
            scalar(&issue.observed_at),
            scalar(&issue.updated_at),
            scalar(&issue.last_seen_at),
            scalar(&issue.created_at),
        ],
        observed_at,
    );
    Ok(LinodeRecord {
        family: "issue".to_owned(),
        provider_kind: "linode.issue".to_owned(),
        schema_ref: "linode/issue/v1".to_owned(),
        tenant_id: tenant_id.to_owned(),
        event_id: event_id(tenant_id, scope_base, "/managed/issues", &provider_id),
        provider_id,
        fields,
        occurred_at,
        payload,
    })
}

fn require_payload_id(value: &Option<WireScalar>) -> Result<(), LinodeError> {
    let value = value
        .as_ref()
        .ok_or(LinodeError::MissingRequiredPayloadField("id"))?;
    let text = value.text();
    if text.is_empty() {
        return Err(LinodeError::MissingRequiredPayloadField("id"));
    }
    if !value.canonical_identity() {
        return Err(LinodeError::InvalidEventIdentity);
    }
    require_event_identity(&text)
}

fn base_fields(tenant_id: &str, record_id: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    for (name, value) in [
        ("external_id", record_id),
        ("family", "issue"),
        ("provider", "linode"),
        ("record_class", "finding"),
        ("schema", "issue"),
        ("source_provider", "linode"),
        ("source_system", "linode"),
        ("tenant_id", tenant_id),
    ] {
        insert(&mut fields, name, value.to_owned());
    }
    fields
}

fn require_field(fields: &BTreeMap<String, String>, name: &'static str) -> Result<(), LinodeError> {
    fields
        .get(name)
        .filter(|value| !value.trim().is_empty())
        .map(|_| ())
        .ok_or(LinodeError::MissingRequiredAttribute(name))
}

fn insert(fields: &mut BTreeMap<String, String>, name: &str, value: String) {
    let value = value.trim();
    if !value.is_empty() {
        fields.insert(name.to_owned(), value.to_owned());
    }
}

fn scalar(value: &Option<WireScalar>) -> String {
    value.as_ref().map(WireScalar::text).unwrap_or_default()
}

fn first<const N: usize>(values: [String; N]) -> String {
    values
        .into_iter()
        .find(|value| !value.trim().is_empty())
        .unwrap_or_default()
}

fn value_text(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(value) => value.trim().to_owned(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Array(values) => values
            .iter()
            .map(value_text)
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => serde_json::to_string(value).unwrap_or_default(),
    }
}
