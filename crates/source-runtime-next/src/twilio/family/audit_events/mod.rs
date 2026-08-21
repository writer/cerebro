//! Go-compatible Twilio audit-events normalization.

mod wire;

use serde_json::Value;
use time::OffsetDateTime;

use super::super::{
    TwilioError, TwilioFamily, TwilioRecord,
    normalize::{
        base_fields, event_id, first, insert, occurred_at, provider_identity, record_identity,
        require_field, require_payload_id, scalar,
    },
};
use wire::AuditEventWire;

pub(in crate::twilio) fn normalize(
    payload: Value,
    tenant_id: &str,
    base_origin: &str,
    path: &str,
    observed_at: OffsetDateTime,
) -> Result<TwilioRecord, TwilioError> {
    let record: AuditEventWire =
        serde_json::from_value(payload.clone()).map_err(|_| TwilioError::InvalidResponse)?;
    require_payload_id(&record.id)?;
    let actor = record.actor.as_ref();
    let user = record.user.as_ref();
    let target = record.target.as_ref();
    let resource = record.resource.as_ref();
    let metadata = record.metadata.as_ref();
    let evidence = record.evidence_cas.as_ref();
    let record_id = provider_identity([
        scalar(&record.id),
        scalar(&record.event_id),
        scalar(&record.uuid),
        scalar(&record.request_id),
    ])?;
    let provider_id = record_identity(&record_id, &record.identity);
    let mut fields = base_fields(
        TwilioFamily::AuditEvents,
        tenant_id,
        &record_id,
        "audit_event",
    );
    let mappings = [
        (
            "actor_email",
            first([
                scalar(&record.actor_email),
                scalar(&actor.and_then(|value| value.email.clone())),
                scalar(&record.email),
                scalar(&user.and_then(|value| value.email.clone())),
            ]),
        ),
        (
            "actor_id",
            first([
                scalar(&record.actor_id),
                scalar(&actor.and_then(|value| value.id.clone())),
                scalar(&record.actor_id_camel),
                scalar(&record.user_id),
                scalar(&user.and_then(|value| value.id.clone())),
            ]),
        ),
        (
            "actor_name",
            first([
                scalar(&record.actor_name),
                scalar(&actor.and_then(|value| value.name.clone())),
                scalar(&user.and_then(|value| value.name.clone())),
            ]),
        ),
        (
            "event_type",
            first([
                scalar(&record.event_type),
                scalar(&record.event_name),
                scalar(&record.action),
                scalar(&record.kind),
            ]),
        ),
        (
            "evidence_cas_commit_id",
            first([
                scalar(&evidence.and_then(|value| value.commit_id.clone())),
                scalar(&record.evidence_cas_commit_id),
                scalar(&record.commit_id),
            ]),
        ),
        (
            "evidence_cas_digest",
            first([
                scalar(&evidence.and_then(|value| value.digest.clone())),
                scalar(&record.evidence_cas_digest),
                scalar(&record.digest),
            ]),
        ),
        (
            "evidence_cas_merkle_root",
            first([
                scalar(&evidence.and_then(|value| value.merkle_root.clone())),
                scalar(&record.evidence_cas_merkle_root),
                scalar(&record.merkle_root),
            ]),
        ),
        (
            "evidence_cas_ref_type",
            first([
                scalar(&evidence.and_then(|value| value.ref_type.clone())),
                scalar(&record.evidence_cas_ref_type),
                scalar(&record.ref_type),
            ]),
        ),
        (
            "evidence_cas_uri",
            first([
                scalar(&evidence.and_then(|value| value.uri.clone())),
                scalar(&record.evidence_cas_uri),
                scalar(&record.uri),
            ]),
        ),
        (
            "observed_at",
            first([
                scalar(&record.observed_at),
                scalar(&record.updated_at),
                scalar(&record.last_seen_at),
            ]),
        ),
        (
            "resource_email",
            first([
                scalar(&record.resource_email),
                scalar(&record.target_email),
                scalar(&target.and_then(|value| value.email.clone())),
            ]),
        ),
        (
            "resource_id",
            first([
                scalar(&record.resource_id),
                scalar(&record.target_id),
                scalar(&target.and_then(|value| value.id.clone())),
                scalar(&resource.and_then(|value| value.id.clone())),
                scalar(&record.object_id),
            ]),
        ),
        (
            "resource_name",
            first([
                scalar(&record.resource_name),
                scalar(&record.target_name),
                scalar(&target.and_then(|value| value.name.clone())),
                scalar(&resource.and_then(|value| value.name.clone())),
                scalar(&record.object_name),
            ]),
        ),
        (
            "resource_type",
            first([
                scalar(&record.resource_type),
                scalar(&record.target_type),
                scalar(&target.and_then(|value| value.kind.clone())),
                scalar(&record.object_type),
            ]),
        ),
        (
            "resource_urn",
            first([
                scalar(&record.resource_urn),
                scalar(&record.urn),
                scalar(&metadata.and_then(|value| value.resource_urn.clone())),
            ]),
        ),
        (
            "source_event_id",
            first([
                scalar(&record.event_id),
                scalar(&record.id),
                scalar(&metadata.and_then(|value| value.event_id.clone())),
            ]),
        ),
    ];
    for (name, value) in mappings {
        insert(&mut fields, name, value);
    }
    for name in ["source_event_id", "event_type", "actor_id"] {
        require_field(&fields, name)?;
    }
    let occurred_at = occurred_at(
        [
            scalar(&record.observed_at),
            scalar(&record.updated_at),
            scalar(&record.last_seen_at),
            scalar(&record.created_at),
            scalar(&record.updated_at_camel),
            scalar(&record.last_seen_at_camel),
            scalar(&record.last_check_in),
            scalar(&record.last_check_in_camel),
            scalar(&record.created_at_camel),
            scalar(&record.timestamp),
        ],
        observed_at,
    );
    Ok(TwilioRecord {
        family: TwilioFamily::AuditEvents.as_str().to_owned(),
        provider_kind: TwilioFamily::AuditEvents.provider_kind().to_owned(),
        schema_ref: TwilioFamily::AuditEvents.schema_ref().to_owned(),
        tenant_id: tenant_id.to_owned(),
        provider_id: provider_id.clone(),
        event_id: event_id(
            tenant_id,
            base_origin,
            path,
            TwilioFamily::AuditEvents,
            &provider_id,
        ),
        fields,
        occurred_at,
        payload,
    })
}
