//! Go-compatible Twilio keys normalization.

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
use wire::KeyWire;

pub(in crate::twilio) fn normalize(
    payload: Value,
    tenant_id: &str,
    base_origin: &str,
    path: &str,
    observed_at: OffsetDateTime,
) -> Result<TwilioRecord, TwilioError> {
    let record: KeyWire =
        serde_json::from_value(payload.clone()).map_err(|_| TwilioError::InvalidResponse)?;
    require_payload_id(&record.id)?;
    let metadata = record.metadata.as_ref();
    let evidence = record.evidence_cas.as_ref();
    let record_id = provider_identity([
        scalar(&record.id),
        scalar(&record.secret_id),
        scalar(&record.name),
        scalar(&record.key),
        scalar(&record.sid),
    ])?;
    let provider_id = record_identity(&record_id, &record.identity)?;
    let mut fields = base_fields(TwilioFamily::Keys, tenant_id, &record_id, "secret");
    let mappings = [
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
            "resource_id",
            first([
                scalar(&record.resource_id),
                scalar(&record.id),
                scalar(&metadata.and_then(|value| value.resource_id.clone())),
            ]),
        ),
        (
            "resource_name",
            first([
                scalar(&record.name),
                scalar(&record.display_name),
                scalar(&record.hostname),
                scalar(&metadata.and_then(|value| value.resource_name.clone())),
            ]),
        ),
        (
            "resource_type",
            first([
                scalar(&record.resource_type),
                scalar(&record.provider_type),
                scalar(&metadata.and_then(|value| value.resource_type.clone())),
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
            "secret_created_at",
            first([
                scalar(&record.created_at),
                scalar(&record.created),
                scalar(&record.date_created),
            ]),
        ),
        (
            "secret_id",
            first([
                scalar(&record.secret_id),
                scalar(&record.id),
                scalar(&record.key),
                scalar(&record.sid),
                scalar(&record.name),
            ]),
        ),
        (
            "secret_last_rotated_at",
            first([
                scalar(&record.secret_last_rotated_at),
                scalar(&record.last_rotated_at),
                scalar(&record.last_rotated),
                scalar(&record.rotated_at),
            ]),
        ),
        (
            "secret_name",
            first([
                scalar(&record.secret_name),
                scalar(&record.name),
                scalar(&record.display_name),
                scalar(&record.label),
                scalar(&record.title),
            ]),
        ),
        (
            "secret_rotation_enabled",
            first([
                scalar(&record.secret_rotation_enabled),
                scalar(&record.rotation_enabled),
                scalar(&record.auto_rotate),
            ]),
        ),
        (
            "secret_status",
            first([
                scalar(&record.secret_status),
                scalar(&record.status),
                scalar(&record.state),
            ]),
        ),
        (
            "secret_type",
            first([
                scalar(&record.secret_type),
                scalar(&record.provider_type),
                scalar(&record.kind),
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
    for name in ["source_event_id", "secret_id", "secret_name"] {
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
        family: TwilioFamily::Keys.as_str().to_owned(),
        provider_kind: TwilioFamily::Keys.provider_kind().to_owned(),
        schema_ref: TwilioFamily::Keys.schema_ref().to_owned(),
        tenant_id: tenant_id.to_owned(),
        provider_id: provider_id.clone(),
        event_id: event_id(
            tenant_id,
            base_origin,
            path,
            TwilioFamily::Keys,
            &provider_id,
        ),
        fields,
        occurred_at,
        payload,
    })
}
