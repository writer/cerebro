//! Go-compatible Twilio accounts normalization.

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
use wire::AccountWire;

pub(in crate::twilio) fn normalize(
    payload: Value,
    tenant_id: &str,
    base_origin: &str,
    path: &str,
    observed_at: OffsetDateTime,
) -> Result<TwilioRecord, TwilioError> {
    let record: AccountWire =
        serde_json::from_value(payload.clone()).map_err(|_| TwilioError::InvalidResponse)?;
    require_payload_id(&record.id)?;
    let profile = record.profile.as_ref();
    let metadata = record.metadata.as_ref();
    let evidence = record.evidence_cas.as_ref();
    let record_id = provider_identity([
        scalar(&record.id),
        scalar(&record.user_id),
        scalar(&record.email),
        scalar(&record.primary_email),
        scalar(&record.login),
    ])?;
    let provider_id = record_identity(&record_id, &record.identity)?;
    let mut fields = base_fields(
        TwilioFamily::Accounts,
        tenant_id,
        &record_id,
        "identity_user",
    );
    let mappings = [
        (
            "created_at",
            first([
                scalar(&record.created_at),
                scalar(&record.created),
                scalar(&profile.and_then(|value| value.created_at.clone())),
            ]),
        ),
        (
            "department",
            first([
                scalar(&record.department),
                scalar(&profile.and_then(|value| value.department.clone())),
            ]),
        ),
        (
            "display_name",
            first([
                scalar(&record.display_name),
                scalar(&record.name),
                scalar(&profile.and_then(|value| value.display_name.clone())),
                scalar(&profile.and_then(|value| value.name.clone())),
            ]),
        ),
        (
            "domain",
            first([
                scalar(&record.domain),
                scalar(&record.tenant_domain),
                scalar(&record.organization_domain),
            ]),
        ),
        (
            "email",
            first([
                scalar(&record.email),
                scalar(&record.primary_email),
                scalar(&profile.and_then(|value| value.email.clone())),
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
            "job_title",
            first([
                scalar(&record.job_title),
                scalar(&record.title),
                scalar(&profile.and_then(|value| value.title.clone())),
            ]),
        ),
        (
            "last_login_at",
            first([
                scalar(&record.last_login_at),
                scalar(&record.last_login),
                scalar(&record.last_seen_at),
            ]),
        ),
        (
            "login",
            first([
                scalar(&record.login),
                scalar(&record.username),
                scalar(&record.email),
                scalar(&profile.and_then(|value| value.login.clone())),
            ]),
        ),
        (
            "manager",
            first([
                scalar(&record.manager),
                scalar(&profile.and_then(|value| value.manager.clone())),
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
            "primary_email",
            first([
                scalar(&record.primary_email),
                scalar(&record.email),
                scalar(&profile.and_then(|value| value.email.clone())),
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
                scalar(&record.kind),
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
            "source_event_id",
            first([
                scalar(&record.event_id),
                scalar(&record.id),
                scalar(&metadata.and_then(|value| value.event_id.clone())),
            ]),
        ),
        (
            "status",
            first([
                scalar(&record.status),
                scalar(&record.state),
                scalar(&record.lifecycle_state),
            ]),
        ),
        (
            "user_id",
            first([
                scalar(&record.user_id),
                scalar(&record.id),
                scalar(&record.uid),
            ]),
        ),
    ];
    for (name, value) in mappings {
        insert(&mut fields, name, value);
    }
    require_field(&fields, "source_event_id")?;
    require_field(&fields, "user_id")?;
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
        family: TwilioFamily::Accounts.as_str().to_owned(),
        provider_kind: TwilioFamily::Accounts.provider_kind().to_owned(),
        schema_ref: TwilioFamily::Accounts.schema_ref().to_owned(),
        tenant_id: tenant_id.to_owned(),
        provider_id: provider_id.clone(),
        event_id: event_id(
            tenant_id,
            base_origin,
            path,
            TwilioFamily::Accounts,
            &provider_id,
        ),
        fields,
        occurred_at,
        payload,
    })
}
