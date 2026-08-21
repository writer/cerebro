//! Go-compatible family normalization.

mod wire;

use std::collections::BTreeMap;

use serde_json::{Value, json};
use time::OffsetDateTime;

use super::{
    GcpIamError, GcpIamFamily, GcpIamRecord,
    normalize::{
        first_nonblank_gcp, insert_gcp_field, normalized_gcp_time, normalized_observed_at,
        sanitize_gcp_event_id,
    },
};

pub(super) fn normalize(
    payload: Value,
    tenant_id: &str,
    project_id: &str,
    service_account_email: &str,
    observed_at: OffsetDateTime,
) -> Result<GcpIamRecord, GcpIamError> {
    let record: wire::ServiceAccountKeyWire =
        serde_json::from_value(payload.clone()).map_err(|_| GcpIamError::InvalidResponse)?;
    let name = record.name.trim().to_owned();
    let provider_id = first_nonblank_gcp([name.as_str(), service_account_email])?;
    let mut fields = BTreeMap::new();
    for (field, value) in [
        ("credential_id", provider_id.clone()),
        ("credential_type", "gcp_service_account_key".to_owned()),
        ("domain", tenant_id.to_owned()),
        ("event_type", "gcp_service_account_key_present".to_owned()),
        (
            "family",
            GcpIamFamily::ServiceAccountKey.as_str().to_owned(),
        ),
        ("resource_id", provider_id.clone()),
        ("resource_type", "service_account_key".to_owned()),
        (
            "status",
            if record.disabled {
                "DISABLED"
            } else {
                "ACTIVE"
            }
            .to_owned(),
        ),
        ("subject_email", service_account_email.to_owned()),
        ("subject_id", service_account_email.to_owned()),
        ("subject_type", "service_account".to_owned()),
    ] {
        insert_gcp_field(&mut fields, field, value);
    }
    let observed_at = normalized_observed_at(observed_at);
    let occurred_at =
        normalized_gcp_time(&record.valid_after_time).unwrap_or_else(|| observed_at.clone());
    Ok(GcpIamRecord {
        family: GcpIamFamily::ServiceAccountKey.as_str().to_owned(),
        provider_kind: GcpIamFamily::ServiceAccountKey.provider_kind().to_owned(),
        schema_ref: GcpIamFamily::ServiceAccountKey.schema_ref().to_owned(),
        tenant_id: tenant_id.to_owned(),
        provider_id: provider_id.clone(),
        event_id: sanitize_gcp_event_id(&format!("gcp-service-account-key-{provider_id}")),
        fields,
        occurred_at,
        payload: json!({
            "raw": payload,
            "project_id": project_id,
            "service_account_email": service_account_email,
        }),
    })
}
