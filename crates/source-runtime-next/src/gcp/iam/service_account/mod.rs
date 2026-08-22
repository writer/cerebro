//! Go-compatible family normalization.

mod wire;

use std::collections::BTreeMap;

use serde_json::{Value, json};
use time::OffsetDateTime;

use super::{
    GcpIamError, GcpIamFamily, GcpIamRecord,
    normalize::{
        first_gcp_value, first_nonblank_gcp, insert_gcp_field, normalized_observed_at,
        sanitize_gcp_event_id,
    },
};

pub(super) fn normalize(
    payload: Value,
    tenant_id: &str,
    project_id: &str,
    observed_at: OffsetDateTime,
) -> Result<GcpIamRecord, GcpIamError> {
    let record: wire::ServiceAccountWire =
        serde_json::from_value(payload.clone()).map_err(|_| GcpIamError::InvalidResponse)?;
    let email = record.email.trim().to_owned();
    let unique_id = record.unique_id.trim().to_owned();
    let name = record.name.trim().to_owned();
    let provider_id = first_nonblank_gcp([email.as_str(), unique_id.as_str(), name.as_str()])?;
    // Go event identity excludes `name`; rejecting name-only records is a
    // deliberate fail-closed tightening over Go's empty-suffix fallback.
    let event_suffix = first_nonblank_gcp([unique_id.as_str(), email.as_str()])?;
    let mut fields = BTreeMap::new();
    insert_gcp_field(
        &mut fields,
        "display_name",
        first_gcp_value([record.display_name, email.clone()]),
    );
    insert_gcp_field(&mut fields, "email", email.clone());
    insert_gcp_field(&mut fields, "domain", tenant_id.to_owned());
    insert_gcp_field(
        &mut fields,
        "family",
        GcpIamFamily::ServiceAccount.as_str().to_owned(),
    );
    insert_gcp_field(&mut fields, "mfa_enrolled", "false".to_owned());
    insert_gcp_field(&mut fields, "principal_type", "service_account".to_owned());
    insert_gcp_field(
        &mut fields,
        "status",
        if record.disabled {
            "DISABLED"
        } else {
            "ACTIVE"
        }
        .to_owned(),
    );
    insert_gcp_field(&mut fields, "unique_id", unique_id);
    insert_gcp_field(
        &mut fields,
        "user_id",
        first_gcp_value([email, record.unique_id, name]),
    );
    Ok(GcpIamRecord {
        family: GcpIamFamily::ServiceAccount.as_str().to_owned(),
        provider_kind: GcpIamFamily::ServiceAccount.provider_kind().to_owned(),
        schema_ref: GcpIamFamily::ServiceAccount.schema_ref().to_owned(),
        tenant_id: tenant_id.to_owned(),
        provider_id,
        event_id: sanitize_gcp_event_id(&format!("gcp-service-account-{event_suffix}")),
        fields,
        occurred_at: normalized_observed_at(observed_at),
        payload: json!({"raw": payload, "project_id": project_id}),
    })
}
