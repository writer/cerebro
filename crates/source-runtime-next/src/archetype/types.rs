use std::collections::BTreeMap;

use serde_json::Value;
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

use super::ArchetypeError;

pub(super) const MAX_PROVIDER_ID: u64 = i64::MAX as u64;

pub(super) const fn valid_provider_id(value: u64) -> bool {
    value > 0 && value <= MAX_PROVIDER_ID
}

/// One decoded Archetype scan used to drive bounded enrichment fanout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchetypeScan {
    /// Provider scan ID.
    pub id: u64,
    /// Provider repository ID attached to the scan.
    pub repository_id: u64,
    /// Provider scan lifecycle status.
    pub status: String,
    /// Go-compatible occurrence time precedence: completed, started, created.
    pub occurred_at: Option<String>,
    pub(super) request_path: String,
    pub(super) payload: Value,
}

impl ArchetypeScan {
    pub(super) fn validate_invariant(&self) -> Result<(), ArchetypeError> {
        if !valid_provider_id(self.id) || !valid_provider_id(self.repository_id) {
            return Err(ArchetypeError::MissingRecordIdentity);
        }
        if self.request_path.trim().is_empty()
            || self.status.trim().is_empty()
            || self.payload.get("id").and_then(Value::as_u64) != Some(self.id)
            || self.payload.get("repository_id").and_then(Value::as_u64) != Some(self.repository_id)
            || self.payload.get("status").and_then(Value::as_str) != Some(self.status.as_str())
            || self.occurred_at != scan_occurrence_time(&self.payload)
        {
            return Err(ArchetypeError::InvalidResponse);
        }
        Ok(())
    }
}

fn scan_occurrence_time(payload: &Value) -> Option<String> {
    let selected = ["completed_at", "started_at", "created_at"]
        .into_iter()
        .find_map(|field| {
            let value = payload.get(field)?.as_str()?;
            (!value.trim().is_empty()).then_some(value)
        });
    selected.and_then(normalized_timestamp)
}

pub(super) fn normalized_timestamp(value: &str) -> Option<String> {
    let parsed = OffsetDateTime::parse(value.trim(), &Rfc3339).ok()?;
    parsed.to_offset(UtcOffset::UTC).format(&Rfc3339).ok()
}

/// One decoded repository identity used to enrich scan-derived records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchetypeRepository {
    /// Provider repository ID.
    pub id: u64,
    /// Repository owner name.
    pub owner: String,
    /// Repository name.
    pub name: String,
}
/// One normalized Archetype record ready for the shared source mapper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchetypeRecord {
    /// Source-catalog family that requested the record.
    pub family: String,
    /// Portable source identifier.
    pub source_id: String,
    /// Go-compatible emitted event kind.
    pub provider_kind: String,
    /// Exact source schema reference selected for the emitted kind.
    pub schema_ref: String,
    /// Tenant identity supplied by the trusted runtime context.
    pub tenant_id: String,
    /// Go-compatible stable event identity.
    pub provider_id: String,
    /// Go-compatible event identity, scoped separately by `tenant_id`.
    pub event_id: String,
    /// Stable credential-free operation that produced the record.
    pub request_kind: String,
    /// Exact credential-free provider path and query that produced the record.
    pub request_path: String,
    /// Selected provider occurrence timestamp or explicit observation fallback.
    pub occurred_at: String,
    /// Portable scalar attributes used by source projection.
    pub fields: BTreeMap<String, String>,
    /// Provider payload with Go-compatible fallback enrichment applied.
    pub payload: Value,
}
