use std::collections::BTreeMap;

use serde_json::Value;
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

use super::ArchetypeError;

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
    pub(super) payload: Value,
}

impl ArchetypeScan {
    pub(super) fn validate_invariant(&self) -> Result<(), ArchetypeError> {
        if self.id == 0 || self.repository_id == 0 {
            return Err(ArchetypeError::MissingRecordIdentity);
        }
        if self.status.trim().is_empty()
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
    ["completed_at", "started_at", "created_at"]
        .into_iter()
        .find_map(|field| payload.get(field)?.as_str().and_then(normalized_timestamp))
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
    /// Go-compatible emitted event kind.
    pub provider_kind: String,
    /// Go-compatible stable event identity.
    pub provider_id: String,
    /// Selected provider occurrence timestamp, when present.
    pub occurred_at: Option<String>,
    /// Portable scalar attributes used by source projection.
    pub fields: BTreeMap<String, String>,
    /// Provider payload with Go-compatible fallback enrichment applied.
    pub payload: Value,
}
