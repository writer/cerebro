//! Deterministic event, discovery, and checkpoint materialization.

use std::{collections::BTreeMap, str::FromStr};

use serde_json::{Map, Value};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

use super::{
    GoogleWorkspaceError, GoogleWorkspaceFamily, GoogleWorkspacePage, GoogleWorkspaceRecord,
    SOURCE_ID,
    normalization::{first_nonempty, first_values, nested_scalar, scalar},
};

/// One Google Workspace event materialized at page observation time.
///
/// Event fields match the Go source after the stricter Discover identity gate
/// succeeds. This is a deliberate fail-closed tightening, not unconditional
/// Read parity for provider records that omit their canonical source identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoogleWorkspaceEvent {
    /// Stable source event identity.
    pub event_id: String,
    /// Tenant domain from source settings.
    pub tenant_id: String,
    /// Source identifier.
    pub source_id: String,
    /// Emitted provider kind.
    pub provider_kind: String,
    /// Public event schema reference.
    pub schema_ref: String,
    /// Go-selected occurrence time, normalized to UTC RFC 3339.
    pub occurred_at: String,
    /// Discovery URN produced from the Go Discover identity contract.
    pub discovery_urn: String,
    /// Source attributes derived from the provider object.
    pub attributes: BTreeMap<String, String>,
    /// Provider object with the Go source's context overlay.
    pub payload: Value,
}

impl GoogleWorkspacePage {
    /// Materialize event, checkpoint, and watermark semantics.
    ///
    /// `observed_at` supplies the clock value used by the Go source for groups,
    /// memberships, role assignments, and invalid or absent provider times.
    /// Records that have only a Go Read fallback identity fail closed because
    /// the same record would be rejected by the Go Discover URN path.
    pub fn materialize(
        &self,
        observed_at: &str,
    ) -> Result<GoogleWorkspaceEventPage, GoogleWorkspaceError> {
        let observed_at = parse_observed_at(observed_at)?;
        if self.records.is_empty() {
            return Ok(GoogleWorkspaceEventPage {
                events: Vec::new(),
                next_cursor: None,
                checkpoint_cursor: None,
                watermark: None,
            });
        }
        let events = self
            .records
            .iter()
            .map(|record| materialize_event(record, observed_at))
            .collect::<Result<Vec<_>, _>>()?;
        let checkpoint_cursor = self.next_cursor.clone().or_else(|| {
            events
                .last()
                .map(|event| event.event_id.trim().to_owned())
                .filter(|value| !value.is_empty())
        });
        let watermark = events.last().map(|event| event.occurred_at.clone());
        Ok(GoogleWorkspaceEventPage {
            events,
            next_cursor: self.next_cursor.clone(),
            checkpoint_cursor,
            watermark,
        })
    }
}

/// One materialized source page without durable checkpoint ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoogleWorkspaceEventPage {
    /// Go-compatible events in provider order.
    pub events: Vec<GoogleWorkspaceEvent>,
    /// Opaque provider cursor exposed for the next read.
    pub next_cursor: Option<String>,
    /// Proposed checkpoint cursor: provider cursor, then final event identity.
    pub checkpoint_cursor: Option<String>,
    /// Final event occurrence time used by the Go source as its watermark.
    pub watermark: Option<String>,
}

fn parse_observed_at(value: &str) -> Result<OffsetDateTime, GoogleWorkspaceError> {
    OffsetDateTime::parse(value.trim(), &Rfc3339)
        .map(|value| value.to_offset(UtcOffset::UTC))
        .map_err(|_| GoogleWorkspaceError::InvalidObservedAt)
}

fn provider_time(value: Option<String>) -> Option<OffsetDateTime> {
    let value = value?;
    let value = value.trim();
    if value.is_empty() || value == "1970-01-01T00:00:00.000Z" {
        return None;
    }
    OffsetDateTime::parse(value, &Rfc3339)
        .ok()
        .map(|value| value.to_offset(UtcOffset::UTC))
}

fn first_provider_time<const N: usize>(values: [Option<String>; N]) -> Option<OffsetDateTime> {
    values.into_iter().find_map(provider_time)
}

fn format_time(value: OffsetDateTime) -> Result<String, GoogleWorkspaceError> {
    value
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|_| GoogleWorkspaceError::InvalidObservedAt)
}

fn materialize_event(
    record: &GoogleWorkspaceRecord,
    observed_at: OffsetDateTime,
) -> Result<GoogleWorkspaceEvent, GoogleWorkspaceError> {
    let family = GoogleWorkspaceFamily::from_str(&record.family)?;
    let object = record
        .payload
        .as_object()
        .ok_or(GoogleWorkspaceError::InvalidRecord)?;
    let occurred_at = match family {
        GoogleWorkspaceFamily::User => first_provider_time([
            scalar(object.get("lastLoginTime")),
            scalar(object.get("creationTime")),
        ])
        .unwrap_or(observed_at),
        GoogleWorkspaceFamily::Audit => {
            provider_time(nested_scalar(object, &["id", "time"])).unwrap_or(observed_at)
        }
        GoogleWorkspaceFamily::Group
        | GoogleWorkspaceFamily::GroupMember
        | GoogleWorkspaceFamily::RoleAssignment => observed_at,
    };
    let event_id = go_event_id(family, object, &record.fields, occurred_at)?;
    let discovery_id = first_nonempty([
        record.fields.get("user_id").cloned(),
        record.fields.get("group_id").cloned(),
        record.fields.get("role_assignment_id").cloned(),
        record.fields.get("event_type").cloned(),
    ])
    .ok_or(GoogleWorkspaceError::MissingDiscoveryIdentity)?;
    let domain = record
        .fields
        .get("domain")
        .cloned()
        .filter(|value| !value.trim().is_empty())
        .ok_or(GoogleWorkspaceError::MissingDomain)?;
    let mut payload = record.payload.clone();
    let payload_object = payload
        .as_object_mut()
        .ok_or(GoogleWorkspaceError::InvalidRecord)?;
    payload_object.insert("domain".to_owned(), Value::String(domain.clone()));
    if family == GoogleWorkspaceFamily::GroupMember {
        let group_key = record
            .fields
            .get("group_id")
            .cloned()
            .filter(|value| !value.trim().is_empty())
            .ok_or(GoogleWorkspaceError::MissingGroupKey)?;
        payload_object.insert("group_key".to_owned(), Value::String(group_key));
    }
    Ok(GoogleWorkspaceEvent {
        event_id,
        tenant_id: domain.clone(),
        source_id: SOURCE_ID.to_owned(),
        provider_kind: family.provider_kind().to_owned(),
        schema_ref: family.schema_ref().to_owned(),
        occurred_at: format_time(occurred_at)?,
        discovery_urn: format!(
            "urn:cerebro:{domain}:google_workspace_{}:{discovery_id}",
            family.as_str()
        ),
        attributes: record.fields.clone(),
        payload,
    })
}

fn go_event_id(
    family: GoogleWorkspaceFamily,
    object: &Map<String, Value>,
    fields: &BTreeMap<String, String>,
    occurred_at: OffsetDateTime,
) -> Result<String, GoogleWorkspaceError> {
    let (prefix, identity) = match family {
        GoogleWorkspaceFamily::User => (
            "google-workspace-user-",
            first_values(object, &["id", "primaryEmail"]),
        ),
        GoogleWorkspaceFamily::Group => (
            "google-workspace-group-",
            first_values(object, &["id", "email"]),
        ),
        GoogleWorkspaceFamily::GroupMember => {
            let group_key = fields.get("group_id").cloned();
            let member_id = first_values(object, &["id", "email"]);
            (
                "google-workspace-group-member-",
                group_key
                    .zip(member_id)
                    .map(|(group, member)| format!("{group}-{member}")),
            )
        }
        GoogleWorkspaceFamily::RoleAssignment => (
            "google-workspace-role-assignment-",
            scalar(object.get("roleAssignmentId")),
        ),
        GoogleWorkspaceFamily::Audit => (
            "google-workspace-audit-",
            first_nonempty([
                nested_scalar(object, &["id", "uniqueQualifier"]),
                fields.get("event_type").cloned(),
                Some((occurred_at.unix_timestamp_nanos() / 1_000_000).to_string()),
            ]),
        ),
    };
    identity
        .filter(|value| !value.trim().is_empty())
        .map(|identity| format!("{prefix}{identity}"))
        .ok_or(GoogleWorkspaceError::MissingRecordIdentity)
}
