//! Shared Go-compatible GCP IAM normalization helpers.

use std::collections::BTreeMap;

use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

use super::GcpIamError;

pub(super) fn insert_gcp_field(fields: &mut BTreeMap<String, String>, name: &str, value: String) {
    let value = value.trim();
    if !value.is_empty() {
        fields.insert(name.to_owned(), value.to_owned());
    }
}

pub(super) fn first_gcp_value<const N: usize>(values: [String; N]) -> String {
    values
        .into_iter()
        .find(|value| !value.trim().is_empty())
        .unwrap_or_default()
}

pub(super) fn first_nonblank_gcp<const N: usize>(values: [&str; N]) -> Result<String, GcpIamError> {
    values
        .into_iter()
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(GcpIamError::MissingProviderIdentity)
}

pub(super) fn sanitize_gcp_event_id(value: &str) -> String {
    value
        .replace([' ', '/', ':'], "-")
        .trim_matches('-')
        .to_owned()
}

pub(super) fn nonblank_gcp(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

pub(super) fn normalized_gcp_time(value: &str) -> Option<String> {
    let parsed = OffsetDateTime::parse(value.trim(), &Rfc3339).ok()?;
    parsed.to_offset(UtcOffset::UTC).format(&Rfc3339).ok()
}

pub(super) fn normalized_observed_at(value: OffsetDateTime) -> String {
    value
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .expect("RFC3339 formats OffsetDateTime")
}

pub(super) fn required_gcp_value(value: &str, error: GcpIamError) -> Result<String, GcpIamError> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned()).ok_or(error)
}
