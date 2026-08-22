//! Go-compatible Linode occurrence-time normalization.

use time::{Date, OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

pub(super) fn occurred_at<const N: usize>(
    values: [String; N],
    observed_at: OffsetDateTime,
) -> String {
    values
        .iter()
        .find_map(|value| normalized_time(value))
        .unwrap_or_else(|| format_time(observed_at))
}

fn normalized_time(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(parsed) = OffsetDateTime::parse(value, &Rfc3339) {
        return Some(format_time(parsed));
    }
    let date_format = time::format_description::parse_borrowed::<2>("[year]-[month]-[day]").ok()?;
    Date::parse(value, &date_format)
        .ok()
        .map(|date| format_time(date.midnight().assume_utc()))
}

fn format_time(value: OffsetDateTime) -> String {
    value
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .expect("RFC3339 formats OffsetDateTime")
}
