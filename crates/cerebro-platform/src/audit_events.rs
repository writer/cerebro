//! Native REST parity for portable audit-event reads.
//!
//! Mirrors the Go `internal/auditevents` contract: bounded query parameters,
//! deterministic descending keyset cursors, record normalization, and the
//! fixed public response allowlist. Cursors are client-controlled encoded
//! resume state, not integrity or authentication tokens: their unkeyed
//! checksum only detects accidental corruption, and every page independently
//! reauthorizes the tenant. Text bounds use Unicode code-point counts.

use std::{error::Error, fmt};

use cerebro_organizational_store::{AuditEventPageQuery, StoredAuditEvent, StoredAuditEventPage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

pub(crate) const MAX_IDENTIFIER_CHARACTERS: usize = 200;
pub(crate) const MAX_SUMMARY_CHARACTERS: usize = 500;
pub(crate) const MAX_QUERY_CHARACTERS: usize = 200;
pub(crate) const MAX_CURSOR_CHARACTERS: usize = 2048;
pub(crate) const DEFAULT_LIMIT: u32 = 100;
pub(crate) const MAX_LIMIT: u32 = 500;
pub(crate) const DEFAULT_MINUTES: i64 = 60;
pub(crate) const MIN_MINUTES: i64 = 5;
pub(crate) const MAX_MINUTES: i64 = 24 * 60;

const CURSOR_VERSION: i64 = 1;
const CURSOR_MAX_AGE_MINUTES: i64 = 15;
const ZERO_TIME: &str = "0001-01-01T00:00:00Z";

const OUTCOME_SUCCESS: &str = "success";
const OUTCOME_FAILURE: &str = "failure";
const OUTCOME_DENIED: &str = "denied";
const OUTCOME_UNKNOWN: &str = "unknown";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuditEventsFailureKind {
    InvalidRequest,
    Unavailable,
}

#[derive(Debug)]
pub(crate) struct AuditEventsFailure {
    kind: AuditEventsFailureKind,
    detail: String,
}

impl AuditEventsFailure {
    fn new(kind: AuditEventsFailureKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    pub(crate) fn kind(&self) -> AuditEventsFailureKind {
        self.kind
    }
}

impl fmt::Display for AuditEventsFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl Error for AuditEventsFailure {}

fn invalid(detail: impl Into<String>) -> AuditEventsFailure {
    AuditEventsFailure::new(AuditEventsFailureKind::InvalidRequest, detail)
}

fn unavailable(detail: impl Into<String>) -> AuditEventsFailure {
    AuditEventsFailure::new(AuditEventsFailureKind::Unavailable, detail)
}

/// Raw public query parameters. Numeric fields stay text so out-of-range and
/// malformed values fail the same strict bounds as the Go handler instead of
/// the framework's deserializer.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct AuditEventsRequestParams {
    #[serde(default)]
    pub(crate) tenant_id: Option<String>,
    #[serde(default)]
    pub(crate) limit: Option<String>,
    #[serde(default)]
    pub(crate) minutes: Option<String>,
    #[serde(default)]
    pub(crate) action: Option<String>,
    #[serde(default)]
    pub(crate) actor: Option<String>,
    #[serde(default)]
    pub(crate) q: Option<String>,
    #[serde(default)]
    pub(crate) resource_type: Option<String>,
    #[serde(default)]
    pub(crate) service: Option<String>,
    #[serde(default)]
    pub(crate) trace_id: Option<String>,
    #[serde(default)]
    pub(crate) outcome: Option<String>,
    #[serde(default)]
    pub(crate) cursor: Option<String>,
}

/// Normalized reader query. `before`/`after` define one immutable time window;
/// `page_before_occurred_at` and `page_before_id` form the stable descending
/// keyset boundary.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AuditEventQuery {
    tenant_id: String,
    action: String,
    actor: String,
    after: OffsetDateTime,
    before: OffsetDateTime,
    limit: u32,
    outcome: String,
    page_before_occurred_at: Option<OffsetDateTime>,
    page_before_id: String,
    query: String,
    resource_type: String,
    service: String,
    trace_id: String,
}

#[derive(Clone, Debug, PartialEq)]
struct NormalizedActor {
    id: String,
    kind: String,
    label: String,
}

#[derive(Clone, Debug, PartialEq)]
struct NormalizedResource {
    id: String,
    resource_type: String,
    label: String,
}

#[derive(Clone, Debug, PartialEq)]
struct NormalizedAuditEvent {
    id: String,
    tenant_id: String,
    action: String,
    actor: Option<NormalizedActor>,
    category: String,
    duration_ms: Option<i64>,
    occurred_at: OffsetDateTime,
    outcome: String,
    request_id: String,
    resource: Option<NormalizedResource>,
    service: String,
    summary: String,
    trace_id: String,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct HttpAuditActor {
    id: String,
    kind: String,
    label: String,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct HttpAuditResource {
    id: String,
    #[serde(rename = "type")]
    resource_type: String,
    label: String,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct HttpAuditEvent {
    id: String,
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor: Option<HttpAuditActor>,
    category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<i64>,
    occurred_at: String,
    outcome: String,
    request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<HttpAuditResource>,
    service: String,
    summary: String,
    trace_id: String,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct HttpWindow {
    start_time: String,
    end_time: String,
}

/// The fixed public response allowlist. Tenant identifiers and projection
/// metadata are never copied into it.
#[derive(Debug, Eq, PartialEq, Serialize)]
pub(crate) struct AuditEventsHttpPage {
    events: Vec<HttpAuditEvent>,
    next_cursor: String,
    status: &'static str,
    window: HttpWindow,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CursorV1 {
    v: i64,
    a: String,
    b: String,
    t: String,
    i: String,
    c: String,
}

/// Convert bounded public query parameters into the stable reader query.
/// Cursor content is client-controlled resume state, so the authorized tenant
/// is always supplied independently by the transport layer.
pub(crate) fn parse_request(
    params: &AuditEventsRequestParams,
    tenant_id: &str,
    now: OffsetDateTime,
) -> Result<AuditEventQuery, AuditEventsFailure> {
    let limit = strict_u32(
        params.limit.as_deref(),
        DEFAULT_LIMIT,
        1,
        MAX_LIMIT,
        "limit",
    )?;
    let minutes = strict_i64(
        params.minutes.as_deref(),
        DEFAULT_MINUTES,
        MIN_MINUTES,
        MAX_MINUTES,
        "minutes",
    )?;
    // Postgres stores microseconds; truncating the window keeps every
    // comparison the response validator makes consistent with what the store
    // can actually apply.
    let now = truncate_to_microseconds(now.to_offset(UtcOffset::UTC));
    let mut query = AuditEventQuery {
        tenant_id: tenant_id.trim().to_owned(),
        action: filter_text("action", params.action.as_deref())?,
        actor: filter_text("actor", params.actor.as_deref())?,
        after: now - Duration::minutes(minutes),
        before: now,
        limit,
        outcome: params
            .outcome
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_lowercase(),
        page_before_occurred_at: None,
        page_before_id: String::new(),
        query: filter_text("q", params.q.as_deref())?,
        resource_type: filter_text("resource_type", params.resource_type.as_deref())?,
        service: filter_text("service", params.service.as_deref())?,
        trace_id: filter_text("trace_id", params.trace_id.as_deref())?,
    };
    if !query.outcome.is_empty() && !valid_outcome(&query.outcome) {
        return Err(invalid("invalid outcome"));
    }
    let cursor_value = optional_text(
        "cursor",
        params.cursor.as_deref().unwrap_or(""),
        MAX_CURSOR_CHARACTERS,
    )?;
    if !cursor_value.is_empty() {
        let cursor = decode_cursor(&cursor_value)?;
        query.after =
            parse_cursor_time(&cursor.a).ok_or_else(|| invalid("invalid cursor window"))?;
        query.before =
            parse_cursor_time(&cursor.b).ok_or_else(|| invalid("invalid cursor window"))?;
        let boundary =
            parse_cursor_time(&cursor.t).ok_or_else(|| invalid("invalid cursor boundary"))?;
        query.page_before_occurred_at = Some(boundary);
        query.page_before_id = cursor.i.trim().to_owned();
        if query.before - query.after != Duration::minutes(minutes)
            || query.before > now + Duration::minutes(1)
            || query.before < now - Duration::minutes(CURSOR_MAX_AGE_MINUTES)
        {
            return Err(invalid("cursor window is expired or invalid"));
        }
        if cursor.c != cursor_checksum(&query, minutes)? {
            return Err(invalid("cursor checksum does not match resume state"));
        }
    }
    validate_query(&query)?;
    Ok(query)
}

/// Enforce the tenant, time-window, keyset, and limit invariants expected by
/// every reader implementation.
pub(crate) fn validate_query(query: &AuditEventQuery) -> Result<(), AuditEventsFailure> {
    if query.tenant_id.trim().is_empty() {
        return Err(invalid("tenant_id is required"));
    }
    required_identifier_text("tenant_id", &query.tenant_id)?;
    if query.after >= query.before {
        return Err(invalid("valid after and before times are required"));
    }
    if query.before - query.after > Duration::minutes(MAX_MINUTES) {
        return Err(invalid(format!(
            "time window must not exceed {MAX_MINUTES} minutes"
        )));
    }
    if query.limit == 0 || query.limit > MAX_LIMIT {
        return Err(invalid(format!("limit must be between 1 and {MAX_LIMIT}")));
    }
    if query.page_before_occurred_at.is_some() && query.page_before_id.trim().is_empty() {
        return Err(invalid("page boundary id is required"));
    }
    if query.page_before_occurred_at.is_none() && !query.page_before_id.trim().is_empty() {
        return Err(invalid("page boundary time is required"));
    }
    optional_text(
        "page boundary id",
        &query.page_before_id,
        MAX_IDENTIFIER_CHARACTERS,
    )?;
    if let Some(boundary) = query.page_before_occurred_at
        && (boundary < query.after || boundary > query.before)
    {
        return Err(invalid("page boundary is outside the query window"));
    }
    if !query.outcome.is_empty() && !valid_outcome(&query.outcome) {
        return Err(invalid("invalid outcome filter"));
    }
    for (field, value) in [
        ("action", &query.action),
        ("actor", &query.actor),
        ("q", &query.query),
        ("resource_type", &query.resource_type),
        ("service", &query.service),
        ("trace_id", &query.trace_id),
    ] {
        optional_text(field, value, MAX_QUERY_CHARACTERS)?;
    }
    Ok(())
}

/// Map a validated query onto the bounded store read scope.
pub(crate) fn store_query(
    query: &AuditEventQuery,
) -> Result<AuditEventPageQuery, AuditEventsFailure> {
    Ok(AuditEventPageQuery {
        tenant_id: query.tenant_id.clone(),
        after: format_rfc3339(query.after)?,
        before: format_rfc3339(query.before)?,
        limit: query.limit,
        action: query.action.clone(),
        actor: query.actor.clone(),
        outcome: query.outcome.clone(),
        resource_type: query.resource_type.clone(),
        service: query.service.clone(),
        trace_id: query.trace_id.clone(),
        text: query.query.clone(),
        page_before_occurred_at: query
            .page_before_occurred_at
            .map(format_rfc3339)
            .transpose()?,
        page_before_id: query.page_before_id.clone(),
    })
}

/// Validate a reader result and convert it into the fixed public response
/// allowlist. Every failure is a reader-integrity failure, never client error.
pub(crate) fn build_page(
    query: &AuditEventQuery,
    page: &StoredAuditEventPage,
) -> Result<AuditEventsHttpPage, AuditEventsFailure> {
    validate_query(query).map_err(|error| unavailable(error.to_string()))?;
    if page.events.len() > query.limit as usize {
        return Err(unavailable("reader returned an oversized audit-event page"));
    }
    let mut events = Vec::with_capacity(page.events.len());
    let mut previous: Option<NormalizedAuditEvent> = None;
    for event in &page.events {
        let normalized = normalize_event(event)
            .map_err(|_| unavailable("reader returned an invalid tenant-scoped audit event"))?;
        if normalized.tenant_id != query.tenant_id
            || normalized.occurred_at < query.after
            || normalized.occurred_at > query.before
        {
            return Err(unavailable(
                "reader returned an invalid tenant-scoped audit event",
            ));
        }
        if let Some(boundary) = query.page_before_occurred_at
            && !strictly_older_than_boundary(&normalized, boundary, &query.page_before_id)
        {
            return Err(unavailable(
                "reader returned an audit event that does not advance the page boundary",
            ));
        }
        if let Some(previous) = &previous
            && (previous.occurred_at < normalized.occurred_at
                || (previous.occurred_at == normalized.occurred_at && previous.id <= normalized.id))
        {
            return Err(unavailable(
                "reader returned audit events outside deterministic order",
            ));
        }
        events.push(http_event(&normalized)?);
        previous = Some(normalized);
    }
    let next_cursor = if page.has_more {
        let Some(previous) = &previous else {
            return Err(unavailable(
                "reader returned an empty nonterminal audit-event page",
            ));
        };
        encode_cursor(query, previous)?
    } else {
        String::new()
    };
    Ok(AuditEventsHttpPage {
        events,
        next_cursor,
        status: if page.partial { "partial" } else { "complete" },
        window: HttpWindow {
            start_time: format_rfc3339(query.after)?,
            end_time: format_rfc3339(query.before)?,
        },
    })
}

/// Validate and copy one stored event into the normalized allowlist.
fn normalize_event(event: &StoredAuditEvent) -> Result<NormalizedAuditEvent, AuditEventsFailure> {
    let id = required_identifier_text("id", &event.id)?;
    let tenant_id = required_identifier_text("tenant_id", &event.tenant_id)?;
    let action = required_identifier_text("action", &event.action)?;
    let category = optional_text("category", &event.category, MAX_IDENTIFIER_CHARACTERS)?;
    let request_id = optional_text("request_id", &event.request_id, MAX_IDENTIFIER_CHARACTERS)?;
    let service = optional_text("service", &event.service, MAX_IDENTIFIER_CHARACTERS)?;
    let summary = optional_text("summary", &event.summary, MAX_SUMMARY_CHARACTERS)?;
    let trace_id = optional_text("trace_id", &event.trace_id, MAX_IDENTIFIER_CHARACTERS)?;
    let outcome = event.outcome.trim().to_lowercase();
    if !valid_outcome(&outcome) {
        return Err(invalid(
            "outcome must be success, failure, denied, or unknown",
        ));
    }
    let occurred_at_raw = event.occurred_at.trim();
    if occurred_at_raw.is_empty() {
        return Err(invalid("occurred_at is required"));
    }
    let occurred_at = OffsetDateTime::parse(occurred_at_raw, &Rfc3339)
        .map_err(|_| invalid("occurred_at must be a valid RFC 3339 timestamp"))?
        .to_offset(UtcOffset::UTC);
    if let Some(duration) = event.duration_ms
        && duration < 0
    {
        return Err(invalid("duration_ms must be non-negative"));
    }
    let actor = normalize_party(
        "actor",
        &event.actor_id,
        &event.actor_kind,
        &event.actor_label,
    )?
    .map(|(id, kind, label)| NormalizedActor { id, kind, label });
    let resource = normalize_party(
        "resource",
        &event.resource_id,
        &event.resource_type,
        &event.resource_label,
    )?
    .map(|(id, resource_type, label)| NormalizedResource {
        id,
        resource_type,
        label,
    });
    Ok(NormalizedAuditEvent {
        id,
        tenant_id,
        action,
        actor,
        category,
        duration_ms: event.duration_ms,
        occurred_at,
        outcome,
        request_id,
        resource,
        service,
        summary,
        trace_id,
    })
}

#[allow(clippy::type_complexity)]
fn normalize_party(
    prefix: &str,
    id: &str,
    kind: &str,
    label: &str,
) -> Result<Option<(String, String, String)>, AuditEventsFailure> {
    let id = optional_text(&format!("{prefix}.id"), id, MAX_IDENTIFIER_CHARACTERS)?;
    let kind = optional_text(&format!("{prefix}.kind"), kind, MAX_IDENTIFIER_CHARACTERS)?;
    let label = optional_text(&format!("{prefix}.label"), label, MAX_IDENTIFIER_CHARACTERS)?;
    if id.is_empty() && kind.is_empty() && label.is_empty() {
        return Ok(None);
    }
    Ok(Some((id, kind, label)))
}

fn http_event(event: &NormalizedAuditEvent) -> Result<HttpAuditEvent, AuditEventsFailure> {
    Ok(HttpAuditEvent {
        id: event.id.clone(),
        action: event.action.clone(),
        actor: event.actor.as_ref().map(|actor| HttpAuditActor {
            id: actor.id.clone(),
            kind: actor.kind.clone(),
            label: actor.label.clone(),
        }),
        category: event.category.clone(),
        duration_ms: event.duration_ms,
        occurred_at: format_rfc3339(event.occurred_at)?,
        outcome: event.outcome.clone(),
        request_id: event.request_id.clone(),
        resource: event.resource.as_ref().map(|resource| HttpAuditResource {
            id: resource.id.clone(),
            resource_type: resource.resource_type.clone(),
            label: resource.label.clone(),
        }),
        service: event.service.clone(),
        summary: event.summary.clone(),
        trace_id: event.trace_id.clone(),
    })
}

fn strictly_older_than_boundary(
    event: &NormalizedAuditEvent,
    occurred_at: OffsetDateTime,
    event_id: &str,
) -> bool {
    if event.occurred_at < occurred_at {
        return true;
    }
    event.occurred_at == occurred_at && event.id.as_str() < event_id.trim()
}

fn encode_cursor(
    query: &AuditEventQuery,
    last: &NormalizedAuditEvent,
) -> Result<String, AuditEventsFailure> {
    if last.id.trim().is_empty() {
        return Err(unavailable("invalid audit-event page boundary"));
    }
    let minutes = (query.before - query.after).whole_minutes();
    let mut resume = query.clone();
    resume.page_before_occurred_at = Some(last.occurred_at);
    resume.page_before_id = last.id.trim().to_owned();
    let cursor = CursorV1 {
        v: CURSOR_VERSION,
        a: format_rfc3339(query.after)?,
        b: format_rfc3339(query.before)?,
        t: format_rfc3339(last.occurred_at)?,
        i: last.id.trim().to_owned(),
        c: cursor_checksum(&resume, minutes)?,
    };
    let payload = serde_json::to_vec(&cursor)
        .map_err(|error| unavailable(format!("encode audit event cursor: {error}")))?;
    let encoded = base64url_encode(&payload);
    if encoded.chars().count() > MAX_CURSOR_CHARACTERS {
        return Err(unavailable("encoded audit-event cursor is too long"));
    }
    Ok(encoded)
}

fn decode_cursor(value: &str) -> Result<CursorV1, AuditEventsFailure> {
    let payload = base64url_decode(value).ok_or_else(|| invalid("invalid cursor"))?;
    let cursor: CursorV1 =
        serde_json::from_slice(&payload).map_err(|_| invalid("invalid cursor"))?;
    if cursor.v != CURSOR_VERSION || cursor.c.len() != Sha256::output_size() * 2 {
        return Err(invalid("unsupported cursor"));
    }
    Ok(cursor)
}

/// Unkeyed checksum over the complete resume state, including the keyset
/// boundary. It detects accidental corruption only; clients can recompute it
/// and it must never be treated as authentication.
fn cursor_checksum(query: &AuditEventQuery, minutes: i64) -> Result<String, AuditEventsFailure> {
    let boundary_time = match query.page_before_occurred_at {
        Some(value) => format_rfc3339(value)?,
        None => ZERO_TIME.to_owned(),
    };
    let values = [
        query.tenant_id.trim().to_owned(),
        query.action.trim().to_lowercase(),
        query.actor.trim().to_lowercase(),
        query.outcome.trim().to_lowercase(),
        query.query.trim().to_owned(),
        query.resource_type.trim().to_lowercase(),
        query.service.trim().to_lowercase(),
        query.trace_id.trim().to_lowercase(),
        format_rfc3339(query.after)?,
        format_rfc3339(query.before)?,
        boundary_time,
        query.page_before_id.trim().to_owned(),
        minutes.to_string(),
        query.limit.to_string(),
    ];
    let mut hash = Sha256::new();
    for value in &values {
        hash.update(value.len().to_string().as_bytes());
        hash.update(b":");
        hash.update(value.as_bytes());
    }
    Ok(hex_encode(&hash.finalize()))
}

fn valid_outcome(value: &str) -> bool {
    matches!(
        value.trim().to_lowercase().as_str(),
        OUTCOME_SUCCESS | OUTCOME_FAILURE | OUTCOME_DENIED | OUTCOME_UNKNOWN
    )
}

fn strict_u32(
    raw: Option<&str>,
    fallback: u32,
    minimum: u32,
    maximum: u32,
    field: &str,
) -> Result<u32, AuditEventsFailure> {
    let raw = raw.unwrap_or("").trim();
    if raw.is_empty() {
        return Ok(fallback);
    }
    let out_of_bounds = || invalid(format!("{field} must be between {minimum} and {maximum}"));
    if !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(out_of_bounds());
    }
    let value = raw.parse::<u32>().map_err(|_| out_of_bounds())?;
    if value < minimum || value > maximum {
        return Err(out_of_bounds());
    }
    Ok(value)
}

fn strict_i64(
    raw: Option<&str>,
    fallback: i64,
    minimum: i64,
    maximum: i64,
    field: &str,
) -> Result<i64, AuditEventsFailure> {
    let raw = raw.unwrap_or("").trim();
    if raw.is_empty() {
        return Ok(fallback);
    }
    let out_of_bounds = || invalid(format!("{field} must be between {minimum} and {maximum}"));
    let value = raw.parse::<i64>().map_err(|_| out_of_bounds())?;
    if value < minimum || value > maximum {
        return Err(out_of_bounds());
    }
    Ok(value)
}

fn filter_text(field: &str, raw: Option<&str>) -> Result<String, AuditEventsFailure> {
    optional_text(field, raw.unwrap_or(""), MAX_QUERY_CHARACTERS)
}

fn required_identifier_text(field: &str, value: &str) -> Result<String, AuditEventsFailure> {
    let value = optional_text(field, value, MAX_IDENTIFIER_CHARACTERS)?;
    if value.is_empty() {
        return Err(invalid(format!("{field} is required")));
    }
    Ok(value)
}

fn optional_text(
    field: &str,
    value: &str,
    max_characters: usize,
) -> Result<String, AuditEventsFailure> {
    let value = value.trim();
    if value.chars().count() > max_characters {
        return Err(invalid(format!(
            "{field} must be at most {max_characters} characters"
        )));
    }
    Ok(value.to_owned())
}

fn parse_cursor_time(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339)
        .ok()
        .map(|parsed| parsed.to_offset(UtcOffset::UTC))
}

fn format_rfc3339(value: OffsetDateTime) -> Result<String, AuditEventsFailure> {
    value
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|error| unavailable(format!("format audit-event time: {error}")))
}

fn truncate_to_microseconds(value: OffsetDateTime) -> OffsetDateTime {
    value
        .replace_nanosecond(value.nanosecond() / 1_000 * 1_000)
        .unwrap_or(value)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

const BASE64_URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded URL-safe base64, matching Go's `base64.RawURLEncoding`.
fn base64url_encode(payload: &[u8]) -> String {
    let mut encoded = String::with_capacity(payload.len().div_ceil(3) * 4);
    for chunk in payload.chunks(3) {
        let group = (u32::from(chunk[0]) << 16)
            | (u32::from(chunk.get(1).copied().unwrap_or(0)) << 8)
            | u32::from(chunk.get(2).copied().unwrap_or(0));
        encoded.push(BASE64_URL_ALPHABET[(group >> 18) as usize & 63] as char);
        encoded.push(BASE64_URL_ALPHABET[(group >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            encoded.push(BASE64_URL_ALPHABET[(group >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            encoded.push(BASE64_URL_ALPHABET[group as usize & 63] as char);
        }
    }
    encoded
}

fn base64url_decode(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut decoded = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in bytes {
        let symbol = decode_base64url_symbol(byte)?;
        buffer = (buffer << 6) | u32::from(symbol);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            decoded.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    Some(decoded)
}

fn decode_base64url_symbol(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(value: &str) -> OffsetDateTime {
        OffsetDateTime::parse(value, &Rfc3339)
            .unwrap()
            .to_offset(UtcOffset::UTC)
    }

    fn now() -> OffsetDateTime {
        ts("2026-08-26T12:00:00Z")
    }

    fn params() -> AuditEventsRequestParams {
        AuditEventsRequestParams::default()
    }

    fn stored(id: &str, occurred_at: &str) -> StoredAuditEvent {
        StoredAuditEvent {
            id: id.to_owned(),
            tenant_id: "tenant-a".to_owned(),
            action: "user.login".to_owned(),
            outcome: "success".to_owned(),
            occurred_at: occurred_at.to_owned(),
            ..StoredAuditEvent::default()
        }
    }

    fn parse(params: &AuditEventsRequestParams) -> Result<AuditEventQuery, AuditEventsFailure> {
        parse_request(params, "tenant-a", now())
    }

    #[test]
    fn defaults_mirror_the_go_contract() {
        let query = parse(&params()).unwrap();
        assert_eq!(query.limit, DEFAULT_LIMIT);
        assert_eq!(query.before, now());
        assert_eq!(query.after, now() - Duration::minutes(DEFAULT_MINUTES));
        assert_eq!(query.tenant_id, "tenant-a");
        assert!(query.page_before_occurred_at.is_none());
        assert!(query.outcome.is_empty());
    }

    #[test]
    fn limit_and_minutes_enforce_strict_bounds() {
        for (limit, minutes, ok) in [
            (Some("500"), Some("1440"), true),
            (Some("1"), Some("5"), true),
            (Some("0"), None, false),
            (Some("501"), None, false),
            (Some("-1"), None, false),
            (Some("+5"), None, false),
            (Some("abc"), None, false),
            (Some("10.5"), None, false),
            (None, Some("4"), false),
            (None, Some("1441"), false),
            (None, Some("-60"), false),
            (None, Some("abc"), false),
        ] {
            let request = AuditEventsRequestParams {
                limit: limit.map(str::to_owned),
                minutes: minutes.map(str::to_owned),
                ..params()
            };
            let result = parse(&request);
            assert_eq!(result.is_ok(), ok, "limit={limit:?} minutes={minutes:?}");
            if !ok {
                let failure = result.unwrap_err();
                assert_eq!(failure.kind(), AuditEventsFailureKind::InvalidRequest);
            }
        }
    }

    #[test]
    fn whitespace_numeric_parameters_fall_back_to_defaults() {
        let request = AuditEventsRequestParams {
            limit: Some("  ".to_owned()),
            minutes: Some(String::new()),
            ..params()
        };
        let query = parse(&request).unwrap();
        assert_eq!(query.limit, DEFAULT_LIMIT);
        assert_eq!(
            query.before - query.after,
            Duration::minutes(DEFAULT_MINUTES)
        );
    }

    #[test]
    fn filters_are_trimmed_and_bounded_by_code_points() {
        let request = AuditEventsRequestParams {
            action: Some("  user.login  ".to_owned()),
            q: Some("é".repeat(MAX_QUERY_CHARACTERS)),
            ..params()
        };
        let query = parse(&request).unwrap();
        assert_eq!(query.action, "user.login");
        assert_eq!(query.query.chars().count(), MAX_QUERY_CHARACTERS);

        let request = AuditEventsRequestParams {
            q: Some("é".repeat(MAX_QUERY_CHARACTERS + 1)),
            ..params()
        };
        let failure = parse(&request).unwrap_err();
        assert_eq!(failure.kind(), AuditEventsFailureKind::InvalidRequest);
        assert!(failure.to_string().contains("q must be at most"));
    }

    #[test]
    fn outcome_filter_is_lowered_and_validated() {
        let request = AuditEventsRequestParams {
            outcome: Some("  DENIED ".to_owned()),
            ..params()
        };
        assert_eq!(parse(&request).unwrap().outcome, "denied");

        let request = AuditEventsRequestParams {
            outcome: Some("bogus".to_owned()),
            ..params()
        };
        assert_eq!(parse(&request).unwrap_err().to_string(), "invalid outcome");
    }

    #[test]
    fn now_is_truncated_to_microseconds() {
        let precise = now().replace_nanosecond(123_456_789).unwrap();
        let query = parse_request(&params(), "tenant-a", precise).unwrap();
        assert_eq!(query.before.nanosecond(), 123_456_000);
        assert_eq!(
            query.before - query.after,
            Duration::minutes(DEFAULT_MINUTES)
        );
    }

    #[test]
    fn cursor_round_trip_resumes_the_same_window_and_boundary() {
        let first = parse(&params()).unwrap();
        let page = StoredAuditEventPage {
            events: vec![
                stored("event-b", "2026-08-26T11:59:00.000001Z"),
                stored("event-a", "2026-08-26T11:58:00Z"),
            ],
            has_more: true,
            partial: false,
        };
        let response = build_page(&first, &page).unwrap();
        assert!(!response.next_cursor.is_empty());
        assert_eq!(response.status, "complete");

        let request = AuditEventsRequestParams {
            cursor: Some(response.next_cursor.clone()),
            ..params()
        };
        let resumed = parse(&request).unwrap();
        assert_eq!(resumed.after, first.after);
        assert_eq!(resumed.before, first.before);
        assert_eq!(
            resumed.page_before_occurred_at,
            Some(ts("2026-08-26T11:58:00Z"))
        );
        assert_eq!(resumed.page_before_id, "event-a");
    }

    #[test]
    fn cursor_requires_matching_minutes_and_filters() {
        let first = parse(&params()).unwrap();
        let page = StoredAuditEventPage {
            events: vec![stored("event-a", "2026-08-26T11:58:00Z")],
            has_more: true,
            partial: false,
        };
        let cursor = build_page(&first, &page).unwrap().next_cursor;

        let request = AuditEventsRequestParams {
            cursor: Some(cursor.clone()),
            minutes: Some("120".to_owned()),
            ..params()
        };
        assert_eq!(
            parse(&request).unwrap_err().to_string(),
            "cursor window is expired or invalid"
        );

        let request = AuditEventsRequestParams {
            cursor: Some(cursor.clone()),
            action: Some("other.action".to_owned()),
            ..params()
        };
        assert_eq!(
            parse(&request).unwrap_err().to_string(),
            "cursor checksum does not match resume state"
        );

        let request = AuditEventsRequestParams {
            cursor: Some(cursor),
            limit: Some("50".to_owned()),
            ..params()
        };
        assert_eq!(
            parse(&request).unwrap_err().to_string(),
            "cursor checksum does not match resume state"
        );
    }

    #[test]
    fn cursor_expires_after_the_bounded_age() {
        let first = parse(&params()).unwrap();
        let page = StoredAuditEventPage {
            events: vec![stored("event-a", "2026-08-26T11:58:00Z")],
            has_more: true,
            partial: false,
        };
        let cursor = build_page(&first, &page).unwrap().next_cursor;
        let request = AuditEventsRequestParams {
            cursor: Some(cursor),
            ..params()
        };
        let later = now() + Duration::minutes(CURSOR_MAX_AGE_MINUTES + 1);
        assert_eq!(
            parse_request(&request, "tenant-a", later)
                .unwrap_err()
                .to_string(),
            "cursor window is expired or invalid"
        );
        let earlier = now() - Duration::minutes(2);
        assert_eq!(
            parse_request(&request, "tenant-a", earlier)
                .unwrap_err()
                .to_string(),
            "cursor window is expired or invalid"
        );
    }

    #[test]
    fn malformed_cursors_are_rejected() {
        for (cursor, detail) in [
            ("not base64!", "invalid cursor"),
            ("AA=", "invalid cursor"),
            (&base64url_encode(b"not json"), "invalid cursor"),
            (
                &base64url_encode(br#"{"v":1,"a":"x","b":"x","t":"x","i":"x","c":"x","z":1}"#),
                "invalid cursor",
            ),
            (
                &base64url_encode(br#"{"v":2,"a":"x","b":"x","t":"x","i":"x","c":"x"}"#),
                "unsupported cursor",
            ),
            (
                &base64url_encode(br#"{"v":1,"a":"x","b":"x","t":"x","i":"x","c":"short"}"#),
                "unsupported cursor",
            ),
        ] {
            let request = AuditEventsRequestParams {
                cursor: Some(cursor.to_owned()),
                ..params()
            };
            let failure = parse(&request).unwrap_err();
            assert_eq!(failure.kind(), AuditEventsFailureKind::InvalidRequest);
            assert_eq!(failure.to_string(), detail, "cursor={cursor}");
        }
    }

    #[test]
    fn cursor_with_unparseable_times_is_rejected() {
        let checksum = "0".repeat(64);
        let window = base64url_encode(
            format!(
                r#"{{"v":1,"a":"nope","b":"2026-08-26T12:00:00Z","t":"2026-08-26T11:00:00Z","i":"e","c":"{checksum}"}}"#
            )
            .as_bytes(),
        );
        let boundary = base64url_encode(
            format!(
                r#"{{"v":1,"a":"2026-08-26T11:00:00Z","b":"2026-08-26T12:00:00Z","t":"nope","i":"e","c":"{checksum}"}}"#
            )
            .as_bytes(),
        );
        for (cursor, detail) in [
            (window, "invalid cursor window"),
            (boundary, "invalid cursor boundary"),
        ] {
            let request = AuditEventsRequestParams {
                cursor: Some(cursor),
                ..params()
            };
            assert_eq!(parse(&request).unwrap_err().to_string(), detail);
        }
    }

    #[test]
    fn oversized_cursor_parameter_is_rejected() {
        let request = AuditEventsRequestParams {
            cursor: Some("A".repeat(MAX_CURSOR_CHARACTERS + 1)),
            ..params()
        };
        assert!(
            parse(&request)
                .unwrap_err()
                .to_string()
                .contains("cursor must be at most")
        );
    }

    #[test]
    fn validate_query_enforces_reader_invariants() {
        let base = parse(&params()).unwrap();

        let mut query = base.clone();
        query.tenant_id = "  ".to_owned();
        assert_eq!(
            validate_query(&query).unwrap_err().to_string(),
            "tenant_id is required"
        );

        let mut query = base.clone();
        query.after = query.before;
        assert_eq!(
            validate_query(&query).unwrap_err().to_string(),
            "valid after and before times are required"
        );

        let mut query = base.clone();
        query.after = query.before - Duration::minutes(MAX_MINUTES + 1);
        assert!(
            validate_query(&query)
                .unwrap_err()
                .to_string()
                .contains("time window must not exceed")
        );

        let mut query = base.clone();
        query.limit = 0;
        assert!(
            validate_query(&query)
                .unwrap_err()
                .to_string()
                .contains("limit must be between")
        );

        let mut query = base.clone();
        query.page_before_occurred_at = Some(query.before);
        assert_eq!(
            validate_query(&query).unwrap_err().to_string(),
            "page boundary id is required"
        );

        let mut query = base.clone();
        query.page_before_id = "event-a".to_owned();
        assert_eq!(
            validate_query(&query).unwrap_err().to_string(),
            "page boundary time is required"
        );

        let mut query = base.clone();
        query.page_before_occurred_at = Some(query.before + Duration::minutes(1));
        query.page_before_id = "event-a".to_owned();
        assert_eq!(
            validate_query(&query).unwrap_err().to_string(),
            "page boundary is outside the query window"
        );

        let mut query = base.clone();
        query.outcome = "bogus".to_owned();
        assert_eq!(
            validate_query(&query).unwrap_err().to_string(),
            "invalid outcome filter"
        );

        let mut query = base;
        query.service = "s".repeat(MAX_QUERY_CHARACTERS + 1);
        assert!(
            validate_query(&query)
                .unwrap_err()
                .to_string()
                .contains("service must be at most")
        );
    }

    #[test]
    fn store_query_carries_the_full_bounded_scope() {
        let request = AuditEventsRequestParams {
            action: Some("user.login".to_owned()),
            actor: Some("alice".to_owned()),
            q: Some("badge".to_owned()),
            resource_type: Some("door".to_owned()),
            service: Some("auth".to_owned()),
            trace_id: Some("trace-1".to_owned()),
            outcome: Some("denied".to_owned()),
            limit: Some("25".to_owned()),
            minutes: Some("30".to_owned()),
            ..params()
        };
        let query = parse(&request).unwrap();
        let scope = store_query(&query).unwrap();
        assert_eq!(scope.tenant_id, "tenant-a");
        assert_eq!(scope.after, "2026-08-26T11:30:00Z");
        assert_eq!(scope.before, "2026-08-26T12:00:00Z");
        assert_eq!(scope.limit, 25);
        assert_eq!(scope.action, "user.login");
        assert_eq!(scope.actor, "alice");
        assert_eq!(scope.outcome, "denied");
        assert_eq!(scope.resource_type, "door");
        assert_eq!(scope.service, "auth");
        assert_eq!(scope.trace_id, "trace-1");
        assert_eq!(scope.text, "badge");
        assert_eq!(scope.page_before_occurred_at, None);
        assert_eq!(scope.page_before_id, "");
    }

    #[test]
    fn store_query_formats_the_keyset_boundary() {
        let mut query = parse(&params()).unwrap();
        query.page_before_occurred_at = Some(ts("2026-08-26T11:58:00.000001Z"));
        query.page_before_id = "event-a".to_owned();
        let scope = store_query(&query).unwrap();
        assert_eq!(
            scope.page_before_occurred_at.as_deref(),
            Some("2026-08-26T11:58:00.000001Z")
        );
        assert_eq!(scope.page_before_id, "event-a");
    }

    #[test]
    fn build_page_serializes_the_fixed_public_allowlist() {
        let query = parse(&params()).unwrap();
        let mut event = stored("event-a", "2026-08-26T11:58:00Z");
        event.actor_id = "alice".to_owned();
        event.actor_kind = "user".to_owned();
        event.actor_label = " Alice ".to_owned();
        event.resource_id = "door-1".to_owned();
        event.resource_type = "door".to_owned();
        event.duration_ms = Some(25);
        event.category = "authentication".to_owned();
        event.summary = "badge accepted".to_owned();
        let page = StoredAuditEventPage {
            events: vec![event],
            has_more: false,
            partial: false,
        };
        let response = build_page(&query, &page).unwrap();
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["status"], "complete");
        assert_eq!(json["next_cursor"], "");
        assert_eq!(json["window"]["start_time"], "2026-08-26T11:00:00Z");
        assert_eq!(json["window"]["end_time"], "2026-08-26T12:00:00Z");
        let event = &json["events"][0];
        assert_eq!(event["id"], "event-a");
        assert_eq!(event["action"], "user.login");
        assert_eq!(event["occurred_at"], "2026-08-26T11:58:00Z");
        assert_eq!(event["outcome"], "success");
        assert_eq!(event["duration_ms"], 25);
        assert_eq!(event["category"], "authentication");
        assert_eq!(event["summary"], "badge accepted");
        assert_eq!(event["actor"]["id"], "alice");
        assert_eq!(event["actor"]["label"], "Alice");
        assert_eq!(event["resource"]["type"], "door");
        assert_eq!(event["resource"]["label"], "");
        assert_eq!(event["request_id"], "");
        assert_eq!(event["service"], "");
        assert_eq!(event["trace_id"], "");
        assert!(event.get("tenant_id").is_none());
    }

    #[test]
    fn empty_actor_resource_and_duration_are_omitted() {
        let query = parse(&params()).unwrap();
        let page = StoredAuditEventPage {
            events: vec![stored("event-a", "2026-08-26T11:58:00Z")],
            has_more: false,
            partial: false,
        };
        let response = build_page(&query, &page).unwrap();
        let event = &serde_json::to_value(&response).unwrap()["events"][0];
        assert!(event.get("actor").is_none());
        assert!(event.get("resource").is_none());
        assert!(event.get("duration_ms").is_none());
    }

    #[test]
    fn partial_pages_are_reported() {
        let query = parse(&params()).unwrap();
        let page = StoredAuditEventPage {
            events: Vec::new(),
            has_more: false,
            partial: true,
        };
        assert_eq!(build_page(&query, &page).unwrap().status, "partial");
    }

    #[test]
    fn build_page_rejects_reader_integrity_violations() {
        let query = parse(&params()).unwrap();

        let oversized = StoredAuditEventPage {
            events: (0..=DEFAULT_LIMIT)
                .map(|index| stored(&format!("event-{index:03}"), "2026-08-26T11:58:00Z"))
                .collect(),
            has_more: false,
            partial: false,
        };
        assert_eq!(
            build_page(&query, &oversized).unwrap_err().to_string(),
            "reader returned an oversized audit-event page"
        );

        let mut foreign = stored("event-a", "2026-08-26T11:58:00Z");
        foreign.tenant_id = "tenant-b".to_owned();
        for event in [
            foreign,
            stored("event-a", "2026-08-26T10:00:00Z"),
            stored("event-a", "2026-08-26T12:01:00Z"),
            StoredAuditEvent {
                outcome: "invalid".to_owned(),
                ..stored("event-a", "2026-08-26T11:58:00Z")
            },
        ] {
            let page = StoredAuditEventPage {
                events: vec![event],
                has_more: false,
                partial: false,
            };
            assert_eq!(
                build_page(&query, &page).unwrap_err().to_string(),
                "reader returned an invalid tenant-scoped audit event"
            );
        }

        let unordered = StoredAuditEventPage {
            events: vec![
                stored("event-a", "2026-08-26T11:50:00Z"),
                stored("event-b", "2026-08-26T11:58:00Z"),
            ],
            has_more: false,
            partial: false,
        };
        assert_eq!(
            build_page(&query, &unordered).unwrap_err().to_string(),
            "reader returned audit events outside deterministic order"
        );

        let duplicate = StoredAuditEventPage {
            events: vec![
                stored("event-a", "2026-08-26T11:58:00Z"),
                stored("event-a", "2026-08-26T11:58:00Z"),
            ],
            has_more: false,
            partial: false,
        };
        assert_eq!(
            build_page(&query, &duplicate).unwrap_err().to_string(),
            "reader returned audit events outside deterministic order"
        );

        let empty_nonterminal = StoredAuditEventPage {
            events: Vec::new(),
            has_more: true,
            partial: false,
        };
        assert_eq!(
            build_page(&query, &empty_nonterminal)
                .unwrap_err()
                .to_string(),
            "reader returned an empty nonterminal audit-event page"
        );

        let mut invalid_query = query;
        invalid_query.limit = 0;
        let page = StoredAuditEventPage::default();
        let failure = build_page(&invalid_query, &page).unwrap_err();
        assert_eq!(failure.kind(), AuditEventsFailureKind::Unavailable);
    }

    #[test]
    fn build_page_enforces_the_keyset_boundary() {
        let mut query = parse(&params()).unwrap();
        query.page_before_occurred_at = Some(ts("2026-08-26T11:58:00Z"));
        query.page_before_id = "event-b".to_owned();

        let advancing = StoredAuditEventPage {
            events: vec![
                stored("event-a", "2026-08-26T11:58:00Z"),
                stored("event-z", "2026-08-26T11:57:00Z"),
            ],
            has_more: false,
            partial: false,
        };
        assert_eq!(build_page(&query, &advancing).unwrap().events.len(), 2);

        let stalled = StoredAuditEventPage {
            events: vec![stored("event-b", "2026-08-26T11:58:00Z")],
            has_more: false,
            partial: false,
        };
        assert_eq!(
            build_page(&query, &stalled).unwrap_err().to_string(),
            "reader returned an audit event that does not advance the page boundary"
        );

        let newer = StoredAuditEventPage {
            events: vec![stored("event-a", "2026-08-26T11:59:00Z")],
            has_more: false,
            partial: false,
        };
        assert_eq!(
            build_page(&query, &newer).unwrap_err().to_string(),
            "reader returned an audit event that does not advance the page boundary"
        );
    }

    #[test]
    fn normalize_event_bounds_every_field() {
        let base = stored("event-a", "2026-08-26T11:58:00Z");

        let normalized = normalize_event(&base).unwrap();
        assert_eq!(normalized.id, "event-a");
        assert_eq!(normalized.occurred_at, ts("2026-08-26T11:58:00Z"));
        assert!(normalized.actor.is_none());
        assert!(normalized.resource.is_none());

        let mut event = base.clone();
        event.id = "  ".to_owned();
        assert_eq!(
            normalize_event(&event).unwrap_err().to_string(),
            "id is required"
        );

        let mut event = base.clone();
        event.action = String::new();
        assert_eq!(
            normalize_event(&event).unwrap_err().to_string(),
            "action is required"
        );

        let mut event = base.clone();
        event.outcome = "MAYBE".to_owned();
        assert_eq!(
            normalize_event(&event).unwrap_err().to_string(),
            "outcome must be success, failure, denied, or unknown"
        );

        let mut event = base.clone();
        event.outcome = " SUCCESS ".to_owned();
        assert_eq!(normalize_event(&event).unwrap().outcome, "success");

        let mut event = base.clone();
        event.occurred_at = String::new();
        assert_eq!(
            normalize_event(&event).unwrap_err().to_string(),
            "occurred_at is required"
        );

        let mut event = base.clone();
        event.occurred_at = "not-a-time".to_owned();
        assert_eq!(
            normalize_event(&event).unwrap_err().to_string(),
            "occurred_at must be a valid RFC 3339 timestamp"
        );

        let mut event = base.clone();
        event.occurred_at = "2026-08-26T13:58:00+02:00".to_owned();
        assert_eq!(
            normalize_event(&event).unwrap().occurred_at,
            ts("2026-08-26T11:58:00Z")
        );

        let mut event = base.clone();
        event.duration_ms = Some(-1);
        assert_eq!(
            normalize_event(&event).unwrap_err().to_string(),
            "duration_ms must be non-negative"
        );

        let mut event = base.clone();
        event.summary = "s".repeat(MAX_SUMMARY_CHARACTERS + 1);
        assert!(
            normalize_event(&event)
                .unwrap_err()
                .to_string()
                .contains("summary must be at most")
        );

        let mut event = base.clone();
        event.actor_label = "a".repeat(MAX_IDENTIFIER_CHARACTERS + 1);
        assert!(
            normalize_event(&event)
                .unwrap_err()
                .to_string()
                .contains("actor.label must be at most")
        );

        let mut event = base;
        event.actor_kind = " service ".to_owned();
        let normalized = normalize_event(&event).unwrap();
        let actor = normalized.actor.unwrap();
        assert_eq!(actor.kind, "service");
        assert_eq!(actor.id, "");
    }

    #[test]
    fn cursor_checksum_is_deterministic_and_boundary_sensitive() {
        let query = parse(&params()).unwrap();
        let first = cursor_checksum(&query, DEFAULT_MINUTES).unwrap();
        assert_eq!(first.len(), 64);
        assert_eq!(first, cursor_checksum(&query, DEFAULT_MINUTES).unwrap());

        let mut resumed = query.clone();
        resumed.page_before_occurred_at = Some(query.before - Duration::minutes(1));
        resumed.page_before_id = "event-a".to_owned();
        assert_ne!(first, cursor_checksum(&resumed, DEFAULT_MINUTES).unwrap());
        assert_ne!(first, cursor_checksum(&query, DEFAULT_MINUTES + 1).unwrap());
    }

    #[test]
    fn base64url_round_trips_and_rejects_invalid_input() {
        for payload in [
            b"".as_slice(),
            b"a".as_slice(),
            b"ab".as_slice(),
            b"abc".as_slice(),
            b"\x00\xff\x7f\x80".as_slice(),
        ] {
            let encoded = base64url_encode(payload);
            assert!(!encoded.contains('='));
            assert_eq!(base64url_decode(&encoded).as_deref(), Some(payload));
        }
        assert_eq!(base64url_encode(b"hello"), "aGVsbG8");
        assert_eq!(base64url_decode("aGVsbG8").unwrap(), b"hello");
        assert!(base64url_decode("aGVsbG8=").is_none());
        assert!(base64url_decode("a").is_none());
        assert!(base64url_decode("a+b/").is_none());
    }

    #[test]
    fn hex_encoding_is_lowercase() {
        assert_eq!(hex_encode(&[0x00, 0xab, 0xff]), "00abff");
    }

    #[test]
    fn encode_cursor_rejects_oversized_output() {
        let mut query = parse(&params()).unwrap();
        query.query = "q".repeat(MAX_QUERY_CHARACTERS);
        let last = NormalizedAuditEvent {
            id: "e".repeat(MAX_IDENTIFIER_CHARACTERS * 8),
            tenant_id: "tenant-a".to_owned(),
            action: "user.login".to_owned(),
            actor: None,
            category: String::new(),
            duration_ms: None,
            occurred_at: query.before - Duration::minutes(1),
            outcome: "success".to_owned(),
            request_id: String::new(),
            resource: None,
            service: String::new(),
            summary: String::new(),
            trace_id: String::new(),
        };
        assert_eq!(
            encode_cursor(&query, &last).unwrap_err().to_string(),
            "encoded audit-event cursor is too long"
        );
    }

    #[test]
    fn failure_kinds_expose_operator_actions() {
        let invalid_failure = invalid("bad request");
        assert_eq!(
            invalid_failure.kind(),
            AuditEventsFailureKind::InvalidRequest
        );
        assert_eq!(invalid_failure.to_string(), "bad request");
        let unavailable_failure = unavailable("backend down");
        assert_eq!(
            unavailable_failure.kind(),
            AuditEventsFailureKind::Unavailable
        );
        assert_eq!(unavailable_failure.to_string(), "backend down");
    }
}
