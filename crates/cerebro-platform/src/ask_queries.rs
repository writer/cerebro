//! Saved ask-query CRUD served natively by the Rust product surface.
//!
//! These handlers mirror the Go bootstrap routes under `/ask-queries`
//! field-for-field: the same validation bounds, the same JSON shapes, and the
//! same tenant-scoped Postgres semantics via [`PostgresLedger`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use cerebro_organizational_model::TenantId;
use cerebro_organizational_store::{AskQueryRecord, AskQueryWrite, PostgresLedger, StoreError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AppState, AuthenticatedTenant, ErrorResponse, bad_request, service_unavailable};

/// Byte bounds shared with the Go handlers (`askQueryMaxNameBytes` and
/// `askQueryMaxQuestionBytes` in `internal/bootstrap/ask_queries.go`).
const ASK_QUERY_MAX_NAME_BYTES: usize = 200;
const ASK_QUERY_MAX_QUESTION_BYTES: usize = 4000;

/// One saved ask query on the wire, mirroring Go's `askQueryView`:
/// `scope_urn` and `model` are omitted when empty, timestamps are RFC 3339 UTC.
#[derive(Debug, Eq, PartialEq, Serialize)]
pub(crate) struct AskQueryView {
    id: String,
    tenant_id: String,
    name: String,
    question: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    scope_urn: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    model: String,
    pinned: bool,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct AskQueryResponse {
    query: AskQueryView,
}

#[derive(Debug, Serialize)]
pub(crate) struct AskQueryListResponse {
    queries: Vec<AskQueryView>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct CreateAskQueryRequest {
    #[serde(default)]
    tenant_id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    question: String,
    #[serde(default)]
    scope_urn: String,
    #[serde(default)]
    model: String,
    #[serde(default)]
    pinned: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct UpdateAskQueryRequest {
    name: Option<String>,
    question: Option<String>,
    scope_urn: Option<String>,
    model: Option<String>,
    pinned: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct ListAskQueriesParams {
    tenant_id: Option<String>,
    limit: Option<u32>,
}

pub(crate) async fn list_ask_queries(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Query(params): Query<ListAskQueriesParams>,
) -> Result<Json<AskQueryListResponse>, (StatusCode, Json<ErrorResponse>)> {
    let ledger = require_ask_query_ledger(&state)?;
    let tenant_id = effective_tenant(&authenticated, params.tenant_id)?;
    let limit = params.limit.unwrap_or(0);
    if params.limit == Some(0) {
        return Err(bad_request(
            "invalid_ask_query_limit",
            "limit must be at least 1.",
        ));
    }
    let queries = ledger
        .list_ask_queries(tenant_id.as_str(), limit)
        .await
        .map_err(ask_query_store_error)?;
    Ok(Json(AskQueryListResponse {
        queries: queries.into_iter().map(ask_query_view).collect(),
    }))
}

pub(crate) async fn create_ask_query(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Json(request): Json<CreateAskQueryRequest>,
) -> Result<(StatusCode, Json<AskQueryResponse>), (StatusCode, Json<ErrorResponse>)> {
    let ledger = require_ask_query_ledger(&state)?;
    let tenant_id = effective_tenant(&authenticated, Some(request.tenant_id))?;
    let (name, question) = normalize_ask_query_content(&request.name, &request.question)
        .map_err(|message| bad_request("invalid_ask_query", message))?;
    let id = new_ask_query_id();
    ledger
        .put_ask_query(&AskQueryWrite {
            id: &id,
            tenant_id: tenant_id.as_str(),
            name: &name,
            question: &question,
            scope_urn: request.scope_urn.trim(),
            model: request.model.trim(),
            pinned: request.pinned.unwrap_or(false),
        })
        .await
        .map_err(ask_query_store_error)?;
    let stored = load_ask_query(ledger, tenant_id.as_str(), &id).await?;
    Ok((
        StatusCode::CREATED,
        Json(AskQueryResponse {
            query: ask_query_view(stored),
        }),
    ))
}

pub(crate) async fn update_ask_query(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Path(query_id): Path<String>,
    Json(request): Json<UpdateAskQueryRequest>,
) -> Result<Json<AskQueryResponse>, (StatusCode, Json<ErrorResponse>)> {
    let ledger = require_ask_query_ledger(&state)?;
    let tenant_id = authenticated.0.as_str();
    let existing = load_ask_query(ledger, tenant_id, &query_id).await?;
    let updated = apply_ask_query_update(&existing, &request)
        .map_err(|message| bad_request("invalid_ask_query", message))?;
    ledger
        .put_ask_query(&AskQueryWrite {
            id: &existing.id,
            tenant_id,
            name: &updated.name,
            question: &updated.question,
            scope_urn: &updated.scope_urn,
            model: &updated.model,
            pinned: updated.pinned,
        })
        .await
        .map_err(ask_query_store_error)?;
    let stored = load_ask_query(ledger, tenant_id, &existing.id).await?;
    Ok(Json(AskQueryResponse {
        query: ask_query_view(stored),
    }))
}

pub(crate) async fn delete_ask_query(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Path(query_id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let ledger = require_ask_query_ledger(&state)?;
    let deleted = ledger
        .delete_ask_query(authenticated.0.as_str(), &query_id)
        .await
        .map_err(ask_query_store_error)?;
    if !deleted {
        return Err(ask_query_not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Post-patch content of one saved ask query, before it is written back.
#[derive(Debug, Eq, PartialEq)]
struct AskQueryUpdate {
    name: String,
    question: String,
    scope_urn: String,
    model: String,
    pinned: bool,
}

/// Mirrors the Go update handler: absent fields keep the stored value, present
/// fields replace it, and the merged name/question pass the shared bounds.
fn apply_ask_query_update(
    existing: &AskQueryRecord,
    request: &UpdateAskQueryRequest,
) -> Result<AskQueryUpdate, String> {
    let name = request.name.as_deref().unwrap_or(&existing.name);
    let question = request.question.as_deref().unwrap_or(&existing.question);
    let (name, question) = normalize_ask_query_content(name, question)?;
    let scope_urn = request.scope_urn.as_deref().map_or_else(
        || existing.scope_urn.clone(),
        |value| value.trim().to_owned(),
    );
    let model = request
        .model
        .as_deref()
        .map_or_else(|| existing.model.clone(), |value| value.trim().to_owned());
    Ok(AskQueryUpdate {
        name,
        question,
        scope_urn,
        model,
        pinned: request.pinned.unwrap_or(existing.pinned),
    })
}

/// Mirrors Go's `normalizeAskQueryContent`: trim both fields, require them
/// non-empty, and bound their sizes in bytes.
fn normalize_ask_query_content(name: &str, question: &str) -> Result<(String, String), String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("name is required".to_owned());
    }
    if name.len() > ASK_QUERY_MAX_NAME_BYTES {
        return Err(format!(
            "name must be at most {ASK_QUERY_MAX_NAME_BYTES} bytes"
        ));
    }
    let question = question.trim();
    if question.is_empty() {
        return Err("question is required".to_owned());
    }
    if question.len() > ASK_QUERY_MAX_QUESTION_BYTES {
        return Err(format!(
            "question must be at most {ASK_QUERY_MAX_QUESTION_BYTES} bytes"
        ));
    }
    Ok((name.to_owned(), question.to_owned()))
}

/// Mirrors Go's `effectiveTenantFilter` under always-on authentication: an
/// absent or empty tenant falls back to the authenticated tenant, and a
/// mismatching tenant is forbidden.
fn effective_tenant(
    authenticated: &AuthenticatedTenant,
    requested: Option<String>,
) -> Result<TenantId, (StatusCode, Json<ErrorResponse>)> {
    match requested
        .map(|tenant| tenant.trim().to_owned())
        .filter(|tenant| !tenant.is_empty())
    {
        Some(requested) => crate::authorized_tenant(authenticated, requested),
        None => Ok(authenticated.0.clone()),
    }
}

/// Identifiers keep Go's `ask-query-` + 16 hex characters shape. Uniqueness
/// comes from time, process, and sequence; every access is tenant-authorized,
/// so the identifier does not need to be unguessable.
fn new_ask_query_id() -> String {
    static ASK_QUERY_ID_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let unix_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let sequence = ASK_QUERY_ID_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut hasher = Sha256::new();
    hasher.update(unix_nanos.to_be_bytes());
    hasher.update(std::process::id().to_be_bytes());
    hasher.update(sequence.to_be_bytes());
    let digest = hasher.finalize();
    let suffix: String = digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("ask-query-{suffix}")
}

fn ask_query_view(record: AskQueryRecord) -> AskQueryView {
    AskQueryView {
        id: record.id,
        tenant_id: record.tenant_id,
        name: record.name,
        question: record.question,
        scope_urn: record.scope_urn,
        model: record.model,
        pinned: record.pinned,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn require_ask_query_ledger(
    state: &AppState,
) -> Result<&PostgresLedger, (StatusCode, Json<ErrorResponse>)> {
    state.runtime_ledger.as_deref().ok_or_else(|| {
        service_unavailable("ask_queries_unavailable", "Ask queries are not configured.")
    })
}

async fn load_ask_query(
    ledger: &PostgresLedger,
    tenant_id: &str,
    query_id: &str,
) -> Result<AskQueryRecord, (StatusCode, Json<ErrorResponse>)> {
    ledger
        .get_ask_query(tenant_id, query_id)
        .await
        .map_err(ask_query_store_error)?
        .ok_or_else(ask_query_not_found)
}

fn ask_query_not_found() -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            code: "ask_query_not_found",
            message: "The saved ask query was not found.".to_owned(),
        }),
    )
}

fn ask_query_store_error(error: StoreError) -> (StatusCode, Json<ErrorResponse>) {
    match error {
        StoreError::Conflict(message) => bad_request("invalid_ask_query", message),
        error => {
            eprintln!("ask query store unavailable: {error}");
            service_unavailable(
                "ask_queries_unavailable",
                "Saved ask queries are temporarily unavailable.",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_trims_and_accepts_bounded_content() {
        let (name, question) = normalize_ask_query_content("  Weekly risk  ", "\tWho owns S3?\n")
            .expect("bounded content is valid");
        assert_eq!(name, "Weekly risk");
        assert_eq!(question, "Who owns S3?");
    }

    #[test]
    fn normalize_requires_name_and_question() {
        assert_eq!(
            normalize_ask_query_content("", "question"),
            Err("name is required".to_owned())
        );
        assert_eq!(
            normalize_ask_query_content("   ", "question"),
            Err("name is required".to_owned()),
            "whitespace-only names trim to empty"
        );
        assert_eq!(
            normalize_ask_query_content("name", ""),
            Err("question is required".to_owned())
        );
        assert_eq!(
            normalize_ask_query_content("name", " \n "),
            Err("question is required".to_owned())
        );
    }

    #[test]
    fn normalize_bounds_are_measured_in_bytes_like_go() {
        let name_at_limit = "n".repeat(ASK_QUERY_MAX_NAME_BYTES);
        let question_at_limit = "q".repeat(ASK_QUERY_MAX_QUESTION_BYTES);
        assert!(normalize_ask_query_content(&name_at_limit, &question_at_limit).is_ok());

        let name_over_limit = "n".repeat(ASK_QUERY_MAX_NAME_BYTES + 1);
        assert_eq!(
            normalize_ask_query_content(&name_over_limit, "question"),
            Err("name must be at most 200 bytes".to_owned())
        );
        let question_over_limit = "q".repeat(ASK_QUERY_MAX_QUESTION_BYTES + 1);
        assert_eq!(
            normalize_ask_query_content("name", &question_over_limit),
            Err("question must be at most 4000 bytes".to_owned())
        );

        // 67 four-byte scalars are 268 bytes but only 67 characters: the bound
        // must reject them, exactly as Go's byte-length check does.
        let multibyte_name = "\u{1F512}".repeat(67);
        assert_eq!(multibyte_name.chars().count(), 67);
        assert_eq!(
            normalize_ask_query_content(&multibyte_name, "question"),
            Err("name must be at most 200 bytes".to_owned())
        );
    }

    #[test]
    fn update_merge_keeps_absent_fields_and_replaces_present_ones() {
        let existing = sample_record();
        let unchanged = apply_ask_query_update(&existing, &UpdateAskQueryRequest::default())
            .expect("empty patch keeps the stored content");
        assert_eq!(
            unchanged,
            AskQueryUpdate {
                name: "Stored name".to_owned(),
                question: "Stored question".to_owned(),
                scope_urn: "urn:cerebro:scope".to_owned(),
                model: "gpt-lite".to_owned(),
                pinned: true,
            }
        );

        let patched = apply_ask_query_update(
            &existing,
            &UpdateAskQueryRequest {
                name: Some("  New name ".to_owned()),
                question: None,
                scope_urn: Some("   ".to_owned()),
                model: Some(" other ".to_owned()),
                pinned: Some(false),
            },
        )
        .expect("patched content is valid");
        assert_eq!(
            patched,
            AskQueryUpdate {
                name: "New name".to_owned(),
                question: "Stored question".to_owned(),
                scope_urn: String::new(),
                model: "other".to_owned(),
                pinned: false,
            }
        );
    }

    #[test]
    fn update_merge_revalidates_merged_content() {
        let existing = sample_record();
        assert_eq!(
            apply_ask_query_update(
                &existing,
                &UpdateAskQueryRequest {
                    name: Some("  ".to_owned()),
                    ..UpdateAskQueryRequest::default()
                },
            ),
            Err("name is required".to_owned())
        );
        assert_eq!(
            apply_ask_query_update(
                &existing,
                &UpdateAskQueryRequest {
                    question: Some("q".repeat(ASK_QUERY_MAX_QUESTION_BYTES + 1)),
                    ..UpdateAskQueryRequest::default()
                },
            ),
            Err("question must be at most 4000 bytes".to_owned())
        );
    }

    #[test]
    fn ask_query_ids_keep_the_go_shape_and_stay_unique() {
        let first = new_ask_query_id();
        let second = new_ask_query_id();
        assert_ne!(first, second);
        for id in [&first, &second] {
            let suffix = id
                .strip_prefix("ask-query-")
                .expect("ids keep the ask-query- prefix");
            assert_eq!(suffix.len(), 16, "8 random bytes hex-encode to 16 chars");
            assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
            assert_eq!(suffix, suffix.to_lowercase());
        }
    }

    #[test]
    fn view_serialization_matches_the_go_contract() {
        let full = serde_json::to_value(ask_query_view(sample_record())).unwrap();
        assert_eq!(
            full,
            serde_json::json!({
                "id": "ask-query-0123456789abcdef",
                "tenant_id": "tenant-demo",
                "name": "Stored name",
                "question": "Stored question",
                "scope_urn": "urn:cerebro:scope",
                "model": "gpt-lite",
                "pinned": true,
                "created_at": "2026-08-26T05:00:00Z",
                "updated_at": "2026-08-26T06:00:00Z",
            })
        );

        let mut sparse = sample_record();
        sparse.scope_urn = String::new();
        sparse.model = String::new();
        sparse.pinned = false;
        let sparse = serde_json::to_value(ask_query_view(sparse)).unwrap();
        assert!(
            sparse.get("scope_urn").is_none() && sparse.get("model").is_none(),
            "empty scope_urn and model are omitted, matching Go's omitempty"
        );
        assert_eq!(sparse["pinned"], serde_json::json!(false));
    }

    #[test]
    fn create_request_tolerates_missing_fields_like_go() {
        let request: CreateAskQueryRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(request.tenant_id, "");
        assert_eq!(request.name, "");
        assert_eq!(request.question, "");
        assert_eq!(request.pinned, None);

        let request: UpdateAskQueryRequest = serde_json::from_str("{}").unwrap();
        assert!(
            request.name.is_none()
                && request.question.is_none()
                && request.scope_urn.is_none()
                && request.model.is_none()
                && request.pinned.is_none()
        );
    }

    fn sample_record() -> AskQueryRecord {
        AskQueryRecord {
            id: "ask-query-0123456789abcdef".to_owned(),
            tenant_id: "tenant-demo".to_owned(),
            name: "Stored name".to_owned(),
            question: "Stored question".to_owned(),
            scope_urn: "urn:cerebro:scope".to_owned(),
            model: "gpt-lite".to_owned(),
            pinned: true,
            created_at: "2026-08-26T05:00:00Z".to_owned(),
            updated_at: "2026-08-26T06:00:00Z".to_owned(),
        }
    }
}
