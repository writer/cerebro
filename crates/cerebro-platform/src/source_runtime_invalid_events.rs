//! Tenant-bound invalid-event inspection for durable source runtimes.

use std::{error::Error, fmt, sync::Arc};

use cerebro_organizational_model::{SourceRuntimeId, TenantId};
use cerebro_organizational_store::{PostgresLedger, StoredSourceRuntime};
use serde::Serialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const LAST_FAILURE_CATEGORY: &str = "__cerebro_runtime_last_failure_category";
const LAST_INVALID_EVENT_ID: &str = "__cerebro_runtime_last_invalid_event_id";
const LAST_INVALID_FIELD: &str = "__cerebro_runtime_last_invalid_field";
const LAST_INVALID_STATUS: &str = "__cerebro_runtime_last_invalid_status";
const LAST_INVALID_OBSERVED_AT: &str = "__cerebro_runtime_last_invalid_observed_at";
const LAST_INVALID_OCCURRED_AT: &str = "__cerebro_runtime_last_invalid_occurred_at";
const LAST_INVALID_DIAGNOSTIC: &str = "__cerebro_runtime_last_invalid_diagnostic";
const LAST_INVALID_RETRYABLE: &str = "__cerebro_runtime_last_invalid_retryable";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceRuntimeInvalidEventsFailureKind {
    InvalidRequest,
    RuntimeUnavailable,
}

#[derive(Debug)]
pub(crate) struct SourceRuntimeInvalidEventsFailure {
    kind: SourceRuntimeInvalidEventsFailureKind,
    detail: String,
}

impl SourceRuntimeInvalidEventsFailure {
    fn new(kind: SourceRuntimeInvalidEventsFailureKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    pub(crate) fn kind(&self) -> SourceRuntimeInvalidEventsFailureKind {
        self.kind
    }
}

impl fmt::Display for SourceRuntimeInvalidEventsFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl Error for SourceRuntimeInvalidEventsFailure {}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub(crate) struct SourceRuntimeInvalidEventsResponse {
    generated_at: String,
    events: Vec<SourceRuntimeInvalidEventRecord>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct SourceRuntimeInvalidEventRecord {
    runtime_id: String,
    source_id: String,
    tenant_id: String,
    failure_category: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fields: Vec<String>,
    status: String,
    retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    occurred_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostic: Option<String>,
}

pub(crate) async fn list_source_runtime_invalid_events(
    ledger: Arc<PostgresLedger>,
    tenant_id: &TenantId,
    runtime_id: &str,
) -> Result<SourceRuntimeInvalidEventsResponse, SourceRuntimeInvalidEventsFailure> {
    let runtime_id = parse_runtime_id(runtime_id)?;
    let runtime = ledger
        .find_source_runtime(&runtime_id)
        .await
        .map_err(runtime_unavailable)?;
    let generated_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(runtime_unavailable)?;
    Ok(response_for_runtime(
        tenant_id,
        runtime.as_ref(),
        generated_at,
    ))
}

fn parse_runtime_id(
    runtime_id: &str,
) -> Result<SourceRuntimeId, SourceRuntimeInvalidEventsFailure> {
    SourceRuntimeId::parse(runtime_id.trim().to_owned()).map_err(|error| {
        SourceRuntimeInvalidEventsFailure::new(
            SourceRuntimeInvalidEventsFailureKind::InvalidRequest,
            error.to_string(),
        )
    })
}

fn response_for_runtime(
    tenant_id: &TenantId,
    runtime: Option<&StoredSourceRuntime>,
    generated_at: String,
) -> SourceRuntimeInvalidEventsResponse {
    let events = runtime
        .filter(|runtime| runtime.tenant_id() == tenant_id)
        .and_then(invalid_event_record)
        .into_iter()
        .collect();
    SourceRuntimeInvalidEventsResponse {
        generated_at,
        events,
    }
}

fn invalid_event_record(runtime: &StoredSourceRuntime) -> Option<SourceRuntimeInvalidEventRecord> {
    let config = runtime.config();
    let failure_category = trimmed(config.get(LAST_FAILURE_CATEGORY)).unwrap_or_default();
    let invalid_field = trimmed(config.get(LAST_INVALID_FIELD));
    if failure_category.is_empty() && invalid_field.is_none() {
        return None;
    }
    let status = trimmed(config.get(LAST_INVALID_STATUS)).unwrap_or_else(|| "terminal".to_owned());
    let retryable = trimmed(config.get(LAST_INVALID_RETRYABLE))
        .is_some_and(|value| value.eq_ignore_ascii_case("true"));
    Some(SourceRuntimeInvalidEventRecord {
        runtime_id: runtime.runtime_id().as_str().trim().to_owned(),
        source_id: runtime.source_id().trim().to_owned(),
        tenant_id: runtime.tenant_id().as_str().trim().to_owned(),
        failure_category,
        fields: invalid_field.into_iter().collect(),
        status,
        retryable,
        observed_at: trimmed(config.get(LAST_INVALID_OBSERVED_AT)),
        occurred_at: trimmed(config.get(LAST_INVALID_OCCURRED_AT)),
        source_event_id: trimmed(config.get(LAST_INVALID_EVENT_ID)),
        diagnostic: trimmed(config.get(LAST_INVALID_DIAGNOSTIC)),
    })
}

fn trimmed(value: Option<&String>) -> Option<String> {
    value
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn runtime_unavailable(error: impl fmt::Display) -> SourceRuntimeInvalidEventsFailure {
    SourceRuntimeInvalidEventsFailure::new(
        SourceRuntimeInvalidEventsFailureKind::RuntimeUnavailable,
        error.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn stored(tenant_id: &str, config: BTreeMap<String, String>) -> StoredSourceRuntime {
        StoredSourceRuntime::new(
            SourceRuntimeId::parse("runtime-a").unwrap(),
            TenantId::parse(tenant_id).unwrap(),
            "github".to_owned(),
            config,
            None,
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn invalid_event_record_is_bounded_to_safe_diagnostic_fields() {
        let runtime = stored(
            "tenant-a",
            BTreeMap::from([
                (LAST_FAILURE_CATEGORY.to_owned(), " malformed ".to_owned()),
                (LAST_INVALID_FIELD.to_owned(), " resource_urn ".to_owned()),
                (LAST_INVALID_EVENT_ID.to_owned(), " event-a ".to_owned()),
                (
                    LAST_INVALID_DIAGNOSTIC.to_owned(),
                    " invalid source event ".to_owned(),
                ),
                (LAST_INVALID_RETRYABLE.to_owned(), "TRUE".to_owned()),
                ("token".to_owned(), "credential:cred-a:token".to_owned()),
            ]),
        );
        let record = invalid_event_record(&runtime).unwrap();
        assert_eq!(record.failure_category, "malformed");
        assert_eq!(record.fields, vec!["resource_urn"]);
        assert_eq!(record.source_event_id.as_deref(), Some("event-a"));
        assert_eq!(record.status, "terminal");
        assert!(record.retryable);
        let json = serde_json::to_value(record).unwrap();
        assert!(!json.to_string().contains("credential:cred-a:token"));
        assert!(json.get("payload").is_none());
    }

    #[test]
    fn missing_foreign_and_clean_runtimes_return_no_events() {
        let tenant_a = TenantId::parse("tenant-a").unwrap();
        let foreign = stored(
            "tenant-b",
            BTreeMap::from([(LAST_FAILURE_CATEGORY.to_owned(), "malformed".to_owned())]),
        );
        let clean = stored("tenant-a", BTreeMap::new());
        for runtime in [None, Some(&foreign), Some(&clean)] {
            let response = response_for_runtime(&tenant_a, runtime, "2026-08-25T00:00:00Z".into());
            assert!(response.events.is_empty());
        }
    }

    #[test]
    fn invalid_event_record_preserves_bounded_timestamps_and_explicit_status() {
        let runtime = stored(
            "tenant-a",
            BTreeMap::from([
                (LAST_INVALID_FIELD.to_owned(), " object_id ".to_owned()),
                (LAST_INVALID_STATUS.to_owned(), " quarantined ".to_owned()),
                (
                    LAST_INVALID_OBSERVED_AT.to_owned(),
                    " 2026-08-25T00:00:00Z ".to_owned(),
                ),
                (
                    LAST_INVALID_OCCURRED_AT.to_owned(),
                    " 2026-08-24T23:59:00Z ".to_owned(),
                ),
                (LAST_INVALID_EVENT_ID.to_owned(), "  ".to_owned()),
                (LAST_INVALID_DIAGNOSTIC.to_owned(), "  ".to_owned()),
                (LAST_INVALID_RETRYABLE.to_owned(), "false".to_owned()),
            ]),
        );
        let record = invalid_event_record(&runtime).unwrap();
        assert_eq!(record.runtime_id, "runtime-a");
        assert_eq!(record.source_id, "github");
        assert_eq!(record.tenant_id, "tenant-a");
        assert_eq!(record.failure_category, "");
        assert_eq!(record.fields, vec!["object_id"]);
        assert_eq!(record.status, "quarantined");
        assert!(!record.retryable);
        assert_eq!(record.observed_at.as_deref(), Some("2026-08-25T00:00:00Z"));
        assert_eq!(record.occurred_at.as_deref(), Some("2026-08-24T23:59:00Z"));
        assert_eq!(record.source_event_id, None);
        assert_eq!(record.diagnostic, None);
    }

    #[test]
    fn same_tenant_response_includes_one_invalid_event_and_generation_time() {
        let tenant = TenantId::parse("tenant-a").unwrap();
        let runtime = stored(
            "tenant-a",
            BTreeMap::from([(LAST_FAILURE_CATEGORY.to_owned(), "malformed".to_owned())]),
        );
        let response =
            response_for_runtime(&tenant, Some(&runtime), "2026-08-25T01:00:00Z".to_owned());
        assert_eq!(response.generated_at, "2026-08-25T01:00:00Z");
        assert_eq!(response.events.len(), 1);
        assert_eq!(response.events[0].failure_category, "malformed");
    }

    #[test]
    fn runtime_selector_and_backend_failures_keep_operator_actions_distinct() {
        assert_eq!(
            parse_runtime_id(" runtime-a ").unwrap().as_str(),
            "runtime-a"
        );
        let invalid = parse_runtime_id("invalid runtime").unwrap_err();
        assert_eq!(
            invalid.kind(),
            SourceRuntimeInvalidEventsFailureKind::InvalidRequest
        );
        assert!(!invalid.to_string().is_empty());

        let unavailable = runtime_unavailable("postgres unavailable");
        assert_eq!(
            unavailable.kind(),
            SourceRuntimeInvalidEventsFailureKind::RuntimeUnavailable
        );
        assert_eq!(unavailable.to_string(), "postgres unavailable");
    }
}
