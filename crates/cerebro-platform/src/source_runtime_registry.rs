//! Tenant-bound source-runtime registry served by the Rust platform.

use std::{collections::BTreeMap, error::Error, fmt, sync::Arc};

use async_trait::async_trait;
use cerebro_organizational_model::{SourceRuntimeId, TenantId};
use cerebro_organizational_store::{PostgresLedger, StoredSourceRuntime};
use cerebro_source_runtime_next::{parse_aws_secret_reference, parse_credential_reference};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const REDACTED_VALUE: &str = "[redacted]";
const RESOURCE_SCOPE_CONFIG_KEY: &str = "cerebro_resource_scope_policy";
const DEFAULT_LIST_LIMIT: u16 = 100;
const MAX_LIST_LIMIT: u16 = 500;
const MAX_RUNTIME_IDS: usize = 500;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceRuntimeRegistryFailureKind {
    InvalidRequest,
    TenantMismatch,
    NotFound,
    Conflict,
    RuntimeUnavailable,
}

#[derive(Debug)]
pub(crate) struct SourceRuntimeRegistryFailure {
    kind: SourceRuntimeRegistryFailureKind,
    detail: String,
}

impl SourceRuntimeRegistryFailure {
    fn new(kind: SourceRuntimeRegistryFailureKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    pub(crate) fn kind(&self) -> SourceRuntimeRegistryFailureKind {
        self.kind
    }
}

impl fmt::Display for SourceRuntimeRegistryFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl Error for SourceRuntimeRegistryFailure {}

#[derive(Clone, Deserialize)]
pub(crate) struct PutSourceRuntimeRequest {
    pub(crate) runtime: Option<SourceRuntimeInput>,
}

#[derive(Clone, Deserialize)]
pub(crate) struct SourceRuntimeInput {
    #[serde(default)]
    pub(crate) id: String,
    pub(crate) source_id: String,
    #[serde(default)]
    pub(crate) tenant_id: String,
    #[serde(default)]
    pub(crate) config: BTreeMap<String, String>,
    pub(crate) checkpoint: Option<Value>,
    pub(crate) next_cursor: Option<Value>,
    pub(crate) last_synced_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct SourceRuntimeView {
    pub(crate) id: String,
    pub(crate) source_id: String,
    pub(crate) tenant_id: String,
    pub(crate) config: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) checkpoint: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) next_cursor: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) last_synced_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct SourceRuntimeResponse {
    pub(crate) runtime: SourceRuntimeView,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct SourceRuntimeListResponse {
    pub(crate) runtimes: Vec<SourceRuntimeView>,
}

#[derive(Clone, Default, Deserialize)]
pub(crate) struct SourceRuntimeListQuery {
    pub(crate) runtime_id: Option<String>,
    pub(crate) runtime_ids: Option<String>,
    pub(crate) source_id: Option<String>,
    pub(crate) limit: Option<u16>,
}

struct SourceRuntimeListPlan {
    limit: u16,
    runtime_ids: Vec<SourceRuntimeId>,
    source_id: Option<String>,
}

fn plan_list_query(
    query: &SourceRuntimeListQuery,
) -> Result<SourceRuntimeListPlan, SourceRuntimeRegistryFailure> {
    let limit = query.limit.unwrap_or(DEFAULT_LIST_LIMIT);
    if limit == 0 || limit > MAX_LIST_LIMIT {
        return Err(invalid_request(
            "Source runtime list limit must be between 1 and 500.",
        ));
    }
    let runtime_ids = runtime_ids(query)?;
    let source_id = query
        .source_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    Ok(SourceRuntimeListPlan {
        limit,
        runtime_ids,
        source_id,
    })
}

fn admit_put_identity(
    tenant_id: &TenantId,
    runtime_id: &str,
    request: PutSourceRuntimeRequest,
) -> Result<(SourceRuntimeId, SourceRuntimeInput), SourceRuntimeRegistryFailure> {
    let runtime_id = parse_runtime_id(runtime_id)?;
    let input = request.runtime.ok_or_else(|| {
        invalid_request("A source runtime definition is required in the runtime field.")
    })?;
    if !input.id.is_empty() && input.id.trim() != runtime_id.as_str() {
        return Err(invalid_request(
            "The source runtime body ID must match the path ID.",
        ));
    }
    if !input.tenant_id.is_empty() && input.tenant_id.trim() != tenant_id.as_str() {
        return Err(SourceRuntimeRegistryFailure::new(
            SourceRuntimeRegistryFailureKind::TenantMismatch,
            "source runtime tenant does not match authenticated tenant",
        ));
    }
    Ok((runtime_id, input))
}

fn reject_caller_owned_progress(
    input: &SourceRuntimeInput,
) -> Result<(), SourceRuntimeRegistryFailure> {
    if input.checkpoint.is_some() || input.next_cursor.is_some() || input.last_synced_at.is_some() {
        return Err(invalid_request(
            "Source runtime progress is owned by durable sync and cannot be supplied to the registry.",
        ));
    }
    Ok(())
}

fn preserved_progress(
    existing: Option<&StoredSourceRuntime>,
    config: &BTreeMap<String, String>,
) -> (Option<Value>, Option<Value>, Option<String>) {
    if existing.is_none_or(|runtime| runtime.config() != config) {
        return (None, None, None);
    }
    let checkpoint = existing.and_then(|runtime| runtime.checkpoint().cloned());
    let next_cursor = existing.and_then(|runtime| runtime.next_cursor().cloned());
    let last_synced_at = existing.and_then(|runtime| runtime.last_synced_at().map(str::to_owned));
    (checkpoint, next_cursor, last_synced_at)
}

#[async_trait]
pub(crate) trait SourceRuntimeRegistryAuthority: Send + Sync {
    async fn put(
        &self,
        tenant_id: &TenantId,
        runtime_id: &str,
        request: PutSourceRuntimeRequest,
    ) -> Result<SourceRuntimeResponse, SourceRuntimeRegistryFailure>;

    async fn get(
        &self,
        tenant_id: &TenantId,
        runtime_id: &str,
    ) -> Result<SourceRuntimeResponse, SourceRuntimeRegistryFailure>;

    async fn list(
        &self,
        tenant_id: &TenantId,
        query: SourceRuntimeListQuery,
    ) -> Result<SourceRuntimeListResponse, SourceRuntimeRegistryFailure>;
}

pub(crate) struct PostgresSourceRuntimeRegistry {
    ledger: Arc<PostgresLedger>,
}

impl PostgresSourceRuntimeRegistry {
    pub(crate) fn new(ledger: Arc<PostgresLedger>) -> Self {
        Self { ledger }
    }
}

#[async_trait]
impl SourceRuntimeRegistryAuthority for PostgresSourceRuntimeRegistry {
    async fn put(
        &self,
        tenant_id: &TenantId,
        runtime_id: &str,
        request: PutSourceRuntimeRequest,
    ) -> Result<SourceRuntimeResponse, SourceRuntimeRegistryFailure> {
        let (runtime_id, input) = admit_put_identity(tenant_id, runtime_id, request)?;
        let existing = self
            .ledger
            .find_source_runtime(&runtime_id)
            .await
            .map_err(runtime_unavailable)?;
        if existing
            .as_ref()
            .is_some_and(|runtime| runtime.tenant_id() != tenant_id)
        {
            return Err(not_found());
        }
        let source_id = input.source_id.trim().to_owned();
        if existing
            .as_ref()
            .is_some_and(|runtime| runtime.source_id() != source_id)
        {
            return Err(invalid_request(
                "An existing source runtime cannot change its source ID.",
            ));
        }
        reject_caller_owned_progress(&input)?;
        let config = admit_config(input.config, existing.as_ref())?;
        let (checkpoint, next_cursor, last_synced_at) =
            preserved_progress(existing.as_ref(), &config);
        let runtime = StoredSourceRuntime::new(
            runtime_id,
            tenant_id.clone(),
            source_id,
            config,
            checkpoint,
            next_cursor,
            last_synced_at,
        )
        .map_err(invalid_request)?;
        let stored = self
            .ledger
            .put_source_runtime(&runtime, existing.as_ref())
            .await
            .map_err(runtime_unavailable)?;
        if !stored {
            let current = self
                .ledger
                .find_source_runtime(runtime.runtime_id())
                .await
                .map_err(runtime_unavailable)?;
            if current
                .as_ref()
                .is_some_and(|runtime| runtime.tenant_id() != tenant_id)
            {
                return Err(not_found());
            }
            return Err(registry_conflict());
        }
        Ok(SourceRuntimeResponse {
            runtime: runtime_view(&runtime),
        })
    }

    async fn get(
        &self,
        tenant_id: &TenantId,
        runtime_id: &str,
    ) -> Result<SourceRuntimeResponse, SourceRuntimeRegistryFailure> {
        let runtime_id = parse_runtime_id(runtime_id)?;
        let runtime = self
            .ledger
            .find_source_runtime(&runtime_id)
            .await
            .map_err(runtime_unavailable)?
            .filter(|runtime| runtime.tenant_id() == tenant_id)
            .ok_or_else(not_found)?;
        Ok(SourceRuntimeResponse {
            runtime: runtime_view(&runtime),
        })
    }

    async fn list(
        &self,
        tenant_id: &TenantId,
        query: SourceRuntimeListQuery,
    ) -> Result<SourceRuntimeListResponse, SourceRuntimeRegistryFailure> {
        let plan = plan_list_query(&query)?;
        let runtimes = self
            .ledger
            .list_source_runtimes(
                tenant_id,
                plan.source_id.as_deref(),
                &plan.runtime_ids,
                plan.limit,
            )
            .await
            .map_err(runtime_unavailable)?;
        Ok(SourceRuntimeListResponse {
            runtimes: runtimes.iter().map(runtime_view).collect(),
        })
    }
}

fn runtime_ids(
    query: &SourceRuntimeListQuery,
) -> Result<Vec<SourceRuntimeId>, SourceRuntimeRegistryFailure> {
    let mut values = Vec::new();
    if let Some(runtime_id) = query.runtime_id.as_deref() {
        values.push(runtime_id);
    }
    if let Some(runtime_ids) = query.runtime_ids.as_deref() {
        values.extend(runtime_ids.split(','));
    }
    if values.len() > MAX_RUNTIME_IDS {
        return Err(invalid_request(
            "runtime_ids cannot include more than 500 values.",
        ));
    }
    let mut parsed = BTreeMap::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let runtime_id = parse_runtime_id(value)?;
        parsed.insert(runtime_id.as_str().to_owned(), runtime_id);
    }
    Ok(parsed.into_values().collect())
}

fn admit_config(
    incoming: BTreeMap<String, String>,
    existing: Option<&StoredSourceRuntime>,
) -> Result<BTreeMap<String, String>, SourceRuntimeRegistryFailure> {
    let mut admitted = BTreeMap::new();
    for (key, value) in incoming {
        if key.trim() != key || key.starts_with("__cerebro_") || key == RESOURCE_SCOPE_CONFIG_KEY {
            return Err(invalid_request(
                "Source runtime config contains a reserved or malformed key.",
            ));
        }
        if sensitive_config_key(&key) {
            if value == REDACTED_VALUE {
                let preserved = existing
                    .and_then(|runtime| runtime.config().get(&key))
                    .ok_or_else(|| {
                        invalid_request(
                            "A redacted credential can only preserve an existing value.",
                        )
                    })?;
                admitted.insert(key, preserved.clone());
                continue;
            }
            if !supported_secret_reference(&value) {
                return Err(invalid_request(
                    "Sensitive source runtime config must use an approved credential reference.",
                ));
            }
        }
        admitted.insert(key, value);
    }
    if let Some(existing) = existing {
        admitted.extend(
            existing
                .config()
                .iter()
                .filter(|(key, _)| {
                    key.starts_with("__cerebro_") || key.as_str() == RESOURCE_SCOPE_CONFIG_KEY
                })
                .map(|(key, value)| (key.clone(), value.clone())),
        );
    }
    Ok(admitted)
}

fn supported_secret_reference(value: &str) -> bool {
    let value = value.trim();
    valid_environment_reference(value)
        || parse_credential_reference(value).is_some()
        || parse_aws_secret_reference(value).is_ok_and(|reference| reference.is_some())
}

fn valid_environment_reference(value: &str) -> bool {
    let Some(name) = value.strip_prefix("env:").map(str::trim) else {
        return false;
    };
    !name.is_empty()
        && name.len() <= 256
        && name.chars().all(|character| {
            character == '_' || character.is_ascii_uppercase() || character.is_ascii_digit()
        })
}

fn sensitive_config_key(key: &str) -> bool {
    let value = key.trim().to_ascii_lowercase();
    if value.is_empty() {
        return false;
    }
    if value.contains("token") || value.contains("secret") || value.contains("password") {
        return true;
    }
    let compact = value.replace(['_', '-', '.'], "");
    compact.contains("apikey")
        || compact.contains("privatekey")
        || compact.contains("accesskey")
        || compact.contains("signingkey")
        || compact == "key"
}

fn runtime_view(runtime: &StoredSourceRuntime) -> SourceRuntimeView {
    let config = runtime
        .config()
        .iter()
        .filter_map(|(key, value)| {
            if key.starts_with("__cerebro_") || key == RESOURCE_SCOPE_CONFIG_KEY {
                return None;
            }
            Some((
                key.clone(),
                if sensitive_config_key(key) {
                    REDACTED_VALUE.to_owned()
                } else {
                    value.clone()
                },
            ))
        })
        .collect();
    SourceRuntimeView {
        id: runtime.runtime_id().as_str().to_owned(),
        source_id: runtime.source_id().to_owned(),
        tenant_id: runtime.tenant_id().as_str().to_owned(),
        config,
        checkpoint: runtime.checkpoint().cloned(),
        next_cursor: runtime.next_cursor().cloned(),
        last_synced_at: runtime.last_synced_at().map(str::to_owned),
    }
}

fn parse_runtime_id(value: &str) -> Result<SourceRuntimeId, SourceRuntimeRegistryFailure> {
    SourceRuntimeId::parse(value.trim().to_owned()).map_err(invalid_request)
}

fn invalid_request(error: impl fmt::Display) -> SourceRuntimeRegistryFailure {
    SourceRuntimeRegistryFailure::new(
        SourceRuntimeRegistryFailureKind::InvalidRequest,
        error.to_string(),
    )
}

fn runtime_unavailable(error: impl fmt::Display) -> SourceRuntimeRegistryFailure {
    SourceRuntimeRegistryFailure::new(
        SourceRuntimeRegistryFailureKind::RuntimeUnavailable,
        error.to_string(),
    )
}

fn not_found() -> SourceRuntimeRegistryFailure {
    SourceRuntimeRegistryFailure::new(
        SourceRuntimeRegistryFailureKind::NotFound,
        "source runtime was not found for authenticated tenant",
    )
}

fn registry_conflict() -> SourceRuntimeRegistryFailure {
    SourceRuntimeRegistryFailure::new(
        SourceRuntimeRegistryFailureKind::Conflict,
        "source runtime changed or acquired a lease during the registry update",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(config: BTreeMap<String, String>) -> StoredSourceRuntime {
        StoredSourceRuntime::new(
            SourceRuntimeId::parse("runtime-a").unwrap(),
            TenantId::parse("tenant-a").unwrap(),
            "github".to_owned(),
            config,
            None,
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn runtime_view_redacts_sensitive_config_and_omits_internal_state() {
        let runtime = stored(BTreeMap::from([
            ("apiKey".to_owned(), "credential:cred-a:token".to_owned()),
            ("family".to_owned(), "users".to_owned()),
            ("__cerebro_runtime_status".to_owned(), "healthy".to_owned()),
        ]));
        let view = runtime_view(&runtime);
        assert_eq!(
            view.config.get("apiKey").map(String::as_str),
            Some(REDACTED_VALUE)
        );
        assert_eq!(view.config.get("family").map(String::as_str), Some("users"));
        assert!(!view.config.contains_key("__cerebro_runtime_status"));
    }

    #[test]
    fn config_admission_rejects_literals_and_preserves_redacted_updates() {
        let existing = stored(BTreeMap::from([(
            "token".to_owned(),
            "credential:cred-a:token".to_owned(),
        )]));
        assert!(
            admit_config(
                BTreeMap::from([("token".to_owned(), "literal".to_owned())]),
                None
            )
            .is_err()
        );
        let admitted = admit_config(
            BTreeMap::from([("token".to_owned(), REDACTED_VALUE.to_owned())]),
            Some(&existing),
        )
        .unwrap();
        assert_eq!(admitted.get("token"), existing.config().get("token"));
    }

    #[test]
    fn runtime_id_filters_are_bounded_deduplicated_and_sorted() {
        let ids = runtime_ids(&SourceRuntimeListQuery {
            runtime_id: Some("runtime-b".to_owned()),
            runtime_ids: Some("runtime-a,runtime-b".to_owned()),
            ..SourceRuntimeListQuery::default()
        })
        .unwrap();
        assert_eq!(
            ids.iter().map(SourceRuntimeId::as_str).collect::<Vec<_>>(),
            vec!["runtime-a", "runtime-b"]
        );
    }

    #[test]
    fn concurrent_registry_update_has_a_distinct_retryable_conflict() {
        assert_eq!(
            registry_conflict().kind(),
            SourceRuntimeRegistryFailureKind::Conflict
        );
    }

    #[test]
    fn registry_failure_helpers_preserve_safe_distinct_states() {
        for (failure, kind, detail) in [
            (
                invalid_request("invalid request"),
                SourceRuntimeRegistryFailureKind::InvalidRequest,
                "invalid request",
            ),
            (
                runtime_unavailable("runtime offline"),
                SourceRuntimeRegistryFailureKind::RuntimeUnavailable,
                "runtime offline",
            ),
            (
                not_found(),
                SourceRuntimeRegistryFailureKind::NotFound,
                "source runtime was not found for authenticated tenant",
            ),
        ] {
            assert_eq!(failure.kind(), kind);
            assert_eq!(failure.to_string(), detail);
        }
    }

    #[test]
    fn runtime_id_filters_reject_invalid_and_oversized_inputs() {
        assert!(
            runtime_ids(&SourceRuntimeListQuery {
                runtime_id: Some(" invalid runtime ".to_owned()),
                ..SourceRuntimeListQuery::default()
            })
            .is_err()
        );

        let oversized = (0..=MAX_RUNTIME_IDS)
            .map(|index| format!("runtime-{index}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            runtime_ids(&SourceRuntimeListQuery {
                runtime_ids: Some(oversized),
                ..SourceRuntimeListQuery::default()
            })
            .is_err()
        );

        let empty = runtime_ids(&SourceRuntimeListQuery {
            runtime_id: Some(" ".to_owned()),
            runtime_ids: Some(",, ".to_owned()),
            ..SourceRuntimeListQuery::default()
        })
        .unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn list_plan_bounds_limit_ids_and_normalizes_source_filter() {
        for limit in [0, MAX_LIST_LIMIT + 1] {
            assert!(
                plan_list_query(&SourceRuntimeListQuery {
                    limit: Some(limit),
                    ..SourceRuntimeListQuery::default()
                })
                .is_err()
            );
        }
        let plan = plan_list_query(&SourceRuntimeListQuery {
            runtime_ids: Some("runtime-b,runtime-a".to_owned()),
            source_id: Some(" github ".to_owned()),
            ..SourceRuntimeListQuery::default()
        })
        .unwrap();
        assert_eq!(plan.limit, DEFAULT_LIST_LIMIT);
        assert_eq!(plan.source_id.as_deref(), Some("github"));
        assert_eq!(
            plan.runtime_ids
                .iter()
                .map(SourceRuntimeId::as_str)
                .collect::<Vec<_>>(),
            vec!["runtime-a", "runtime-b"]
        );
        let empty_source = plan_list_query(&SourceRuntimeListQuery {
            source_id: Some(" ".to_owned()),
            limit: Some(MAX_LIST_LIMIT),
            ..SourceRuntimeListQuery::default()
        })
        .unwrap();
        assert!(empty_source.source_id.is_none());
    }

    fn put_input() -> SourceRuntimeInput {
        SourceRuntimeInput {
            id: "runtime-a".to_owned(),
            source_id: "github".to_owned(),
            tenant_id: "tenant-a".to_owned(),
            config: BTreeMap::new(),
            checkpoint: None,
            next_cursor: None,
            last_synced_at: None,
        }
    }

    #[test]
    fn put_identity_requires_matching_path_body_and_authenticated_tenant() {
        let tenant = TenantId::parse("tenant-a").unwrap();
        let (runtime_id, input) = admit_put_identity(
            &tenant,
            "runtime-a",
            PutSourceRuntimeRequest {
                runtime: Some(put_input()),
            },
        )
        .unwrap();
        assert_eq!(runtime_id.as_str(), "runtime-a");
        assert_eq!(input.source_id, "github");

        assert!(
            admit_put_identity(
                &tenant,
                "",
                PutSourceRuntimeRequest {
                    runtime: Some(put_input()),
                },
            )
            .is_err()
        );
        assert!(
            admit_put_identity(
                &tenant,
                "runtime-a",
                PutSourceRuntimeRequest { runtime: None },
            )
            .is_err()
        );

        let mut wrong_id = put_input();
        wrong_id.id = "runtime-b".to_owned();
        assert!(
            admit_put_identity(
                &tenant,
                "runtime-a",
                PutSourceRuntimeRequest {
                    runtime: Some(wrong_id),
                },
            )
            .is_err()
        );

        let mut wrong_tenant = put_input();
        wrong_tenant.tenant_id = "tenant-b".to_owned();
        let error = admit_put_identity(
            &tenant,
            "runtime-a",
            PutSourceRuntimeRequest {
                runtime: Some(wrong_tenant),
            },
        )
        .err()
        .unwrap();
        assert_eq!(
            error.kind(),
            SourceRuntimeRegistryFailureKind::TenantMismatch
        );
    }

    #[test]
    fn put_admission_rejects_every_caller_owned_progress_field() {
        assert!(reject_caller_owned_progress(&put_input()).is_ok());
        for input in [
            SourceRuntimeInput {
                checkpoint: Some(serde_json::json!({"offset": 1})),
                ..put_input()
            },
            SourceRuntimeInput {
                next_cursor: Some(serde_json::json!({"cursor": "next"})),
                ..put_input()
            },
            SourceRuntimeInput {
                last_synced_at: Some("2026-08-25T00:00:00Z".to_owned()),
                ..put_input()
            },
        ] {
            assert!(reject_caller_owned_progress(&input).is_err());
        }
    }

    #[test]
    fn unchanged_config_preserves_progress_while_config_changes_reset_it() {
        let config = BTreeMap::from([("family".to_owned(), "users".to_owned())]);
        let runtime = StoredSourceRuntime::new(
            SourceRuntimeId::parse("runtime-progress-plan").unwrap(),
            TenantId::parse("tenant-progress-plan").unwrap(),
            "github".to_owned(),
            config.clone(),
            Some(serde_json::json!({"offset": 7})),
            Some(serde_json::json!({"cursor": "next"})),
            Some("2026-08-25T00:00:00Z".to_owned()),
        )
        .unwrap();
        let preserved = preserved_progress(Some(&runtime), &config);
        assert_eq!(preserved.0, Some(serde_json::json!({"offset": 7})));
        assert_eq!(preserved.1, Some(serde_json::json!({"cursor": "next"})));
        assert_eq!(preserved.2.as_deref(), Some("2026-08-25T00:00:00Z"));

        let changed = BTreeMap::from([("family".to_owned(), "groups".to_owned())]);
        assert_eq!(
            preserved_progress(Some(&runtime), &changed),
            (None, None, None)
        );
        assert_eq!(preserved_progress(None, &config), (None, None, None));
    }

    #[test]
    fn config_admission_rejects_reserved_keys_and_redacted_new_credentials() {
        for key in [
            " malformed ",
            "__cerebro_internal",
            RESOURCE_SCOPE_CONFIG_KEY,
        ] {
            assert!(
                admit_config(BTreeMap::from([(key.to_owned(), "value".to_owned())]), None).is_err()
            );
        }
        assert!(
            admit_config(
                BTreeMap::from([("access_token".to_owned(), REDACTED_VALUE.to_owned())]),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn config_admission_accepts_only_supported_secret_reference_forms() {
        for reference in [
            "env:PROVIDER_TOKEN",
            "credential:provider-test:token",
            "aws-sm://provider-test/token",
        ] {
            assert!(
                admit_config(
                    BTreeMap::from([("token".to_owned(), reference.to_owned())]),
                    None,
                )
                .is_ok(),
                "reference {reference}"
            );
        }
        for invalid in [
            "env:",
            "env:lowercase",
            "env:PROVIDER-TOKEN",
            "env:PROVIDER/TOKEN",
            "literal",
        ] {
            assert!(!supported_secret_reference(invalid), "reference {invalid}");
        }
    }

    #[test]
    fn config_admission_preserves_runtime_owned_internal_state() {
        let existing = stored(BTreeMap::from([
            ("__cerebro_runtime_status".to_owned(), "healthy".to_owned()),
            (RESOURCE_SCOPE_CONFIG_KEY.to_owned(), "tenant".to_owned()),
            ("family".to_owned(), "users".to_owned()),
        ]));
        let admitted = admit_config(
            BTreeMap::from([("family".to_owned(), "groups".to_owned())]),
            Some(&existing),
        )
        .unwrap();
        assert_eq!(admitted.get("family").map(String::as_str), Some("groups"));
        assert_eq!(
            admitted.get("__cerebro_runtime_status").map(String::as_str),
            Some("healthy")
        );
        assert_eq!(
            admitted.get(RESOURCE_SCOPE_CONFIG_KEY).map(String::as_str),
            Some("tenant")
        );
    }

    #[test]
    fn sensitive_key_detection_is_conservative_without_overmatching_plain_keys() {
        for key in [
            "token",
            "client_secret",
            "password",
            "api-key",
            "private.key",
            "access_key",
            "signing-key",
            "key",
        ] {
            assert!(sensitive_config_key(key), "key {key}");
        }
        for key in ["", "family", "keyboard_layout", "monkey"] {
            assert!(!sensitive_config_key(key), "key {key}");
        }
    }

    #[test]
    fn runtime_view_preserves_progress_and_redacts_every_sensitive_shape() {
        let runtime = StoredSourceRuntime::new(
            SourceRuntimeId::parse("runtime-progress").unwrap(),
            TenantId::parse("tenant-progress").unwrap(),
            "github".to_owned(),
            BTreeMap::from([
                ("private-key".to_owned(), "env:PRIVATE_KEY".to_owned()),
                ("family".to_owned(), "users".to_owned()),
                (RESOURCE_SCOPE_CONFIG_KEY.to_owned(), "tenant".to_owned()),
            ]),
            Some(serde_json::json!({"offset": 2})),
            Some(serde_json::json!({"cursor": "next"})),
            Some("2026-08-25T00:00:00Z".to_owned()),
        )
        .unwrap();
        let view = runtime_view(&runtime);
        assert_eq!(view.id, "runtime-progress");
        assert_eq!(view.source_id, "github");
        assert_eq!(view.tenant_id, "tenant-progress");
        assert_eq!(
            view.config.get("private-key").map(String::as_str),
            Some(REDACTED_VALUE)
        );
        assert!(!view.config.contains_key(RESOURCE_SCOPE_CONFIG_KEY));
        assert_eq!(view.checkpoint, Some(serde_json::json!({"offset": 2})));
        assert_eq!(
            view.next_cursor,
            Some(serde_json::json!({"cursor": "next"}))
        );
        assert_eq!(view.last_synced_at.as_deref(), Some("2026-08-25T00:00:00Z"));
    }
}
