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
        if input.checkpoint.is_some()
            || input.next_cursor.is_some()
            || input.last_synced_at.is_some()
        {
            return Err(invalid_request(
                "Source runtime progress is owned by durable sync and cannot be supplied to the registry.",
            ));
        }
        let config = admit_config(input.config, existing.as_ref())?;
        let progress_is_current = existing
            .as_ref()
            .is_some_and(|runtime| runtime.config() == &config);
        let checkpoint = progress_is_current
            .then(|| {
                existing
                    .as_ref()
                    .and_then(|runtime| runtime.checkpoint().cloned())
            })
            .flatten();
        let next_cursor = progress_is_current
            .then(|| {
                existing
                    .as_ref()
                    .and_then(|runtime| runtime.next_cursor().cloned())
            })
            .flatten();
        let last_synced_at = progress_is_current
            .then(|| {
                existing
                    .as_ref()
                    .and_then(|runtime| runtime.last_synced_at().map(str::to_owned))
            })
            .flatten();
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
        let limit = query.limit.unwrap_or(DEFAULT_LIST_LIMIT);
        if limit == 0 || limit > MAX_LIST_LIMIT {
            return Err(invalid_request(
                "Source runtime list limit must be between 1 and 500.",
            ));
        }
        let runtime_ids = runtime_ids(&query)?;
        let source_id = query
            .source_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let runtimes = self
            .ledger
            .list_source_runtimes(tenant_id, source_id, &runtime_ids, limit)
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
}
