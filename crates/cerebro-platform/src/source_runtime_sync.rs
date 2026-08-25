//! Tenant-bound source-runtime synchronization served by the Rust platform.

use std::{error::Error, fmt, sync::Arc};

use async_trait::async_trait;
use cerebro_organizational_graph::GraphWriteReceipt;
use cerebro_organizational_model::{SourceRuntimeId, TenantId};
use cerebro_organizational_store::{DurableGraphStore, Neo4jProjector, PostgresLedger};
use cerebro_source_runtime_next::{
    CatalogGraphMapper, CollectionRequest, CredentialLeaseReference, EgressPolicy,
    EgressRequestContext, HttpProviderAccess, HttpSourceConnector, OperationScopedCredentialLease,
    RuntimeError, SourceRuntime, SourceRuntimeOperation, canonical_digest,
    contains_aws_secret_references, contains_credential_references, resolve_aws_secret_references,
    resolve_environment_references,
};
use serde::Serialize;
use time::OffsetDateTime;
use zeroize::Zeroize;

use super::{
    AwsSecretsManagerReader, CatalogAuthSettings, load_catalog, required_config, required_env,
    required_secret_env_or_file, resolved_auth, source_config_environment_allowlist,
    source_runtime_lease_owner, source_runtime_lease_ttl_millis,
    start_source_runtime_lease_renewal,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceRuntimeSyncFailureKind {
    InvalidRequest,
    NotFound,
    Conflict,
    ProviderUnavailable,
    RuntimeUnavailable,
}

#[derive(Debug)]
pub(crate) struct SourceRuntimeSyncFailure {
    kind: SourceRuntimeSyncFailureKind,
    detail: String,
}

impl SourceRuntimeSyncFailure {
    pub(crate) fn new(kind: SourceRuntimeSyncFailureKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    pub(crate) fn kind(&self) -> SourceRuntimeSyncFailureKind {
        self.kind
    }
}

impl fmt::Display for SourceRuntimeSyncFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl Error for SourceRuntimeSyncFailure {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct SourceRuntimeSyncReceipt {
    pub(crate) runtime_id: String,
    pub(crate) source_id: String,
    pub(crate) family_id: String,
    pub(crate) graph: GraphWriteReceipt,
}

#[async_trait]
pub(crate) trait SourceRuntimeSyncAuthority: Send + Sync {
    async fn sync(
        &self,
        tenant_id: &TenantId,
        runtime_id: &str,
    ) -> Result<SourceRuntimeSyncReceipt, SourceRuntimeSyncFailure>;
}

#[derive(Default)]
pub(crate) struct EnvironmentSourceRuntimeSync;

#[async_trait]
impl SourceRuntimeSyncAuthority for EnvironmentSourceRuntimeSync {
    async fn sync(
        &self,
        tenant_id: &TenantId,
        runtime_id: &str,
    ) -> Result<SourceRuntimeSyncReceipt, SourceRuntimeSyncFailure> {
        let runtime_id = SourceRuntimeId::parse(runtime_id.to_owned()).map_err(|error| {
            SourceRuntimeSyncFailure::new(
                SourceRuntimeSyncFailureKind::InvalidRequest,
                error.to_string(),
            )
        })?;
        sync_stored_runtime(runtime_id, Some(tenant_id)).await
    }
}

pub(crate) async fn sync_from_environment() -> Result<(), Box<dyn Error>> {
    let runtime_id = SourceRuntimeId::parse(required_env("CEREBRO_SOURCE_RUNTIME_ID")?)?;
    let receipt = sync_stored_runtime(runtime_id, None)
        .await
        .map_err(|error| -> Box<dyn Error> { Box::new(error) })?;
    println!("{}", serde_json::to_string_pretty(&receipt.graph)?);
    Ok(())
}

async fn sync_stored_runtime(
    runtime_id: SourceRuntimeId,
    expected_tenant: Option<&TenantId>,
) -> Result<SourceRuntimeSyncReceipt, SourceRuntimeSyncFailure> {
    let postgres_dsn = required_env("CEREBRO_POSTGRES_DSN").map_err(runtime_unavailable)?;
    let lease_ledger = Arc::new(
        PostgresLedger::connect_tls(&postgres_dsn)
            .await
            .map_err(runtime_unavailable)?,
    );
    lease_ledger.migrate().await.map_err(runtime_unavailable)?;
    let stored_runtime = lease_ledger
        .find_source_runtime(&runtime_id)
        .await
        .map_err(runtime_unavailable)?
        .ok_or_else(source_runtime_not_found)?;
    if expected_tenant.is_some_and(|tenant| tenant != stored_runtime.tenant_id()) {
        return Err(source_runtime_not_found());
    }
    let tenant_id = stored_runtime.tenant_id().clone();
    let source_id = stored_runtime.source_id().to_owned();
    let cursor = stored_runtime.cursor().map(str::to_owned);
    let mut config = resolve_environment_references(
        &source_id,
        stored_runtime.config(),
        &source_config_environment_allowlist(),
        |name| std::env::var(name).ok(),
    )
    .map_err(invalid_request)?;
    if contains_credential_references(&config) {
        let mut vault_key = required_secret_env_or_file("CEREBRO_CONNECTOR_CREDENTIAL_KEY")
            .map_err(runtime_unavailable)?;
        let resolved = lease_ledger
            .resolve_connector_credential_references(&stored_runtime, &config, &vault_key)
            .await;
        vault_key.zeroize();
        config = resolved.map_err(runtime_unavailable)?;
    }
    if contains_aws_secret_references(&config) {
        let reader = AwsSecretsManagerReader::from_env().map_err(runtime_unavailable)?;
        config = resolve_aws_secret_references(
            tenant_id.as_str(),
            &source_id,
            runtime_id.as_str(),
            &config,
            &reader,
        )
        .await
        .map_err(runtime_unavailable)?;
    }
    let family_id = required_config(&config, "family").map_err(invalid_request)?;
    let base_url = required_config(&config, "base_url").map_err(invalid_request)?;

    let catalog = load_catalog().map_err(runtime_unavailable)?;
    let source = catalog
        .get(&source_id)
        .ok_or_else(|| {
            SourceRuntimeSyncFailure::new(
                SourceRuntimeSyncFailureKind::InvalidRequest,
                format!("source {source_id} is not in the catalog"),
            )
        })?
        .clone();
    let auth = resolved_auth(
        source.auth(),
        CatalogAuthSettings::from_source(&source),
        &mut config,
    )
    .map_err(invalid_request)?;
    let lease_ttl_millis = source_runtime_lease_ttl_millis().map_err(invalid_request)?;
    let lease_owner = source_runtime_lease_owner();
    let fence = lease_ledger
        .acquire_source_runtime_lease(&tenant_id, &runtime_id, &lease_owner, lease_ttl_millis)
        .await
        .map_err(runtime_unavailable)?
        .ok_or_else(|| {
            SourceRuntimeSyncFailure::new(
                SourceRuntimeSyncFailureKind::Conflict,
                "source runtime is already leased",
            )
        })?;
    let (stop_renewal, renewal_failure, renewal_task) =
        start_source_runtime_lease_renewal(lease_ledger.clone(), fence.clone(), lease_ttl_millis);
    let mut renewal_failure = renewal_failure;
    let outcome = {
        let execution = async {
            let request_intent_digest = canonical_digest(&serde_json::json!({
                "operation": "ReadPage",
                "tenant_id": tenant_id.as_str(),
                "runtime_id": runtime_id.as_str(),
                "source_id": source_id,
                "family_id": family_id,
                "cursor": cursor,
                "lease_generation": fence.generation(),
            }));
            let access_context = EgressRequestContext {
                tenant_id: tenant_id.as_str().to_owned(),
                runtime_id: runtime_id.as_str().to_owned(),
                source_id: source_id.clone(),
                family_id: family_id.clone(),
                operation: SourceRuntimeOperation::ReadPage,
                request_intent_digest: request_intent_digest.clone(),
                logical_page_id: format!(
                    "page:{}:{}:{}",
                    runtime_id.as_str(),
                    family_id,
                    fence.generation()
                ),
                source_generation: fence.generation(),
                authority_epoch: 1,
            };
            let lease_scope = access_context.lease_scope().map_err(invalid_request)?;
            let issued_at_millis =
                i64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
                    .map_err(invalid_request)?;
            let credential_lease_ttl_millis =
                i64::try_from(lease_ttl_millis).map_err(invalid_request)?;
            let credential_lease = OperationScopedCredentialLease::new(
                CredentialLeaseReference::new(
                    format!("lease:{}", &request_intent_digest[..16]),
                    lease_scope,
                    issued_at_millis,
                    credential_lease_ttl_millis,
                )
                .map_err(invalid_request)?,
            );
            let mut allowed_origins = vec![base_url.clone()];
            if let Some(token_url) = auth.oauth_token_url() {
                allowed_origins.push(token_url.to_owned());
            }
            let egress_policy = EgressPolicy::live(
                tenant_id.as_str(),
                &family_id,
                &request_intent_digest,
                allowed_origins,
            )
            .map_err(invalid_request)?;
            let connector =
                HttpSourceConnector::new(source.clone(), &family_id, &base_url, config, auth)
                    .map_err(invalid_request)?
                    .with_provider_access(HttpProviderAccess::new(
                        access_context,
                        egress_policy,
                        credential_lease,
                    ));

            let ledger = PostgresLedger::connect_tls(&postgres_dsn)
                .await
                .map_err(runtime_unavailable)?;
            ledger.migrate().await.map_err(runtime_unavailable)?;
            let identity_resolution = ledger
                .identity_resolution_snapshot(&tenant_id)
                .await
                .map_err(runtime_unavailable)?;
            let mapper = CatalogGraphMapper::new(source, env!("CARGO_PKG_VERSION"))
                .map_err(invalid_request)?
                .with_identity_resolution(identity_resolution);
            let neo4j_uri = required_env("CEREBRO_NEO4J_URI").map_err(runtime_unavailable)?;
            let neo4j_username =
                required_env("CEREBRO_NEO4J_USERNAME").map_err(runtime_unavailable)?;
            let neo4j_password =
                required_env("CEREBRO_NEO4J_PASSWORD").map_err(runtime_unavailable)?;
            let projector = Neo4jProjector::connect(&neo4j_uri, &neo4j_username, &neo4j_password)
                .await
                .map_err(runtime_unavailable)?;
            projector.migrate().await.map_err(runtime_unavailable)?;
            let store = DurableGraphStore::new(ledger, projector);
            let mut runtime = SourceRuntime::new(connector, mapper, store);
            let request = CollectionRequest {
                tenant_id,
                source_runtime_id: runtime_id.clone(),
                cursor,
            };
            runtime
                .sync_fenced(request, &fence)
                .await
                .map_err(|error| match error {
                    RuntimeError::Collect(error) => SourceRuntimeSyncFailure::new(
                        SourceRuntimeSyncFailureKind::ProviderUnavailable,
                        error.to_string(),
                    ),
                    RuntimeError::ScopeMismatch => SourceRuntimeSyncFailure::new(
                        SourceRuntimeSyncFailureKind::InvalidRequest,
                        "source runtime scope does not match the collected batch",
                    ),
                    RuntimeError::Map(error) => SourceRuntimeSyncFailure::new(
                        SourceRuntimeSyncFailureKind::InvalidRequest,
                        error.to_string(),
                    ),
                    RuntimeError::Store(error) => SourceRuntimeSyncFailure::new(
                        SourceRuntimeSyncFailureKind::RuntimeUnavailable,
                        error.to_string(),
                    ),
                })
        };
        tokio::pin!(execution);
        tokio::select! {
            biased;
            result = &mut execution => result,
            failure = &mut renewal_failure => Err(SourceRuntimeSyncFailure::new(
                SourceRuntimeSyncFailureKind::Conflict,
                failure.unwrap_or_else(|_| {
                    "source runtime lease renewal stopped unexpectedly".to_owned()
                }),
            )),
        }
    };
    let _ = stop_renewal.send(());
    if let Err(error) = renewal_task.await {
        eprintln!("source runtime lease renewal task failed after commit: {error}");
    }
    match lease_ledger.release_source_runtime_lease(&fence).await {
        Ok(true) => {}
        Ok(false) => {
            eprintln!(
                "source runtime lease changed before release; the successor lease was preserved"
            )
        }
        Err(error) => eprintln!("source runtime lease release failed after commit: {error}"),
    }
    let graph = outcome?;
    Ok(SourceRuntimeSyncReceipt {
        runtime_id: runtime_id.as_str().to_owned(),
        source_id,
        family_id,
        graph,
    })
}

fn invalid_request(error: impl fmt::Display) -> SourceRuntimeSyncFailure {
    SourceRuntimeSyncFailure::new(
        SourceRuntimeSyncFailureKind::InvalidRequest,
        error.to_string(),
    )
}

fn runtime_unavailable(error: impl fmt::Display) -> SourceRuntimeSyncFailure {
    SourceRuntimeSyncFailure::new(
        SourceRuntimeSyncFailureKind::RuntimeUnavailable,
        error.to_string(),
    )
}

fn source_runtime_not_found() -> SourceRuntimeSyncFailure {
    SourceRuntimeSyncFailure::new(
        SourceRuntimeSyncFailureKind::NotFound,
        "source runtime is not stored",
    )
}
