#![forbid(unsafe_code)]

//! Rust-native source collection and graph admission boundary.

mod append_log;
mod http;
mod mapper;

pub use append_log::{AppendLogDecodeError, CommittedSourceEvent, CommittedSourceInput};
pub use http::{HttpConnectorError, HttpSourceConnector, ResolvedAuth};
pub use mapper::{CatalogGraphMapper, CatalogMapperError, IdentityResolutionSnapshot};

use std::{collections::BTreeMap, error::Error, fmt};

use async_trait::async_trait;
use cerebro_organizational_graph::{GraphError, GraphWriteReceipt, OrganizationalGraph};
use cerebro_organizational_model::{
    CollectionReceipt, CompleteCollection, GraphDelta, ObservationId, SourceRuntimeId, TenantId,
};
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CollectionRequest {
    pub tenant_id: TenantId,
    pub source_runtime_id: SourceRuntimeId,
    pub cursor: Option<String>,
}

/// A durable database fence for one source-runtime execution.
///
/// The generation changes whenever lease ownership changes. A provider result
/// may commit only while the exact tenant, runtime, owner, and generation still
/// hold the source-runtime row. The database remains the authority; this value
/// contains no credential material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRuntimeLeaseFence {
    tenant_id: TenantId,
    source_runtime_id: SourceRuntimeId,
    owner: String,
    generation: u64,
}

impl SourceRuntimeLeaseFence {
    pub fn new(
        tenant_id: TenantId,
        source_runtime_id: SourceRuntimeId,
        owner: impl Into<String>,
        generation: u64,
    ) -> Result<Self, &'static str> {
        let owner = owner.into();
        if owner.is_empty()
            || owner.trim() != owner
            || owner.len() > 255
            || owner.chars().any(char::is_control)
        {
            return Err("source runtime lease owner is invalid");
        }
        if generation == 0 {
            return Err("source runtime lease generation must be positive");
        }
        Ok(Self {
            tenant_id,
            source_runtime_id,
            owner,
            generation,
        })
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn source_runtime_id(&self) -> &SourceRuntimeId {
        &self.source_runtime_id
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceRecord {
    pub observation_id: ObservationId,
    pub family: String,
    pub provider_kind: String,
    pub provider_id: String,
    pub fields: BTreeMap<String, String>,
    pub payload: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "collection_mode", rename_all = "snake_case")]
pub enum CollectedScope {
    Complete(CompleteCollection),
    NonAuthoritative(CollectionReceipt),
}

impl CollectedScope {
    pub fn receipt(&self) -> &CollectionReceipt {
        match self {
            Self::Complete(value) => value.receipt(),
            Self::NonAuthoritative(value) => value,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CollectedBatch {
    pub scope: CollectedScope,
    pub records: Vec<SourceRecord>,
    pub next_cursor: Option<String>,
}

#[async_trait]
pub trait SourceConnector: Send {
    type Error: Error + Send + Sync + 'static;

    async fn collect(&mut self, request: CollectionRequest) -> Result<CollectedBatch, Self::Error>;
}

pub trait GraphMapper {
    type Error: Error + Send + Sync + 'static;

    /// Mapping returns a domain-validated `GraphDelta`. No unvalidated entity
    /// or relationship wire type crosses into the graph engine.
    fn map(&self, batch: &CollectedBatch) -> Result<GraphDelta, Self::Error>;
}

#[async_trait]
pub trait GraphSink: Send {
    type Error: Error + Send + Sync + 'static;

    async fn apply(
        &mut self,
        batch: &CollectedBatch,
        delta: GraphDelta,
    ) -> Result<GraphWriteReceipt, Self::Error>;
}

#[async_trait]
pub trait FencedGraphSink: GraphSink {
    /// Commit only while the exact durable source-runtime lease still exists.
    async fn apply_fenced(
        &mut self,
        batch: &CollectedBatch,
        delta: GraphDelta,
        fence: &SourceRuntimeLeaseFence,
    ) -> Result<GraphWriteReceipt, Self::Error>;
}

#[async_trait]
impl GraphSink for OrganizationalGraph {
    type Error = GraphError;

    async fn apply(
        &mut self,
        _batch: &CollectedBatch,
        delta: GraphDelta,
    ) -> Result<GraphWriteReceipt, Self::Error> {
        OrganizationalGraph::apply(self, delta)
    }
}

#[derive(Debug)]
pub enum RuntimeError<CollectError, MapError, StoreError> {
    Collect(CollectError),
    ScopeMismatch,
    Map(MapError),
    Store(StoreError),
}

pub type SyncError<Connector, Mapper, Store> = RuntimeError<
    <Connector as SourceConnector>::Error,
    <Mapper as GraphMapper>::Error,
    <Store as GraphSink>::Error,
>;

impl<CollectError, MapError, StoreError> fmt::Display
    for RuntimeError<CollectError, MapError, StoreError>
where
    CollectError: fmt::Display,
    MapError: fmt::Display,
    StoreError: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Collect(error) => write!(formatter, "source collection failed: {error}"),
            Self::ScopeMismatch => {
                formatter.write_str("source returned data outside the requested tenant or runtime")
            }
            Self::Map(error) => write!(formatter, "graph mapping failed: {error}"),
            Self::Store(error) => write!(formatter, "graph commit failed: {error}"),
        }
    }
}

impl<CollectError, MapError, StoreError> Error for RuntimeError<CollectError, MapError, StoreError>
where
    CollectError: Error + 'static,
    MapError: Error + 'static,
    StoreError: Error + 'static,
{
}

pub struct SourceRuntime<Connector, Mapper, Store> {
    connector: Connector,
    mapper: Mapper,
    store: Store,
}

impl<Connector, Mapper, Store> SourceRuntime<Connector, Mapper, Store>
where
    Connector: SourceConnector,
    Mapper: GraphMapper,
    Store: GraphSink,
{
    pub fn new(connector: Connector, mapper: Mapper, store: Store) -> Self {
        Self {
            connector,
            mapper,
            store,
        }
    }

    pub async fn sync(
        &mut self,
        request: CollectionRequest,
    ) -> Result<GraphWriteReceipt, SyncError<Connector, Mapper, Store>> {
        let requested_tenant = request.tenant_id.clone();
        let requested_runtime = request.source_runtime_id.clone();
        let batch = self
            .connector
            .collect(request)
            .await
            .map_err(RuntimeError::Collect)?;
        if batch.scope.receipt().tenant_id() != &requested_tenant
            || batch.scope.receipt().source_runtime_id() != &requested_runtime
        {
            return Err(RuntimeError::ScopeMismatch);
        }
        let delta = self.mapper.map(&batch).map_err(RuntimeError::Map)?;
        if delta.collection().tenant_id() != &requested_tenant
            || delta.collection().source_runtime_id() != &requested_runtime
        {
            return Err(RuntimeError::ScopeMismatch);
        }
        self.store
            .apply(&batch, delta)
            .await
            .map_err(RuntimeError::Store)
    }

    /// Collect and commit under one database-checked source-runtime lease.
    ///
    /// The fence is checked before provider I/O and again inside the durable
    /// graph transaction. Losing the lease therefore prevents a stale worker
    /// from committing provider results after another worker takes ownership.
    pub async fn sync_fenced(
        &mut self,
        request: CollectionRequest,
        fence: &SourceRuntimeLeaseFence,
    ) -> Result<GraphWriteReceipt, SyncError<Connector, Mapper, Store>>
    where
        Store: FencedGraphSink,
    {
        let requested_tenant = request.tenant_id.clone();
        let requested_runtime = request.source_runtime_id.clone();
        if fence.tenant_id() != &requested_tenant || fence.source_runtime_id() != &requested_runtime
        {
            return Err(RuntimeError::ScopeMismatch);
        }
        let batch = self
            .connector
            .collect(request)
            .await
            .map_err(RuntimeError::Collect)?;
        if batch.scope.receipt().tenant_id() != &requested_tenant
            || batch.scope.receipt().source_runtime_id() != &requested_runtime
        {
            return Err(RuntimeError::ScopeMismatch);
        }
        let delta = self.mapper.map(&batch).map_err(RuntimeError::Map)?;
        if delta.collection().tenant_id() != &requested_tenant
            || delta.collection().source_runtime_id() != &requested_runtime
        {
            return Err(RuntimeError::ScopeMismatch);
        }
        self.store
            .apply_fenced(&batch, delta, fence)
            .await
            .map_err(RuntimeError::Store)
    }

    pub fn into_store(self) -> Store {
        self.store
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        error::Error,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use cerebro_organizational_model::{
        CollectionId, Entity, EntityId, EntityKind, GraphAssertion, ModelError, ObservationId,
        ObservationRef, RelationKind, RelationshipAssertion,
    };

    use super::*;

    struct FixtureSource;

    #[async_trait]
    impl SourceConnector for FixtureSource {
        type Error = Infallible;

        async fn collect(
            &mut self,
            request: CollectionRequest,
        ) -> Result<CollectedBatch, Self::Error> {
            Ok(CollectedBatch {
                scope: CollectedScope::Complete(
                    CompleteCollection::new(
                        request.tenant_id,
                        request.source_runtime_id,
                        CollectionId::parse("collection-1").unwrap(),
                        "organization",
                        10,
                    )
                    .unwrap(),
                ),
                records: Vec::new(),
                next_cursor: None,
            })
        }
    }

    struct FixtureMapper;

    impl GraphMapper for FixtureMapper {
        type Error = ModelError;

        fn map(&self, batch: &CollectedBatch) -> Result<GraphDelta, Self::Error> {
            let CollectedScope::Complete(collection) = &batch.scope else {
                unreachable!()
            };
            let tenant = collection.receipt().tenant_id().clone();
            let team = Entity::canonical(
                tenant.clone(),
                EntityId::parse("team-1")?,
                EntityKind::Team,
                "Team",
            )?;
            let repository = Entity::canonical(
                tenant,
                EntityId::parse("repository-1")?,
                EntityKind::Repository,
                "Repository",
            )?;
            let provenance = cerebro_organizational_model::AssertionProvenance::direct(
                vec![ObservationRef::new(
                    collection.receipt(),
                    ObservationId::parse("observation-1")?,
                    "fixture",
                )?],
                "fixture-mapper",
                "v1",
            )?;
            let assertion =
                RelationshipAssertion::new(&team, RelationKind::Owns, &repository, provenance, 10)?;
            let mut builder = collection.clone().begin_delta();
            builder.add_entity(team)?;
            builder.add_entity(repository)?;
            builder.add_assertion(GraphAssertion::Relationship(assertion))?;
            Ok(builder.build())
        }
    }

    struct CountingSource(Arc<AtomicUsize>);

    #[async_trait]
    impl SourceConnector for CountingSource {
        type Error = Infallible;

        async fn collect(
            &mut self,
            request: CollectionRequest,
        ) -> Result<CollectedBatch, Self::Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            let mut source = FixtureSource;
            source.collect(request).await
        }
    }

    struct FencedFixtureStore;

    #[async_trait]
    impl GraphSink for FencedFixtureStore {
        type Error = Infallible;

        async fn apply(
            &mut self,
            _batch: &CollectedBatch,
            _delta: GraphDelta,
        ) -> Result<GraphWriteReceipt, Self::Error> {
            unreachable!("scope mismatch must fail before the store")
        }
    }

    #[async_trait]
    impl FencedGraphSink for FencedFixtureStore {
        async fn apply_fenced(
            &mut self,
            _batch: &CollectedBatch,
            _delta: GraphDelta,
            _fence: &SourceRuntimeLeaseFence,
        ) -> Result<GraphWriteReceipt, Self::Error> {
            unreachable!("scope mismatch must fail before the store")
        }
    }

    #[test]
    fn source_runtime_lease_fence_rejects_unbounded_identity() {
        let tenant = TenantId::parse("tenant-a").unwrap();
        let runtime = SourceRuntimeId::parse("runtime-a").unwrap();
        assert!(SourceRuntimeLeaseFence::new(tenant.clone(), runtime.clone(), "", 1).is_err());
        assert!(
            SourceRuntimeLeaseFence::new(tenant.clone(), runtime.clone(), " owner", 1).is_err()
        );
        assert!(SourceRuntimeLeaseFence::new(tenant.clone(), runtime.clone(), "owner", 0).is_err());
        assert_eq!(
            SourceRuntimeLeaseFence::new(tenant, runtime, "worker:one", 7)
                .unwrap()
                .generation(),
            7
        );
    }

    #[tokio::test]
    async fn mismatched_lease_fence_fails_before_provider_collection() {
        let collections = Arc::new(AtomicUsize::new(0));
        let mut runtime = SourceRuntime::new(
            CountingSource(collections.clone()),
            FixtureMapper,
            FencedFixtureStore,
        );
        let result = runtime
            .sync_fenced(
                CollectionRequest {
                    tenant_id: TenantId::parse("tenant-a").unwrap(),
                    source_runtime_id: SourceRuntimeId::parse("runtime-a").unwrap(),
                    cursor: None,
                },
                &SourceRuntimeLeaseFence::new(
                    TenantId::parse("tenant-b").unwrap(),
                    SourceRuntimeId::parse("runtime-a").unwrap(),
                    "worker:one",
                    1,
                )
                .unwrap(),
            )
            .await;
        assert!(matches!(result, Err(RuntimeError::ScopeMismatch)));
        assert_eq!(collections.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn rust_runtime_owns_collection_mapping_and_graph_commit() -> Result<(), Box<dyn Error>> {
        let mut runtime =
            SourceRuntime::new(FixtureSource, FixtureMapper, OrganizationalGraph::new());
        let receipt = runtime
            .sync(CollectionRequest {
                tenant_id: TenantId::parse("tenant-a")?,
                source_runtime_id: SourceRuntimeId::parse("github-prod")?,
                cursor: None,
            })
            .await?;
        assert_eq!(receipt.entities_upserted, 2);
        assert_eq!(receipt.assertions_upserted, 1);
        Ok(())
    }
}
