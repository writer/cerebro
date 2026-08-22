#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Rust-native source collection and graph admission boundary.

mod abnormal_security;
mod abuseipdb;
mod activecampaign;
mod activtrak;
mod acunetix;
mod ada_support;
mod amplitude;
mod anthropic;
mod append_log;
mod archetype;
// Provider-local work-management runtime kernel.
mod asana;
mod aurelius;
mod aws_account;
mod aws_codebuild;
mod aws_network_manager;
mod aws_secret_store;
mod azure;
mod cerebro_source;
mod cloudflare;
mod cosmo;
mod credential_lease;
mod deepseek;
mod deposit;
mod discord;
mod docker_hub;
mod egress;
mod email_domain_health;
mod evidence_cas;
mod fixture_parity;
mod gcp;
mod github;
mod google_workspace;
mod grc;
mod http;
mod jumpcloud;
mod kubernetes;
mod linode;
mod mapper;
mod okta;
mod openai;
mod panopticon;
mod protocol;
mod provider_failure;
mod runtime_config;
mod sdk;
mod security_tooling_map;
mod sentinelone;
mod slack;
pub mod source_execution;
mod tailscale;
mod trivy;
mod twilio;
mod vulnview;

pub use abnormal_security::{
    AbnormalSecurityCheckpointCandidate, AbnormalSecurityEntityFact, AbnormalSecurityError,
    AbnormalSecurityEventContract, AbnormalSecurityFamily, AbnormalSecurityKernel,
    AbnormalSecurityPage, AbnormalSecurityProjectionFacts, AbnormalSecurityRecord,
    AbnormalSecurityRequest, AbnormalSecurityRuntimeDefinition, project_abnormal_security_records,
};
pub use abuseipdb::{
    AbuseIpDbCheckpointCandidate, AbuseIpDbEntityFact, AbuseIpDbError, AbuseIpDbEventContract,
    AbuseIpDbFamily, AbuseIpDbFilters, AbuseIpDbKernel, AbuseIpDbPage, AbuseIpDbProjectionFacts,
    AbuseIpDbRecord, AbuseIpDbRelationFact, AbuseIpDbRequest, AbuseIpDbRuntimeDefinition,
    project_abuseipdb_records,
};
pub use activecampaign::{
    ActiveCampaignCheckpointCandidate, ActiveCampaignEntityFact, ActiveCampaignError,
    ActiveCampaignEventContract, ActiveCampaignFamily, ActiveCampaignKernel, ActiveCampaignPage,
    ActiveCampaignProjectionFacts, ActiveCampaignRecord, ActiveCampaignRequest,
    ActiveCampaignRuntimeDefinition, project_activecampaign_records,
};
pub use activtrak::{
    ActivTrakCheckpointCandidate, ActivTrakEntityFact, ActivTrakError, ActivTrakEventContract,
    ActivTrakFamily, ActivTrakKernel, ActivTrakPage, ActivTrakProjectionFacts, ActivTrakRecord,
    ActivTrakRequest, ActivTrakRuntimeDefinition, project_activtrak_records,
};
pub use acunetix::{
    AcunetixCheckpointCandidate, AcunetixEntityFact, AcunetixError, AcunetixEventContract,
    AcunetixFamily, AcunetixKernel, AcunetixPage, AcunetixProjectionFacts, AcunetixRecord,
    AcunetixRequest, AcunetixRuntimeDefinition, project_acunetix_records,
};
pub use ada_support::{
    AdaSupportCheckpointCandidate, AdaSupportEntityFact, AdaSupportError, AdaSupportEventContract,
    AdaSupportFamily, AdaSupportKernel, AdaSupportPage, AdaSupportProjectionFacts,
    AdaSupportRecord, AdaSupportRequest, AdaSupportRuntimeDefinition, project_ada_support_records,
};
pub use amplitude::{
    AmplitudeError, AmplitudeFamily, AmplitudeKernel, AmplitudePage, AmplitudeRecord,
    AmplitudeRequest,
};
pub use anthropic::{
    AnthropicAuthentication, AnthropicError, AnthropicFamily, AnthropicKernel, AnthropicPage,
    AnthropicRecord, AnthropicRequest, AnthropicScope,
};
pub use append_log::{AppendLogDecodeError, CommittedSourceEvent, CommittedSourceInput};
pub use archetype::{
    ArchetypeError, ArchetypeFamily, ArchetypeKernel, ArchetypePage, ArchetypeRecord,
    ArchetypeRepository, ArchetypeRequest, ArchetypeRequestKind, ArchetypeScan,
    VulnerabilityCollectionState,
};
pub use asana::{
    AsanaCheckpointCandidate, AsanaEntityFact, AsanaError, AsanaEventContract, AsanaFamily,
    AsanaKernel, AsanaPage, AsanaProjectionFacts, AsanaRecord, AsanaRelationFact, AsanaRequest,
    AsanaRuntimeDefinition, project_asana_records,
};
pub use aurelius::{
    AureliusCursor, AureliusError, AureliusFamily, AureliusKernel, AureliusPage, AureliusRecord,
};
pub use aws_account::{
    AwsAccountContactError, AwsAccountContactKernel, AwsAccountContactOutcome,
    AwsAccountContactPage, AwsAccountContactRecord, AwsAccountContactRequest,
    AwsAccountContactRequestKind,
};
pub use aws_codebuild::{
    AwsCodeBuildBatch, AwsCodeBuildError, AwsCodeBuildFamily, AwsCodeBuildKernel,
    AwsCodeBuildRecord, AwsCodeBuildRequest, AwsCodeBuildRequestKind,
};
pub use aws_network_manager::{
    AwsNetworkManagerBatch, AwsNetworkManagerError, AwsNetworkManagerFamily,
    AwsNetworkManagerKernel, AwsNetworkManagerRecord, AwsNetworkManagerRequest,
    AwsNetworkManagerRequestKind,
};
pub use aws_secret_store::{
    AwsSecretReadError, AwsSecretReader, AwsSecretReference, AwsSecretResolutionError,
    AwsSecretValue, contains_aws_secret_references, parse_aws_secret_reference,
    resolve_aws_secret_references,
};
pub use azure::{
    AzureAuthenticationMethodsPolicyError, AzureAuthenticationMethodsPolicyKernel,
    AzureAuthenticationMethodsPolicyPage, AzureAuthenticationMethodsPolicyRecord,
    AzureAuthenticationMethodsPolicyRequest,
};
pub use cerebro_source::{
    CerebroSourceError, CerebroSourceFamily, CerebroSourceKernel, CerebroSourcePage,
    CerebroSourceRecord,
};
pub use cloudflare::{
    CloudflareError, CloudflareFamily, CloudflareKernel, CloudflarePage, CloudflareRecord,
    CloudflareRequest, CloudflareRequestKind, CloudflareScope,
};
pub use cosmo::{CosmoError, CosmoFamily, CosmoKernel, CosmoPage, CosmoRecord};
pub use credential_lease::{
    CredentialLeaseError, CredentialLeaseReference, CredentialLeaseScope, CredentialLeaseStatus,
    LeaseClock, OperationScopedCredentialLease,
};
pub use deepseek::{
    DeepSeekCheckpointCandidate, DeepSeekEntityFact, DeepSeekError, DeepSeekEventContract,
    DeepSeekFamily, DeepSeekKernel, DeepSeekPage, DeepSeekProjectionFacts, DeepSeekRecord,
    DeepSeekRelationFact, DeepSeekRequest, DeepSeekRuntimeDefinition, project_deepseek_records,
};
pub use deposit::{
    DepositIngestError, DepositIngestReceipt, DepositIngestRequest, build_deposit_receipt,
};
pub use discord::{
    DiscordError, DiscordFamily, DiscordKernel, DiscordPage, DiscordRecord, DiscordRequest,
};
pub use docker_hub::{
    DockerHubCheckpointCandidate, DockerHubEntityFact, DockerHubError, DockerHubEventContract,
    DockerHubFamily, DockerHubKernel, DockerHubPage, DockerHubProjectionFacts, DockerHubRecord,
    DockerHubRequest, DockerHubRuntimeDefinition, project_docker_hub_records,
};
pub use egress::{
    EgressDecision, EgressDecisionKind, EgressMode, EgressPolicy, EgressPolicyError,
    EgressRequestContext,
};
pub use email_domain_health::{
    EmailDomainDkimSelector, EmailDomainDnsQuery, EmailDomainDnsQueryKind, EmailDomainDnsSnapshot,
    EmailDomainHealth, EmailDomainHealthError, EmailDomainHealthIssue, EmailDomainHealthKernel,
    EmailDomainHealthPage, EmailDomainHealthRecord, EmailDomainMxRecord,
};
pub use evidence_cas::{
    EvidenceCasConfig, EvidenceCasContract, EvidenceCasError, EvidenceCasKernel, EvidenceCasPage,
    EvidenceCasRecord, EvidenceCasRequest, EvidenceCasRequestKind,
};
pub use fixture_parity::{
    FixtureParityComparison, FixtureParityDuplicate, FixtureParityEvent, FixtureParityInput,
    FixtureParityMatrix, FixtureParityOperation, FixtureParityPage, FixtureParityQuarantine,
    FixtureParityReceipt, build_fixture_parity_matrix, compare_fixture_parity,
    execute_fixture_parity_page, fixture_excluded_family_reasons,
};
pub use gcp::{
    GcpContentInspection, GcpDataClassification, GcpIamError, GcpIamFamily, GcpIamFilters,
    GcpIamKernel, GcpIamPage, GcpIamRecord, GcpIamRequest, GcpObjectContentKernel,
};
pub use github::{
    GitHubActorResolution, GitHubCheckpointCandidate, GitHubContinuation, GitHubError,
    GitHubEventContract, GitHubFamily, GitHubFilters, GitHubKernel, GitHubPage, GitHubRecord,
    GitHubRequest, GitHubRequestKind, GitHubRuntimeDefinition,
};
pub use google_workspace::{
    GoogleWorkspaceError, GoogleWorkspaceFamily, GoogleWorkspaceFilters, GoogleWorkspaceKernel,
    GoogleWorkspaceOutcome, GoogleWorkspacePage, GoogleWorkspaceRecord, GoogleWorkspaceRequest,
};
pub use grc::{GrcError, GrcFamily, GrcKernel, GrcPage, GrcRecord, GrcRequest};
pub use http::{HttpConnectorError, HttpProviderAccess, HttpSourceConnector, ResolvedAuth};
pub use jumpcloud::{
    JumpCloudCheckpointCandidate, JumpCloudEntityFact, JumpCloudError, JumpCloudEventContract,
    JumpCloudFamily, JumpCloudFilters, JumpCloudKernel, JumpCloudPage, JumpCloudProjectionFacts,
    JumpCloudRecord, JumpCloudRelationFact, JumpCloudRequest, JumpCloudResponseMetadata,
    JumpCloudRuntimeDefinition, project_jumpcloud_records,
};
pub use kubernetes::{
    KubernetesConfig, KubernetesError, KubernetesFamily, KubernetesKernel, KubernetesPage,
    KubernetesProjection, KubernetesProjectionEntity, KubernetesProjectionLink, KubernetesRecord,
    KubernetesRequest, KubernetesRuntimeDefinition,
};
pub use linode::{LinodeError, LinodeKernel, LinodePage, LinodeRecord, LinodeRequest};
pub use mapper::{CatalogGraphMapper, CatalogMapperError, IdentityResolutionSnapshot};
pub use okta::{
    OktaError, OktaFamily, OktaFilters, OktaKernel, OktaPage, OktaRecord, OktaRequest, OktaResponse,
};
pub use openai::{
    OpenAiAuthRequirement, OpenAiCheckpoint, OpenAiError, OpenAiFamily, OpenAiKernel, OpenAiPage,
    OpenAiRecord, OpenAiRequest, OpenAiRequestInput,
};
pub use panopticon::{
    PanopticonError, PanopticonFamily, PanopticonKernel, PanopticonOutcome, PanopticonPage,
    PanopticonRecord, PanopticonRequest,
};
pub use protocol::{
    AuthorityEvidence, ProtocolError, SourceRuntimeEnvelope, SourceRuntimeErrorShape,
    SourceRuntimeOperation, SourceRuntimeReceipt, SourceRuntimeResult, canonical_digest,
    canonical_digest_vectors, validate_authority_evidence, validate_envelope,
    validate_envelope_json,
};
pub use provider_failure::{
    ProviderFailureCategory, ProviderFailureClassification, ProviderFailureKind,
    classify_http_connector_failure, classify_provider_failure,
};
pub use runtime_config::{
    RuntimeConfigError, contains_credential_references, parse_credential_reference,
    resolve_environment_references,
};
pub use sdk::{
    SdkIntegrationPostureEvent, SdkPushedTelemetry, SdkTelemetryError,
    normalize_sdk_pushed_telemetry,
};
pub use security_tooling_map::{
    SecurityToolingMapError, SecurityToolingMapFamily, SecurityToolingMapKernel,
    SecurityToolingMapPage, SecurityToolingMapRecord, SecurityToolingMapRequest,
};
pub use sentinelone::{
    SentinelOneError, SentinelOneFamily, SentinelOneFilters, SentinelOneKernel, SentinelOneOutcome,
    SentinelOnePage, SentinelOneRecord, SentinelOneRequest,
};
pub use slack::{
    SlackCheckpoint, SlackError, SlackFamily, SlackFilters, SlackKernel, SlackPage, SlackRecord,
    SlackRequest,
};
pub use tailscale::{
    TailscaleCheckpointCandidate, TailscaleEntityFact, TailscaleError, TailscaleEventContract,
    TailscaleFamily, TailscaleKernel, TailscalePage, TailscaleProjectionFacts, TailscaleRecord,
    TailscaleRelationFact, TailscaleRequest, TailscaleResponseMetadata, TailscaleRuntimeDefinition,
    project_tailscale_records,
};
pub use trivy::{TrivyError, TrivyFamily, TrivyKernel, TrivyPage, TrivyRecord};
pub use twilio::{
    TwilioError, TwilioFamily, TwilioFilters, TwilioKernel, TwilioPage, TwilioRecord, TwilioRequest,
};
pub use vulnview::{
    VulnViewError, VulnViewFamily, VulnViewFilters, VulnViewKernel, VulnViewPage, VulnViewRecord,
    VulnViewRequest,
};

use std::{collections::BTreeMap, error::Error, fmt};

use async_trait::async_trait;
use cerebro_organizational_graph::{GraphError, GraphWriteReceipt, OrganizationalGraph};
use cerebro_organizational_model::{
    CollectionReceipt, CompleteCollection, GraphDelta, ObservationId, SourceRuntimeId, TenantId,
};
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Tenant-scoped instruction passed to a source connector for one collection.
pub struct CollectionRequest {
    /// Tenant whose provider data may be returned.
    pub tenant_id: TenantId,
    /// Durable source-runtime instance executing the collection.
    pub source_runtime_id: SourceRuntimeId,
    /// Provider cursor from the preceding batch, when collection is paginated.
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
    /// Construct a positive-generation fence for one tenant and runtime owner.
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

    /// Return the tenant protected by this fence.
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Return the source-runtime instance protected by this fence.
    pub fn source_runtime_id(&self) -> &SourceRuntimeId {
        &self.source_runtime_id
    }

    /// Return the validated lease-owner identity.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Return the database generation that must still own the runtime row.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// One normalized provider record emitted by a source connector.
pub struct SourceRecord {
    /// Stable source observation that supports this record.
    pub observation_id: ObservationId,
    /// Catalog family that determines projection behavior.
    pub family: String,
    /// Provider-specific resource kind.
    pub provider_kind: String,
    /// Provider-owned identifier within that kind.
    pub provider_id: String,
    /// Sorted scalar fields selected by the source catalog.
    pub fields: BTreeMap<String, String>,
    /// Structured provider payload retained for family-specific mapping.
    pub payload: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "collection_mode", rename_all = "snake_case")]
/// Authority carried by a collected batch.
pub enum CollectedScope {
    /// A complete authoritative collection may close absent provider facts.
    Complete(CompleteCollection),
    /// An incremental collection may add observations but cannot prove absence.
    NonAuthoritative(CollectionReceipt),
}

impl CollectedScope {
    /// Return the collection receipt shared by either authority mode.
    pub fn receipt(&self) -> &CollectionReceipt {
        match self {
            Self::Complete(value) => value.receipt(),
            Self::NonAuthoritative(value) => value,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// A bounded connector result and the cursor for its next provider page.
pub struct CollectedBatch {
    /// Completeness authority for every record in this batch.
    pub scope: CollectedScope,
    /// Normalized source records collected under the receipt.
    pub records: Vec<SourceRecord>,
    /// Cursor to resume provider collection, or `None` at the terminal page.
    pub next_cursor: Option<String>,
}

#[async_trait]
/// Provider adapter that collects one tenant-scoped batch.
pub trait SourceConnector: Send {
    /// Connector-specific collection failure.
    type Error: Error + Send + Sync + 'static;

    /// Collect the requested page without widening its tenant or runtime scope.
    async fn collect(&mut self, request: CollectionRequest) -> Result<CollectedBatch, Self::Error>;
}

/// Deterministic projection from validated source records into graph mutations.
pub trait GraphMapper {
    /// Mapper-specific projection or domain-validation failure.
    type Error: Error + Send + Sync + 'static;

    /// Mapping returns a domain-validated `GraphDelta`. No unvalidated entity
    /// or relationship wire type crosses into the graph engine.
    fn map(&self, batch: &CollectedBatch) -> Result<GraphDelta, Self::Error>;
}

#[async_trait]
/// Durable graph commit boundary for a collected batch.
pub trait GraphSink: Send {
    /// Storage-specific commit failure.
    type Error: Error + Send + Sync + 'static;

    /// Atomically apply a validated graph delta for `batch`.
    async fn apply(
        &mut self,
        batch: &CollectedBatch,
        delta: GraphDelta,
    ) -> Result<GraphWriteReceipt, Self::Error>;
}

#[async_trait]
/// Graph sink that verifies durable lease ownership inside the commit path.
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
/// Failure stage for one source-runtime synchronization.
pub enum RuntimeError<CollectError, MapError, StoreError> {
    /// Provider collection failed before mapping.
    Collect(CollectError),
    /// Connector, mapper, request, or fence tenant/runtime scopes disagree.
    ScopeMismatch,
    /// Source records could not be projected into a valid graph delta.
    Map(MapError),
    /// Durable graph commit failed.
    Store(StoreError),
}

/// Concrete synchronization error derived from a connector, mapper, and sink.
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

/// Executes collect, scope validation, mapping, and durable graph commit.
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
    /// Assemble a runtime from its provider connector, mapper, and graph sink.
    pub fn new(connector: Connector, mapper: Mapper, store: Store) -> Self {
        Self {
            connector,
            mapper,
            store,
        }
    }

    /// Collect and commit one batch after checking every tenant/runtime boundary.
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

    /// Consume the runtime and return its graph sink.
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
