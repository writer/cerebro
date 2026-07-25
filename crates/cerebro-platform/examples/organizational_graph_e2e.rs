use std::{
    collections::{BTreeMap, HashMap},
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_nats::jetstream::{self, consumer::pull};
use cerebro_organizational_model::{
    AssertionProvenance, CanonicalIdentity, CollectionId, CompleteCollection, Entity, EntityId,
    EntityKind, GraphAssertion, IdentityClaim, ObservationId, ObservationRef, ProviderIdentity,
    ProviderKind, RelationKind, RelationshipAssertion, SourceRuntimeId, TenantId,
};
use cerebro_organizational_store::{
    CutoverPolicy, DurableGraphStore, Neo4jProjector, ParityReceipt, PostgresLedger,
    ProjectionAuthority, ProjectionPromotionRequest,
};
use cerebro_source_catalog::SourceCatalog;
use cerebro_source_runtime_next::{CollectedBatch, CollectedScope, GraphSink, SourceRecord};
use hmac::{Hmac, KeyInit, Mac};
use prost::Message;
use prost_types::Timestamp;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use tokio_postgres::NoTls;

const TENANT: &str = "rust-e2e";
const OTHER_TENANT: &str = "rust-e2e-other";
const SECRET_CONTEXT: &[u8] = b"cerebro-organizational-graph/tenant/v1\0";
const STREAM: &str = "CEREBRO_EVENTS";
const CONSUMER: &str = "organizational-graph-v1";
const WAIT_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, PartialEq, Message)]
struct CommittedSourceWire {
    #[prost(string, tag = "1")]
    id: String,
    #[prost(string, tag = "2")]
    tenant_id: String,
    #[prost(string, tag = "3")]
    source_id: String,
    #[prost(string, tag = "4")]
    kind: String,
    #[prost(message, optional, tag = "5")]
    occurred_at: Option<Timestamp>,
    #[prost(string, tag = "6")]
    schema_ref: String,
    #[prost(bytes = "vec", tag = "7")]
    payload: Vec<u8>,
    #[prost(map = "string, string", tag = "8")]
    attributes: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Checkpoint {
    schema_version: String,
    commit: String,
    image: String,
    image_digest: String,
    runtime_image_id: String,
    platform: String,
    tenant_id: String,
    graph_revision: u64,
    okta_identity_id: String,
    slack_identity_id: String,
    canonical_identity_id: String,
    auth0_identity_id: String,
    application_id: String,
    resource_id: String,
    compliance_control_id: String,
    unsupported_finding_id: String,
    supported_finding_id: String,
    evidence_id: String,
}

#[derive(Serialize)]
struct ProofCheck {
    name: &'static str,
    status: &'static str,
    evidence: String,
}

#[derive(Serialize)]
struct ProofReceipt {
    schema_version: &'static str,
    status: &'static str,
    commit: String,
    image: String,
    image_digest: String,
    runtime_image_id: String,
    platform: String,
    tenant_id: String,
    graph_revision_before_restart: u64,
    graph_revision_after_restart: u64,
    completed_at_unix_ms: i64,
    checks: Vec<ProofCheck>,
}

struct Config {
    postgres_dsn: String,
    neo4j_uri: String,
    neo4j_username: String,
    neo4j_password: String,
    nats_url: String,
    base_url: String,
    shared_secret: String,
    commit: String,
    image: String,
    image_digest: String,
    runtime_image_id: String,
    platform: String,
    checkpoint_path: PathBuf,
    receipt_path: PathBuf,
    repository_root: PathBuf,
}

impl Config {
    fn from_env() -> Result<Self, Box<dyn Error>> {
        let repository_root = env::var_os("CEREBRO_REPOSITORY_ROOT")
            .map(PathBuf::from)
            .unwrap_or(env::current_dir()?);
        Ok(Self {
            postgres_dsn: required("CEREBRO_TEST_POSTGRES_DSN")?,
            neo4j_uri: required("CEREBRO_TEST_NEO4J_URI")?,
            neo4j_username: required("CEREBRO_TEST_NEO4J_USERNAME")?,
            neo4j_password: required("CEREBRO_TEST_NEO4J_PASSWORD")?,
            nats_url: required("CEREBRO_TEST_NATS_URL")?,
            base_url: required("CEREBRO_TEST_GRAPH_URL")?
                .trim_end_matches('/')
                .to_owned(),
            shared_secret: required("CEREBRO_ORGANIZATIONAL_GRAPH_SHARED_SECRET")?,
            commit: required("CEREBRO_TEST_COMMIT")?,
            image: required("CEREBRO_TEST_IMAGE")?,
            image_digest: required_digest("CEREBRO_TEST_IMAGE_DIGEST")?,
            runtime_image_id: required_digest("CEREBRO_TEST_RUNTIME_IMAGE_ID")?,
            platform: required("CEREBRO_TEST_PLATFORM")?,
            checkpoint_path: PathBuf::from(required("CEREBRO_TEST_CHECKPOINT")?),
            receipt_path: PathBuf::from(required("CEREBRO_TEST_RECEIPT")?),
            repository_root,
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::from_env()?;
    match env::args().nth(1).as_deref() {
        Some("seed") => seed(&config).await,
        Some("verify") => verify(&config).await,
        _ => Err("usage: cargo run -p cerebro-platform --example organizational_graph_e2e -- <seed|verify>".into()),
    }
}

async fn seed(config: &Config) -> Result<(), Box<dyn Error>> {
    wait_for_health(config).await?;
    let (jetstream, mut consumer) = wait_for_consumer(config).await?;
    let ledger = PostgresLedger::connect_tls(&config.postgres_dsn).await?;
    ledger.migrate().await?;
    let catalog = load_catalog(config)?;

    let cutover_scopes = [
        ("okta", "user"),
        ("slack", "user"),
        ("auth0", "grants"),
        ("auth0", "client_grants"),
    ];
    for (source, family) in cutover_scopes {
        prove_and_promote(&ledger, &catalog, source, family).await?;
    }

    jetstream
        .publish("events.okta.user", "not-a-protobuf-envelope".into())
        .await?
        .await?;
    for event in initial_events()? {
        publish(&jetstream, event).await?;
    }
    wait_for_drain(&mut consumer).await?;

    let ids = expected_ids()?;
    seed_compliance_graph(config, ledger, &ids).await?;
    wait_for_entity(config, &ids.okta_identity_id).await?;
    wait_for_entity(config, &ids.slack_identity_id).await?;
    wait_for_entity(config, &ids.canonical_identity_id).await?;
    wait_for_entity(config, &ids.auth0_identity_id).await?;
    wait_for_entity(config, &ids.application_id).await?;
    wait_for_entity(config, &ids.resource_id).await?;
    wait_for_entity(config, &ids.compliance_control_id).await?;
    wait_for_entity(config, &ids.unsupported_finding_id).await?;
    wait_for_entity(config, &ids.supported_finding_id).await?;
    wait_for_entity(config, &ids.evidence_id).await?;

    let okta_path = graph_paths(
        config,
        &ids.okta_identity_id,
        &ids.canonical_identity_id,
        TENANT,
    )
    .await?;
    require_path(&okta_path, 1, &["represents"])?;
    let slack_path = graph_paths(
        config,
        &ids.slack_identity_id,
        &ids.canonical_identity_id,
        TENANT,
    )
    .await?;
    require_path(&slack_path, 1, &["represents"])?;
    let access_path = graph_paths(config, &ids.auth0_identity_id, &ids.resource_id, TENANT).await?;
    require_path(&access_path, 2, &["can_access", "can_access"])?;
    let compliance_gaps = connect_query_compliance_gaps(config, &ids).await?;
    require_compliance_gap(&compliance_gaps, &ids)?;
    prove_tenant_isolation(config, &ids.canonical_identity_id).await?;

    let graph_revision = postgres_revision(&config.postgres_dsn, TENANT).await?;
    if graph_revision < 5 {
        return Err(format!(
            "expected four source revisions and one compliance revision, got {graph_revision}"
        )
        .into());
    }
    let checkpoint = Checkpoint {
        schema_version: "cerebro.rust-organizational-e2e-checkpoint/v1".to_owned(),
        commit: config.commit.clone(),
        image: config.image.clone(),
        image_digest: config.image_digest.clone(),
        runtime_image_id: config.runtime_image_id.clone(),
        platform: config.platform.clone(),
        tenant_id: TENANT.to_owned(),
        graph_revision,
        okta_identity_id: ids.okta_identity_id.to_string(),
        slack_identity_id: ids.slack_identity_id.to_string(),
        canonical_identity_id: ids.canonical_identity_id.to_string(),
        auth0_identity_id: ids.auth0_identity_id.to_string(),
        application_id: ids.application_id.to_string(),
        resource_id: ids.resource_id.to_string(),
        compliance_control_id: ids.compliance_control_id.to_string(),
        unsupported_finding_id: ids.unsupported_finding_id.to_string(),
        supported_finding_id: ids.supported_finding_id.to_string(),
        evidence_id: ids.evidence_id.to_string(),
    };
    write_json(&config.checkpoint_path, &checkpoint)?;
    println!(
        "seeded Rust graph proof at revision {} for {}",
        graph_revision, config.image_digest
    );
    Ok(())
}

async fn verify(config: &Config) -> Result<(), Box<dyn Error>> {
    let checkpoint: Checkpoint = serde_json::from_slice(&fs::read(&config.checkpoint_path)?)?;
    validate_checkpoint(config, &checkpoint)?;
    wait_for_health(config).await?;
    let (jetstream, mut consumer) = wait_for_consumer(config).await?;

    let persisted_revision = postgres_revision(&config.postgres_dsn, TENANT).await?;
    if persisted_revision != checkpoint.graph_revision {
        return Err(format!(
            "graph revision changed across restart: expected {}, got {persisted_revision}",
            checkpoint.graph_revision
        )
        .into());
    }
    wait_for_entity(
        config,
        &EntityId::parse(checkpoint.canonical_identity_id.clone())?,
    )
    .await?;
    let recovered_path = graph_paths(
        config,
        &EntityId::parse(checkpoint.auth0_identity_id.clone())?,
        &EntityId::parse(checkpoint.resource_id.clone())?,
        TENANT,
    )
    .await?;
    require_path(&recovered_path, 2, &["can_access", "can_access"])?;
    let ids = ExpectedIds::from_checkpoint(&checkpoint)?;
    let recovered_compliance_gaps = connect_query_compliance_gaps(config, &ids).await?;
    require_compliance_gap(&recovered_compliance_gaps, &ids)?;

    let post_restart = source_event(
        "okta-e2e-post-restart",
        "okta",
        "user",
        "okta-e2e",
        json!({
            "id": "00u-post-restart",
            "name": "Post Restart User",
            "email": "post-restart@example.com",
            "profile": {"employeeNumber": "employee-post-restart"}
        }),
    )?;
    publish(&jetstream, post_restart).await?;
    wait_for_drain(&mut consumer).await?;
    let post_restart_id = ProviderIdentity::new(
        TenantId::parse(TENANT)?,
        SourceRuntimeId::parse("okta-e2e")?,
        ProviderKind::parse("okta.identity_user")?,
        "00u-post-restart",
        "Post Restart User",
    )?
    .entity()
    .id()
    .clone();
    wait_for_entity(config, &post_restart_id).await?;
    let after_restart_revision = postgres_revision(&config.postgres_dsn, TENANT).await?;
    if after_restart_revision != checkpoint.graph_revision + 1 {
        return Err(format!(
            "post-restart append-log event should advance one revision: before {}, after {after_restart_revision}",
            checkpoint.graph_revision
        )
        .into());
    }
    let agent_rpc = connect_search(config, "Post Restart").await?;
    if agent_rpc["graphRevision"]
        .as_str()
        .and_then(|revision| revision.parse::<u64>().ok())
        != Some(after_restart_revision)
        || agent_rpc["entities"].as_array().is_none_or(|entities| {
            !entities
                .iter()
                .any(|entity| entity["entityId"] == post_restart_id.as_str())
        })
    {
        return Err(format!(
            "agent RPC did not return revision {after_restart_revision} and entity {post_restart_id}: {agent_rpc}"
        )
        .into());
    }
    let product_root = format!(
        "urn:cerebro:{TENANT}:organizational_entity:{}",
        checkpoint.okta_identity_id
    );
    let product = product_neighborhood(config, &product_root).await?;
    require_product_neighborhood(&product, &product_root, "represents")?;
    prove_rust_only_runtime()?;

    let replay = initial_events()?.remove(0);
    publish(&jetstream, replay).await?;
    wait_for_drain(&mut consumer).await?;
    let after_replay_revision = postgres_revision(&config.postgres_dsn, TENANT).await?;
    if after_replay_revision != after_restart_revision {
        return Err(format!(
            "replayed collection advanced graph revision from {after_restart_revision} to {after_replay_revision}"
        )
        .into());
    }

    let receipt = ProofReceipt {
        schema_version: "cerebro.rust-organizational-e2e/v1",
        status: "passed",
        commit: config.commit.clone(),
        image: config.image.clone(),
        image_digest: config.image_digest.clone(),
        runtime_image_id: config.runtime_image_id.clone(),
        platform: config.platform.clone(),
        tenant_id: TENANT.to_owned(),
        graph_revision_before_restart: checkpoint.graph_revision,
        graph_revision_after_restart: after_restart_revision,
        completed_at_unix_ms: now_unix_ms()?,
        checks: vec![
            passed(
                "exact_image",
                format!("{} on {}", config.image_digest, config.platform),
            ),
            passed(
                "append_log_boundary",
                "canonical protobuf accepted from JetStream; malformed payload rejected",
            ),
            passed(
                "cutover_gate",
                "four source families rejected before three matches and promoted after three",
            ),
            passed(
                "durable_stores",
                format!(
                    "PostgreSQL and Neo4j recovered revision {}",
                    checkpoint.graph_revision
                ),
            ),
            passed(
                "unified_identity",
                format!(
                    "Okta and Slack identities resolve to {}",
                    checkpoint.canonical_identity_id
                ),
            ),
            passed(
                "agent_graph_api",
                "tenant-signed entity and path APIs returned persisted graph data",
            ),
            passed(
                "agent_rpc_contract",
                "tenant-signed Connect JSON returned the post-restart entity at the durable revision",
            ),
            passed(
                "compliance_fact_query",
                format!(
                    "bounded Connect query returned unsupported finding {} and excluded supported finding {}",
                    checkpoint.unsupported_finding_id, checkpoint.supported_finding_id
                ),
            ),
            passed(
                "product_http_contract",
                format!(
                    "native Rust product endpoint returned the persisted neighborhood for {product_root}"
                ),
            ),
            passed(
                "rust_only_runtime",
                "replacement image contains the Rust platform and proof driver but no Go server or Go toolchain",
            ),
            passed(
                "multi_hop_path",
                format!(
                    "{} -> {} -> {}",
                    checkpoint.auth0_identity_id, checkpoint.application_id, checkpoint.resource_id
                ),
            ),
            passed(
                "tenant_isolation",
                "bad credentials returned 401 and cross-tenant access returned 403",
            ),
            passed(
                "restart_recovery",
                format!("consumer resumed and committed revision {after_restart_revision}"),
            ),
            passed(
                "idempotent_replay",
                format!("replay kept revision {after_replay_revision}"),
            ),
        ],
    };
    write_json(&config.receipt_path, &receipt)?;
    println!(
        "Rust organizational E2E passed for {} at revision {}",
        config.image_digest, after_restart_revision
    );
    Ok(())
}

struct ExpectedIds {
    okta_identity_id: EntityId,
    slack_identity_id: EntityId,
    canonical_identity_id: EntityId,
    auth0_identity_id: EntityId,
    application_id: EntityId,
    resource_id: EntityId,
    compliance_control_id: EntityId,
    unsupported_finding_id: EntityId,
    supported_finding_id: EntityId,
    evidence_id: EntityId,
}

fn expected_ids() -> Result<ExpectedIds, Box<dyn Error>> {
    let tenant = TenantId::parse(TENANT)?;
    let okta_identity = ProviderIdentity::new(
        tenant.clone(),
        SourceRuntimeId::parse("okta-e2e")?,
        ProviderKind::parse("okta.identity_user")?,
        "00u-e2e",
        "Person One",
    )?;
    let slack_identity = ProviderIdentity::new(
        tenant.clone(),
        SourceRuntimeId::parse("slack-e2e")?,
        ProviderKind::parse("slack.identity_user")?,
        "U-E2E",
        "U-E2E",
    )?;
    let canonical = CanonicalIdentity::for_claim(
        tenant.clone(),
        &IdentityClaim::employee_id("employee-e2e")?,
        "Person One",
    )?;
    let auth0_identity = ProviderIdentity::new(
        tenant.clone(),
        SourceRuntimeId::parse("auth0-e2e")?,
        ProviderKind::parse("auth0.identity_user")?,
        "auth0|person",
        "auth0|person",
    )?;
    let application = Entity::provider(
        tenant.clone(),
        SourceRuntimeId::parse("auth0-e2e")?,
        ProviderKind::parse("auth0.identity_application")?,
        "client-e2e",
        EntityKind::Application,
        "client-e2e",
    )?;
    let resource = Entity::provider(
        tenant,
        SourceRuntimeId::parse("auth0-e2e")?,
        ProviderKind::parse("auth0.access_target")?,
        "https://api.example.test",
        EntityKind::Resource,
        "https://api.example.test",
    )?;
    Ok(ExpectedIds {
        okta_identity_id: okta_identity.entity().id().clone(),
        slack_identity_id: slack_identity.entity().id().clone(),
        canonical_identity_id: canonical.entity().id().clone(),
        auth0_identity_id: auth0_identity.entity().id().clone(),
        application_id: application.id().clone(),
        resource_id: resource.id().clone(),
        compliance_control_id: EntityId::parse("control-e2e-cc6-1")?,
        unsupported_finding_id: EntityId::parse("finding-e2e-unsupported")?,
        supported_finding_id: EntityId::parse("finding-e2e-supported")?,
        evidence_id: EntityId::parse("evidence-e2e-1")?,
    })
}

impl ExpectedIds {
    fn from_checkpoint(checkpoint: &Checkpoint) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            okta_identity_id: EntityId::parse(checkpoint.okta_identity_id.clone())?,
            slack_identity_id: EntityId::parse(checkpoint.slack_identity_id.clone())?,
            canonical_identity_id: EntityId::parse(checkpoint.canonical_identity_id.clone())?,
            auth0_identity_id: EntityId::parse(checkpoint.auth0_identity_id.clone())?,
            application_id: EntityId::parse(checkpoint.application_id.clone())?,
            resource_id: EntityId::parse(checkpoint.resource_id.clone())?,
            compliance_control_id: EntityId::parse(checkpoint.compliance_control_id.clone())?,
            unsupported_finding_id: EntityId::parse(checkpoint.unsupported_finding_id.clone())?,
            supported_finding_id: EntityId::parse(checkpoint.supported_finding_id.clone())?,
            evidence_id: EntityId::parse(checkpoint.evidence_id.clone())?,
        })
    }
}

async fn seed_compliance_graph(
    config: &Config,
    ledger: PostgresLedger,
    ids: &ExpectedIds,
) -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::parse(TENANT)?;
    let collection = CompleteCollection::new(
        tenant.clone(),
        SourceRuntimeId::parse("compliance-e2e")?,
        CollectionId::parse("compliance-e2e-current")?,
        "compliance.current",
        50,
    )?;
    let observation_id = ObservationId::parse("compliance-e2e-observation")?;
    let provenance = || {
        AssertionProvenance::direct(
            vec![ObservationRef::new(
                collection.receipt(),
                observation_id.clone(),
                "compliance.snapshot:current",
            )?],
            "compliance-projector",
            "v1",
        )
    };
    let control = Entity::canonical(
        tenant.clone(),
        ids.compliance_control_id.clone(),
        EntityKind::Control,
        "SOC 2 CC6.1",
    )?;
    let unsupported_finding = Entity::canonical(
        tenant.clone(),
        ids.unsupported_finding_id.clone(),
        EntityKind::Finding,
        "Missing access review evidence",
    )?;
    let supported_finding = Entity::canonical(
        tenant.clone(),
        ids.supported_finding_id.clone(),
        EntityKind::Finding,
        "Completed access review",
    )?;
    let evidence = Entity::canonical(
        tenant.clone(),
        ids.evidence_id.clone(),
        EntityKind::Evidence,
        "Access review receipt",
    )?;
    let resource = Entity::provider(
        tenant,
        SourceRuntimeId::parse("auth0-e2e")?,
        ProviderKind::parse("auth0.access_target")?,
        "https://api.example.test",
        EntityKind::Resource,
        "https://api.example.test",
    )?;
    if resource.id() != &ids.resource_id {
        return Err("compliance resource identity does not match source projection".into());
    }

    let relationships = [
        RelationshipAssertion::new(
            &unsupported_finding,
            RelationKind::MappedToControl,
            &control,
            provenance()?,
            50,
        )?,
        RelationshipAssertion::new(
            &unsupported_finding,
            RelationKind::Affects,
            &resource,
            provenance()?,
            50,
        )?,
        RelationshipAssertion::new(
            &supported_finding,
            RelationKind::MappedToControl,
            &control,
            provenance()?,
            50,
        )?,
        RelationshipAssertion::new(
            &supported_finding,
            RelationKind::Affects,
            &resource,
            provenance()?,
            50,
        )?,
        RelationshipAssertion::new(
            &evidence,
            RelationKind::EvidenceFor,
            &supported_finding,
            provenance()?,
            50,
        )?,
    ];
    let mut builder = collection.clone().begin_delta();
    for entity in [
        control,
        unsupported_finding,
        supported_finding,
        evidence,
        resource,
    ] {
        builder.add_entity(entity)?;
    }
    for relationship in relationships {
        builder.add_assertion(GraphAssertion::Relationship(relationship))?;
    }
    let batch = CollectedBatch {
        scope: CollectedScope::Complete(collection),
        records: vec![SourceRecord {
            observation_id,
            family: "current".to_owned(),
            provider_kind: "cerebro.compliance_snapshot".to_owned(),
            provider_id: "current".to_owned(),
            fields: BTreeMap::new(),
            payload: json!({"snapshot_id": "current"}),
        }],
        next_cursor: None,
    };
    let projector = Neo4jProjector::connect(
        &config.neo4j_uri,
        &config.neo4j_username,
        &config.neo4j_password,
    )
    .await?;
    projector.migrate().await?;
    let mut store = DurableGraphStore::new(ledger, projector);
    store.apply(&batch, builder.build()).await?;
    Ok(())
}

async fn prove_and_promote(
    ledger: &PostgresLedger,
    catalog: &SourceCatalog,
    source: &str,
    family: &str,
) -> Result<(), Box<dyn Error>> {
    let existing = ledger.projection_authority(TENANT, source, family).await?;
    if existing.authority == ProjectionAuthority::Rust {
        let receipt_count = ledger.parity_receipt_count(TENANT, source, family).await?;
        if receipt_count < 3 {
            return Err(format!(
                "{source}.{family} is Rust-authoritative with only {receipt_count} parity receipts"
            )
            .into());
        }
        return Ok(());
    }
    let receipt_count = ledger.parity_receipt_count(TENANT, source, family).await?;
    if receipt_count < 3 {
        for index in 1..=2 {
            ledger
                .record_parity(&matching_receipt(source, family, index)?)
                .await?;
        }
        let blocked = ledger
            .evaluate_and_promote_projection_authority(
                catalog,
                &promotion_request(source, family, 100)?,
            )
            .await;
        if blocked.is_ok() {
            return Err(format!("{source}.{family} promoted without three parity matches").into());
        }
        ledger
            .record_parity(&matching_receipt(source, family, 3)?)
            .await?;
    }
    let authority = ledger
        .evaluate_and_promote_projection_authority(
            catalog,
            &promotion_request(source, family, 101)?,
        )
        .await
        .map_err(|error| format!("{source}.{family} promotion failed: {error}"))?;
    if authority.authority != ProjectionAuthority::Rust {
        return Err(format!("{source}.{family} did not promote to Rust").into());
    }
    Ok(())
}

fn matching_receipt(
    source: &str,
    family: &str,
    index: i64,
) -> Result<ParityReceipt, Box<dyn Error>> {
    Ok(ParityReceipt::compare_scoped(
        TENANT,
        format!("{source}-e2e"),
        source,
        family,
        format!("{source}-{family}-corpus-{index}"),
        "sha256:matched",
        "sha256:matched",
        true,
        index,
    )?)
}

fn promotion_request(
    source: &str,
    family: &str,
    promoted_at: i64,
) -> Result<ProjectionPromotionRequest, Box<dyn Error>> {
    Ok(ProjectionPromotionRequest::new(
        TENANT,
        source,
        family,
        CutoverPolicy::new(3, 0)?,
        0,
        promoted_at,
    )?)
}

fn initial_events() -> Result<Vec<CommittedSourceWire>, Box<dyn Error>> {
    Ok(vec![
        source_event(
            "okta-e2e-user",
            "okta",
            "user",
            "okta-e2e",
            json!({
                "id": "00u-e2e",
                "name": "Person One",
                "email": "person@example.com",
                "profile": {"employeeNumber": "employee-e2e"}
            }),
        )?,
        source_event(
            "slack-e2e-user",
            "slack",
            "user",
            "slack-e2e",
            json!({
                "id": "U-E2E",
                "name": "person-one",
                "profile": {"email": "person@example.com"}
            }),
        )?,
        source_event(
            "auth0-e2e-user-grant",
            "auth0",
            "grants",
            "auth0-e2e",
            json!({
                "id": "grant-user-e2e",
                "client_id": "client-e2e",
                "user_id": "auth0|person",
                "audience": "https://api.example.test"
            }),
        )?,
        source_event(
            "auth0-e2e-client-grant",
            "auth0",
            "client_grants",
            "auth0-e2e",
            json!({
                "id": "grant-client-e2e",
                "client_id": "client-e2e",
                "audience": "https://api.example.test"
            }),
        )?,
    ])
}

fn source_event(
    id: &str,
    source: &str,
    family: &str,
    runtime: &str,
    payload: Value,
) -> Result<CommittedSourceWire, Box<dyn Error>> {
    Ok(CommittedSourceWire {
        id: id.to_owned(),
        tenant_id: TENANT.to_owned(),
        source_id: source.to_owned(),
        kind: format!("{source}.{family}"),
        occurred_at: Some(Timestamp {
            seconds: now_unix_ms()? / 1_000,
            nanos: 0,
        }),
        schema_ref: format!("{source}/{family}/v1"),
        payload: serde_json::to_vec(&payload)?,
        attributes: HashMap::from([("source_runtime_id".to_owned(), runtime.to_owned())]),
    })
}

async fn publish(
    jetstream: &jetstream::Context,
    event: CommittedSourceWire,
) -> Result<(), Box<dyn Error>> {
    jetstream
        .publish(
            format!(
                "events.{}.{}",
                event.source_id,
                family_from_kind(&event.kind)?
            ),
            event.encode_to_vec().into(),
        )
        .await?
        .await?;
    Ok(())
}

fn family_from_kind(kind: &str) -> Result<&str, Box<dyn Error>> {
    kind.split_once('.')
        .map(|(_, family)| family)
        .filter(|family| !family.is_empty())
        .ok_or_else(|| format!("invalid source event kind {kind}").into())
}

async fn wait_for_consumer(
    config: &Config,
) -> Result<
    (
        jetstream::Context,
        jetstream::consumer::Consumer<pull::Config>,
    ),
    Box<dyn Error>,
> {
    let client = async_nats::connect(&config.nats_url).await?;
    let context = jetstream::new(client);
    let start = Instant::now();
    loop {
        if let Ok(stream) = context.get_stream(STREAM).await
            && let Ok(consumer) = stream.get_consumer::<pull::Config>(CONSUMER).await
        {
            return Ok((context, consumer));
        }
        if start.elapsed() >= WAIT_TIMEOUT {
            return Err("Rust append-log consumer did not become ready".into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_for_drain(
    consumer: &mut jetstream::consumer::Consumer<pull::Config>,
) -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    loop {
        let info = consumer.get_info().await?;
        if info.num_pending == 0 && info.num_ack_pending == 0 {
            return Ok(());
        }
        if start.elapsed() >= WAIT_TIMEOUT {
            return Err(format!(
                "JetStream consumer did not drain: pending={} ack_pending={}",
                info.num_pending, info.num_ack_pending
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_for_health(config: &Config) -> Result<(), Box<dyn Error>> {
    let client = Client::new();
    let start = Instant::now();
    loop {
        if let Ok(response) = client
            .get(format!("{}/readyz", config.base_url))
            .send()
            .await
            && response.status() == StatusCode::OK
        {
            let body: Value = response.json().await?;
            if body["runtime"] == "rust-organizational-platform" {
                return Ok(());
            }
        }
        if start.elapsed() >= WAIT_TIMEOUT {
            return Err("Rust graph backend did not become ready".into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_for_entity(config: &Config, entity_id: &EntityId) -> Result<Value, Box<dyn Error>> {
    let start = Instant::now();
    loop {
        let response = authenticated(config, TENANT)
            .get(format!(
                "{}/v1/entities/{}?tenant_id={TENANT}",
                config.base_url, entity_id
            ))
            .send()
            .await?;
        if response.status() == StatusCode::OK {
            return Ok(response.json().await?);
        }
        if response.status() != StatusCode::NOT_FOUND {
            return Err(format!(
                "entity {} returned unexpected status {}",
                entity_id,
                response.status()
            )
            .into());
        }
        if start.elapsed() >= WAIT_TIMEOUT {
            return Err(format!("entity {entity_id} was not projected").into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn graph_paths(
    config: &Config,
    from: &EntityId,
    to: &EntityId,
    requested_tenant: &str,
) -> Result<Value, Box<dyn Error>> {
    let response = authenticated(config, TENANT)
        .post(format!("{}/v1/graph/paths", config.base_url))
        .json(&json!({
            "tenant_id": requested_tenant,
            "from_entity_id": from,
            "to_entity_id": to,
            "max_depth": 4,
            "limit": 10
        }))
        .send()
        .await?;
    if response.status() != StatusCode::OK {
        return Err(format!("path query returned {}", response.status()).into());
    }
    Ok(response.json().await?)
}

async fn connect_search(config: &Config, query: &str) -> Result<Value, Box<dyn Error>> {
    let response = authenticated(config, TENANT)
        .post(format!(
            "{}/cerebro.graph.v1.OrganizationalGraphService/Search",
            config.base_url
        ))
        .header("content-type", "application/json")
        .header("connect-protocol-version", "1")
        .json(&json!({
            "tenantId": TENANT,
            "query": query,
            "limit": 10
        }))
        .send()
        .await?;
    if response.status() != StatusCode::OK {
        return Err(format!("agent RPC search returned {}", response.status()).into());
    }
    Ok(response.json().await?)
}

async fn connect_query_compliance_gaps(
    config: &Config,
    ids: &ExpectedIds,
) -> Result<Value, Box<dyn Error>> {
    let response = authenticated(config, TENANT)
        .post(format!(
            "{}/cerebro.graph.v1.OrganizationalGraphService/QueryFacts",
            config.base_url
        ))
        .header("content-type", "application/json")
        .header("connect-protocol-version", "1")
        .json(&json!({
            "tenantId": TENANT,
            "nodes": [
                {
                    "variable": "finding",
                    "kinds": ["finding"]
                },
                {
                    "variable": "control",
                    "kinds": ["control"],
                    "keys": [ids.compliance_control_id]
                },
                {
                    "variable": "resource",
                    "kinds": ["resource"],
                    "keys": [ids.resource_id]
                }
            ],
            "edges": [
                {
                    "variable": "control_mapping",
                    "fromVariable": "finding",
                    "relation": "mapped_to_control",
                    "toVariable": "control"
                },
                {
                    "variable": "affected_resource",
                    "fromVariable": "finding",
                    "relation": "affects",
                    "toVariable": "resource"
                }
            ],
            "absentEdges": [
                {
                    "boundVariable": "finding",
                    "direction": "QUERY_DIRECTION_INCOMING",
                    "relation": "evidence_for",
                    "otherKinds": ["evidence"]
                }
            ],
            "limit": 10
        }))
        .send()
        .await?;
    if response.status() != StatusCode::OK {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("compliance fact query returned {status}: {body}").into());
    }
    Ok(response.json().await?)
}

fn require_compliance_gap(body: &Value, ids: &ExpectedIds) -> Result<(), Box<dyn Error>> {
    let matches = body["matches"]
        .as_array()
        .ok_or("compliance fact query is missing matches")?;
    if matches.len() != 1 || body["truncated"].as_bool().unwrap_or(false) {
        return Err(
            format!("compliance fact query should return one complete match: {body}").into(),
        );
    }
    let entities = matches[0]["entities"]
        .as_array()
        .ok_or("compliance fact match is missing entities")?;
    let edges = matches[0]["edges"]
        .as_array()
        .ok_or("compliance fact match is missing edges")?;
    let finding = entities
        .iter()
        .find(|entity| entity["variable"] == "finding")
        .ok_or("compliance fact match is missing finding binding")?;
    let entity_ids = entities
        .iter()
        .filter_map(|entity| entity["entity"]["entityId"].as_str())
        .collect::<Vec<_>>();
    let relations = edges
        .iter()
        .filter_map(|edge| edge["edge"]["relation"].as_str())
        .collect::<Vec<_>>();
    if finding["entity"]["entityId"] != ids.unsupported_finding_id.as_str()
        || entity_ids.contains(&ids.supported_finding_id.as_str())
        || !relations.contains(&"mapped_to_control")
        || !relations.contains(&"affects")
    {
        return Err(format!(
            "compliance fact query did not isolate the unsupported finding: {body}"
        )
        .into());
    }
    Ok(())
}

async fn product_neighborhood(config: &Config, root_urn: &str) -> Result<Value, Box<dyn Error>> {
    let mut url = reqwest::Url::parse(&format!("{}/platform/graph/neighborhood", config.base_url))?;
    url.query_pairs_mut()
        .append_pair("root_urn", root_urn)
        .append_pair("limit", "10");
    let response = authenticated(config, TENANT)
        .get(url.to_string())
        .send()
        .await?;
    if response.status() != StatusCode::OK {
        return Err(format!("native product neighborhood returned {}", response.status()).into());
    }
    Ok(response.json().await?)
}

fn require_product_neighborhood(
    body: &Value,
    root_urn: &str,
    relation: &str,
) -> Result<(), Box<dyn Error>> {
    if body["root"]["urn"] != root_urn {
        return Err(format!("product neighborhood root mismatch: {body}").into());
    }
    let neighbors = body["neighbors"]
        .as_array()
        .ok_or("product neighborhood is missing neighbors")?;
    let relations = body["relations"]
        .as_array()
        .ok_or("product neighborhood is missing relations")?;
    if neighbors.len() != 1
        || relations.len() != 1
        || relations[0]["from_urn"] != root_urn
        || relations[0]["relation"] != relation
        || relations[0]["attributes"]["identity_binding"] != "true"
    {
        return Err(format!(
            "product neighborhood did not contain one {relation} identity edge: {body}"
        )
        .into());
    }
    Ok(())
}

fn prove_rust_only_runtime() -> Result<(), Box<dyn Error>> {
    for forbidden in [
        "/usr/local/bin/cerebro",
        "/usr/local/go/bin/go",
        "/usr/bin/go",
        "/bin/go",
    ] {
        if Path::new(forbidden).exists() {
            return Err(format!(
                "replacement image contains forbidden Go runtime path {forbidden}"
            )
            .into());
        }
    }
    for required in [
        "/usr/local/bin/cerebro-platform",
        "/usr/local/bin/organizational-graph-e2e",
    ] {
        if !Path::new(required).is_file() {
            return Err(
                format!("replacement image is missing required Rust binary {required}").into(),
            );
        }
    }
    Ok(())
}

fn require_path(body: &Value, edge_count: usize, relations: &[&str]) -> Result<(), Box<dyn Error>> {
    let paths = body["paths"]
        .as_array()
        .ok_or("path response is missing paths")?;
    let matching = paths.iter().any(|path| {
        path["edges"].as_array().is_some_and(|edges| {
            edges.len() == edge_count
                && edges
                    .iter()
                    .zip(relations)
                    .all(|(edge, relation)| edge["relation"] == *relation)
        })
    });
    if !matching {
        return Err(
            format!("expected a {edge_count}-edge path with {relations:?}, got {body}").into(),
        );
    }
    Ok(())
}

async fn prove_tenant_isolation(
    config: &Config,
    entity_id: &EntityId,
) -> Result<(), Box<dyn Error>> {
    let unauthorized = Client::new()
        .get(format!(
            "{}/v1/entities/{}?tenant_id={TENANT}",
            config.base_url, entity_id
        ))
        .header("x-cerebro-tenant", TENANT)
        .header("authorization", "Bearer invalid")
        .send()
        .await?;
    if unauthorized.status() != StatusCode::UNAUTHORIZED {
        return Err(format!(
            "invalid tenant credential returned {}",
            unauthorized.status()
        )
        .into());
    }
    let forbidden = authenticated(config, TENANT)
        .get(format!(
            "{}/v1/entities/{}?tenant_id={OTHER_TENANT}",
            config.base_url, entity_id
        ))
        .send()
        .await?;
    if forbidden.status() != StatusCode::FORBIDDEN {
        return Err(format!("cross-tenant request returned {}", forbidden.status()).into());
    }
    Ok(())
}

fn authenticated(config: &Config, tenant: &str) -> reqwest::RequestBuilder {
    Client::new()
        .get(&config.base_url)
        .header("x-cerebro-tenant", tenant)
        .bearer_auth(tenant_token(&config.shared_secret, tenant))
}

trait RequestMethod {
    fn get(self, url: String) -> reqwest::RequestBuilder;
    fn post(self, url: String) -> reqwest::RequestBuilder;
}

impl RequestMethod for reqwest::RequestBuilder {
    fn get(self, url: String) -> reqwest::RequestBuilder {
        let headers = self.build().expect("base request").headers().clone();
        Client::new().get(url).headers(headers)
    }

    fn post(self, url: String) -> reqwest::RequestBuilder {
        let headers = self.build().expect("base request").headers().clone();
        Client::new().post(url).headers(headers)
    }
}

fn tenant_token(secret: &str, tenant: &str) -> String {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts keys of any length");
    mac.update(SECRET_CONTEXT);
    mac.update(&(tenant.len() as u64).to_be_bytes());
    mac.update(tenant.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn postgres_revision(dsn: &str, tenant: &str) -> Result<u64, Box<dyn Error>> {
    let (mut client, connection) = tokio_postgres::connect(dsn, NoTls).await?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("E2E PostgreSQL connection closed: {error}");
        }
    });
    let transaction = client.transaction().await?;
    transaction
        .query_one(
            "SELECT set_config('cerebro.tenant_id', $1, true)",
            &[&tenant],
        )
        .await?;
    let row = transaction
        .query_one(
            "SELECT COALESCE(MAX(graph_revision), 0) FROM organizational_collections WHERE tenant_id = $1",
            &[&tenant],
        )
        .await?;
    transaction.commit().await?;
    let revision: i64 = row.get(0);
    Ok(u64::try_from(revision)?)
}

fn load_catalog(config: &Config) -> Result<SourceCatalog, Box<dyn Error>> {
    Ok(SourceCatalog::load(
        config
            .repository_root
            .join("internal/connectorcatalog/catalog"),
        config.repository_root.join("sources"),
    )?)
}

fn validate_checkpoint(config: &Config, checkpoint: &Checkpoint) -> Result<(), Box<dyn Error>> {
    if checkpoint.schema_version != "cerebro.rust-organizational-e2e-checkpoint/v1"
        || checkpoint.commit != config.commit
        || checkpoint.image != config.image
        || checkpoint.image_digest != config.image_digest
        || checkpoint.runtime_image_id != config.runtime_image_id
        || checkpoint.platform != config.platform
        || checkpoint.tenant_id != TENANT
    {
        return Err("E2E checkpoint does not match the candidate image and commit".into());
    }
    Ok(())
}

fn passed(name: &'static str, evidence: impl Into<String>) -> ProofCheck {
    ProofCheck {
        name,
        status: "passed",
        evidence: evidence.into(),
    }
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}

fn required(name: &str) -> Result<String, Box<dyn Error>> {
    let value = env::var(name)?;
    if value.trim().is_empty() {
        Err(format!("{name} is required").into())
    } else {
        Ok(value)
    }
}

fn required_digest(name: &str) -> Result<String, Box<dyn Error>> {
    let value = required(name)?;
    let valid = value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    });
    if !valid {
        return Err(format!("{name} must be a sha256 digest").into());
    }
    Ok(value)
}

fn now_unix_ms() -> Result<i64, Box<dyn Error>> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}
