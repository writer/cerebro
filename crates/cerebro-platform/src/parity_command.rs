use std::{
    collections::BTreeMap,
    env,
    error::Error,
    io::{self, Read},
    path::PathBuf,
};

use cerebro_organizational_model::{
    CollectionId, CollectionReceipt, CompleteCollection, ObservationId, SourceRuntimeId, TenantId,
};
use cerebro_organizational_store::{
    ParityReceipt, SemanticFact, SemanticFactKind, SemanticSnapshot,
};
use cerebro_source_catalog::SourceCatalog;
use cerebro_source_runtime_next::{
    CatalogGraphMapper, CollectedBatch, CollectedScope, GraphMapper, SourceRecord,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const RUST_PROJECTOR_REVISION: &str = "rust-catalog-semantic-v1";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ParityRunWire {
    tenant_id: String,
    source_runtime_id: String,
    source_id: String,
    family_id: String,
    collection_id: String,
    complete: bool,
    observed_at_unix_ms: i64,
    compared_at_unix_ms: i64,
    projection_lag: u64,
    input_digest: String,
    legacy_projector_revision: String,
    rust_projector_revision: String,
    runtime_versions: BTreeMap<String, String>,
    records: Vec<RecordWire>,
    legacy_facts: Vec<FactWire>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordWire {
    observation_id: String,
    family: String,
    provider_kind: String,
    provider_id: String,
    fields: BTreeMap<String, String>,
    payload: serde_json::Value,
    event_kind: String,
    event_attributes: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FactWire {
    kind: String,
    parts: Vec<String>,
}

pub(crate) async fn compare_projection() -> Result<(), Box<dyn Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let wire: ParityRunWire = serde_json::from_str(&input)?;
    let receipt = run_comparison(wire)?;
    if let Ok(connection_string) = env::var("CEREBRO_ORGANIZATIONAL_POSTGRES_URL") {
        let ledger =
            cerebro_organizational_store::PostgresLedger::connect_tls(&connection_string).await?;
        ledger.migrate().await?;
        ledger.record_parity(&receipt).await?;
    } else if env::var("CEREBRO_PARITY_REQUIRE_PERSISTENCE").as_deref() == Ok("true") {
        return Err(
            "CEREBRO_ORGANIZATIONAL_POSTGRES_URL is required when parity persistence is required"
                .into(),
        );
    }
    serde_json::to_writer(io::stdout(), &receipt)?;
    println!();
    Ok(())
}

fn run_comparison(mut wire: ParityRunWire) -> Result<ParityReceipt, Box<dyn Error>> {
    validate_wire(&wire)?;
    let encoded_records = serde_json::to_vec(&wire.records)?;
    let computed_input_digest = digest(&encoded_records);
    if wire.input_digest != computed_input_digest {
        return Err(format!(
            "input digest {} does not match records {}",
            wire.input_digest, computed_input_digest
        )
        .into());
    }
    let root = repository_root()?;
    let catalog = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )?;
    let source = catalog
        .get(&wire.source_id)
        .ok_or_else(|| format!("source {} is not in the catalog", wire.source_id))?
        .clone();
    if !source
        .families()
        .iter()
        .any(|family| family.id() == wire.family_id)
    {
        return Err(format!(
            "family {} is not in source {}",
            wire.family_id, wire.source_id
        )
        .into());
    }
    let tenant_id = TenantId::parse(wire.tenant_id.clone())?;
    let source_runtime_id = SourceRuntimeId::parse(wire.source_runtime_id.clone())?;
    let collection_id = CollectionId::parse(wire.collection_id.clone())?;
    let scope = format!("{}.{}", wire.source_id, wire.family_id);
    let collected_scope = if wire.complete {
        CollectedScope::Complete(CompleteCollection::new(
            tenant_id,
            source_runtime_id,
            collection_id,
            scope,
            wire.observed_at_unix_ms,
        )?)
    } else {
        CollectedScope::NonAuthoritative(CollectionReceipt::partial(
            tenant_id,
            source_runtime_id,
            collection_id,
            scope,
            wire.observed_at_unix_ms,
        )?)
    };
    let records = wire
        .records
        .into_iter()
        .map(|record| {
            if record.family != wire.family_id {
                return Err(format!(
                    "observation {} belongs to family {}, not {}",
                    record.observation_id, record.family, wire.family_id
                )
                .into());
            }
            Ok(SourceRecord {
                observation_id: ObservationId::parse(record.observation_id)?,
                family: record.family,
                provider_kind: record.provider_kind,
                provider_id: record.provider_id,
                fields: record.fields,
                payload: record.payload,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let batch = CollectedBatch {
        scope: collected_scope,
        records,
        next_cursor: None,
    };
    let mapper = CatalogGraphMapper::new(source, RUST_PROJECTOR_REVISION)?;
    let delta = mapper.map(&batch)?;
    let rust_revision = if wire.rust_projector_revision.trim().is_empty() {
        RUST_PROJECTOR_REVISION.to_owned()
    } else {
        wire.rust_projector_revision.clone()
    };
    let rust = SemanticSnapshot::from_delta(
        wire.source_id.clone(),
        wire.family_id.clone(),
        computed_input_digest,
        rust_revision,
        &delta,
    )?;
    let legacy_facts = wire
        .legacy_facts
        .drain(..)
        .map(|fact| SemanticFact::new(SemanticFactKind::parse(&fact.kind)?, fact.parts))
        .collect::<Result<Vec<_>, _>>()?;
    let legacy = SemanticSnapshot::from_facts(
        wire.tenant_id,
        wire.source_runtime_id,
        wire.source_id,
        wire.family_id,
        wire.collection_id,
        wire.input_digest,
        wire.legacy_projector_revision,
        wire.complete,
        legacy_facts,
    )?;
    wire.runtime_versions
        .entry("rust".to_owned())
        .or_insert_with(|| env!("CARGO_PKG_VERSION").to_owned());
    Ok(ParityReceipt::compare_snapshots(
        &legacy,
        &rust,
        wire.projection_lag,
        wire.compared_at_unix_ms,
        wire.runtime_versions,
    )?)
}

fn validate_wire(wire: &ParityRunWire) -> Result<(), Box<dyn Error>> {
    if wire.records.is_empty() {
        return Err("records are required".into());
    }
    if wire.legacy_facts.is_empty() {
        return Err("legacy_facts are required; run the Go parity adapter first".into());
    }
    if wire.compared_at_unix_ms <= 0 || wire.observed_at_unix_ms <= 0 {
        return Err("comparison and observation times must be positive".into());
    }
    if wire.legacy_projector_revision.trim().is_empty() {
        return Err("legacy_projector_revision is required".into());
    }
    Ok(())
}

fn repository_root() -> Result<PathBuf, Box<dyn Error>> {
    if let Some(root) = env::var_os("CEREBRO_REPOSITORY_ROOT") {
        return Ok(PathBuf::from(root));
    }
    let current = env::current_dir()?;
    if current.join("Cargo.toml").is_file()
        && current.join("internal/connectorcatalog/catalog").is_dir()
    {
        return Ok(current);
    }
    Err("run compare-projection from the repository root or set CEREBRO_REPOSITORY_ROOT".into())
}

fn digest(bytes: &[u8]) -> String {
    let bytes = Sha256::digest(bytes);
    let mut value = String::with_capacity(7 + bytes.len() * 2);
    value.push_str("sha256:");
    for byte in bytes {
        value.push_str(&format!("{byte:02x}"));
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_legacy_facts_are_rejected() {
        let wire = ParityRunWire {
            tenant_id: "tenant-a".to_owned(),
            source_runtime_id: "box-prod".to_owned(),
            source_id: "box".to_owned(),
            family_id: "content_assets".to_owned(),
            collection_id: "collection-1".to_owned(),
            complete: true,
            observed_at_unix_ms: 10,
            compared_at_unix_ms: 11,
            projection_lag: 0,
            input_digest: "sha256:test".to_owned(),
            legacy_projector_revision: "legacy".to_owned(),
            rust_projector_revision: "rust".to_owned(),
            runtime_versions: BTreeMap::new(),
            records: vec![RecordWire {
                observation_id: "observation-1".to_owned(),
                family: "content_assets".to_owned(),
                provider_kind: "box.content_assets".to_owned(),
                provider_id: "asset-1".to_owned(),
                fields: BTreeMap::new(),
                payload: serde_json::json!({"id": "asset-1"}),
                event_kind: "box.content_assets".to_owned(),
                event_attributes: BTreeMap::new(),
            }],
            legacy_facts: Vec::new(),
        };
        assert_eq!(
            validate_wire(&wire).unwrap_err().to_string(),
            "legacy_facts are required; run the Go parity adapter first"
        );
    }
}
