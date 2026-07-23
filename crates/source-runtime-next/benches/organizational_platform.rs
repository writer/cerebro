use std::{
    collections::BTreeMap,
    env,
    hint::black_box,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use cerebro_organizational_graph::OrganizationalGraph;
use cerebro_organizational_model::{
    CollectionId, CompleteCollection, ObservationId, SourceRuntimeId, TenantId,
};
use cerebro_source_catalog::SourceCatalog;
use cerebro_source_runtime_next::{
    CatalogGraphMapper, CollectedBatch, CollectedScope, GraphMapper, SourceRecord,
};

const DEFAULT_SAMPLE_MILLISECONDS: u64 = 500;
const DEFAULT_SAMPLES: usize = 5;
const RECORD_COUNTS: [usize; 3] = [100, 1_000, 5_000];

fn main() {
    if cfg!(debug_assertions) {
        return;
    }
    let sample_duration = Duration::from_millis(environment_u64(
        "ORGANIZATIONAL_BENCH_SAMPLE_MS",
        DEFAULT_SAMPLE_MILLISECONDS,
    ));
    let samples = usize::try_from(environment_u64(
        "ORGANIZATIONAL_BENCH_SAMPLES",
        DEFAULT_SAMPLES as u64,
    ))
    .expect("sample count fits usize");
    let root = repository_root();
    let catalog = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )
    .expect("checked-in source catalog compiles");
    let source = catalog.get("box").expect("Box source exists").clone();
    let mapper = CatalogGraphMapper::new(source, "organizational-platform-benchmark-v1")
        .expect("benchmark mapper is valid");

    for record_count in RECORD_COUNTS {
        let batch = asset_batch(record_count);
        verify_projection(&mapper, &batch, record_count);
        report(
            &format!(
                "BenchmarkOrganizationalPlatformRust/projection/box_assets/records_{record_count}"
            ),
            record_count,
            sample_duration,
            samples,
            || {
                let delta = mapper.map(black_box(&batch)).expect("projection succeeds");
                black_box(delta.entities().len())
            },
        );
        report(
            &format!(
                "BenchmarkOrganizationalPlatformRust/admission/box_assets/records_{record_count}"
            ),
            record_count,
            sample_duration,
            samples,
            || {
                let delta = mapper.map(black_box(&batch)).expect("projection succeeds");
                let mut graph = OrganizationalGraph::new();
                let receipt = graph.apply(delta).expect("graph admission succeeds");
                black_box(receipt.entities_upserted)
            },
        );
        let mut populated_graph = OrganizationalGraph::new();
        populated_graph
            .apply(mapper.map(&batch).expect("initial projection succeeds"))
            .expect("initial graph admission succeeds");
        report(
            &format!(
                "BenchmarkOrganizationalPlatformRust/refresh/box_assets/records_{record_count}"
            ),
            record_count,
            sample_duration,
            samples,
            || {
                let delta = mapper.map(black_box(&batch)).expect("projection succeeds");
                let receipt = populated_graph
                    .apply(delta)
                    .expect("graph refresh succeeds");
                black_box(receipt.entities_upserted)
            },
        );
    }
}

fn report(
    name: &str,
    record_count: usize,
    sample_duration: Duration,
    samples: usize,
    mut operation: impl FnMut() -> usize,
) {
    black_box(operation());
    let iterations = calibrated_iterations(&mut operation, sample_duration);
    for _ in 0..samples {
        let elapsed = run_iterations(&mut operation, iterations);
        let nanos_per_operation = elapsed.as_nanos() / u128::from(iterations);
        let nanos_per_record =
            nanos_per_operation / u128::try_from(record_count).expect("record count fits u128");
        println!("{name}\t{iterations}\t{nanos_per_operation} ns/op\t{nanos_per_record} ns/record");
    }
}

fn calibrated_iterations(operation: &mut impl FnMut() -> usize, target: Duration) -> u64 {
    let calibration_target = target.min(Duration::from_millis(100));
    let mut iterations = 1_u64;
    loop {
        let elapsed = run_iterations(operation, iterations);
        if elapsed >= calibration_target {
            let scaled = (iterations as f64 * target.as_secs_f64() / elapsed.as_secs_f64())
                .ceil()
                .max(1.0);
            return scaled as u64;
        }
        iterations = iterations.saturating_mul(2);
        assert!(iterations != u64::MAX, "benchmark calibration overflowed");
    }
}

fn run_iterations(operation: &mut impl FnMut() -> usize, iterations: u64) -> Duration {
    let started = Instant::now();
    for _ in 0..iterations {
        black_box(operation());
    }
    started.elapsed()
}

fn verify_projection(mapper: &CatalogGraphMapper, batch: &CollectedBatch, record_count: usize) {
    let delta = mapper.map(batch).expect("projection succeeds");
    assert_eq!(delta.entities().len(), record_count);
    assert!(delta.assertions().is_empty());
    let mut resource_ids = delta
        .entities()
        .iter()
        .map(|entity| {
            entity
                .properties()
                .get("resource_id")
                .expect("resource id exists")
                .as_str()
        })
        .collect::<Vec<_>>();
    resource_ids.sort_unstable();
    assert_eq!(
        resource_ids.first().copied(),
        Some("asset-00000"),
        "first provider id"
    );
    let expected_last = format!("asset-{:05}", record_count - 1);
    assert_eq!(
        resource_ids.last().copied(),
        Some(expected_last.as_str()),
        "last provider id"
    );
}

fn asset_batch(record_count: usize) -> CollectedBatch {
    let collection = CompleteCollection::new(
        TenantId::parse("benchmark-tenant").expect("tenant id"),
        SourceRuntimeId::parse("box-benchmark").expect("source runtime id"),
        CollectionId::parse(format!("box-assets-{record_count}")).expect("collection id"),
        "box.content_assets",
        1_784_675_200_000,
    )
    .expect("complete collection");
    let records = (0..record_count)
        .map(|index| {
            let id = format!("asset-{index:05}");
            SourceRecord {
                observation_id: ObservationId::parse(format!("observation-{index:05}"))
                    .expect("observation id"),
                family: "content_assets".to_owned(),
                provider_kind: "box.content_assets".to_owned(),
                provider_id: id.clone(),
                fields: BTreeMap::new(),
                payload: serde_json::json!({
                    "id": id,
                    "name": format!("Asset {index:05}"),
                    "type": "file",
                    "resource_urn": format!(
                        "urn:cerebro:benchmark-tenant:runtime_file:asset-{index:05}"
                    ),
                }),
            }
        })
        .collect();
    CollectedBatch {
        scope: CollectedScope::Complete(collection),
        records,
        next_cursor: None,
    }
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root")
}

fn environment_u64(name: &str, fallback: u64) -> u64 {
    match env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("{name} must be an unsigned integer")),
        Err(env::VarError::NotPresent) => fallback,
        Err(env::VarError::NotUnicode(_)) => panic!("{name} must be Unicode"),
    }
}
