//! Stable smoke benchmark for the two path-count-sensitive kernel operations.
//!
//! This executable intentionally avoids a statistics framework: repository checks
//! need a bounded, dependency-light timing signal rather than a performance claim.

use std::hint::black_box;
use std::time::{Duration, Instant};

use cerebro_security_path_kernel::{
    CollectionReceipt, Completeness, NodeRef, ProofEdge, SecurityPath, Snapshot, compare,
    rank_candidate_cuts,
};

/// Number of measured calls after warm-up.
const ITERATIONS: usize = 100;

fn main() {
    let before = snapshot("before", "2026-07-15T08:00:00Z", Vec::new());
    // Direct native helpers are benchmarked beyond the content-bound request limit
    // to expose scaling regressions. A 1,000-path fixture is not an admissible Wasm
    // EvaluationRequest and must never be interpreted as a production input bound.
    let paths = (0..1_000).map(path).collect::<Vec<_>>();
    let after = snapshot("after", "2026-07-15T08:05:00Z", paths.clone());
    report("compare_1000_paths", || {
        black_box(compare(Some(&before), &after).expect("benchmark comparison"));
    });
    report("rank_1000_paths", || {
        black_box(rank_candidate_cuts(&paths));
    });
}

/// Warms one operation, measures a fixed batch, and emits integer nanoseconds/call.
fn report(name: &str, operation: impl Fn()) {
    // Warm-up removes first-use allocation and instruction-cache effects from the
    // bounded measurement without trying to estimate statistical confidence.
    for _ in 0..10 {
        operation();
    }
    let started = Instant::now();
    for _ in 0..ITERATIONS {
        operation();
    }
    let elapsed = started.elapsed();
    let per_operation = elapsed / u32::try_from(ITERATIONS).expect("bounded iterations");
    println!("{name}: {} ns/op", nanos(per_operation));
}

/// Converts a per-operation duration without narrowing its nanosecond count.
fn nanos(duration: Duration) -> u128 {
    duration.as_nanos()
}

/// Builds two paths per route and four paths per shared edge.
///
/// The resulting fixture makes comparison scale with route grouping while cut
/// ranking must aggregate both route and path coverage for each edge.
fn path(index: usize) -> SecurityPath {
    SecurityPath {
        id: format!("path-{index:04}"),
        route_id: format!("route-{:04}", index / 2),
        public_principal: NodeRef {
            urn: "public-principal".to_owned(),
            ..NodeRef::default()
        },
        exposed_resource: NodeRef {
            urn: format!("resource-{index:04}"),
            ..NodeRef::default()
        },
        proof_edges: vec![ProofEdge {
            id: format!("edge-{:04}", index / 4),
            relation: "can_reach".to_owned(),
            source_runtime_id: "runtime-a".to_owned(),
            ..ProofEdge::default()
        }],
        ..SecurityPath::default()
    }
}

/// Builds the minimum complete snapshot accepted by direct comparison.
fn snapshot(id: &str, observed_at: &str, paths: Vec<SecurityPath>) -> Snapshot {
    Snapshot {
        id: id.to_owned(),
        tenant_id: "tenant-a".to_owned(),
        scope_id: "scope-a".to_owned(),
        detector_id: "detector-a".to_owned(),
        detector_revision: "revision-a".to_owned(),
        observation_id: format!("observation-{id}"),
        observed_at: observed_at.to_owned(),
        collection_receipt: CollectionReceipt {
            id: format!("receipt-{id}"),
            source_runtime_id: "runtime-a".to_owned(),
            source_id: "source-a".to_owned(),
            runtime_watermark: observed_at.to_owned(),
            last_synced_at: observed_at.to_owned(),
            collection_mode: "graph_reset_full_scan".to_owned(),
            graph_checkpoint_id: format!("checkpoint-{id}"),
            graph_run_id: format!("run-{id}"),
            graph_checkpoint_complete: true,
            graph_checkpoint_current: true,
            observed_path_count: paths.len(),
            total_path_count: paths.len(),
            lease_held: true,
            digest: format!("receipt-digest-{id}"),
            ..CollectionReceipt::default()
        },
        completeness: Completeness {
            state: "complete".to_owned(),
            reasons: Vec::new(),
        },
        paths,
        path_set_digest: format!("path-set-{id}"),
        digest: format!("sha256:{:064x}", id.len()),
    }
}
