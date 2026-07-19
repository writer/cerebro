use cerebro_security_path_kernel::{
    CollectionReceipt, Completeness, NodeRef, ProofEdge, RuntimeCollectionReceipt, SecurityPath,
    Snapshot, compare, rank_candidate_cuts, verify_observed_absent,
};

const BEFORE_TIME: &str = "2026-07-15T08:00:00Z";
const AFTER_TIME: &str = "2026-07-15T08:05:00Z";

#[test]
fn path_order_does_not_change_comparison_or_cut_decisions() {
    let before = snapshot("before", BEFORE_TIME, Vec::new());
    let baseline_paths = (0..32).map(path).collect::<Vec<_>>();
    let baseline = compare(
        Some(&before),
        &snapshot("after", AFTER_TIME, baseline_paths.clone()),
    )
    .expect("baseline comparison");

    for rotation in 0..baseline_paths.len() {
        let mut permuted = baseline_paths.clone();
        permuted.rotate_left(rotation);
        if rotation % 2 == 1 {
            permuted.reverse();
        }
        let actual = compare(
            Some(&before),
            &snapshot("after", AFTER_TIME, permuted.clone()),
        )
        .expect("permuted comparison");
        assert_eq!(actual, baseline, "rotation {rotation}");
        assert_eq!(rank_candidate_cuts(&permuted), baseline.candidate_edge_cuts);
    }
}

#[test]
fn incomplete_evidence_never_produces_observed_absent() {
    let reference = snapshot("before", BEFORE_TIME, vec![path(0)]);
    for index in 0..64 {
        let mut after = snapshot("after", AFTER_TIME, Vec::new());
        after.completeness = Completeness {
            state: "incomplete".to_owned(),
            reasons: vec![format!("deterministic_incomplete_reason_{index}")],
        };
        let decision = verify_observed_absent(&reference, &after, &["path-000".to_owned()])
            .expect("incomplete verification decision");
        assert_eq!(decision.state, "indeterminate");
        assert_eq!(
            decision.reasons,
            [format!("deterministic_incomplete_reason_{index}")]
        );
    }
}

#[test]
fn duplicated_requested_paths_normalize_to_one_verification_target() {
    let reference = snapshot("before", BEFORE_TIME, vec![path(0)]);
    let after = snapshot("after", AFTER_TIME, Vec::new());
    let decision = verify_observed_absent(
        &reference,
        &after,
        &[
            " path-000 ".to_owned(),
            "path-000".to_owned(),
            "path-000".to_owned(),
        ],
    )
    .expect("normalized verification target");
    assert_eq!(decision.requested_path_ids, ["path-000"]);
    assert_eq!(decision.state, "observed_absent");
}

fn path(index: usize) -> SecurityPath {
    SecurityPath {
        id: format!("path-{index:03}"),
        route_id: format!("route-{:03}", index / 2),
        public_principal: NodeRef {
            urn: "public-principal".to_owned(),
            ..NodeRef::default()
        },
        proof_edges: vec![
            ProofEdge {
                id: format!("shared-edge-{:03}", index / 4),
                relation: "can_reach".to_owned(),
                source_runtime_id: "runtime-a".to_owned(),
                ..ProofEdge::default()
            },
            ProofEdge {
                id: format!("specific-edge-{index:03}"),
                relation: "can_assume".to_owned(),
                source_runtime_id: "runtime-a".to_owned(),
                ..ProofEdge::default()
            },
        ],
        ..SecurityPath::default()
    }
}

fn snapshot(id: &str, observed_at: &str, paths: Vec<SecurityPath>) -> Snapshot {
    let runtime_receipt = RuntimeCollectionReceipt {
        source_runtime_id: "runtime-a".to_owned(),
        source_id: "source-a".to_owned(),
        provider_family: "family-a".to_owned(),
        config_revision: "revision-a".to_owned(),
        runtime_watermark: observed_at.to_owned(),
        last_synced_at: observed_at.to_owned(),
        graph_checkpoint_id: format!("checkpoint-{id}"),
        graph_run_id: format!("run-{id}"),
        graph_run_started_at: observed_at.to_owned(),
        graph_run_finished_at: observed_at.to_owned(),
        graph_checkpoint_complete: true,
        graph_checkpoint_current: true,
        ..RuntimeCollectionReceipt::default()
    };
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
            proof_runtime_ids: vec!["runtime-a".to_owned()],
            runtime_receipts: vec![runtime_receipt],
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
