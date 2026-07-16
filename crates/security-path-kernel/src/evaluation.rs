use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::model::{
    CandidateEdgeCut, CollectionReceipt, ComparisonDecision, EvaluationRequest, EvaluationResponse,
    KernelError, ProofChange, ProofEdge, RuntimeCollectionReceipt, SecurityPath, Snapshot,
    VerificationDecision,
};

pub const ABI_VERSION: u32 = 1;
#[cfg(target_arch = "wasm32")]
pub(crate) const MAX_INPUT_BYTES: usize = 8 << 20;
#[cfg(target_arch = "wasm32")]
pub(crate) const MAX_OUTPUT_BYTES: usize = 8 << 20;

const COMPLETE: &str = "complete";
const INITIAL: &str = "initial_observation";
const COMPARED: &str = "compared";
const INDETERMINATE: &str = "indeterminate";
const OBSERVED_ABSENT: &str = "observed_absent";
const STILL_OBSERVED: &str = "still_observed";
const FULL_GRAPH_COLLECTION: &str = "graph_reset_full_scan";
const CANDIDATE_ONLY: &str = "candidate_only";

pub fn evaluate(request: EvaluationRequest) -> Result<EvaluationResponse, KernelError> {
    match request {
        EvaluationRequest::Compare { before, after } => Ok(EvaluationResponse::Compare {
            result: compare(before.as_ref(), &after)?,
        }),
        EvaluationRequest::VerifyObservedAbsent {
            reference,
            after,
            requested_path_ids,
        } => Ok(EvaluationResponse::VerifyObservedAbsent {
            result: verify_observed_absent(&reference, &after, &requested_path_ids)?,
        }),
        EvaluationRequest::RankCandidateCuts { paths } => {
            Ok(EvaluationResponse::RankCandidateCuts {
                result: rank_candidate_cuts(&paths),
            })
        }
    }
}

pub fn compare(
    before: Option<&Snapshot>,
    after: &Snapshot,
) -> Result<ComparisonDecision, KernelError> {
    validate_snapshot(after)?;
    let mut decision = ComparisonDecision::default();
    let Some(before) = before else {
        decision.state = INITIAL.to_owned();
        decision.digest = comparison_digest(&decision);
        return Ok(decision);
    };
    validate_snapshot(before)?;
    validate_shared_scope(before, after)?;
    validate_after_time(before, after)?;
    if !snapshot_is_complete(before) || !snapshot_is_complete(after) {
        decision.state = INDETERMINATE.to_owned();
        decision.digest = comparison_digest(&decision);
        return Ok(decision);
    }

    decision.state = COMPARED.to_owned();
    let before_routes = paths_by_route(&before.paths);
    let after_routes = paths_by_route(&after.paths);
    let route_ids: BTreeSet<&str> = before_routes
        .keys()
        .chain(after_routes.keys())
        .map(String::as_str)
        .collect();
    let mut newly_observed = Vec::new();
    for route_id in route_ids {
        let before_paths = before_routes.get(route_id).cloned().unwrap_or_default();
        let after_paths = after_routes.get(route_id).cloned().unwrap_or_default();
        match (before_paths.is_empty(), after_paths.is_empty()) {
            (true, false) => {
                for path in after_paths {
                    decision.newly_observed_path_ids.push(path.id.clone());
                    newly_observed.push(path.clone());
                }
            }
            (false, true) => {
                decision
                    .no_longer_observed_path_ids
                    .extend(before_paths.iter().map(|path| path.id.clone()));
            }
            (false, false) if same_path_ids(&before_paths, &after_paths) => {
                decision.unchanged_routes += 1;
            }
            (false, false) => decision.proof_changed.push(ProofChange {
                route_id: route_id.to_owned(),
                before_path_ids: path_ids(&before_paths),
                after_path_ids: path_ids(&after_paths),
            }),
            (true, true) => {}
        }
    }
    decision.newly_observed_path_ids.sort();
    decision.no_longer_observed_path_ids.sort();
    decision.candidate_edge_cuts = rank_candidate_cuts(&newly_observed);
    decision.digest = comparison_digest(&decision);
    Ok(decision)
}

pub fn verify_observed_absent(
    reference: &Snapshot,
    after: &Snapshot,
    requested_path_ids: &[String],
) -> Result<VerificationDecision, KernelError> {
    validate_snapshot(reference)?;
    validate_snapshot(after)?;
    validate_shared_scope(reference, after)?;
    validate_after_time(reference, after)?;
    let path_ids = normalized_strings(requested_path_ids.iter().map(String::as_str));
    if path_ids.is_empty() {
        return Err(KernelError::InvalidInput(
            "at least one requested path is required",
        ));
    }
    let reference_by_path: BTreeMap<&str, &SecurityPath> = reference
        .paths
        .iter()
        .map(|path| (path.id.as_str(), path))
        .collect();
    let mut requested_reference_paths = Vec::with_capacity(path_ids.len());
    let mut route_ids = BTreeSet::new();
    for path_id in &path_ids {
        let Some(path) = reference_by_path.get(path_id.as_str()) else {
            return Err(KernelError::InvalidRequestedPath(path_id.clone()));
        };
        route_ids.insert(path.route_id.clone());
        requested_reference_paths.push((*path).clone());
    }

    let reference_runtime_ids = security_path_runtime_ids(&requested_reference_paths);
    let required_runtime_ids = normalized_strings(
        reference_runtime_ids
            .iter()
            .chain(security_path_runtime_ids(&after.paths).iter())
            .map(String::as_str),
    );
    let mut decision = VerificationDecision {
        requested_path_ids: path_ids,
        requested_route_ids: route_ids.into_iter().collect(),
        state: INDETERMINATE.to_owned(),
        ..VerificationDecision::default()
    };
    if !snapshot_is_complete(after) {
        decision.reasons =
            normalized_strings(after.completeness.reasons.iter().map(String::as_str));
    } else if after.collection_receipt.collection_mode != FULL_GRAPH_COLLECTION {
        decision.reasons = vec!["fresh_graph_collection_required".to_owned()];
    } else {
        decision.reasons = verification_runtime_receipt_reasons(
            &reference.collection_receipt,
            &after.collection_receipt,
            &reference_runtime_ids,
            &required_runtime_ids,
        );
        if decision.reasons.is_empty() {
            let route_set: BTreeSet<&str> = decision
                .requested_route_ids
                .iter()
                .map(String::as_str)
                .collect();
            let mut still_observed = after
                .paths
                .iter()
                .filter(|path| route_set.contains(path.route_id.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            sort_paths(&mut still_observed);
            decision.still_observed_path_ids = path_ids_owned(&still_observed);
            if still_observed.is_empty() {
                decision.state = OBSERVED_ABSENT.to_owned();
            } else {
                decision.state = STILL_OBSERVED.to_owned();
                decision.candidate_edge_cuts = rank_candidate_cuts(&still_observed);
            }
        }
    }
    decision.digest = verification_digest(&decision);
    Ok(decision)
}

pub fn rank_candidate_cuts(paths: &[SecurityPath]) -> Vec<CandidateEdgeCut> {
    struct Coverage {
        edge: ProofEdge,
        route_ids: BTreeSet<String>,
        path_ids: BTreeSet<String>,
    }

    let mut ordered_paths = paths.to_vec();
    sort_paths(&mut ordered_paths);
    let mut by_edge = BTreeMap::<String, Coverage>::new();
    for path in ordered_paths {
        let mut seen = BTreeSet::new();
        for edge in path.proof_edges {
            if edge.id.is_empty() || !seen.insert(edge.id.clone()) {
                continue;
            }
            let coverage = by_edge.entry(edge.id.clone()).or_insert_with(|| Coverage {
                edge,
                route_ids: BTreeSet::new(),
                path_ids: BTreeSet::new(),
            });
            coverage.route_ids.insert(path.route_id.clone());
            coverage.path_ids.insert(path.id.clone());
        }
    }
    let mut candidates = by_edge
        .into_values()
        .map(|coverage| {
            let covered_route_ids = coverage.route_ids.into_iter().collect::<Vec<_>>();
            let covered_path_ids = coverage.path_ids.into_iter().collect::<Vec<_>>();
            CandidateEdgeCut {
                state: CANDIDATE_ONLY.to_owned(),
                edge: coverage.edge,
                route_coverage: covered_route_ids.len(),
                path_coverage: covered_path_ids.len(),
                covered_route_ids,
                covered_path_ids,
                ..CandidateEdgeCut::default()
            }
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        right
            .route_coverage
            .cmp(&left.route_coverage)
            .then_with(|| right.path_coverage.cmp(&left.path_coverage))
            .then_with(|| {
                candidate_edge_cut_priority(&left.edge.relation)
                    .cmp(&candidate_edge_cut_priority(&right.edge.relation))
            })
            .then_with(|| left.edge.id.cmp(&right.edge.id))
    });
    for (index, candidate) in candidates.iter_mut().enumerate() {
        candidate.rank = index + 1;
    }
    candidates
}

fn validate_snapshot(snapshot: &Snapshot) -> Result<(), KernelError> {
    if snapshot.id.trim().is_empty()
        || snapshot.digest.trim().is_empty()
        || snapshot.tenant_id.trim().is_empty()
        || snapshot.scope_id.trim().is_empty()
        || snapshot.detector_id.trim().is_empty()
        || snapshot.detector_revision.trim().is_empty()
        || snapshot.observation_id.trim().is_empty()
        || snapshot.observed_at.trim().is_empty()
    {
        return Err(KernelError::InvalidSnapshot("identity is required"));
    }
    parse_time(&snapshot.observed_at)?;
    Ok(())
}

fn validate_shared_scope(before: &Snapshot, after: &Snapshot) -> Result<(), KernelError> {
    if before.tenant_id != after.tenant_id
        || before.scope_id != after.scope_id
        || before.detector_id != after.detector_id
        || before.detector_revision != after.detector_revision
    {
        return Err(KernelError::InvalidInput(
            "snapshots must share tenant, scope, and detector revision",
        ));
    }
    Ok(())
}

fn validate_after_time(before: &Snapshot, after: &Snapshot) -> Result<(), KernelError> {
    if parse_time(&after.observed_at)? <= parse_time(&before.observed_at)? {
        return Err(KernelError::InvalidInput(
            "later snapshot must follow the reference snapshot",
        ));
    }
    Ok(())
}

fn parse_time(value: &str) -> Result<OffsetDateTime, KernelError> {
    OffsetDateTime::parse(value.trim(), &Rfc3339).map_err(|_| KernelError::InvalidTime)
}

fn nonzero_time(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty() && value != "0001-01-01T00:00:00Z"
}

fn snapshot_is_complete(snapshot: &Snapshot) -> bool {
    let receipt = &snapshot.collection_receipt;
    snapshot.completeness.state == COMPLETE
        && snapshot.completeness.reasons.is_empty()
        && !receipt.source_runtime_id.is_empty()
        && !receipt.source_id.is_empty()
        && nonzero_time(&receipt.runtime_watermark)
        && nonzero_time(&receipt.last_synced_at)
        && !receipt.graph_checkpoint_id.is_empty()
        && !receipt.graph_run_id.is_empty()
        && receipt.graph_checkpoint_complete
        && receipt.graph_checkpoint_current
        && receipt.observed_path_count == snapshot.paths.len()
        && receipt.observed_path_count == receipt.total_path_count
        && receipt.lease_held
        && receipt.limitations.is_empty()
}

fn paths_by_route(paths: &[SecurityPath]) -> BTreeMap<String, Vec<&SecurityPath>> {
    let mut result = BTreeMap::<String, Vec<&SecurityPath>>::new();
    for path in paths {
        result.entry(path.route_id.clone()).or_default().push(path);
    }
    for values in result.values_mut() {
        values.sort_by(|left, right| left.id.cmp(&right.id));
    }
    result
}

fn same_path_ids(left: &[&SecurityPath], right: &[&SecurityPath]) -> bool {
    path_ids(left) == path_ids(right)
}

fn path_ids(paths: &[&SecurityPath]) -> Vec<String> {
    let mut ids = paths.iter().map(|path| path.id.clone()).collect::<Vec<_>>();
    ids.sort();
    ids
}

fn path_ids_owned(paths: &[SecurityPath]) -> Vec<String> {
    let mut ids = paths.iter().map(|path| path.id.clone()).collect::<Vec<_>>();
    ids.sort();
    ids
}

fn sort_paths(paths: &mut [SecurityPath]) {
    paths.sort_by(|left, right| {
        left.route_id
            .cmp(&right.route_id)
            .then_with(|| left.id.cmp(&right.id))
    });
}

fn normalized_strings<'a>(values: impl Iterator<Item = &'a str>) -> Vec<String> {
    values
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn security_path_runtime_ids(paths: &[SecurityPath]) -> Vec<String> {
    let mut runtime_ids = BTreeSet::new();
    for path in paths {
        for edge in path
            .proof_edges
            .iter()
            .chain(path.ownerships.iter().map(|ownership| &ownership.edge))
        {
            for runtime_id in edge
                .assertion_runtime_ids
                .iter()
                .chain(std::iter::once(&edge.source_runtime_id))
            {
                let runtime_id = runtime_id.trim();
                if !runtime_id.is_empty() {
                    runtime_ids.insert(runtime_id.to_owned());
                }
            }
        }
    }
    runtime_ids.into_iter().collect()
}

fn verification_runtime_receipt_reasons(
    reference: &CollectionReceipt,
    after: &CollectionReceipt,
    reference_runtime_ids: &[String],
    required_runtime_ids: &[String],
) -> Vec<String> {
    let after_scope: BTreeSet<&str> = after
        .proof_runtime_ids
        .iter()
        .map(|value| value.trim())
        .collect();
    let reference_receipts = runtime_receipts_by_id(&reference.runtime_receipts);
    let after_receipts = runtime_receipts_by_id(&after.runtime_receipts);
    let reference_runtime_set: BTreeSet<&str> =
        reference_runtime_ids.iter().map(String::as_str).collect();
    let mut reasons = Vec::new();
    for runtime_id in required_runtime_ids {
        if !after_scope.contains(runtime_id.as_str()) {
            reasons.push(format!("verification_runtime_scope_missing:{runtime_id}"));
            continue;
        }
        let Some(after_receipt) = after_receipts.get(runtime_id.as_str()) else {
            reasons.push(format!("verification_runtime_receipt_missing:{runtime_id}"));
            continue;
        };
        reasons.extend(runtime_receipt_incomplete_reasons(
            &format!("verification_runtime:{runtime_id}:"),
            after_receipt,
        ));
        if !reference_runtime_set.contains(runtime_id.as_str()) {
            continue;
        }
        let Some(reference_receipt) = reference_receipts.get(runtime_id.as_str()) else {
            reasons.push(format!("reference_runtime_receipt_missing:{runtime_id}"));
            continue;
        };
        if after_receipt.provider_family != reference_receipt.provider_family {
            reasons.push(format!(
                "verification_runtime_provider_family_changed:{runtime_id}"
            ));
        }
        if after_receipt.config_revision != reference_receipt.config_revision {
            reasons.push(format!(
                "verification_runtime_config_revision_changed:{runtime_id}"
            ));
        }
    }
    normalized_strings(reasons.iter().map(String::as_str))
}

fn runtime_receipts_by_id(
    receipts: &[RuntimeCollectionReceipt],
) -> BTreeMap<&str, &RuntimeCollectionReceipt> {
    receipts
        .iter()
        .filter_map(|receipt| {
            let runtime_id = receipt.source_runtime_id.trim();
            (!runtime_id.is_empty()).then_some((runtime_id, receipt))
        })
        .collect()
}

fn runtime_receipt_incomplete_reasons(
    prefix: &str,
    receipt: &RuntimeCollectionReceipt,
) -> Vec<String> {
    let mut reasons = Vec::new();
    for (missing, suffix) in [
        (receipt.source_id.is_empty(), "source_missing"),
        (
            receipt.provider_family.is_empty(),
            "provider_family_missing",
        ),
        (
            receipt.config_revision.is_empty(),
            "config_revision_missing",
        ),
        (
            !nonzero_time(&receipt.runtime_watermark),
            "runtime_watermark_missing",
        ),
        (!nonzero_time(&receipt.last_synced_at), "last_sync_missing"),
        (
            receipt.graph_checkpoint_id.is_empty(),
            "graph_checkpoint_missing",
        ),
        (receipt.graph_run_id.is_empty(), "graph_run_missing"),
        (
            !nonzero_time(&receipt.graph_run_started_at)
                || !nonzero_time(&receipt.graph_run_finished_at),
            "graph_run_time_missing",
        ),
        (
            !receipt.graph_checkpoint_complete,
            "graph_checkpoint_incomplete",
        ),
        (
            !receipt.graph_checkpoint_current,
            "graph_checkpoint_not_current",
        ),
    ] {
        if missing {
            reasons.push(format!("{prefix}{suffix}"));
        }
    }
    reasons.extend(
        receipt
            .limitations
            .iter()
            .map(|limitation| format!("{prefix}{limitation}")),
    );
    reasons
}

fn candidate_edge_cut_priority(relation: &str) -> u8 {
    match relation {
        "can_reach" => 0,
        "can_admin" | "can_perform" | "can_assume" | "can_impersonate" => 1,
        "runs_as" | "attached_to" | "assigned_to" | "member_of" | "depends_on" => 2,
        "belongs_to" => 4,
        _ => 3,
    }
}

fn comparison_digest(decision: &ComparisonDecision) -> String {
    let mut values = vec![
        "security-path-comparison-decision/v1".to_owned(),
        decision.state.clone(),
        decision.unchanged_routes.to_string(),
    ];
    append_values(&mut values, "new", &decision.newly_observed_path_ids);
    append_values(
        &mut values,
        "removed",
        &decision.no_longer_observed_path_ids,
    );
    for change in &decision.proof_changed {
        values.push("proof_changed".to_owned());
        values.push(change.route_id.clone());
        append_values(&mut values, "before", &change.before_path_ids);
        append_values(&mut values, "after", &change.after_path_ids);
    }
    append_cut_values(&mut values, &decision.candidate_edge_cuts);
    digest_strings(&values)
}

fn verification_digest(decision: &VerificationDecision) -> String {
    let mut values = vec![
        "security-path-verification-decision/v1".to_owned(),
        decision.state.clone(),
    ];
    append_values(&mut values, "requested_path", &decision.requested_path_ids);
    append_values(
        &mut values,
        "requested_route",
        &decision.requested_route_ids,
    );
    append_values(&mut values, "reason", &decision.reasons);
    append_values(
        &mut values,
        "still_observed",
        &decision.still_observed_path_ids,
    );
    append_cut_values(&mut values, &decision.candidate_edge_cuts);
    digest_strings(&values)
}

fn append_values(target: &mut Vec<String>, label: &str, values: &[String]) {
    for value in values {
        target.push(label.to_owned());
        target.push(value.clone());
    }
}

fn append_cut_values(target: &mut Vec<String>, cuts: &[CandidateEdgeCut]) {
    for cut in cuts {
        target.push("cut".to_owned());
        target.push(cut.rank.to_string());
        target.push(cut.state.clone());
        target.push(cut.edge.id.clone());
        target.push(cut.edge.relation.clone());
        target.push(cut.route_coverage.to_string());
        target.push(cut.path_coverage.to_string());
        append_values(target, "cut_route", &cut.covered_route_ids);
        append_values(target, "cut_path", &cut.covered_path_ids);
    }
}

fn digest_strings(values: &[String]) -> String {
    let mut digest = Sha256::new();
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            digest.update([0]);
        }
        digest.update(value.as_bytes());
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(71);
    output.push_str("sha256:");
    for byte in digest.finalize() {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Completeness, RuntimeCollectionReceipt};

    const BEFORE_TIME: &str = "2026-07-15T08:00:00Z";
    const AFTER_TIME: &str = "2026-07-15T08:05:00Z";

    fn path(id: &str, route_id: &str, edge_id: &str, runtime_id: &str) -> SecurityPath {
        SecurityPath {
            id: id.to_owned(),
            route_id: route_id.to_owned(),
            proof_edges: vec![ProofEdge {
                id: edge_id.to_owned(),
                relation: "can_reach".to_owned(),
                source_runtime_id: runtime_id.to_owned(),
                ..ProofEdge::default()
            }],
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
                collection_mode: FULL_GRAPH_COLLECTION.to_owned(),
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
                state: COMPLETE.to_owned(),
                reasons: Vec::new(),
            },
            paths,
            path_set_digest: format!("path-set-{id}"),
            digest: format!("snapshot-digest-{id}"),
        }
    }

    #[test]
    fn comparison_classifies_routes_and_ranks_shared_cut() {
        let before = snapshot(
            "before",
            BEFORE_TIME,
            vec![path("removed", "route-removed", "edge-old", "runtime-a")],
        );
        let after = snapshot(
            "after",
            AFTER_TIME,
            vec![
                path("new-a", "route-new-a", "shared-edge", "runtime-a"),
                path("new-b", "route-new-b", "shared-edge", "runtime-a"),
            ],
        );
        let decision = compare(Some(&before), &after).expect("compare snapshots");
        assert_eq!(decision.state, COMPARED);
        assert_eq!(decision.newly_observed_path_ids, ["new-a", "new-b"]);
        assert_eq!(decision.no_longer_observed_path_ids, ["removed"]);
        assert_eq!(decision.candidate_edge_cuts[0].edge.id, "shared-edge");
        assert_eq!(decision.candidate_edge_cuts[0].route_coverage, 2);
        assert!(decision.digest.starts_with("sha256:"));
    }

    #[test]
    fn comparison_reports_indeterminate_for_incomplete_snapshot() {
        let before = snapshot("before", BEFORE_TIME, Vec::new());
        let mut after = snapshot("after", AFTER_TIME, Vec::new());
        after.completeness.state = "incomplete".to_owned();
        after.completeness.reasons = vec!["proof_runtime_receipt_missing:runtime-a".to_owned()];
        let decision = compare(Some(&before), &after).expect("compare snapshots");
        assert_eq!(decision.state, INDETERMINATE);
        assert!(decision.newly_observed_path_ids.is_empty());
    }

    #[test]
    fn verification_requires_fresh_receipt_for_each_assertion_runtime() {
        let mut reference_path = path("path-a", "route-a", "edge-a", "runtime-a");
        reference_path.proof_edges[0]
            .assertion_runtime_ids
            .push("runtime-b".to_owned());
        let mut reference = snapshot("before", BEFORE_TIME, vec![reference_path]);
        reference.collection_receipt.proof_runtime_ids =
            vec!["runtime-a".to_owned(), "runtime-b".to_owned()];
        let mut runtime_b = reference.collection_receipt.runtime_receipts[0].clone();
        runtime_b.source_runtime_id = "runtime-b".to_owned();
        reference
            .collection_receipt
            .runtime_receipts
            .push(runtime_b);
        let after = snapshot("after", AFTER_TIME, Vec::new());

        let decision = verify_observed_absent(&reference, &after, &["path-a".to_owned()])
            .expect("verify absence");
        assert_eq!(decision.state, INDETERMINATE);
        assert_eq!(
            decision.reasons,
            ["verification_runtime_scope_missing:runtime-b"]
        );
    }

    #[test]
    fn verification_accepts_fresh_complete_absence() {
        let reference = snapshot(
            "before",
            BEFORE_TIME,
            vec![path("path-a", "route-a", "edge-a", "runtime-a")],
        );
        let after = snapshot("after", AFTER_TIME, Vec::new());
        let decision = verify_observed_absent(&reference, &after, &["path-a".to_owned()])
            .expect("verify absence");
        assert_eq!(decision.state, OBSERVED_ABSENT);
        assert!(decision.reasons.is_empty());
        assert!(decision.digest.starts_with("sha256:"));
    }

    #[test]
    fn request_rejects_unknown_fields() {
        let error = serde_json::from_str::<EvaluationRequest>(
            r#"{"operation":"rank_candidate_cuts","paths":[],"unknown":true}"#,
        )
        .expect_err("unknown request fields must fail");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn shared_candidate_cut_corpus_decodes() {
        let request = serde_json::from_str::<EvaluationRequest>(include_str!(
            "../../../internal/securitypathdelta/testdata/rust_shadow/shared_cut.json"
        ))
        .expect("shared candidate-cut corpus must decode");
        let response = evaluate(request).expect("shared candidate-cut corpus must evaluate");
        let EvaluationResponse::RankCandidateCuts { result } = response else {
            panic!("candidate-cut corpus returned another operation");
        };
        assert_eq!(result[0].route_coverage, 2);
    }

    #[test]
    fn comparison_is_order_independent() {
        let before = snapshot("before", BEFORE_TIME, Vec::new());
        let mut paths = vec![
            path("path-b", "route-b", "edge-b", "runtime-a"),
            path("path-a", "route-a", "edge-a", "runtime-a"),
        ];
        let first = compare(Some(&before), &snapshot("after", AFTER_TIME, paths.clone()))
            .expect("first comparison");
        paths.reverse();
        let second = compare(Some(&before), &snapshot("after", AFTER_TIME, paths))
            .expect("second comparison");
        assert_eq!(first, second);
    }
}
