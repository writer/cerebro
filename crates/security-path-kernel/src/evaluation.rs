use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::model::{
    CandidateEdgeCut, CollectionReceipt, ComparisonDecision, DECISION_INPUT_V1, DecisionRequest,
    DecisionResponse, EvaluationRequest, EvaluationResponse, KernelError, ProofChange, ProofEdge,
    RuntimeCollectionReceipt, SecurityPath, Snapshot, VerificationDecision,
};

/// Version of the exported WebAssembly calling convention.
///
/// This is independent of [`DECISION_INPUT_V1`]: the ABI version describes
/// memory exchange with a host, while the schema version describes JSON data.
pub const ABI_VERSION: u32 = 1;
#[cfg(target_arch = "wasm32")]
/// Maximum JSON request allocation accepted by the WebAssembly guest.
pub(crate) const MAX_INPUT_BYTES: usize = 8 << 20;
#[cfg(target_arch = "wasm32")]
/// Maximum serialized JSON response retained by the WebAssembly guest.
pub(crate) const MAX_OUTPUT_BYTES: usize = 8 << 20;

// Decision states are wire values shared with the Go authority path. Changing any
// value is a schema change even though the constants are private to this crate.
const COMPLETE: &str = "complete";
const INITIAL: &str = "initial_observation";
const COMPARED: &str = "compared";
const INDETERMINATE: &str = "indeterminate";
const OBSERVED_ABSENT: &str = "observed_absent";
const STILL_OBSERVED: &str = "still_observed";
const FULL_GRAPH_COLLECTION: &str = "graph_reset_full_scan";
const CANDIDATE_ONLY: &str = "candidate_only";

// Semantic limits are enforced before hashing or evaluation so work and output
// remain bounded on both native and WebAssembly hosts.
const MAX_PATHS: usize = 100;
const MAX_PROOF_EDGES_PER_PATH: usize = 64;
const MAX_RUNTIME_RECEIPTS: usize = 256;
const MAX_REQUESTED_PATH_IDS: usize = 256;
const MAX_STRING_BYTES: usize = 4_096;

/// Validates a content-bound request and evaluates its decision operation.
///
/// The supplied `input_digest` must match the canonical digest of `request`.
/// Callers that are constructing a new request should use
/// [`bind_decision_input`] instead of calculating the digest themselves.
///
/// # Errors
///
/// Returns [`KernelError::UnsupportedSchemaVersion`] for an unknown schema,
/// [`KernelError::InputDigestMismatch`] when the request was changed after it
/// was bound, or an operation-specific validation error.
pub fn evaluate(request: EvaluationRequest) -> Result<EvaluationResponse, KernelError> {
    if request.schema_version != DECISION_INPUT_V1 {
        return Err(KernelError::UnsupportedSchemaVersion);
    }
    let computed_digest = decision_input_digest(&request.request)?;
    if request.input_digest != computed_digest {
        return Err(KernelError::InputDigestMismatch);
    }
    evaluate_verified(request.request, computed_digest)
}

/// Evaluates a request after its envelope schema and digest have been verified.
///
/// Validation is repeated through [`ValidatedDecisionRequest`] so internal callers
/// cannot accidentally bypass semantic bounds merely by skipping [`evaluate`].
pub(crate) fn evaluate_verified(
    request: DecisionRequest,
    input_digest: String,
) -> Result<EvaluationResponse, KernelError> {
    let request = ValidatedDecisionRequest::new(request)?;
    let source_snapshot_digests = source_snapshot_digests(&request.0);
    let response = match request.0 {
        DecisionRequest::Compare { before, after } => DecisionResponse::Compare {
            result: compare(before.as_ref(), &after)?,
        },
        DecisionRequest::VerifyObservedAbsent {
            reference,
            after,
            requested_path_ids,
        } => DecisionResponse::VerifyObservedAbsent {
            result: verify_observed_absent(&reference, &after, &requested_path_ids)?,
        },
        DecisionRequest::RankCandidateCuts { paths } => DecisionResponse::RankCandidateCuts {
            result: rank_candidate_cuts(&paths),
        },
    };
    Ok(EvaluationResponse {
        schema_version: DECISION_INPUT_V1.to_owned(),
        input_digest,
        source_snapshot_digests,
        response,
    })
}

/// Validates an operation and binds its decision-relevant input to a canonical digest.
///
/// The returned envelope is ready for [`evaluate`]. Binding makes mutation or
/// substitution of any field consumed by the v1 decision operations detectable at
/// the evaluation boundary. Rich display and provenance fields that the operations
/// do not inspect are intentionally excluded to preserve Go/Rust wire parity.
///
/// # Errors
///
/// Returns a validation error when the operation exceeds kernel limits or
/// contains an invalid snapshot, path, receipt, timestamp, or identifier.
pub fn bind_decision_input(request: DecisionRequest) -> Result<EvaluationRequest, KernelError> {
    validate_decision_request(&request)?;
    let input_digest = decision_input_digest(&request)?;
    Ok(EvaluationRequest {
        schema_version: DECISION_INPUT_V1.to_owned(),
        input_digest,
        request,
    })
}

/// Typestate wrapper proving that a decision request satisfies all kernel bounds.
///
/// The tuple field is private and construction is restricted to [`Self::new`], so
/// downstream evaluation can rely on the validation pass having completed.
struct ValidatedDecisionRequest(DecisionRequest);

impl ValidatedDecisionRequest {
    /// Validates `request` and returns the only admissible internal representation.
    fn new(request: DecisionRequest) -> Result<Self, KernelError> {
        validate_decision_request(&request)?;
        Ok(Self(request))
    }
}

/// Compares two observations of the same detector scope.
///
/// With no `before` snapshot the result is `initial_observation` and does not
/// classify any path as newly observed. With two complete snapshots, paths are
/// compared by route and path identity. If either snapshot is incomplete, the
/// result is `indeterminate`; absence is never inferred from partial evidence.
///
/// # Errors
///
/// Returns an error when a snapshot is invalid, the scopes or detector revisions
/// differ, or `after.observed_at` does not strictly follow the earlier snapshot.
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
    // Route identity represents the effective exposure. Exact path identity only
    // distinguishes alternative proofs for that same route.
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

/// Determines whether requested reference paths are absent from a later scan.
///
/// Verification is route-based: if any path for a requested path's route remains,
/// the result is `still_observed`. `observed_absent` requires a complete later
/// snapshot produced by `graph_reset_full_scan`, current and complete runtime
/// receipts for every relevant source runtime, and compatible provider/config
/// identity. Any missing authority produces `indeterminate` with reason codes.
///
/// # Errors
///
/// Returns an error when either snapshot is invalid, the snapshots do not share
/// scope, time does not advance, no path is requested, or a requested identifier
/// is absent from the reference snapshot.
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

    // Reference runtimes prove that the original paths were recollected. Runtimes
    // present only in the later snapshot are included as well so newly introduced
    // evidence cannot participate without a current receipt.
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

/// Ranks proof edges by how many distinct routes and paths they cover.
///
/// Ranking is deterministic: route coverage descends first, then path coverage,
/// relation priority, and edge identifier. Duplicate edge identifiers within a
/// path count once. Results are always marked `candidate_only`; they are planning
/// hints, not authorization to mutate infrastructure and not verification that a
/// cut preserves intended access.
pub fn rank_candidate_cuts(paths: &[SecurityPath]) -> Vec<CandidateEdgeCut> {
    struct Coverage {
        edge: ProofEdge,
        route_ids: BTreeSet<String>,
        path_ids: BTreeSet<String>,
    }

    let mut ordered_paths = paths.to_vec();
    sort_paths(&mut ordered_paths);
    // Ordered paths and a BTreeMap make both representative-edge selection and
    // final tie-breaking stable. If an edge ID appears on multiple paths, the
    // first deterministically ordered path supplies the representative payload.
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

/// Calculates the v1 digest over the fields consumed by the selected operation.
///
/// This field order mirrors the Go host's reduced wire structs. It is therefore a
/// cross-language protocol: reordering fields, adding fields, or changing encodings
/// requires a new schema identifier and parity vector.
fn decision_input_digest(request: &DecisionRequest) -> Result<String, KernelError> {
    let mut hasher = DecisionInputHasher::new();
    match request {
        DecisionRequest::Compare { before, after } => {
            hasher.string("compare");
            hasher.boolean(before.is_some());
            if let Some(before) = before {
                hash_snapshot(&mut hasher, before);
            }
            hash_snapshot(&mut hasher, after);
        }
        DecisionRequest::VerifyObservedAbsent {
            reference,
            after,
            requested_path_ids,
        } => {
            hasher.string("verify_observed_absent");
            hash_snapshot(&mut hasher, reference);
            hash_snapshot(&mut hasher, after);
            hash_strings(&mut hasher, requested_path_ids);
        }
        DecisionRequest::RankCandidateCuts { paths } => {
            hasher.string("rank_candidate_cuts");
            hasher.unsigned(paths.len());
            for path in paths {
                hash_security_path(&mut hasher, path);
            }
        }
    }
    Ok(hasher.finish())
}

/// Domain-separated, length-prefixed encoder for the v1 input digest.
///
/// Length prefixes prevent adjacent strings from being resegmented into the same
/// byte stream. Counts use fixed-width big-endian `u64` so 32-bit Wasm and 64-bit
/// native hosts calculate identical digests.
struct DecisionInputHasher(Sha256);

impl DecisionInputHasher {
    /// Starts a digest in the decision-input-v1 domain.
    fn new() -> Self {
        let mut digest = Sha256::new();
        digest.update(DECISION_INPUT_V1.as_bytes());
        digest.update([0]);
        Self(digest)
    }

    /// Appends one byte string with its length, preserving empty values distinctly.
    fn string(&mut self, value: &str) {
        self.unsigned(value.len());
        self.0.update(value.as_bytes());
    }

    /// Appends a single canonical byte for a boolean value.
    fn boolean(&mut self, value: bool) {
        self.0.update([u8::from(value)]);
    }

    /// Appends a collection length or bounded count as big-endian `u64`.
    fn unsigned(&mut self, value: usize) {
        self.0.update((value as u64).to_be_bytes());
    }

    /// Finalizes the digest in the repository's `sha256:<lower-hex>` form.
    fn finish(self) -> String {
        format_sha256(self.0.finalize())
    }
}

/// Appends the authority, completeness, path, and declared snapshot-digest fields.
///
/// Receipt telemetry that is not consumed by these decisions is intentionally
/// absent, matching the Go `rustSnapshotInput` projection.
fn hash_snapshot(hasher: &mut DecisionInputHasher, snapshot: &Snapshot) {
    let receipt = &snapshot.collection_receipt;
    for value in [
        &snapshot.id,
        &snapshot.tenant_id,
        &snapshot.scope_id,
        &snapshot.detector_id,
        &snapshot.detector_revision,
        &snapshot.observation_id,
        &snapshot.observed_at,
        &receipt.source_runtime_id,
        &receipt.source_id,
        &receipt.runtime_watermark,
        &receipt.last_synced_at,
        &receipt.collection_mode,
        &receipt.graph_checkpoint_id,
        &receipt.graph_run_id,
    ] {
        hasher.string(value);
    }
    hasher.boolean(receipt.graph_checkpoint_complete);
    hasher.boolean(receipt.graph_checkpoint_current);
    hasher.unsigned(receipt.observed_path_count);
    hasher.unsigned(receipt.total_path_count);
    hasher.boolean(receipt.lease_held);
    hash_strings(hasher, &receipt.limitations);
    hash_strings(hasher, &receipt.proof_runtime_ids);
    hasher.unsigned(receipt.runtime_receipts.len());
    for runtime_receipt in &receipt.runtime_receipts {
        hash_runtime_receipt(hasher, runtime_receipt);
    }
    hasher.string(&snapshot.completeness.state);
    hash_strings(hasher, &snapshot.completeness.reasons);
    hasher.unsigned(snapshot.paths.len());
    for path in &snapshot.paths {
        hash_security_path(hasher, path);
    }
    hasher.string(&snapshot.digest);
}

/// Appends every per-runtime field used to establish fresh compatible collection.
fn hash_runtime_receipt(hasher: &mut DecisionInputHasher, receipt: &RuntimeCollectionReceipt) {
    for value in [
        &receipt.source_runtime_id,
        &receipt.source_id,
        &receipt.provider_family,
        &receipt.config_revision,
        &receipt.runtime_watermark,
        &receipt.last_synced_at,
        &receipt.graph_checkpoint_id,
        &receipt.graph_run_id,
        &receipt.graph_run_started_at,
        &receipt.graph_run_finished_at,
    ] {
        hasher.string(value);
    }
    hasher.boolean(receipt.graph_checkpoint_complete);
    hasher.boolean(receipt.graph_checkpoint_current);
    hash_strings(hasher, &receipt.limitations);
}

/// Appends the path identity and edge material consumed by kernel decisions.
///
/// Node display data, materiality, provenance, and owner display metadata do not
/// affect comparison, verification, or ranking and are outside the v1 wire digest.
fn hash_security_path(hasher: &mut DecisionInputHasher, path: &SecurityPath) {
    hasher.string(&path.id);
    hasher.string(&path.route_id);
    hasher.unsigned(path.proof_edges.len());
    for edge in &path.proof_edges {
        hash_proof_edge(hasher, edge);
    }
    hasher.unsigned(path.ownerships.len());
    for ownership in &path.ownerships {
        hash_proof_edge(hasher, &ownership.edge);
    }
}

/// Appends the edge identity, relation, and runtime authority used by decisions.
fn hash_proof_edge(hasher: &mut DecisionInputHasher, edge: &ProofEdge) {
    hasher.string(&edge.id);
    hasher.string(&edge.relation);
    hasher.string(&edge.source_runtime_id);
    hash_strings(hasher, &edge.assertion_runtime_ids);
}

/// Appends an ordered string collection, including its element count.
fn hash_strings(hasher: &mut DecisionInputHasher, values: &[String]) {
    hasher.unsigned(values.len());
    for value in values {
        hasher.string(value);
    }
}

/// Returns source snapshot digests in the operation's stable receipt order.
///
/// Comparisons emit earlier then later when an earlier snapshot exists;
/// verification emits reference then later; cut ranking has no snapshot source.
fn source_snapshot_digests(request: &DecisionRequest) -> Vec<String> {
    match request {
        DecisionRequest::Compare { before, after } => before
            .iter()
            .map(|snapshot| snapshot.digest.clone())
            .chain(std::iter::once(after.digest.clone()))
            .collect(),
        DecisionRequest::VerifyObservedAbsent {
            reference, after, ..
        } => vec![reference.digest.clone(), after.digest.clone()],
        DecisionRequest::RankCandidateCuts { .. } => Vec::new(),
    }
}

/// Applies operation-specific structural, uniqueness, and size validation.
///
/// Snapshot operations validate both semantic snapshot identity and the deeper
/// bounded object graph. Ranking has no snapshot envelope, so it validates paths
/// directly.
fn validate_decision_request(request: &DecisionRequest) -> Result<(), KernelError> {
    match request {
        DecisionRequest::Compare { before, after } => {
            if let Some(before) = before {
                validate_snapshot(before)?;
                validate_snapshot_bounds(before)?;
            }
            validate_snapshot(after)?;
            validate_snapshot_bounds(after)
        }
        DecisionRequest::VerifyObservedAbsent {
            reference,
            after,
            requested_path_ids,
        } => {
            validate_snapshot(reference)?;
            validate_snapshot_bounds(reference)?;
            validate_snapshot(after)?;
            validate_snapshot_bounds(after)?;
            validate_unique_strings(
                requested_path_ids,
                MAX_REQUESTED_PATH_IDS,
                "too many requested path identifiers",
                "requested path identifiers must be unique",
            )?;
            for value in requested_path_ids {
                validate_required_string(value, "requested path identity is required")?;
            }
            Ok(())
        }
        DecisionRequest::RankCandidateCuts { paths } => validate_paths(paths),
    }
}

/// Bounds every snapshot string and repeated field reachable by the v1 kernel.
///
/// This pass is intentionally separate from [`validate_snapshot`]: public
/// comparison helpers need semantic identity checks, while bound requests must
/// additionally constrain work before hashing and Wasm evaluation.
fn validate_snapshot_bounds(snapshot: &Snapshot) -> Result<(), KernelError> {
    for value in [
        &snapshot.id,
        &snapshot.tenant_id,
        &snapshot.scope_id,
        &snapshot.detector_id,
        &snapshot.detector_revision,
        &snapshot.observation_id,
        &snapshot.observed_at,
        &snapshot.digest,
        &snapshot.completeness.state,
    ] {
        validate_bounded_string(value)?;
    }
    for reason in &snapshot.completeness.reasons {
        validate_bounded_string(reason)?;
    }
    validate_paths(&snapshot.paths)?;
    let receipt = &snapshot.collection_receipt;
    for value in [
        &receipt.source_runtime_id,
        &receipt.source_id,
        &receipt.runtime_watermark,
        &receipt.last_synced_at,
        &receipt.collection_mode,
        &receipt.graph_checkpoint_id,
        &receipt.graph_run_id,
    ] {
        validate_bounded_string(value)?;
    }
    validate_unique_strings(
        &receipt.proof_runtime_ids,
        MAX_RUNTIME_RECEIPTS,
        "too many proof runtime identifiers",
        "proof runtime identifiers must be unique",
    )?;
    if receipt.runtime_receipts.len() > MAX_RUNTIME_RECEIPTS {
        return Err(KernelError::InvalidInput("too many runtime receipts"));
    }
    let mut runtime_ids = BTreeSet::new();
    for runtime_receipt in &receipt.runtime_receipts {
        validate_required_string(
            &runtime_receipt.source_runtime_id,
            "runtime receipt identity is required",
        )?;
        if !runtime_ids.insert(runtime_receipt.source_runtime_id.trim()) {
            return Err(KernelError::InvalidInput(
                "runtime receipt identifiers must be unique",
            ));
        }
        for value in [
            &runtime_receipt.source_runtime_id,
            &runtime_receipt.source_id,
            &runtime_receipt.provider_family,
            &runtime_receipt.config_revision,
            &runtime_receipt.runtime_watermark,
            &runtime_receipt.last_synced_at,
            &runtime_receipt.graph_checkpoint_id,
            &runtime_receipt.graph_run_id,
            &runtime_receipt.graph_run_started_at,
            &runtime_receipt.graph_run_finished_at,
        ] {
            validate_bounded_string(value)?;
        }
        for limitation in &runtime_receipt.limitations {
            validate_bounded_string(limitation)?;
        }
    }
    for limitation in &receipt.limitations {
        validate_bounded_string(limitation)?;
    }
    Ok(())
}

/// Validates path, edge, and assertion-runtime bounds and local uniqueness.
///
/// Path identifiers are unique across the request. Edge identifiers need only be
/// unique within one path because a shared edge is precisely what cut ranking
/// aggregates across paths.
fn validate_paths(paths: &[SecurityPath]) -> Result<(), KernelError> {
    if paths.len() > MAX_PATHS {
        return Err(KernelError::InvalidInput("too many security paths"));
    }
    let mut path_ids = BTreeSet::new();
    for path in paths {
        validate_required_string(&path.id, "path identity is required")?;
        validate_required_string(&path.route_id, "route identity is required")?;
        if !path_ids.insert(path.id.trim()) {
            return Err(KernelError::InvalidInput("path identifiers must be unique"));
        }
        if path.proof_edges.len() + path.ownerships.len() > MAX_PROOF_EDGES_PER_PATH {
            return Err(KernelError::InvalidInput("too many proof edges"));
        }
        let mut edge_ids = BTreeSet::new();
        for edge in path
            .proof_edges
            .iter()
            .chain(path.ownerships.iter().map(|ownership| &ownership.edge))
        {
            validate_required_string(&edge.id, "proof edge identity is required")?;
            validate_required_string(&edge.relation, "proof edge relation is required")?;
            if !edge_ids.insert(edge.id.trim()) {
                return Err(KernelError::InvalidInput(
                    "proof edge identifiers must be unique within a path",
                ));
            }
            for value in [&edge.id, &edge.relation, &edge.source_runtime_id] {
                validate_bounded_string(value)?;
            }
            validate_unique_strings(
                &edge.assertion_runtime_ids,
                MAX_RUNTIME_RECEIPTS,
                "too many assertion runtime identifiers",
                "assertion runtime identifiers must be unique",
            )?;
        }
    }
    Ok(())
}

/// Validates a bounded string list and rejects duplicates after trimming.
///
/// Values themselves are retained verbatim; trimming is only the identity rule
/// used to prevent whitespace aliases from bypassing uniqueness checks.
fn validate_unique_strings(
    values: &[String],
    maximum: usize,
    too_many: &'static str,
    duplicated: &'static str,
) -> Result<(), KernelError> {
    if values.len() > maximum {
        return Err(KernelError::InvalidInput(too_many));
    }
    let mut unique = BTreeSet::new();
    for value in values {
        validate_bounded_string(value)?;
        if !unique.insert(value.trim()) {
            return Err(KernelError::InvalidInput(duplicated));
        }
    }
    Ok(())
}

/// Requires a bounded string with at least one non-whitespace character.
fn validate_required_string(value: &str, reason: &'static str) -> Result<(), KernelError> {
    validate_bounded_string(value)?;
    if value.trim().is_empty() {
        return Err(KernelError::InvalidInput(reason));
    }
    Ok(())
}

/// Rejects a string whose UTF-8 representation exceeds the per-field byte limit.
fn validate_bounded_string(value: &str) -> Result<(), KernelError> {
    if value.len() > MAX_STRING_BYTES {
        return Err(KernelError::InvalidInput("string exceeds size limit"));
    }
    Ok(())
}

/// Validates the semantic identity, declared digest shape, and observation time.
///
/// This does not recompute the snapshot digest: the snapshot producer owns that
/// content-addressing contract, while this kernel binds the supplied digest into
/// its input receipt and validates the decision fields independently.
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
    if !is_sha256_digest(&snapshot.digest) {
        return Err(KernelError::InvalidSnapshot(
            "digest must be a sha256 value",
        ));
    }
    parse_time(&snapshot.observed_at)?;
    Ok(())
}

/// Checks the repository's prefixed 256-bit hexadecimal digest representation.
fn is_sha256_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

/// Prevents comparison across tenant, scope, detector, or detector-revision boundaries.
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

/// Requires a strict temporal advance so equal observations cannot imply change.
fn validate_after_time(before: &Snapshot, after: &Snapshot) -> Result<(), KernelError> {
    if parse_time(&after.observed_at)? <= parse_time(&before.observed_at)? {
        return Err(KernelError::InvalidInput(
            "later snapshot must follow the reference snapshot",
        ));
    }
    Ok(())
}

/// Parses an RFC 3339 time after removing insignificant surrounding whitespace.
fn parse_time(value: &str) -> Result<OffsetDateTime, KernelError> {
    OffsetDateTime::parse(value.trim(), &Rfc3339).map_err(|_| KernelError::InvalidTime)
}

/// Distinguishes an asserted timestamp from empty and Go zero-time encodings.
///
/// Full RFC 3339 syntax is checked for snapshot observation times. Receipt times
/// are authority claims supplied by the host and currently use this presence test.
fn nonzero_time(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty() && value != "0001-01-01T00:00:00Z"
}

/// Evaluates the top-level collection proof required to infer path absence.
///
/// Completeness requires agreement between detector state, graph checkpoint,
/// path counts, lease ownership, and an unqualified collection receipt. Per-runtime
/// freshness is checked separately by [`verification_runtime_receipt_reasons`].
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

/// Groups paths by effective route and sorts each route's exact proof identities.
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

/// Reports whether two route groups contain the same exact proof identities.
fn same_path_ids(left: &[&SecurityPath], right: &[&SecurityPath]) -> bool {
    path_ids(left) == path_ids(right)
}

/// Copies and sorts identifiers from borrowed paths.
fn path_ids(paths: &[&SecurityPath]) -> Vec<String> {
    let mut ids = paths.iter().map(|path| path.id.clone()).collect::<Vec<_>>();
    ids.sort();
    ids
}

/// Copies and sorts identifiers from an owned path slice.
fn path_ids_owned(paths: &[SecurityPath]) -> Vec<String> {
    let mut ids = paths.iter().map(|path| path.id.clone()).collect::<Vec<_>>();
    ids.sort();
    ids
}

/// Orders paths by effective route and then exact proof identity.
fn sort_paths(paths: &mut [SecurityPath]) {
    paths.sort_by(|left, right| {
        left.route_id
            .cmp(&right.route_id)
            .then_with(|| left.id.cmp(&right.id))
    });
}

/// Trims, removes empty values, deduplicates, and lexically sorts strings.
fn normalized_strings<'a>(values: impl Iterator<Item = &'a str>) -> Vec<String> {
    values
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Collects every source or assertion runtime that contributes an edge to `paths`.
///
/// Ownership edges participate because they are proof material too. Empty values
/// are ignored and the returned runtime identities are sorted and unique.
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

/// Returns stable reasons that runtime evidence cannot prove fresh absence.
///
/// Every required runtime must be declared in the later proof scope and have a
/// complete current receipt. Runtimes that supported a requested reference path
/// must additionally preserve provider family and configuration revision; a
/// changed collection contract cannot prove that the old evidence disappeared.
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
        // Missing scope or receipt authority is terminal for this runtime: there is
        // no trustworthy receipt against which deeper fields can be evaluated.
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

/// Indexes non-empty runtime receipts by their trimmed authority identity.
///
/// Bound requests have already rejected duplicates, so collection into a map
/// cannot silently replace one validated receipt with another.
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

/// Expands one runtime receipt into stable, caller-prefixed limitation codes.
///
/// The prefix binds otherwise generic failures to the exact required runtime.
/// Provider-supplied limitation codes are preserved after the same prefix.
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

/// Maps relation semantics to the deterministic cut-ranking tie-break order.
///
/// Direct reachability ranks ahead of privilege and attachment relations;
/// `belongs_to` ranks last because it usually describes containment rather than
/// an actionable access edge. Unknown relations retain a stable middle priority.
fn candidate_edge_cut_priority(relation: &str) -> u8 {
    match relation {
        "can_reach" => 0,
        "can_admin" | "can_perform" | "can_assume" | "can_impersonate" => 1,
        "runs_as" | "attached_to" | "assigned_to" | "member_of" | "depends_on" => 2,
        "belongs_to" => 4,
        _ => 3,
    }
}

/// Calculates the v1 content digest for a comparison decision.
///
/// The digest excludes its own field and preserves the already normalized result
/// order. The domain label prevents reuse as another decision type.
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

/// Calculates the v1 content digest for an absence-verification decision.
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

/// Appends labeled repeated values to a decision-digest transcript.
fn append_values(target: &mut Vec<String>, label: &str, values: &[String]) {
    for value in values {
        target.push(label.to_owned());
        target.push(value.clone());
    }
}

/// Appends the decision-relevant fields of ranked cut candidates.
///
/// Full edge provenance is intentionally absent because the decision output and
/// its digest expose only edge identity, relation, coverage, rank, and state.
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

/// Hashes a normalized decision transcript using the established v1 encoding.
///
/// Transcript elements are separated by a NUL byte. This legacy output encoding
/// is distinct from the length-prefixed input digest and must remain byte-for-byte
/// stable until a new decision-digest version is introduced.
fn digest_strings(values: &[String]) -> String {
    let mut digest = Sha256::new();
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            digest.update([0]);
        }
        digest.update(value.as_bytes());
    }
    format_sha256(digest.finalize())
}

/// Formats digest bytes as lowercase hexadecimal with the `sha256:` prefix.
fn format_sha256(value: impl IntoIterator<Item = u8>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(71);
    output.push_str("sha256:");
    for byte in value {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Completeness, OwnershipProof, RuntimeCollectionReceipt};

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
            digest: format!("sha256:{:064x}", id.len()),
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
        let request = serde_json::from_str::<DecisionRequest>(include_str!(
            "../../../internal/securitypathdelta/testdata/rust_shadow/shared_cut.json"
        ))
        .expect("shared candidate-cut corpus must decode");
        let response = evaluate(bind_decision_input(request).expect("bind decision input"))
            .expect("shared candidate-cut corpus must evaluate");
        let DecisionResponse::RankCandidateCuts { result } = response.response else {
            panic!("candidate-cut corpus returned another operation");
        };
        assert_eq!(result[0].route_coverage, 2);
    }

    #[test]
    fn evaluation_rejects_unknown_version_and_wrong_digest() {
        let request = DecisionRequest::RankCandidateCuts {
            paths: vec![path("path-a", "route-a", "edge-a", "runtime-a")],
        };
        let mut unsupported = bind_decision_input(request.clone()).expect("bind request");
        unsupported.schema_version = "security-path-decision-input/v2".to_owned();
        assert_eq!(
            evaluate(unsupported),
            Err(KernelError::UnsupportedSchemaVersion)
        );

        let mut tampered = bind_decision_input(request).expect("bind request");
        tampered.input_digest = format!("sha256:{:064x}", 1);
        assert_eq!(evaluate(tampered), Err(KernelError::InputDigestMismatch));
    }

    #[test]
    fn decision_input_digest_matches_v1_vector() {
        let request = DecisionRequest::RankCandidateCuts {
            paths: vec![SecurityPath {
                id: "path-a".to_owned(),
                route_id: "route-a".to_owned(),
                proof_edges: vec![ProofEdge {
                    id: "edge-a".to_owned(),
                    relation: "CAN_ACCESS".to_owned(),
                    source_runtime_id: "runtime-a".to_owned(),
                    assertion_runtime_ids: vec!["runtime-a".to_owned()],
                    ..ProofEdge::default()
                }],
                ..SecurityPath::default()
            }],
        };
        let bound = bind_decision_input(request).expect("bind request");
        assert_eq!(
            bound.input_digest,
            "sha256:40c2ec2e9d328dd86013f22d0de984902d70d248a2d1780d1b63d2c1166fa1a8"
        );
    }

    #[test]
    fn decision_input_rejects_duplicate_identity_and_semantic_overflow() {
        let duplicated = path("path-a", "route-a", "edge-a", "runtime-a");
        assert!(matches!(
            bind_decision_input(DecisionRequest::RankCandidateCuts {
                paths: vec![duplicated.clone(), duplicated],
            }),
            Err(KernelError::InvalidInput("path identifiers must be unique"))
        ));

        let paths = (0..=MAX_PATHS)
            .map(|index| {
                path(
                    &format!("path-{index}"),
                    &format!("route-{index}"),
                    &format!("edge-{index}"),
                    "runtime-a",
                )
            })
            .collect();
        assert!(matches!(
            bind_decision_input(DecisionRequest::RankCandidateCuts { paths }),
            Err(KernelError::InvalidInput("too many security paths"))
        ));
    }

    #[test]
    fn decision_input_binds_every_operation_and_snapshot_source() {
        let before = snapshot(
            "before",
            BEFORE_TIME,
            vec![path("path-a", "route-a", "edge-a", "runtime-a")],
        );
        let after = snapshot("after", AFTER_TIME, Vec::new());
        let bound = bind_decision_input(DecisionRequest::Compare {
            before: Some(before.clone()),
            after: after.clone(),
        })
        .expect("bind comparison");
        let response = evaluate(bound.clone()).expect("evaluate comparison");
        assert_eq!(response.schema_version, DECISION_INPUT_V1);
        assert_eq!(response.input_digest, bound.input_digest);
        assert_eq!(
            response.source_snapshot_digests,
            [before.digest.clone(), after.digest.clone()]
        );
        assert!(matches!(
            response.response,
            DecisionResponse::Compare { .. }
        ));

        let bound = bind_decision_input(DecisionRequest::Compare {
            before: None,
            after: after.clone(),
        })
        .expect("bind baseline comparison");
        let response = evaluate(bound).expect("evaluate baseline comparison");
        assert_eq!(
            response.source_snapshot_digests.as_slice(),
            std::slice::from_ref(&after.digest)
        );

        let bound = bind_decision_input(DecisionRequest::VerifyObservedAbsent {
            reference: before.clone(),
            after,
            requested_path_ids: vec!["path-a".to_owned()],
        })
        .expect("bind verification");
        let response = evaluate(bound).expect("evaluate verification");
        assert_eq!(
            response.source_snapshot_digests,
            [
                before.digest.clone(),
                format!("sha256:{:064x}", "after".len())
            ]
        );
        assert!(matches!(
            response.response,
            DecisionResponse::VerifyObservedAbsent { .. }
        ));
    }

    fn assert_invalid(request: DecisionRequest, expected: KernelError) {
        assert_eq!(
            bind_decision_input(request).expect_err("decision input must fail"),
            expected
        );
    }

    fn compare_after(after: Snapshot) -> DecisionRequest {
        DecisionRequest::Compare {
            before: None,
            after,
        }
    }

    #[test]
    fn decision_input_enforces_string_receipt_and_path_bounds() {
        let mut after = snapshot("after", AFTER_TIME, Vec::new());
        after.digest = "not-a-sha256".to_owned();
        assert_invalid(
            compare_after(after),
            KernelError::InvalidSnapshot("digest must be a sha256 value"),
        );

        let oversized = "x".repeat(MAX_STRING_BYTES + 1);
        let mut after = snapshot("after", AFTER_TIME, Vec::new());
        after.completeness.reasons.push(oversized.clone());
        assert_invalid(
            compare_after(after),
            KernelError::InvalidInput("string exceeds size limit"),
        );

        let mut after = snapshot("after", AFTER_TIME, Vec::new());
        after.collection_receipt.proof_runtime_ids =
            vec!["runtime-a".to_owned(), " runtime-a ".to_owned()];
        assert_invalid(
            compare_after(after),
            KernelError::InvalidInput("proof runtime identifiers must be unique"),
        );

        let mut after = snapshot("after", AFTER_TIME, Vec::new());
        after.collection_receipt.proof_runtime_ids = (0..=MAX_RUNTIME_RECEIPTS)
            .map(|index| format!("runtime-{index}"))
            .collect();
        assert_invalid(
            compare_after(after),
            KernelError::InvalidInput("too many proof runtime identifiers"),
        );

        let mut after = snapshot("after", AFTER_TIME, Vec::new());
        let receipt = after.collection_receipt.runtime_receipts[0].clone();
        after
            .collection_receipt
            .runtime_receipts
            .extend(std::iter::repeat_n(receipt, MAX_RUNTIME_RECEIPTS));
        assert_invalid(
            compare_after(after),
            KernelError::InvalidInput("too many runtime receipts"),
        );

        let mut after = snapshot("after", AFTER_TIME, Vec::new());
        let mut duplicate = after.collection_receipt.runtime_receipts[0].clone();
        duplicate.source_runtime_id = " runtime-a ".to_owned();
        after.collection_receipt.runtime_receipts.push(duplicate);
        assert_invalid(
            compare_after(after),
            KernelError::InvalidInput("runtime receipt identifiers must be unique"),
        );

        let mut after = snapshot("after", AFTER_TIME, Vec::new());
        after.collection_receipt.runtime_receipts[0].source_runtime_id = "  ".to_owned();
        assert_invalid(
            compare_after(after),
            KernelError::InvalidInput("runtime receipt identity is required"),
        );

        let mut after = snapshot("after", AFTER_TIME, Vec::new());
        after.collection_receipt.runtime_receipts[0]
            .limitations
            .push(oversized.clone());
        assert_invalid(
            compare_after(after),
            KernelError::InvalidInput("string exceeds size limit"),
        );

        let mut after = snapshot("after", AFTER_TIME, Vec::new());
        after.collection_receipt.limitations.push(oversized);
        assert_invalid(
            compare_after(after),
            KernelError::InvalidInput("string exceeds size limit"),
        );
    }

    #[test]
    fn decision_input_enforces_requested_path_and_edge_identity() {
        let reference = snapshot(
            "before",
            BEFORE_TIME,
            vec![path("path-a", "route-a", "edge-a", "runtime-a")],
        );
        let after = snapshot("after", AFTER_TIME, Vec::new());
        for (requested_path_ids, expected) in [
            (
                vec!["path-a".to_owned(), " path-a ".to_owned()],
                "requested path identifiers must be unique",
            ),
            (vec![" ".to_owned()], "requested path identity is required"),
        ] {
            assert_invalid(
                DecisionRequest::VerifyObservedAbsent {
                    reference: reference.clone(),
                    after: after.clone(),
                    requested_path_ids,
                },
                KernelError::InvalidInput(expected),
            );
        }
        assert_invalid(
            DecisionRequest::VerifyObservedAbsent {
                reference,
                after,
                requested_path_ids: (0..=MAX_REQUESTED_PATH_IDS)
                    .map(|index| format!("path-{index}"))
                    .collect(),
            },
            KernelError::InvalidInput("too many requested path identifiers"),
        );

        let mut invalid = path(" ", "route-a", "edge-a", "runtime-a");
        assert_invalid(
            DecisionRequest::RankCandidateCuts {
                paths: vec![invalid.clone()],
            },
            KernelError::InvalidInput("path identity is required"),
        );
        invalid.id = "path-a".to_owned();
        invalid.route_id = " ".to_owned();
        assert_invalid(
            DecisionRequest::RankCandidateCuts {
                paths: vec![invalid.clone()],
            },
            KernelError::InvalidInput("route identity is required"),
        );
        invalid.route_id = "route-a".to_owned();
        invalid.proof_edges[0].id = " ".to_owned();
        assert_invalid(
            DecisionRequest::RankCandidateCuts {
                paths: vec![invalid.clone()],
            },
            KernelError::InvalidInput("proof edge identity is required"),
        );
        invalid.proof_edges[0].id = "edge-a".to_owned();
        invalid.proof_edges[0].relation = " ".to_owned();
        assert_invalid(
            DecisionRequest::RankCandidateCuts {
                paths: vec![invalid.clone()],
            },
            KernelError::InvalidInput("proof edge relation is required"),
        );

        let mut duplicated_edge = path("path-a", "route-a", "edge-a", "runtime-a");
        duplicated_edge.ownerships.push(OwnershipProof {
            edge: duplicated_edge.proof_edges[0].clone(),
            ..OwnershipProof::default()
        });
        assert_invalid(
            DecisionRequest::RankCandidateCuts {
                paths: vec![duplicated_edge],
            },
            KernelError::InvalidInput("proof edge identifiers must be unique within a path"),
        );

        let mut too_many_edges = path("path-a", "route-a", "edge-a", "runtime-a");
        too_many_edges.proof_edges = (0..=MAX_PROOF_EDGES_PER_PATH)
            .map(|index| ProofEdge {
                id: format!("edge-{index}"),
                relation: "can_reach".to_owned(),
                ..ProofEdge::default()
            })
            .collect();
        assert_invalid(
            DecisionRequest::RankCandidateCuts {
                paths: vec![too_many_edges],
            },
            KernelError::InvalidInput("too many proof edges"),
        );

        let mut assertion_ids = path("path-a", "route-a", "edge-a", "runtime-a");
        assertion_ids.proof_edges[0].assertion_runtime_ids =
            vec!["runtime-a".to_owned(), " runtime-a ".to_owned()];
        assert_invalid(
            DecisionRequest::RankCandidateCuts {
                paths: vec![assertion_ids],
            },
            KernelError::InvalidInput("assertion runtime identifiers must be unique"),
        );
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
