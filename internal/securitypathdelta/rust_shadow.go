package securitypathdelta

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"time"

	"github.com/writer/cerebro/internal/wasmjson"
)

const (
	securityPathEvaluatorABIVersion = 1
	securityPathEvaluatorMaxInput   = 8 << 20
	securityPathEvaluatorMaxOutput  = 8 << 20

	RustShadowMatch          = "match"
	RustShadowEvaluatorError = "rust_error"
	RustShadowResultMismatch = "result_mismatch"
)

var ErrRustEvaluatorUnavailable = errors.New("rust security path evaluator is unavailable")

//go:embed evaluator.wasm
var securityPathEvaluatorWasm []byte

var securityPathEvaluator = wasmjson.New(wasmjson.Config{
	Name:              "embedded security path evaluator",
	Module:            securityPathEvaluatorWasm,
	ABIVersion:        securityPathEvaluatorABIVersion,
	ABIVersionExport:  "cerebro_security_path_abi_version",
	AllocateExport:    "cerebro_security_path_alloc",
	EvaluateExport:    "cerebro_security_path_evaluate",
	MemoryLimitPages:  512,
	MaxInputBytes:     securityPathEvaluatorMaxInput,
	MaxOutputBytes:    securityPathEvaluatorMaxOutput,
	InitializeTimeout: 30 * time.Second,
	CallTimeout:       2 * time.Second,
})

// RustShadowResult records bounded parity evidence without exposing path or tenant data.
type RustShadowResult struct {
	Operation  string `json:"operation"`
	Status     string `json:"status"`
	GoDigest   string `json:"go_digest,omitempty"`
	RustDigest string `json:"rust_digest,omitempty"`
}

type rustComparisonRequest struct {
	Operation string             `json:"operation"`
	Before    *rustSnapshotInput `json:"before,omitempty"`
	After     rustSnapshotInput  `json:"after"`
}

type rustVerificationRequest struct {
	Operation        string            `json:"operation"`
	Reference        rustSnapshotInput `json:"reference"`
	After            rustSnapshotInput `json:"after"`
	RequestedPathIDs []string          `json:"requested_path_ids"`
}

type rustCandidateCutsRequest struct {
	Operation string                  `json:"operation"`
	Paths     []rustSecurityPathInput `json:"paths"`
}

type rustSnapshotInput struct {
	ID               string                     `json:"id"`
	TenantID         string                     `json:"tenant_id"`
	ScopeID          string                     `json:"scope_id"`
	DetectorID       string                     `json:"detector_id"`
	DetectorRevision string                     `json:"detector_revision"`
	ObservationID    string                     `json:"observation_id"`
	ObservedAt       time.Time                  `json:"observed_at"`
	Receipt          rustCollectionReceiptInput `json:"collection_receipt"`
	Completeness     Completeness               `json:"completeness"`
	Paths            []rustSecurityPathInput    `json:"paths"`
	Digest           string                     `json:"digest"`
}

type rustCollectionReceiptInput struct {
	SourceRuntimeID         string                              `json:"source_runtime_id"`
	SourceID                string                              `json:"source_id"`
	RuntimeWatermark        time.Time                           `json:"runtime_watermark"`
	LastSyncedAt            time.Time                           `json:"last_synced_at"`
	CollectionMode          string                              `json:"collection_mode"`
	GraphCheckpointID       string                              `json:"graph_checkpoint_id"`
	GraphRunID              string                              `json:"graph_run_id"`
	GraphCheckpointComplete bool                                `json:"graph_checkpoint_complete"`
	GraphCheckpointCurrent  bool                                `json:"graph_checkpoint_current"`
	ObservedPathCount       int                                 `json:"observed_path_count"`
	TotalPathCount          int                                 `json:"total_path_count"`
	LeaseHeld               bool                                `json:"lease_held"`
	Limitations             []string                            `json:"limitations,omitempty"`
	ProofRuntimeIDs         []string                            `json:"proof_runtime_ids,omitempty"`
	RuntimeReceipts         []rustRuntimeCollectionReceiptInput `json:"runtime_receipts,omitempty"`
}

type rustRuntimeCollectionReceiptInput struct {
	SourceRuntimeID         string    `json:"source_runtime_id"`
	SourceID                string    `json:"source_id,omitempty"`
	ProviderFamily          string    `json:"provider_family,omitempty"`
	ConfigRevision          string    `json:"config_revision,omitempty"`
	RuntimeWatermark        time.Time `json:"runtime_watermark,omitempty"`
	LastSyncedAt            time.Time `json:"last_synced_at,omitempty"`
	GraphCheckpointID       string    `json:"graph_checkpoint_id,omitempty"`
	GraphRunID              string    `json:"graph_run_id,omitempty"`
	GraphRunStartedAt       time.Time `json:"graph_run_started_at,omitempty"`
	GraphRunFinishedAt      time.Time `json:"graph_run_finished_at,omitempty"`
	GraphCheckpointComplete bool      `json:"graph_checkpoint_complete"`
	GraphCheckpointCurrent  bool      `json:"graph_checkpoint_current"`
	Limitations             []string  `json:"limitations,omitempty"`
}

type rustSecurityPathInput struct {
	ID         string                   `json:"id"`
	RouteID    string                   `json:"route_id"`
	ProofEdges []rustProofEdgeInput     `json:"proof_edges"`
	Ownerships []rustOwnershipEdgeInput `json:"ownerships,omitempty"`
}

type rustOwnershipEdgeInput struct {
	Edge rustProofEdgeInput `json:"edge"`
}

type rustProofEdgeInput struct {
	ID                  string   `json:"id"`
	Relation            string   `json:"relation"`
	SourceRuntimeID     string   `json:"source_runtime_id,omitempty"`
	AssertionRuntimeIDs []string `json:"assertion_runtime_ids,omitempty"`
}

type rustComparisonResponse struct {
	Operation string                 `json:"operation"`
	Result    rustComparisonDecision `json:"result"`
}

type rustVerificationResponse struct {
	Operation string                   `json:"operation"`
	Result    rustVerificationDecision `json:"result"`
}

type rustCandidateCutsResponse struct {
	Operation string             `json:"operation"`
	Result    []CandidateEdgeCut `json:"result"`
}

type rustProofChange struct {
	RouteID       string   `json:"route_id"`
	BeforePathIDs []string `json:"before_path_ids"`
	AfterPathIDs  []string `json:"after_path_ids"`
}

type rustComparisonDecision struct {
	State                   string             `json:"state"`
	NewlyObservedPathIDs    []string           `json:"newly_observed_path_ids,omitempty"`
	NoLongerObservedPathIDs []string           `json:"no_longer_observed_path_ids,omitempty"`
	ProofChanged            []rustProofChange  `json:"proof_changed,omitempty"`
	UnchangedRoutes         int                `json:"unchanged_routes"`
	CandidateEdgeCuts       []CandidateEdgeCut `json:"candidate_edge_cuts,omitempty"`
	Digest                  string             `json:"digest"`
}

type rustVerificationDecision struct {
	RequestedPathIDs     []string           `json:"requested_path_ids"`
	RequestedRouteIDs    []string           `json:"requested_route_ids"`
	State                string             `json:"state"`
	Reasons              []string           `json:"reasons,omitempty"`
	StillObservedPathIDs []string           `json:"still_observed_path_ids,omitempty"`
	CandidateEdgeCuts    []CandidateEdgeCut `json:"candidate_edge_cuts,omitempty"`
	Digest               string             `json:"digest"`
}

// CompareRustShadow compares the Rust decision with the validated Go result without changing it.
func CompareRustShadow(ctx context.Context, before *Snapshot, after Snapshot, oracle Delta) RustShadowResult {
	want := comparisonDecisionFromDelta(oracle)
	result := RustShadowResult{Operation: "compare", GoDigest: want.Digest}
	var response rustComparisonResponse
	if err := evaluateRustSecurityPath(ctx, rustComparisonRequest{
		Operation: "compare", Before: rustSnapshotPointer(before), After: rustSnapshotFromSnapshot(after),
	}, &response); err != nil {
		result.Status = RustShadowEvaluatorError
		return result
	}
	result.RustDigest = response.Result.Digest
	if response.Operation != "compare" || !reflect.DeepEqual(response.Result, want) {
		result.Status = RustShadowResultMismatch
		return result
	}
	result.Status = RustShadowMatch
	return result
}

// VerifyObservedAbsentRustShadow compares the Rust decision with the validated Go result without changing it.
func VerifyObservedAbsentRustShadow(ctx context.Context, reference Snapshot, after Snapshot, requestedPathIDs []string, oracle Verification) RustShadowResult {
	want := verificationDecisionFromResult(oracle)
	result := RustShadowResult{Operation: "verify_observed_absent", GoDigest: want.Digest}
	var response rustVerificationResponse
	if err := evaluateRustSecurityPath(ctx, rustVerificationRequest{
		Operation: "verify_observed_absent", Reference: rustSnapshotFromSnapshot(reference),
		After: rustSnapshotFromSnapshot(after), RequestedPathIDs: requestedPathIDs,
	}, &response); err != nil {
		result.Status = RustShadowEvaluatorError
		return result
	}
	result.RustDigest = response.Result.Digest
	if response.Operation != "verify_observed_absent" || !reflect.DeepEqual(response.Result, want) {
		result.Status = RustShadowResultMismatch
		return result
	}
	result.Status = RustShadowMatch
	return result
}

func rankCandidateCutsRust(ctx context.Context, paths []SecurityPath) ([]CandidateEdgeCut, error) {
	var response rustCandidateCutsResponse
	if err := evaluateRustSecurityPath(ctx, rustCandidateCutsRequest{
		Operation: "rank_candidate_cuts", Paths: rustSecurityPaths(paths),
	}, &response); err != nil {
		return nil, err
	}
	if response.Operation != "rank_candidate_cuts" {
		return nil, fmt.Errorf("%w: unexpected operation", ErrRustEvaluatorUnavailable)
	}
	return response.Result, nil
}

func rustSnapshotPointer(snapshot *Snapshot) *rustSnapshotInput {
	if snapshot == nil {
		return nil
	}
	value := rustSnapshotFromSnapshot(*snapshot)
	return &value
}

func rustSnapshotFromSnapshot(snapshot Snapshot) rustSnapshotInput {
	receipt := snapshot.Receipt
	runtimeReceipts := make([]rustRuntimeCollectionReceiptInput, 0, len(receipt.RuntimeReceipts))
	for _, runtimeReceipt := range receipt.RuntimeReceipts {
		runtimeReceipts = append(runtimeReceipts, rustRuntimeCollectionReceiptInput{
			SourceRuntimeID: runtimeReceipt.SourceRuntimeID, SourceID: runtimeReceipt.SourceID,
			ProviderFamily: runtimeReceipt.ProviderFamily, ConfigRevision: runtimeReceipt.ConfigRevision,
			RuntimeWatermark: runtimeReceipt.RuntimeWatermark, LastSyncedAt: runtimeReceipt.LastSyncedAt,
			GraphCheckpointID: runtimeReceipt.GraphCheckpointID, GraphRunID: runtimeReceipt.GraphRunID,
			GraphRunStartedAt: runtimeReceipt.GraphRunStartedAt, GraphRunFinishedAt: runtimeReceipt.GraphRunFinishedAt,
			GraphCheckpointComplete: runtimeReceipt.GraphCheckpointComplete, GraphCheckpointCurrent: runtimeReceipt.GraphCheckpointCurrent,
			Limitations: append([]string(nil), runtimeReceipt.Limitations...),
		})
	}
	return rustSnapshotInput{
		ID: snapshot.ID, TenantID: snapshot.TenantID, ScopeID: snapshot.ScopeID,
		DetectorID: snapshot.DetectorID, DetectorRevision: snapshot.DetectorRevision,
		ObservationID: snapshot.ObservationID, ObservedAt: snapshot.ObservedAt,
		Receipt: rustCollectionReceiptInput{
			SourceRuntimeID: receipt.SourceRuntimeID, SourceID: receipt.SourceID,
			RuntimeWatermark: receipt.RuntimeWatermark, LastSyncedAt: receipt.LastSyncedAt,
			CollectionMode: receipt.CollectionMode, GraphCheckpointID: receipt.GraphCheckpointID, GraphRunID: receipt.GraphRunID,
			GraphCheckpointComplete: receipt.GraphCheckpointComplete, GraphCheckpointCurrent: receipt.GraphCheckpointCurrent,
			ObservedPathCount: receipt.ObservedPathCount, TotalPathCount: receipt.TotalPathCount, LeaseHeld: receipt.LeaseHeld,
			Limitations: append([]string(nil), receipt.Limitations...), ProofRuntimeIDs: append([]string(nil), receipt.ProofRuntimeIDs...),
			RuntimeReceipts: runtimeReceipts,
		},
		Completeness: snapshot.Completeness,
		Paths:        rustSecurityPaths(snapshot.Paths),
		Digest:       snapshot.Digest,
	}
}

func rustSecurityPaths(paths []SecurityPath) []rustSecurityPathInput {
	result := make([]rustSecurityPathInput, 0, len(paths))
	for _, path := range paths {
		proofEdges := make([]rustProofEdgeInput, 0, len(path.ProofEdges))
		for _, edge := range path.ProofEdges {
			proofEdges = append(proofEdges, rustProofEdge(edge))
		}
		ownerships := make([]rustOwnershipEdgeInput, 0, len(path.Ownerships))
		for _, ownership := range path.Ownerships {
			ownerships = append(ownerships, rustOwnershipEdgeInput{Edge: rustProofEdge(ownership.Edge)})
		}
		result = append(result, rustSecurityPathInput{
			ID: path.ID, RouteID: path.RouteID, ProofEdges: proofEdges, Ownerships: ownerships,
		})
	}
	return result
}

func rustProofEdge(edge ProofEdge) rustProofEdgeInput {
	return rustProofEdgeInput{
		ID: edge.ID, Relation: edge.Relation, SourceRuntimeID: edge.SourceRuntimeID,
		AssertionRuntimeIDs: append([]string(nil), edge.AssertionRuntimeIDs...),
	}
}

func evaluateRustSecurityPath(ctx context.Context, request any, response any) error {
	payload, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("%w: encode request: %w", ErrRustEvaluatorUnavailable, err)
	}
	output, err := securityPathEvaluator.Evaluate(ctx, payload)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRustEvaluatorUnavailable, err)
	}
	if err := decodeStrictRustResponse(output, response); err != nil {
		return fmt.Errorf("%w: decode response: %w", ErrRustEvaluatorUnavailable, err)
	}
	return nil
}

func decodeStrictRustResponse(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON response values")
		}
		return fmt.Errorf("trailing JSON response: %w", err)
	}
	return nil
}

func comparisonDecisionFromDelta(delta Delta) rustComparisonDecision {
	decision := rustComparisonDecision{
		State:                   string(delta.State),
		NewlyObservedPathIDs:    securityPathIDs(delta.NewlyObserved),
		NoLongerObservedPathIDs: securityPathIDs(delta.NoLongerObserved),
		UnchangedRoutes:         delta.UnchangedRoutes,
		CandidateEdgeCuts:       rustCandidateEdgeCuts(delta.CandidateEdgeCuts),
	}
	for _, change := range delta.ProofChanged {
		decision.ProofChanged = append(decision.ProofChanged, rustProofChange{
			RouteID: change.RouteID, BeforePathIDs: securityPathIDs(change.BeforePaths), AfterPathIDs: securityPathIDs(change.AfterPaths),
		})
	}
	decision.Digest = rustComparisonDecisionDigest(decision)
	return decision
}

func verificationDecisionFromResult(verification Verification) rustVerificationDecision {
	decision := rustVerificationDecision{
		RequestedPathIDs:     append([]string(nil), verification.RequestedPathIDs...),
		RequestedRouteIDs:    append([]string(nil), verification.RequestedRouteIDs...),
		State:                string(verification.State),
		Reasons:              append([]string(nil), verification.Reasons...),
		StillObservedPathIDs: securityPathIDs(verification.StillObserved),
		CandidateEdgeCuts:    rustCandidateEdgeCuts(verification.CandidateEdgeCuts),
	}
	decision.Digest = rustVerificationDecisionDigest(decision)
	return decision
}

func securityPathIDs(paths []SecurityPath) []string {
	if len(paths) == 0 {
		return nil
	}
	ids := make([]string, 0, len(paths))
	for _, path := range paths {
		ids = append(ids, path.ID)
	}
	sort.Strings(ids)
	return ids
}

func rustCandidateEdgeCuts(values []CandidateEdgeCut) []CandidateEdgeCut {
	if len(values) == 0 {
		return nil
	}
	out := make([]CandidateEdgeCut, len(values))
	for index, value := range values {
		out[index] = value
		out[index].CoveredRouteIDs = append([]string(nil), value.CoveredRouteIDs...)
		out[index].CoveredPathIDs = append([]string(nil), value.CoveredPathIDs...)
		out[index].Edge = ProofEdge{
			ID: value.Edge.ID, Relation: value.Edge.Relation, SourceRuntimeID: value.Edge.SourceRuntimeID,
			AssertionRuntimeIDs: append([]string(nil), value.Edge.AssertionRuntimeIDs...),
		}
	}
	return out
}

func rustComparisonDecisionDigest(decision rustComparisonDecision) string {
	values := []string{"security-path-comparison-decision/v1", decision.State, fmt.Sprint(decision.UnchangedRoutes)}
	values = appendDecisionValues(values, "new", decision.NewlyObservedPathIDs)
	values = appendDecisionValues(values, "removed", decision.NoLongerObservedPathIDs)
	for _, change := range decision.ProofChanged {
		values = append(values, "proof_changed", change.RouteID)
		values = appendDecisionValues(values, "before", change.BeforePathIDs)
		values = appendDecisionValues(values, "after", change.AfterPathIDs)
	}
	values = appendCutDecisionValues(values, decision.CandidateEdgeCuts)
	return digestStrings(values...)
}

func rustVerificationDecisionDigest(decision rustVerificationDecision) string {
	values := []string{"security-path-verification-decision/v1", decision.State}
	values = appendDecisionValues(values, "requested_path", decision.RequestedPathIDs)
	values = appendDecisionValues(values, "requested_route", decision.RequestedRouteIDs)
	values = appendDecisionValues(values, "reason", decision.Reasons)
	values = appendDecisionValues(values, "still_observed", decision.StillObservedPathIDs)
	values = appendCutDecisionValues(values, decision.CandidateEdgeCuts)
	return digestStrings(values...)
}

func appendDecisionValues(target []string, label string, values []string) []string {
	for _, value := range values {
		target = append(target, label, value)
	}
	return target
}

func appendCutDecisionValues(target []string, cuts []CandidateEdgeCut) []string {
	for _, cut := range cuts {
		target = append(target,
			"cut", fmt.Sprint(cut.Rank), cut.State, cut.Edge.ID, cut.Edge.Relation,
			fmt.Sprint(cut.RouteCoverage), fmt.Sprint(cut.PathCoverage),
		)
		target = appendDecisionValues(target, "cut_route", cut.CoveredRouteIDs)
		target = appendDecisionValues(target, "cut_path", cut.CoveredPathIDs)
	}
	return target
}
