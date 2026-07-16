package securitypathdelta

import (
	"context"
	_ "embed"
	"encoding/json"
	"testing"
	"testing/fstest"
	"time"

	"github.com/writer/cerebro/internal/wasmjson/wasmjsontest"
)

//go:embed testdata/rust_shadow/shared_cut.json
var sharedCutCorpus []byte

//go:embed testdata/rust_shadow/relation_priority.json
var relationPriorityCorpus []byte

func TestCompareRustShadowMatchesGoDecision(t *testing.T) {
	t.Parallel()
	beforeAt := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	afterAt := beforeAt.Add(5 * time.Minute)
	before := mustSnapshot(t, snapshotInput("before", beforeAt, true,
		testPath("removed", "principal-a", "permission-a", "runs_as", "before", beforeAt),
	))
	after := mustSnapshot(t, snapshotInput("after", afterAt, true,
		testPath("new-a", "principal-b", "permission-b", "can_assume", "after-a", afterAt),
		testPath("new-b", "principal-b", "permission-b", "can_assume", "after-b", afterAt),
	))
	delta, err := Compare(&before, after)
	if err != nil {
		t.Fatal(err)
	}
	result := CompareRustShadow(context.Background(), &before, after, delta)
	if result.Status != RustShadowMatch || result.GoDigest == "" || result.GoDigest != result.RustDigest {
		t.Fatalf("CompareRustShadow() = %#v, want matching non-empty digests", result)
	}
	if result.SchemaVersion != securityPathDecisionInputV1 || result.InputDigest == "" ||
		len(result.SourceSnapshotDigests) != 2 || result.SourceSnapshotDigests[0] != before.Digest || result.SourceSnapshotDigests[1] != after.Digest {
		t.Fatalf("CompareRustShadow() receipt = %#v, want bound input and snapshots", result)
	}
}

func TestCompareRustShadowReportsBoundedMismatch(t *testing.T) {
	t.Parallel()
	beforeAt := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	before := mustSnapshot(t, snapshotInput("before", beforeAt, true))
	after := mustSnapshot(t, snapshotInput("after", beforeAt.Add(time.Minute), true))
	delta, err := Compare(&before, after)
	if err != nil {
		t.Fatal(err)
	}
	delta.State = DeltaStateInitial
	result := CompareRustShadow(context.Background(), &before, after, delta)
	if result.Status != RustShadowResultMismatch {
		t.Fatalf("CompareRustShadow() = %#v, want result_mismatch", result)
	}
}

func TestRustDecisionEnvelopeRejectsWrongVersionAndDigest(t *testing.T) {
	t.Parallel()
	request := rustCandidateCutsRequest{Operation: "rank_candidate_cuts", Paths: []rustSecurityPathInput{}}
	payload, _, _, err := marshalRustEvaluationRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	var envelope rustEvaluationRequest
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}

	envelope.SchemaVersion = "security-path-decision-input/v2"
	unsupported, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := securityPathEvaluator.Evaluate(context.Background(), unsupported); err == nil {
		t.Fatal("unsupported schema version evaluated successfully")
	}

	envelope.SchemaVersion = securityPathDecisionInputV1
	envelope.InputDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := securityPathEvaluator.Evaluate(context.Background(), tampered); err == nil {
		t.Fatal("tampered input digest evaluated successfully")
	}
}

func TestRustDecisionInputDigestChangesWithDecisionField(t *testing.T) {
	t.Parallel()
	first := rustCandidateCutsRequest{Operation: "rank_candidate_cuts", Paths: []rustSecurityPathInput{{
		ID: "path-a", RouteID: "route-a", ProofEdges: []rustProofEdgeInput{{
			ID: "edge-a", Relation: "CAN_ACCESS", SourceRuntimeID: "runtime-a",
			AssertionRuntimeIDs: []string{"runtime-a"},
		}},
	}}}
	second := first
	second.Paths = append([]rustSecurityPathInput(nil), first.Paths...)
	second.Paths[0].ProofEdges = append([]rustProofEdgeInput(nil), first.Paths[0].ProofEdges...)
	second.Paths[0].ProofEdges[0].Relation = "CAN_ASSUME"
	_, firstDigest, _, err := marshalRustEvaluationRequest(first)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != "sha256:40c2ec2e9d328dd86013f22d0de984902d70d248a2d1780d1b63d2c1166fa1a8" {
		t.Fatalf("unexpected V1 digest: %s", firstDigest)
	}
	_, secondDigest, _, err := marshalRustEvaluationRequest(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest == secondDigest {
		t.Fatalf("decision input digests are equal: %s", firstDigest)
	}
}

func TestRustDecisionRejectsPathOverflow(t *testing.T) {
	t.Parallel()
	paths := make([]SecurityPath, 0, 101)
	for index := range 101 {
		id := benchmarkIndex(index)
		paths = append(paths, SecurityPath{
			ID: "path-" + id, RouteID: "route-" + id,
			ProofEdges: []ProofEdge{{ID: "edge-" + id, Relation: "can_reach"}},
		})
	}
	if _, err := rankCandidateCutsRust(context.Background(), paths); err == nil {
		t.Fatal("101-path request evaluated successfully")
	}
}

func TestVerifyObservedAbsentRustShadowMatchesGoDecision(t *testing.T) {
	t.Parallel()
	beforeAt := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	reference := mustSnapshot(t, snapshotInput("reference", beforeAt, true,
		testPath("resource-a", "principal-a", "permission-a", "can_assume", "reference", beforeAt),
	))
	after := mustSnapshot(t, snapshotInput("after", beforeAt.Add(5*time.Minute), true))
	requested := []string{reference.Paths[0].ID}
	verification, err := VerifyObservedAbsent(reference, after, requested)
	if err != nil {
		t.Fatal(err)
	}
	result := VerifyObservedAbsentRustShadow(context.Background(), reference, after, requested, verification)
	if result.Status != RustShadowMatch || result.GoDigest == "" || result.GoDigest != result.RustDigest {
		var response rustVerificationResponse
		if _, err := evaluateRustSecurityPath(context.Background(), rustVerificationRequest{
			Operation: "verify_observed_absent", Reference: rustSnapshotFromSnapshot(reference),
			After: rustSnapshotFromSnapshot(after), RequestedPathIDs: requested,
		}, &response); err != nil {
			t.Fatal(err)
		}
		t.Fatalf("VerifyObservedAbsentRustShadow() = %#v, want matching non-empty digests\nrust=%#v\ngo=%#v", result, response.Result, verificationDecisionFromResult(verification))
	}
}

func TestRustCandidateCutDifferentialCorpus(t *testing.T) {
	t.Parallel()
	filesystem := fstest.MapFS{
		"cases/shared_cut.json":        {Data: sharedCutCorpus},
		"cases/relation_priority.json": {Data: relationPriorityCorpus},
	}
	inputs := wasmjsontest.LoadInputs[rustCandidateCutsCorpusInput](t, filesystem, "cases/*.json", securityPathEvaluatorMaxInput)
	wasmjsontest.RunCorpus(t, context.Background(), inputs, wasmjsontest.Differential[rustCandidateCutsCorpusInput, []CandidateEdgeCut]{
		MaxInputBytes: securityPathEvaluatorMaxInput,
		Oracle: func(input rustCandidateCutsCorpusInput) []CandidateEdgeCut {
			return rustCandidateEdgeCuts(RankCandidateEdgeCuts(input.Paths))
		},
		Candidate: func(ctx context.Context, input wasmjsontest.Input[rustCandidateCutsCorpusInput]) ([]CandidateEdgeCut, error) {
			return rankCandidateCutsRust(ctx, input.Value.Paths)
		},
	})
}

type rustCandidateCutsCorpusInput struct {
	Operation string         `json:"operation"`
	Paths     []SecurityPath `json:"paths"`
}

func BenchmarkRustSecurityPathComparisonWarm(b *testing.B) {
	before, after, delta := benchmarkSnapshots(b)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		result := CompareRustShadow(context.Background(), &before, after, delta)
		if result.Status != RustShadowMatch {
			b.Fatalf("CompareRustShadow() = %#v", result)
		}
	}
}

func BenchmarkRustSecurityPathEvaluatorWarm(b *testing.B) {
	before, after, _ := benchmarkSnapshots(b)
	payload, _, _, err := marshalRustEvaluationRequest(rustComparisonRequest{
		Operation: "compare", Before: rustSnapshotPointer(&before), After: rustSnapshotFromSnapshot(after),
	})
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := securityPathEvaluator.Evaluate(context.Background(), payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRustSecurityPathEvaluatorEmptyWarm(b *testing.B) {
	observedAt := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	before := mustSnapshotBenchmark(b, snapshotInput("before-empty", observedAt, true))
	after := mustSnapshotBenchmark(b, snapshotInput("after-empty", observedAt.Add(time.Minute), true))
	payload, _, _, err := marshalRustEvaluationRequest(rustComparisonRequest{
		Operation: "compare", Before: rustSnapshotPointer(&before), After: rustSnapshotFromSnapshot(after),
	})
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := securityPathEvaluator.Evaluate(context.Background(), payload); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkSnapshots(b *testing.B) (Snapshot, Snapshot, Delta) {
	b.Helper()
	observedAt := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	before := mustSnapshotBenchmark(b, snapshotInput("before", observedAt, true))
	paths := make([]ObservedPath, 0, 100)
	for index := range 100 {
		paths = append(paths, testPath(
			"resource-"+benchmarkIndex(index), "principal-"+benchmarkIndex(index), "permission-"+benchmarkIndex(index),
			"can_assume", benchmarkIndex(index), observedAt.Add(time.Minute),
		))
	}
	after := mustSnapshotBenchmark(b, snapshotInput("after", observedAt.Add(time.Minute), true, paths...))
	delta, err := Compare(&before, after)
	if err != nil {
		b.Fatal(err)
	}
	return before, after, delta
}

func mustSnapshotBenchmark(b *testing.B, input SnapshotInput) Snapshot {
	b.Helper()
	snapshot, err := NewSnapshot(input)
	if err != nil {
		b.Fatal(err)
	}
	return snapshot
}

func benchmarkIndex(index int) string {
	const digits = "0123456789"
	return string([]byte{digits[(index/100)%10], digits[(index/10)%10], digits[index%10]})
}
