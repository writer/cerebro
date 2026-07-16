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
		if err := evaluateRustSecurityPath(context.Background(), rustVerificationRequest{
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
	payload, err := json.Marshal(rustComparisonRequest{
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
	payload, err := json.Marshal(rustComparisonRequest{
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
