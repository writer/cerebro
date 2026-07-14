package complianceassessment

import (
	"context"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/observability"
)

type memoryPinnedHistory struct {
	manifests map[string]InputManifest
	revisions map[string][]byte
	results   map[string][]ObjectiveResult
}

func (history memoryPinnedHistory) LoadManifest(_ context.Context, digest string) (InputManifest, bool, error) {
	value, ok := history.manifests[digest]
	return value, ok, nil
}

func (history memoryPinnedHistory) LoadRevision(_ context.Context, revision ManifestRevision) ([]byte, bool, error) {
	value, ok := history.revisions[revision.RevisionID]
	return append([]byte(nil), value...), ok, nil
}

func (history memoryPinnedHistory) LoadResultSet(_ context.Context, digest string) ([]ObjectiveResult, bool, error) {
	value, ok := history.results[digest]
	return append([]ObjectiveResult(nil), value...), ok, nil
}

type staticPinnedReplayer struct {
	results []ObjectiveResult
	calls   *int
}

func (replayer staticPinnedReplayer) Replay(_ context.Context, input PinnedReplayInput) ([]ObjectiveResult, error) {
	*replayer.calls++
	return append([]ObjectiveResult(nil), replayer.results...), nil
}

func TestVerifyDeterministicReplayUsesOnlyPinnedHistory(t *testing.T) {
	history, manifestHash, resultHash, results := validReplayFixture(t)
	calls := 0
	input := ReplayVerificationInput{
		ExpectedManifestHash: manifestHash,
		ExpectedResultHash:   resultHash,
		History:              history,
		Replayer:             staticPinnedReplayer{results: results, calls: &calls},
	}
	first, err := VerifyDeterministicReplay(context.Background(), input)
	if err != nil {
		t.Fatalf("VerifyDeterministicReplay() error = %v", err)
	}
	second, err := VerifyDeterministicReplay(context.Background(), input)
	if err != nil {
		t.Fatalf("second VerifyDeterministicReplay() error = %v", err)
	}
	if first.Status != ReplayVerified || first.ReplayedResultHash != resultHash {
		t.Fatalf("receipt = %#v", first)
	}
	if first.ReceiptDigest == "" || first.ReceiptDigest != second.ReceiptDigest {
		t.Fatalf("receipt digest is not deterministic: %q != %q", first.ReceiptDigest, second.ReceiptDigest)
	}
	if calls != 2 {
		t.Fatalf("replayer calls = %d, want 2", calls)
	}
}

func TestVerifyDeterministicReplayReportsTypedHistoricalGapWithoutReplaying(t *testing.T) {
	history, manifestHash, resultHash, results := validReplayFixture(t)
	delete(history.revisions, "profile-r1")
	calls := 0
	receipt, err := VerifyDeterministicReplay(context.Background(), ReplayVerificationInput{
		ExpectedManifestHash: manifestHash,
		ExpectedResultHash:   resultHash,
		History:              history,
		Replayer:             staticPinnedReplayer{results: results, calls: &calls},
	})
	if err != nil {
		t.Fatalf("VerifyDeterministicReplay() error = %v", err)
	}
	if receipt.Status != ReplayGap || len(receipt.HistoricalGaps) != 1 || receipt.HistoricalGaps[0].Kind != HistoricalGapRevision {
		t.Fatalf("receipt = %#v", receipt)
	}
	if calls != 0 {
		t.Fatalf("replayer calls = %d, want 0 when history is incomplete", calls)
	}
}

func TestVerifyDeterministicReplayReportsResultMismatch(t *testing.T) {
	history, manifestHash, resultHash, results := validReplayFixture(t)
	changed := append([]ObjectiveResult(nil), results...)
	changed[0].ID = "assessment-result-changed"
	calls := 0
	receipt, err := VerifyDeterministicReplay(context.Background(), ReplayVerificationInput{
		ExpectedManifestHash: manifestHash,
		ExpectedResultHash:   resultHash,
		History:              history,
		Replayer:             staticPinnedReplayer{results: changed, calls: &calls},
	})
	if err != nil {
		t.Fatalf("VerifyDeterministicReplay() error = %v", err)
	}
	if receipt.Status != ReplayMismatched || len(receipt.Mismatches) != 1 || receipt.Mismatches[0].Kind != ReplayMismatchReplayedResult {
		t.Fatalf("receipt = %#v", receipt)
	}
}

func TestReplayMetricsExposeVerifiedMismatchAndGap(t *testing.T) {
	old := observability.Default
	observability.Default = observability.NewRegistry()
	t.Cleanup(func() { observability.Default = old })

	history, manifestHash, resultHash, results := validReplayFixture(t)
	calls := 0
	_, _ = VerifyDeterministicReplay(context.Background(), ReplayVerificationInput{
		ExpectedManifestHash: manifestHash, ExpectedResultHash: resultHash, History: history,
		Replayer: staticPinnedReplayer{results: results, calls: &calls},
	})
	changed := append([]ObjectiveResult(nil), results...)
	changed[0].ID = "changed-result"
	_, _ = VerifyDeterministicReplay(context.Background(), ReplayVerificationInput{
		ExpectedManifestHash: manifestHash, ExpectedResultHash: resultHash, History: history,
		Replayer: staticPinnedReplayer{results: changed, calls: &calls},
	})
	delete(history.results, resultHash)
	_, _ = VerifyDeterministicReplay(context.Background(), ReplayVerificationInput{
		ExpectedManifestHash: manifestHash, ExpectedResultHash: resultHash, History: history,
		Replayer: staticPinnedReplayer{results: results, calls: &calls},
	})
	rendered := observability.Default.Render()
	for _, metric := range []string{
		`cerebro_assurance_replay_total{status="verified"} 1`,
		`cerebro_assurance_replay_total{status="mismatch"} 1`,
		`cerebro_assurance_replay_total{status="historical_gap"} 1`,
	} {
		if !strings.Contains(rendered, metric) {
			t.Fatalf("metrics missing %q:\n%s", metric, rendered)
		}
	}
}

func validReplayFixture(t *testing.T) (memoryPinnedHistory, string, string, []ObjectiveResult) {
	t.Helper()
	manifest := validManifest()
	revisions := map[string][]byte{
		"profile-r1": []byte(`{"kind":"profile","revision":1}`),
		"catalog-r1": []byte(`{"kind":"catalog","revision":1}`),
	}
	for index := range manifest.Revisions {
		manifest.Revisions[index].Digest = digestBytes(revisions[manifest.Revisions[index].RevisionID])
	}
	manifestHash, err := CanonicalManifestDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	result := validObjectiveResult()
	result.EvidenceIDs = []string{"evidence-1"}
	result.SourceRuntimeIDs = []string{"runtime-1"}
	results := []ObjectiveResult{result}
	resultHash, err := CanonicalResultSetDigest(results)
	if err != nil {
		t.Fatal(err)
	}
	history := memoryPinnedHistory{
		manifests: map[string]InputManifest{manifestHash: manifest},
		revisions: revisions,
		results:   map[string][]ObjectiveResult{resultHash: results},
	}
	return history, manifestHash, resultHash, results
}
