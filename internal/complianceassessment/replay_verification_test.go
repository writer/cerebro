package complianceassessment

import (
	"context"
	"strings"
	"testing"
	"time"

	platformjobs "github.com/writer/cerebro/internal/jobs"
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

func TestVerifyDeterministicReplayAcceptsStoredMultiChunkHashAcrossOrderPermutations(t *testing.T) {
	history, manifestHash, _, _ := validReplayFixture(t)
	manifest := history.manifests[manifestHash]
	now := time.Date(2026, 7, 11, 19, 0, 0, 0, time.UTC)
	results := validResults(now, 501)
	for index := range results {
		results[index].ID = "result-" + results[len(results)-index-1].ObjectiveID
	}

	store := newRunStore()
	jobs := platformjobs.New(newRunJobStore(now))
	service := NewAssessmentService(store, &runLog{}, jobs, &testCollector{manifest: manifest, results: results})
	service.now = func() time.Time { return now }
	jobs.WithRunner(JobKindComplianceAssessment, service.Runner())
	plan := recordPublishedPlan(t, service, now)
	run, _, err := service.RequestRun(context.Background(), RunRequest{
		TenantID: plan.TenantID, PlanRevisionID: plan.RevisionID,
		PeriodStart: now.Add(-time.Hour), PeriodEnd: now,
		IdempotencyKey: "replay-multi-chunk", RequestedBy: "assessor-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := jobs.Wait(context.Background()); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	completed, err := store.GetRun(context.Background(), run.TenantID, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.InputHash == "" || completed.InputManifest == nil || completed.ResultCount != uint64(len(results)) {
		t.Fatalf("completed run = %#v", completed)
	}
	planArtifact := plan
	planArtifact.Status = PlanDraft
	planArtifact.PublishedAt = time.Time{}
	planArtifact.PublishedBy = ""
	planArtifact.Version--
	planArtifact.ContentDigest = ""
	encodedPlan, err := canonicalBytes(planArtifact)
	if err != nil {
		t.Fatal(err)
	}
	if digestBytes(encodedPlan) != plan.ContentDigest {
		t.Fatalf("plan artifact digest = %q, want %q", digestBytes(encodedPlan), plan.ContentDigest)
	}
	chunks, err := store.ListResultChunks(context.Background(), run.TenantID, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 3 {
		t.Fatalf("chunk count = %d, want 3", len(chunks))
	}
	storedResults := make([]ObjectiveResult, 0, len(results))
	for _, chunk := range chunks {
		storedResults = append(storedResults, chunk.Results...)
	}
	history.manifests = map[string]InputManifest{completed.InputHash: *completed.InputManifest}
	history.revisions = map[string][]byte{plan.RevisionID: encodedPlan}
	history.results = map[string][]ObjectiveResult{completed.AutomatedResultHash: storedResults}
	replayed := append([]ObjectiveResult(nil), storedResults...)
	for left, right := 0, len(replayed)-1; left < right; left, right = left+1, right-1 {
		replayed[left], replayed[right] = replayed[right], replayed[left]
	}
	calls := 0
	receipt, err := VerifyDeterministicReplay(context.Background(), ReplayVerificationInput{
		ExpectedManifestHash: completed.InputHash,
		ExpectedResultHash:   completed.AutomatedResultHash,
		History:              history,
		Replayer:             staticPinnedReplayer{results: replayed, calls: &calls},
	})
	if err != nil {
		t.Fatalf("VerifyDeterministicReplay() error = %v", err)
	}
	if receipt.Status != ReplayVerified || receipt.ReplayedResultHash != completed.AutomatedResultHash {
		t.Fatalf("receipt = %#v", receipt)
	}
	if calls != 1 {
		t.Fatalf("replayer calls = %d, want 1", calls)
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
