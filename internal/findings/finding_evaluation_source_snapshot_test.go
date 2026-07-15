package findings

import (
	"context"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphstore"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestFindingEvaluationSourceSnapshotFailsClosed(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*cerebrov1.SourceRuntime)
	}{
		{name: "rejected records", mutate: func(runtime *cerebrov1.SourceRuntime) { runtime.Config[findingSnapshotRejectedKey] = "1" }},
		{name: "failed runtime", mutate: func(runtime *cerebrov1.SourceRuntime) { runtime.Config[findingSnapshotStatusKey] = "failed" }},
		{name: "record count overflow", mutate: func(runtime *cerebrov1.SourceRuntime) { runtime.Config[findingSnapshotAcceptedKey] = "13" }},
		{name: "missing progress hash", mutate: func(runtime *cerebrov1.SourceRuntime) { delete(runtime.Config, findingSnapshotProgressHashKey) }},
		{name: "contract failure", mutate: func(runtime *cerebrov1.SourceRuntime) { runtime.Config[findingSnapshotContractKey] = "failing" }},
		{name: "partial cursor", mutate: func(runtime *cerebrov1.SourceRuntime) { runtime.NextCursor = &cerebrov1.SourceCursor{Opaque: "next"} }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runtime := trustedFindingRuntime("runtime-1", "okta", "user", now)
			test.mutate(runtime)
			if snapshot := findingEvaluationSourceSnapshot(runtime); snapshot.Complete == nil || snapshot.GetComplete() {
				t.Fatalf("snapshot complete = %v, want false", snapshot.Complete)
			}
		})
	}
	runtime := trustedFindingRuntime("runtime-1", "okta", "user", now)
	if snapshot := findingEvaluationSourceSnapshot(runtime); snapshot.Complete == nil || !snapshot.GetComplete() {
		t.Fatalf("healthy snapshot complete = %v, want true", snapshot.Complete)
	}
}

func TestGraphEvaluationBindsEverySourceAndDetectsProjectionChange(t *testing.T) {
	t.Parallel()
	sourceAt := time.Date(2026, 7, 14, 11, 0, 0, 0, time.UTC)
	evaluationAt := sourceAt.Add(10 * time.Minute)
	okta := trustedFindingRuntime("runtime-okta", "okta", "user", sourceAt)
	github := trustedFindingRuntime("runtime-github", "github", "audit", sourceAt)
	runtimeStore := &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{okta.GetId(): okta, github.GetId(): github}}
	runStore := &sourceSnapshotGraphRunStore{runs: map[string]graphstore.IngestRun{
		okta.GetId():   completedGraphRun("graph-okta-1", okta.GetId(), "checkpoint-okta-1", sourceAt.Add(time.Minute)),
		github.GetId(): completedGraphRun("graph-github-1", github.GetId(), "checkpoint-github-1", sourceAt.Add(time.Minute)),
	}}
	rule := &sourceSnapshotGraphRule{
		multiSourceStubGraphRule: multiSourceStubGraphRule{
			stubGraphRule:    stubGraphRule{spec: &cerebrov1.RuleSpec{Id: "cross-source-rule"}},
			supportedSources: []string{"okta", "github"},
		},
		definition: RuleDefinition{ID: "cross-source-rule", EventKinds: []string{"okta.user", "github.audit"}},
	}
	service := &Service{runtimeStore: runtimeStore, graphRunStore: runStore}
	run := newGraphFindingEvaluationRun(okta.GetId(), rule.Spec().GetId(), evaluationAt)
	service.bindGraphEvaluationSourceSnapshots(context.Background(), run, okta, rule, evaluationAt)
	if run.SourceDependencyComplete == nil || !run.GetSourceDependencyComplete() || len(run.GetSourceSnapshots()) != 2 || !findingEvaluationSourceSnapshotsTrusted(run, true) {
		t.Fatalf("bound source envelope = %#v, want two complete dependencies", run)
	}

	runStore.runs[github.GetId()] = completedGraphRun("graph-github-2", github.GetId(), "checkpoint-github-2", sourceAt.Add(2*time.Minute))
	service.verifyGraphEvaluationSourceSnapshots(context.Background(), run)
	if findingEvaluationSourceSnapshotsTrusted(run, true) {
		t.Fatal("source envelope remained trusted after graph checkpoint changed")
	}
}

func TestTrustedSourceResolutionGate(t *testing.T) {
	t.Parallel()
	untrusted := &cerebrov1.FindingEvaluationRun{SourceDependencyComplete: proto.Bool(false)}
	if !(&Service{}).canResolveFromFindingEvaluationRun(untrusted, false) {
		t.Fatal("default service unexpectedly changed existing resolution behavior")
	}
	if (&Service{}).WithTrustedSourceResolution().canResolveFromFindingEvaluationRun(untrusted, false) {
		t.Fatal("trusted source resolution allowed an incomplete source envelope")
	}
}

type sourceSnapshotGraphRule struct {
	multiSourceStubGraphRule
	definition RuleDefinition
}

func (r *sourceSnapshotGraphRule) RuleMetadata() RuleDefinition { return r.definition }

type sourceSnapshotGraphRunStore struct {
	runs map[string]graphstore.IngestRun
}

func (s *sourceSnapshotGraphRunStore) ListIngestRuns(_ context.Context, filter graphstore.IngestRunFilter) ([]graphstore.IngestRun, error) {
	run, ok := s.runs[filter.RuntimeID]
	if !ok {
		return nil, nil
	}
	return []graphstore.IngestRun{run}, nil
}

func trustedFindingRuntime(runtimeID, sourceID, family string, sourceAt time.Time) *cerebrov1.SourceRuntime {
	return &cerebrov1.SourceRuntime{
		Id: runtimeID, TenantId: "tenant-1", SourceId: sourceID,
		LastSyncedAt: timestamppb.New(sourceAt), Checkpoint: &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(sourceAt)},
		Config: map[string]string{
			"family": family, findingSnapshotStatusKey: "completed", findingSnapshotScannedKey: "12", findingSnapshotAcceptedKey: "12",
			findingSnapshotRejectedKey: "0", findingSnapshotFailureKey: "", findingSnapshotContractKey: "passing",
			findingSnapshotProgressHashKey: "sha256:trusted-runtime",
		},
	}
}

func completedGraphRun(id, runtimeID, checkpointID string, finishedAt time.Time) graphstore.IngestRun {
	return graphstore.IngestRun{
		ID: id, RuntimeID: runtimeID, CheckpointID: checkpointID, Status: graphstore.IngestRunStatusCompleted,
		FinishedAt: finishedAt.UTC().Format(time.RFC3339Nano),
	}
}
