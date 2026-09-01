package bootstrap

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/graphagent"
	"github.com/writer/cerebro/internal/ports"
)

type featureAttackPathReader struct{}

func (*featureAttackPathReader) ListCloudAttackPaths(context.Context, ports.CloudAttackPathRequest) (*ports.CloudAttackPathResult, error) {
	return &ports.CloudAttackPathResult{}, nil
}

func TestFeatureDependencyBundlesAreNilSafe(t *testing.T) {
	deps := Dependencies{}

	if got := newReportFeatureDeps(deps); got.Findings != nil || got.GraphNeighborhoods != nil || got.Reports != nil {
		t.Fatalf("newReportFeatureDeps() = %#v, want nil stores", got)
	}
	if got := newRuntimeFeatureDeps(deps, nil); got.Sources != nil || got.Runtimes != nil || got.AppendLog != nil || got.Projector != nil || got.RuntimeConfigStore != nil {
		t.Fatalf("newRuntimeFeatureDeps() = %#v, want nil dependencies", got)
	}
	if got := newClaimFeatureDeps(deps); got.Runtimes != nil || got.Claims != nil || got.ProjectionState != nil || got.ProjectionGraph != nil {
		t.Fatalf("newClaimFeatureDeps() = %#v, want nil stores", got)
	}
	if got := newFindingFeatureDeps(deps); got.Runtimes != nil || got.EventReplayer != nil || got.Findings != nil || got.EvaluationRuns != nil || got.Evidence != nil || got.Claims != nil || got.Candidates != nil || got.ProjectionGraph != nil || got.GraphCatalog != nil || got.GraphRawCypher != nil || got.AppendLog != nil {
		t.Fatalf("newFindingFeatureDeps() = %#v, want nil dependencies", got)
	}
	if got := newKnowledgeFeatureDeps(deps); got.ProjectionGraph != nil || got.GraphCatalog != nil || got.AppendLog != nil {
		t.Fatalf("newKnowledgeFeatureDeps() = %#v, want nil dependencies", got)
	}
	if got := newGraphQueryFeatureDeps(deps); got.GraphNeighborhoods != nil || got.GraphRawCypher != nil || got.GraphCatalog != nil || got.GraphExposure != nil || got.GraphAttackPaths != nil {
		t.Fatalf("newGraphQueryFeatureDeps() = %#v, want nil graph query store", got)
	}
	if got := newGraphIngestFeatureDeps(deps, nil); got.Sources != nil || got.Runtimes != nil || got.Projector != nil || got.GraphStore != nil || got.RuntimeConfigStore != nil {
		t.Fatalf("newGraphIngestFeatureDeps() = %#v, want nil dependencies", got)
	}
	if got := newWorkflowReplayFeatureDeps(deps); got.EventReplayer != nil || got.ProjectionGraph != nil || got.GraphCatalog != nil {
		t.Fatalf("newWorkflowReplayFeatureDeps() = %#v, want nil dependencies", got)
	}
	if got := newJobFeatureDeps(deps); got.Jobs != nil {
		t.Fatalf("newJobFeatureDeps() = %#v, want nil job store", got)
	}
	if got := newRuntimeResponseFeatureDeps(deps); got.Blocklist != nil {
		t.Fatalf("newRuntimeResponseFeatureDeps() = %#v, want nil runtime response store", got)
	}
	if got := newGraphReasoningFeatureDeps(deps); got.GraphReads != (ports.GraphReadCapabilities{}) || got.GraphAgentLLM != nil || got.TrajectoryStore != nil {
		t.Fatalf("newGraphReasoningFeatureDeps() = %#v, want nil dependencies", got)
	}
}

func TestProductReadDependencyBundlesPreferConfiguredAuthority(t *testing.T) {
	legacy := &stubGraphStore{}
	authority := &stubGraphStore{}
	attackPaths := &featureAttackPathReader{}
	graphReads := NewGraphReadCapabilities(authority)
	graphReads.CloudAttackPaths = attackPaths
	deps := Dependencies{
		GraphStore:    legacy,
		GraphReads:    graphReads,
		GraphAgentLLM: graphagent.NewStubLLMClient(),
	}

	if got := newReportFeatureDeps(deps).GraphNeighborhoods; got != authority {
		t.Fatalf("report graph neighborhoods = %#v, want configured authority", got)
	}
	if got := newFindingFeatureDeps(deps).GraphRawCypher; got != authority {
		t.Fatalf("finding raw Cypher graph = %#v, want configured authority", got)
	}
	if got := newFindingFeatureDeps(deps).GraphCatalog; got != authority {
		t.Fatalf("finding relation catalog = %#v, want configured authority", got)
	}
	if got := newKnowledgeFeatureDeps(deps).GraphCatalog; got != authority {
		t.Fatalf("knowledge relation catalog = %#v, want configured authority", got)
	}
	if got := newWorkflowReplayFeatureDeps(deps).GraphCatalog; got != authority {
		t.Fatalf("workflow replay relation catalog = %#v, want configured authority", got)
	}
	if got := newGraphQueryFeatureDeps(deps); got.GraphNeighborhoods != authority || got.GraphRawCypher != authority || got.GraphCatalog != authority || got.GraphExposure != authority || got.GraphAttackPaths != attackPaths {
		t.Fatalf("graph query service = %#v, want configured authority for all capabilities", got)
	}
	if got := newGraphReasoningFeatureDeps(deps); got.GraphReads.Neighborhoods != authority || got.GraphReads.RawCypher != authority || got.GraphReads.EntityKindCounts != authority || got.GraphReads.RelationCounts != authority {
		t.Fatalf("graph reasoning queries = %#v, want configured authority", got)
	}
}

func TestProductReadDependencyBundlesDoNotFallbackToLegacyGraphStore(t *testing.T) {
	deps := Dependencies{
		GraphStore:    &stubGraphStore{},
		GraphAgentLLM: graphagent.NewStubLLMClient(),
	}

	if got := newReportFeatureDeps(deps).GraphNeighborhoods; got != nil {
		t.Fatalf("report graph queries = %#v, want nil without configured authority", got)
	}
	if got := newFindingFeatureDeps(deps).GraphRawCypher; got != nil {
		t.Fatalf("finding graph queries = %#v, want nil without configured authority", got)
	}
	if got := newFindingFeatureDeps(deps).GraphCatalog; got != nil {
		t.Fatalf("finding relation catalog = %#v, want nil without configured authority", got)
	}
	if got := newKnowledgeFeatureDeps(deps).GraphCatalog; got != nil {
		t.Fatalf("knowledge relation catalog = %#v, want nil without configured authority", got)
	}
	if got := newWorkflowReplayFeatureDeps(deps).GraphCatalog; got != nil {
		t.Fatalf("workflow replay relation catalog = %#v, want nil without configured authority", got)
	}
	if got := newGraphQueryFeatureDeps(deps); got.GraphNeighborhoods != nil || got.GraphRawCypher != nil || got.GraphCatalog != nil || got.GraphExposure != nil || got.GraphAttackPaths != nil {
		t.Fatalf("graph query service = %#v, want nil without configured authority", got)
	}
	if got := newGraphReasoningFeatureDeps(deps); got.GraphReads != (ports.GraphReadCapabilities{}) {
		t.Fatalf("graph reasoning queries = %#v, want nil without configured authority", got)
	}
}
