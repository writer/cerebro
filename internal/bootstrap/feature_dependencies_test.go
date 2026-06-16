package bootstrap

import "testing"

func TestFeatureDependencyBundlesAreNilSafe(t *testing.T) {
	deps := Dependencies{}

	if got := newReportFeatureDeps(deps); got.Findings != nil || got.GraphQueries != nil || got.Reports != nil {
		t.Fatalf("newReportFeatureDeps() = %#v, want nil stores", got)
	}
	if got := newRuntimeFeatureDeps(deps, nil); got.Sources != nil || got.Runtimes != nil || got.AppendLog != nil || got.Projector != nil || got.RuntimeConfigStore != nil {
		t.Fatalf("newRuntimeFeatureDeps() = %#v, want nil dependencies", got)
	}
	if got := newClaimFeatureDeps(deps); got.Runtimes != nil || got.Claims != nil || got.ProjectionState != nil || got.ProjectionGraph != nil {
		t.Fatalf("newClaimFeatureDeps() = %#v, want nil stores", got)
	}
	if got := newFindingFeatureDeps(deps); got.Runtimes != nil || got.EventReplayer != nil || got.Findings != nil || got.EvaluationRuns != nil || got.Evidence != nil || got.Claims != nil || got.Candidates != nil || got.ProjectionGraph != nil || got.GraphQueries != nil || got.AppendLog != nil {
		t.Fatalf("newFindingFeatureDeps() = %#v, want nil dependencies", got)
	}
	if got := newKnowledgeFeatureDeps(deps); got.GraphQueries != nil || got.ProjectionGraph != nil || got.AppendLog != nil {
		t.Fatalf("newKnowledgeFeatureDeps() = %#v, want nil dependencies", got)
	}
	if got := newGraphQueryFeatureDeps(deps); got.GraphQueries != nil {
		t.Fatalf("newGraphQueryFeatureDeps() = %#v, want nil graph query store", got)
	}
	if got := newGraphIngestFeatureDeps(deps, nil); got.Sources != nil || got.Runtimes != nil || got.Projector != nil || got.GraphStore != nil || got.RuntimeConfigStore != nil {
		t.Fatalf("newGraphIngestFeatureDeps() = %#v, want nil dependencies", got)
	}
	if got := newWorkflowReplayFeatureDeps(deps); got.EventReplayer != nil || got.ProjectionGraph != nil {
		t.Fatalf("newWorkflowReplayFeatureDeps() = %#v, want nil dependencies", got)
	}
	if got := newJobFeatureDeps(deps); got.Jobs != nil {
		t.Fatalf("newJobFeatureDeps() = %#v, want nil job store", got)
	}
	if got := newRuntimeResponseFeatureDeps(deps); got.Blocklist != nil {
		t.Fatalf("newRuntimeResponseFeatureDeps() = %#v, want nil runtime response store", got)
	}
	if got := newGraphReasoningFeatureDeps(deps); got.GraphQueries != nil || got.GraphAgentLLM != nil || got.TrajectoryStore != nil {
		t.Fatalf("newGraphReasoningFeatureDeps() = %#v, want nil dependencies", got)
	}
}
