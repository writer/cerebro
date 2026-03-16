package runtimegraph

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/runtime"
)

func TestMaterializeObservationsIntoGraphAddsObservationNode(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "deployment:prod/api",
		Kind: graph.NodeKindDeployment,
		Name: "api",
	})

	observation := &runtime.RuntimeObservation{
		Source:      "tetragon",
		Kind:        runtime.ObservationKindProcessExec,
		ObservedAt:  time.Date(2026, 3, 16, 19, 0, 0, 0, time.UTC),
		RecordedAt:  time.Date(2026, 3, 16, 19, 0, 1, 0, time.UTC),
		WorkloadRef: "deployment:prod/api",
		Namespace:   "prod",
		Process: &runtime.ProcessEvent{
			Name: "sh",
			Path: "/bin/sh",
		},
	}

	req, err := BuildObservationWriteRequest(observation)
	if err != nil {
		t.Fatalf("BuildObservationWriteRequest returned error: %v", err)
	}

	result := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, time.Date(2026, 3, 16, 19, 1, 0, 0, time.UTC))
	if result.ObservationsConsidered != 1 {
		t.Fatalf("ObservationsConsidered = %d, want 1", result.ObservationsConsidered)
	}
	if result.ObservationsMaterialized != 1 {
		t.Fatalf("ObservationsMaterialized = %d, want 1", result.ObservationsMaterialized)
	}
	if result.ObservationsSkipped != 0 {
		t.Fatalf("ObservationsSkipped = %d, want 0", result.ObservationsSkipped)
	}
	if result.MissingSubjects != 0 {
		t.Fatalf("MissingSubjects = %d, want 0", result.MissingSubjects)
	}
	if result.WorkloadTargetEdgesCreated != 1 {
		t.Fatalf("WorkloadTargetEdgesCreated = %d, want 1", result.WorkloadTargetEdgesCreated)
	}

	node, ok := g.GetNode(req.ID)
	if !ok {
		t.Fatalf("observation node %q not found", req.ID)
	}
	if node.Kind != graph.NodeKindObservation {
		t.Fatalf("node.Kind = %q, want %q", node.Kind, graph.NodeKindObservation)
	}
	if node.Provider != "tetragon" {
		t.Fatalf("node.Provider = %q, want tetragon", node.Provider)
	}
	if got := testMetadataString(node.Properties, "observation_type"); got != "process_exec" {
		t.Fatalf("node.properties.observation_type = %q, want process_exec", got)
	}
	if got := testMetadataString(node.Properties, "subject_id"); got != "deployment:prod/api" {
		t.Fatalf("node.properties.subject_id = %q, want deployment:prod/api", got)
	}
	if got := testMetadataString(node.Properties, "detail"); got != "process exec /bin/sh" {
		t.Fatalf("node.properties.detail = %q, want process exec /bin/sh", got)
	}
	if issues := graph.GlobalSchemaRegistry().ValidateNode(node); len(issues) != 0 {
		t.Fatalf("ValidateNode returned issues: %+v", issues)
	}

	outEdges := g.GetOutEdges(req.ID)
	if len(outEdges) != 1 {
		t.Fatalf("len(outEdges) = %d, want 1", len(outEdges))
	}
	if outEdges[0].Kind != graph.EdgeKindTargets || outEdges[0].Target != "deployment:prod/api" {
		t.Fatalf("edge = %+v, want targets edge to deployment:prod/api", outEdges[0])
	}
	if issues := graph.GlobalSchemaRegistry().ValidateEdge(outEdges[0], node, mustNode(t, g, "deployment:prod/api")); len(issues) != 0 {
		t.Fatalf("ValidateEdge returned issues: %+v", issues)
	}

	workloadEdges := g.GetOutEdges("deployment:prod/api")
	if len(workloadEdges) != 1 {
		t.Fatalf("len(workloadEdges) = %d, want 1", len(workloadEdges))
	}
	if workloadEdges[0].Kind != graph.EdgeKindTargets || workloadEdges[0].Target != req.ID {
		t.Fatalf("workload edge = %+v, want targets edge to %s", workloadEdges[0], req.ID)
	}
	if issues := graph.GlobalSchemaRegistry().ValidateEdge(workloadEdges[0], mustNode(t, g, "deployment:prod/api"), node); len(issues) != 0 {
		t.Fatalf("ValidateEdge(workload edge) returned issues: %+v", issues)
	}

	meta := g.Metadata()
	if meta.BuiltAt.IsZero() {
		t.Fatal("metadata.BuiltAt should not be zero")
	}
	if meta.NodeCount != g.NodeCount() || meta.EdgeCount != g.EdgeCount() {
		t.Fatalf("metadata counts = %d/%d, want %d/%d", meta.NodeCount, meta.EdgeCount, g.NodeCount(), g.EdgeCount())
	}
}

func TestMaterializeObservationsIntoGraphSkipsMissingSubjects(t *testing.T) {
	g := graph.New()
	observation := &runtime.RuntimeObservation{
		Source:     "otel",
		Kind:       runtime.ObservationKindTraceLink,
		ObservedAt: time.Date(2026, 3, 16, 19, 5, 0, 0, time.UTC),
		Trace: &runtime.TraceContext{
			TraceID:     "abc123",
			ServiceName: "checkout",
		},
		Metadata: map[string]any{
			"service_namespace": "storefront",
		},
	}

	result := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, time.Date(2026, 3, 16, 19, 6, 0, 0, time.UTC))
	if result.ObservationsConsidered != 1 {
		t.Fatalf("ObservationsConsidered = %d, want 1", result.ObservationsConsidered)
	}
	if result.ObservationsMaterialized != 0 {
		t.Fatalf("ObservationsMaterialized = %d, want 0", result.ObservationsMaterialized)
	}
	if result.ObservationsSkipped != 1 {
		t.Fatalf("ObservationsSkipped = %d, want 1", result.ObservationsSkipped)
	}
	if result.MissingSubjects != 1 {
		t.Fatalf("MissingSubjects = %d, want 1", result.MissingSubjects)
	}
	if result.InvalidObservations != 0 {
		t.Fatalf("InvalidObservations = %d, want 0", result.InvalidObservations)
	}
	if g.NodeCount() != 0 || g.EdgeCount() != 0 {
		t.Fatalf("graph counts = %d/%d, want 0/0", g.NodeCount(), g.EdgeCount())
	}
}

func TestMaterializeObservationsIntoGraphSkipsObservationsWithoutConcreteSubject(t *testing.T) {
	g := graph.New()
	observation := &runtime.RuntimeObservation{
		Source:     "falco",
		Kind:       runtime.ObservationKindRuntimeAlert,
		ObservedAt: time.Date(2026, 3, 16, 19, 10, 0, 0, time.UTC),
	}

	result := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, time.Date(2026, 3, 16, 19, 11, 0, 0, time.UTC))
	if result.ObservationsConsidered != 1 {
		t.Fatalf("ObservationsConsidered = %d, want 1", result.ObservationsConsidered)
	}
	if result.ObservationsMaterialized != 0 {
		t.Fatalf("ObservationsMaterialized = %d, want 0", result.ObservationsMaterialized)
	}
	if result.ObservationsSkipped != 1 {
		t.Fatalf("ObservationsSkipped = %d, want 1", result.ObservationsSkipped)
	}
	if result.MissingSubjects != 1 {
		t.Fatalf("MissingSubjects = %d, want 1", result.MissingSubjects)
	}
	if result.InvalidObservations != 0 {
		t.Fatalf("InvalidObservations = %d, want 0", result.InvalidObservations)
	}
	if !errors.Is(result.LastError, ErrMissingObservationSubject) {
		t.Fatalf("LastError = %v, want ErrMissingObservationSubject", result.LastError)
	}
}
func TestMaterializeObservationsIntoGraphRefreshesBuiltAtOnSubsequentWrites(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "deployment:prod/api",
		Kind: graph.NodeKindDeployment,
		Name: "api",
	})

	firstNow := time.Date(2026, 3, 16, 19, 30, 0, 0, time.UTC)
	secondNow := firstNow.Add(5 * time.Minute)

	firstObservation := &runtime.RuntimeObservation{
		Source:      "tetragon",
		Kind:        runtime.ObservationKindProcessExec,
		ObservedAt:  firstNow.Add(-10 * time.Second),
		WorkloadRef: "deployment:prod/api",
		Process: &runtime.ProcessEvent{
			Name: "sh",
			Path: "/bin/sh",
		},
	}
	secondObservation := &runtime.RuntimeObservation{
		Source:      "tetragon",
		Kind:        runtime.ObservationKindProcessExec,
		ObservedAt:  secondNow.Add(-10 * time.Second),
		WorkloadRef: "deployment:prod/api",
		Process: &runtime.ProcessEvent{
			Name: "bash",
			Path: "/bin/bash",
		},
	}

	firstResult := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{firstObservation}, firstNow)
	if firstResult.ObservationsMaterialized != 1 {
		t.Fatalf("first ObservationsMaterialized = %d, want 1", firstResult.ObservationsMaterialized)
	}
	if got := g.Metadata().BuiltAt; !got.Equal(firstNow) {
		t.Fatalf("after first materialization BuiltAt = %s, want %s", got, firstNow)
	}

	secondResult := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{secondObservation}, secondNow)
	if secondResult.ObservationsMaterialized != 1 {
		t.Fatalf("second ObservationsMaterialized = %d, want 1", secondResult.ObservationsMaterialized)
	}
	if got := g.Metadata().BuiltAt; !got.Equal(secondNow) {
		t.Fatalf("after second materialization BuiltAt = %s, want %s", got, secondNow)
	}
}

func TestMaterializeObservationsIntoGraphDoesNotAddReverseTargetEdgeForServiceSubjects(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "service:storefront/checkout",
		Kind: graph.NodeKindService,
		Name: "checkout",
	})

	observation := &runtime.RuntimeObservation{
		Source:     "otel",
		Kind:       runtime.ObservationKindTraceLink,
		ObservedAt: time.Date(2026, 3, 16, 19, 20, 0, 0, time.UTC),
		Trace: &runtime.TraceContext{
			TraceID:     "abc123",
			ServiceName: "checkout",
		},
		Metadata: map[string]any{
			"service_namespace": "storefront",
		},
	}

	result := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, time.Date(2026, 3, 16, 19, 21, 0, 0, time.UTC))
	if result.WorkloadTargetEdgesCreated != 0 {
		t.Fatalf("WorkloadTargetEdgesCreated = %d, want 0", result.WorkloadTargetEdgesCreated)
	}
	if len(g.GetOutEdges("service:storefront/checkout")) != 0 {
		t.Fatalf("service out edge count = %d, want 0", len(g.GetOutEdges("service:storefront/checkout")))
	}
}

func TestMaterializeObservationsIntoGraphDoesNotDuplicateReverseTargetEdges(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "deployment:prod/api",
		Kind: graph.NodeKindDeployment,
		Name: "api",
	})

	observation := &runtime.RuntimeObservation{
		ID:          "runtime:process_exec:abc",
		Source:      "tetragon",
		Kind:        runtime.ObservationKindProcessExec,
		ObservedAt:  time.Date(2026, 3, 16, 19, 0, 0, 0, time.UTC),
		RecordedAt:  time.Date(2026, 3, 16, 19, 0, 1, 0, time.UTC),
		WorkloadRef: "deployment:prod/api",
		Process: &runtime.ProcessEvent{
			Name: "sh",
			Path: "/bin/sh",
		},
	}

	first := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, time.Date(2026, 3, 16, 19, 1, 0, 0, time.UTC))
	second := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, time.Date(2026, 3, 16, 19, 2, 0, 0, time.UTC))

	if first.WorkloadTargetEdgesCreated != 1 {
		t.Fatalf("first WorkloadTargetEdgesCreated = %d, want 1", first.WorkloadTargetEdgesCreated)
	}
	if second.WorkloadTargetEdgesCreated != 0 {
		t.Fatalf("second WorkloadTargetEdgesCreated = %d, want 0", second.WorkloadTargetEdgesCreated)
	}
	if got := len(g.GetOutEdges("deployment:prod/api")); got != 1 {
		t.Fatalf("len(workload out edges) = %d, want 1", got)
	}
}

func TestGraphAddEdgeIfMissingReturnsFalseWhenSchemaRejectsEdge(t *testing.T) {
	g := graph.New()
	g.SetSchemaValidationMode(graph.SchemaValidationEnforce)
	g.AddNode(&graph.Node{
		ID:   "deployment:prod/api",
		Kind: graph.NodeKindDeployment,
		Name: "api",
	})

	added := graph.AddEdgeIfMissing(g, &graph.Edge{
		ID:     "deployment:prod/api->observation:missing:targets",
		Source: "deployment:prod/api",
		Target: "observation:missing",
		Kind:   graph.EdgeKindTargets,
		Effect: graph.EdgeEffectAllow,
	})
	if added {
		t.Fatal("expected addRuntimeGraphEdgeIfMissing to report false when schema rejects edge")
	}
	if got := len(g.GetOutEdges("deployment:prod/api")); got != 0 {
		t.Fatalf("len(workload out edges) = %d, want 0", got)
	}
}

func TestClassifyObservationMaterializationErrorTreatsSubjectNotFoundAsMissingSubject(t *testing.T) {
	if got := classifyObservationMaterializationError(fmt.Errorf("subject not found: service:storefront/checkout")); got != observationMaterializationErrorMissingSubject {
		t.Fatalf("classifyObservationMaterializationError(subject not found) = %v, want %v", got, observationMaterializationErrorMissingSubject)
	}
}

func mustNode(t *testing.T, g *graph.Graph, id string) *graph.Node {
	t.Helper()
	node, ok := g.GetNode(id)
	if !ok {
		t.Fatalf("node %q not found", id)
	}
	return node
}
