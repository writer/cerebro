package runtimegraph

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/runtime"
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
	if got := testNodeStringProperty(node, "observation_type"); got != "process_exec" {
		t.Fatalf("node.properties.observation_type = %q, want process_exec", got)
	}
	if got := testNodeStringProperty(node, "subject_id"); got != "deployment:prod/api" {
		t.Fatalf("node.properties.subject_id = %q, want deployment:prod/api", got)
	}
	if got := testNodeStringProperty(node, "detail"); got != "process exec /bin/sh" {
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

func TestMaterializeObservationsIntoGraphCorroboratesMatchingObservations(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "deployment:prod/api",
		Kind: graph.NodeKindDeployment,
		Name: "api",
	})

	base := time.Date(2026, 3, 16, 22, 0, 1, 0, time.UTC)
	primaryObservation := &runtime.RuntimeObservation{
		ID:          "obs:tetragon",
		Source:      "tetragon",
		Kind:        runtime.ObservationKindProcessExec,
		ObservedAt:  base,
		RecordedAt:  base.Add(time.Second),
		WorkloadRef: "deployment:prod/api",
		Process: &runtime.ProcessEvent{
			Path: "/usr/bin/curl",
			User: "root",
		},
	}
	corroboratingObservation := &runtime.RuntimeObservation{
		ID:          "obs:falco",
		Source:      "falco",
		Kind:        runtime.ObservationKindProcessExec,
		ObservedAt:  base.Add(2 * time.Second),
		RecordedAt:  base.Add(3 * time.Second),
		WorkloadRef: "deployment:prod/api",
		ImageRef:    "ghcr.io/acme/api:1.2.3",
		Tags:        []string{"process", "curl"},
		Process: &runtime.ProcessEvent{
			Path: "/usr/bin/curl",
			User: "root",
		},
	}

	result := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{primaryObservation, corroboratingObservation}, base.Add(time.Minute))
	if result.ObservationsMaterialized != 2 {
		t.Fatalf("ObservationsMaterialized = %d, want 2", result.ObservationsMaterialized)
	}

	primaryReq, err := BuildObservationWriteRequest(primaryObservation)
	if err != nil {
		t.Fatalf("BuildObservationWriteRequest(primary) returned error: %v", err)
	}
	corroboratingReq, err := BuildObservationWriteRequest(corroboratingObservation)
	if err != nil {
		t.Fatalf("BuildObservationWriteRequest(corroborating) returned error: %v", err)
	}

	primaryNode := mustNode(t, g, primaryReq.ID)
	if got := testMetadataString(primaryNode.Properties, "correlation_key"); got == "" {
		t.Fatal("expected primary correlation_key to be populated")
	}
	if got, ok := primaryNode.Properties["correlation_primary"].(bool); !ok || !got {
		t.Fatalf("primary correlation_primary = %#v, want true", primaryNode.Properties["correlation_primary"])
	}
	if got := primaryNode.Properties["corroboration_count"]; got != 2 {
		t.Fatalf("primary corroboration_count = %#v, want 2", got)
	}
	if got := primaryNode.Properties["corroborating_source_count"]; got != 2 {
		t.Fatalf("primary corroborating_source_count = %#v, want 2", got)
	}
	if got := primaryNode.Properties["corroboration_multiplier"]; got != 1.5 {
		t.Fatalf("primary corroboration_multiplier = %#v, want 1.5", got)
	}
	if got := testNodeProperty(primaryNode, "confidence"); got != 0.75 {
		t.Fatalf("primary confidence = %#v, want 0.75", got)
	}
	if got := testMetadataString(primaryNode.Properties, "image_ref"); got != "ghcr.io/acme/api:1.2.3" {
		t.Fatalf("primary image_ref = %q, want corroborating metadata to enrich primary", got)
	}
	if got := testStringSliceProperty(primaryNode.Properties, "corroborating_sources"); len(got) != 2 || got[0] != "falco" || got[1] != "tetragon" {
		t.Fatalf("primary corroborating_sources = %#v, want [falco tetragon]", got)
	}
	if got := testStringSliceProperty(primaryNode.Properties, "tags"); len(got) != 2 || got[0] != "curl" || got[1] != "process" {
		t.Fatalf("primary tags = %#v, want merged corroborating tags", got)
	}

	corroboratingNode := mustNode(t, g, corroboratingReq.ID)
	if got, ok := corroboratingNode.Properties["correlation_primary"].(bool); !ok || got {
		t.Fatalf("corroborating correlation_primary = %#v, want false", corroboratingNode.Properties["correlation_primary"])
	}
	if got := testMetadataString(corroboratingNode.Properties, "corroboration_primary_id"); got != primaryReq.ID {
		t.Fatalf("corroboration_primary_id = %q, want %q", got, primaryReq.ID)
	}
	if got := testNodeProperty(corroboratingNode, "confidence"); got != runtimeObservationBaseConfidence {
		t.Fatalf("corroborating confidence = %#v, want %f", got, runtimeObservationBaseConfidence)
	}

	corroborates := testFindEdgeInList(g.GetOutEdges(corroboratingReq.ID), graph.EdgeKindCorroborates, primaryReq.ID)
	if corroborates == nil {
		t.Fatalf("expected corroborates edge from %s to %s", corroboratingReq.ID, primaryReq.ID)
	}
	if got := testMetadataString(corroborates.Properties, "correlation_key"); got != testMetadataString(primaryNode.Properties, "correlation_key") {
		t.Fatalf("corroborates correlation_key = %q, want %q", got, testMetadataString(primaryNode.Properties, "correlation_key"))
	}
	if issues := graph.GlobalSchemaRegistry().ValidateEdge(corroborates, corroboratingNode, primaryNode); len(issues) != 0 {
		t.Fatalf("ValidateEdge(corroborates) returned issues: %+v", issues)
	}
}

func TestMaterializeObservationsIntoGraphDoesNotCorroborateAcrossCorrelationBuckets(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "deployment:prod/api",
		Kind: graph.NodeKindDeployment,
		Name: "api",
	})

	base := time.Date(2026, 3, 16, 22, 5, 4, 0, time.UTC)
	first := &runtime.RuntimeObservation{
		ID:          "obs:first",
		Source:      "tetragon",
		Kind:        runtime.ObservationKindDNSQuery,
		ObservedAt:  base,
		RecordedAt:  base.Add(time.Second),
		WorkloadRef: "deployment:prod/api",
		Network: &runtime.NetworkEvent{
			Domain: "db.internal",
			DstIP:  "10.0.0.20",
		},
	}
	second := &runtime.RuntimeObservation{
		ID:          "obs:second",
		Source:      "falco",
		Kind:        runtime.ObservationKindDNSQuery,
		ObservedAt:  base.Add(2 * time.Second),
		RecordedAt:  base.Add(3 * time.Second),
		WorkloadRef: "deployment:prod/api",
		Network: &runtime.NetworkEvent{
			Domain: "db.internal",
			DstIP:  "10.0.0.20",
		},
	}

	MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{first, second}, base.Add(time.Minute))

	firstReq, err := BuildObservationWriteRequest(first)
	if err != nil {
		t.Fatalf("BuildObservationWriteRequest(first) returned error: %v", err)
	}
	secondReq, err := BuildObservationWriteRequest(second)
	if err != nil {
		t.Fatalf("BuildObservationWriteRequest(second) returned error: %v", err)
	}
	firstNode := mustNode(t, g, firstReq.ID)
	secondNode := mustNode(t, g, secondReq.ID)
	if testFindEdgeInList(g.GetOutEdges(firstReq.ID), graph.EdgeKindCorroborates, secondReq.ID) != nil {
		t.Fatalf("did not expect corroborates edge from %s to %s across bucket boundary", firstReq.ID, secondReq.ID)
	}
	if testFindEdgeInList(g.GetOutEdges(secondReq.ID), graph.EdgeKindCorroborates, firstReq.ID) != nil {
		t.Fatalf("did not expect corroborates edge from %s to %s across bucket boundary", secondReq.ID, firstReq.ID)
	}
	if got := firstNode.Properties["corroboration_count"]; got != 1 {
		t.Fatalf("first corroboration_count = %#v, want 1", got)
	}
	if got := secondNode.Properties["corroboration_count"]; got != 1 {
		t.Fatalf("second corroboration_count = %#v, want 1", got)
	}
}

func TestMaterializeObservationsIntoGraphDoesNotInflateConfidenceForUntrustedSourceAliases(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "deployment:prod/api",
		Kind: graph.NodeKindDeployment,
		Name: "api",
	})

	base := time.Date(2026, 3, 16, 22, 0, 2, 0, time.UTC)
	first := &runtime.RuntimeObservation{
		ID:          "obs:untrusted-1",
		Source:      "collector-a",
		Kind:        runtime.ObservationKindProcessExec,
		ObservedAt:  base,
		RecordedAt:  base.Add(time.Second),
		WorkloadRef: "deployment:prod/api",
		Process: &runtime.ProcessEvent{
			Path: "/usr/bin/curl",
			User: "root",
		},
	}
	second := &runtime.RuntimeObservation{
		ID:          "obs:untrusted-2",
		Source:      "collector-b",
		Kind:        runtime.ObservationKindProcessExec,
		ObservedAt:  base.Add(time.Second),
		RecordedAt:  base.Add(2 * time.Second),
		WorkloadRef: "deployment:prod/api",
		Process: &runtime.ProcessEvent{
			Path: "/usr/bin/curl",
			User: "root",
		},
	}

	result := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{first, second}, base.Add(time.Minute))
	if result.ObservationsMaterialized != 2 {
		t.Fatalf("ObservationsMaterialized = %d, want 2", result.ObservationsMaterialized)
	}

	firstReq, err := BuildObservationWriteRequest(first)
	if err != nil {
		t.Fatalf("BuildObservationWriteRequest(first) returned error: %v", err)
	}
	primaryNode := mustNode(t, g, firstReq.ID)
	if got := primaryNode.Properties["corroborating_source_count"]; got != 1 {
		t.Fatalf("corroborating_source_count = %#v, want 1", got)
	}
	if got := primaryNode.Properties["corroboration_multiplier"]; got != 1.0 {
		t.Fatalf("corroboration_multiplier = %#v, want 1.0", got)
	}
	if got := testNodeProperty(primaryNode, "confidence"); got != runtimeObservationBaseConfidence {
		t.Fatalf("confidence = %#v, want %f", got, runtimeObservationBaseConfidence)
	}
	if got := testStringSliceProperty(primaryNode.Properties, "corroborating_sources"); len(got) != 0 {
		t.Fatalf("corroborating_sources = %#v, want empty for untrusted aliases", got)
	}
}

func TestMaterializeObservationsIntoGraphProjectsRepresentativeObservationKinds(t *testing.T) {
	cases := []struct {
		name            string
		subject         *graph.Node
		observation     *runtime.RuntimeObservation
		wantType        string
		wantSubjectID   string
		wantDetail      string
		wantReverseEdge bool
	}{
		{
			name: "file write",
			subject: &graph.Node{
				ID:   "deployment:prod/api",
				Kind: graph.NodeKindDeployment,
				Name: "api",
			},
			observation: &runtime.RuntimeObservation{
				ID:          "runtime:file_write:seed",
				Source:      "falco",
				Kind:        runtime.ObservationKindFileWrite,
				ObservedAt:  time.Date(2026, 3, 16, 19, 2, 0, 0, time.UTC),
				RecordedAt:  time.Date(2026, 3, 16, 19, 2, 1, 0, time.UTC),
				WorkloadRef: "deployment:prod/api",
				File: &runtime.FileEvent{
					Path: "/tmp/seed.txt",
				},
			},
			wantType:        "file_write",
			wantSubjectID:   "deployment:prod/api",
			wantDetail:      "file write /tmp/seed.txt",
			wantReverseEdge: true,
		},
		{
			name: "network flow",
			subject: &graph.Node{
				ID:   "deployment:prod/api",
				Kind: graph.NodeKindDeployment,
				Name: "api",
			},
			observation: &runtime.RuntimeObservation{
				ID:          "runtime:network_flow:seed",
				Source:      "hubble",
				Kind:        runtime.ObservationKindNetworkFlow,
				ObservedAt:  time.Date(2026, 3, 16, 19, 3, 0, 0, time.UTC),
				RecordedAt:  time.Date(2026, 3, 16, 19, 3, 1, 0, time.UTC),
				WorkloadRef: "deployment:prod/api",
				Network: &runtime.NetworkEvent{
					Protocol: "tcp",
					SrcIP:    "10.0.0.10",
					SrcPort:  12345,
					DstIP:    "10.0.0.20",
					DstPort:  443,
				},
			},
			wantType:        "network_flow",
			wantSubjectID:   "deployment:prod/api",
			wantDetail:      "network flow tcp 10.0.0.10:12345 -> 10.0.0.20:443",
			wantReverseEdge: true,
		},
		{
			name: "dns query",
			subject: &graph.Node{
				ID:   "deployment:prod/api",
				Kind: graph.NodeKindDeployment,
				Name: "api",
			},
			observation: &runtime.RuntimeObservation{
				ID:          "runtime:dns_query:seed",
				Source:      "hubble",
				Kind:        runtime.ObservationKindDNSQuery,
				ObservedAt:  time.Date(2026, 3, 16, 19, 4, 0, 0, time.UTC),
				RecordedAt:  time.Date(2026, 3, 16, 19, 4, 1, 0, time.UTC),
				WorkloadRef: "deployment:prod/api",
				Network: &runtime.NetworkEvent{
					Domain: "db.internal",
					DstIP:  "10.0.0.30",
				},
			},
			wantType:        "dns_query",
			wantSubjectID:   "deployment:prod/api",
			wantDetail:      "dns query db.internal",
			wantReverseEdge: true,
		},
		{
			name: "kubernetes audit",
			subject: &graph.Node{
				ID:   "deployment:prod/api",
				Kind: graph.NodeKindDeployment,
				Name: "api",
			},
			observation: &runtime.RuntimeObservation{
				ID:          "runtime:k8s_audit:seed",
				Source:      "k8s_audit",
				Kind:        runtime.ObservationKindKubernetesAudit,
				ObservedAt:  time.Date(2026, 3, 16, 19, 5, 0, 0, time.UTC),
				RecordedAt:  time.Date(2026, 3, 16, 19, 5, 1, 0, time.UTC),
				WorkloadRef: "deployment:prod/api",
				ControlPlane: &runtime.ControlPlaneContext{
					Verb:      "delete",
					Resource:  "pods",
					Namespace: "prod",
					Name:      "api-7f9d",
					User:      "system:admin",
				},
			},
			wantType:        "k8s_audit",
			wantSubjectID:   "deployment:prod/api",
			wantDetail:      "k8s audit delete pods prod/api-7f9d",
			wantReverseEdge: true,
		},
		{
			name: "runtime alert",
			subject: &graph.Node{
				ID:   "deployment:prod/api",
				Kind: graph.NodeKindDeployment,
				Name: "api",
			},
			observation: &runtime.RuntimeObservation{
				ID:          "runtime:alert:seed",
				Source:      "falco",
				Kind:        runtime.ObservationKindRuntimeAlert,
				ObservedAt:  time.Date(2026, 3, 16, 19, 6, 0, 0, time.UTC),
				RecordedAt:  time.Date(2026, 3, 16, 19, 6, 1, 0, time.UTC),
				WorkloadRef: "deployment:prod/api",
				Metadata: map[string]any{
					"signal_name": "unexpected_shell",
					"severity":    "high",
				},
			},
			wantType:        "runtime_alert",
			wantSubjectID:   "deployment:prod/api",
			wantDetail:      "runtime alert unexpected_shell",
			wantReverseEdge: true,
		},
		{
			name: "trace link",
			subject: &graph.Node{
				ID:   "service:storefront/checkout",
				Kind: graph.NodeKindService,
				Name: "checkout",
			},
			observation: &runtime.RuntimeObservation{
				ID:         "runtime:trace_link:seed",
				Source:     "otel",
				Kind:       runtime.ObservationKindTraceLink,
				ObservedAt: time.Date(2026, 3, 16, 19, 7, 0, 0, time.UTC),
				RecordedAt: time.Date(2026, 3, 16, 19, 7, 1, 0, time.UTC),
				Trace: &runtime.TraceContext{
					TraceID:     "trace-1",
					ServiceName: "checkout",
				},
				Metadata: map[string]any{
					"service_namespace": "storefront",
				},
			},
			wantType:        "trace_link",
			wantSubjectID:   "service:storefront/checkout",
			wantDetail:      "trace link checkout",
			wantReverseEdge: false,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			g := graph.New()
			g.AddNode(tt.subject)

			result := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{tt.observation}, tt.observation.ObservedAt.Add(time.Minute))
			if result.ObservationsMaterialized != 1 {
				t.Fatalf("ObservationsMaterialized = %d, want 1", result.ObservationsMaterialized)
			}
			if result.ObservationsSkipped != 0 {
				t.Fatalf("ObservationsSkipped = %d, want 0", result.ObservationsSkipped)
			}
			if tt.wantReverseEdge && result.WorkloadTargetEdgesCreated != 1 {
				t.Fatalf("WorkloadTargetEdgesCreated = %d, want 1", result.WorkloadTargetEdgesCreated)
			}
			if !tt.wantReverseEdge && result.WorkloadTargetEdgesCreated != 0 {
				t.Fatalf("WorkloadTargetEdgesCreated = %d, want 0", result.WorkloadTargetEdgesCreated)
			}

			observationNodeID := "observation:" + tt.observation.ID
			node := mustNode(t, g, observationNodeID)
			if got := testNodeStringProperty(node, "observation_type"); got != tt.wantType {
				t.Fatalf("observation_type = %q, want %q", got, tt.wantType)
			}
			if got := testNodeStringProperty(node, "subject_id"); got != tt.wantSubjectID {
				t.Fatalf("subject_id = %q, want %q", got, tt.wantSubjectID)
			}
			if got := testNodeStringProperty(node, "detail"); got != tt.wantDetail {
				t.Fatalf("detail = %q, want %q", got, tt.wantDetail)
			}
			if issues := graph.GlobalSchemaRegistry().ValidateNode(node); len(issues) != 0 {
				t.Fatalf("ValidateNode returned issues: %+v", issues)
			}

			outEdges := g.GetOutEdges(observationNodeID)
			if len(outEdges) != 1 {
				t.Fatalf("len(outEdges) = %d, want 1", len(outEdges))
			}
			if outEdges[0].Kind != graph.EdgeKindTargets || outEdges[0].Target != tt.wantSubjectID {
				t.Fatalf("edge = %+v, want targets edge to %s", outEdges[0], tt.wantSubjectID)
			}
			if issues := graph.GlobalSchemaRegistry().ValidateEdge(outEdges[0], node, mustNode(t, g, tt.wantSubjectID)); len(issues) != 0 {
				t.Fatalf("ValidateEdge returned issues: %+v", issues)
			}

			subjectEdges := g.GetOutEdges(tt.wantSubjectID)
			if tt.wantReverseEdge {
				if len(subjectEdges) != 1 {
					t.Fatalf("len(subjectEdges) = %d, want 1", len(subjectEdges))
				}
				if subjectEdges[0].Kind != graph.EdgeKindTargets || subjectEdges[0].Target != observationNodeID {
					t.Fatalf("reverse edge = %+v, want targets edge to %s", subjectEdges[0], observationNodeID)
				}
			} else if len(subjectEdges) != 0 {
				t.Fatalf("len(subjectEdges) = %d, want 0", len(subjectEdges))
			}
		})
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

func TestMaterializeObservationsIntoGraphAddsTraceCallEdge(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "service:storefront/checkout", Kind: graph.NodeKindService, Name: "checkout"})
	g.AddNode(&graph.Node{ID: "service:storefront/payments", Kind: graph.NodeKindService, Name: "payments"})

	observation := &runtime.RuntimeObservation{
		ID:         "runtime:trace_link:checkout-payments-1",
		Source:     "otel",
		Kind:       runtime.ObservationKindTraceLink,
		ObservedAt: time.Date(2026, 3, 17, 17, 20, 0, 0, time.UTC),
		RecordedAt: time.Date(2026, 3, 17, 17, 20, 5, 0, time.UTC),
		Trace: &runtime.TraceContext{
			TraceID:     "trace-1",
			SpanID:      "span-1",
			ServiceName: "checkout",
		},
		Metadata: map[string]any{
			"service_namespace":             "storefront",
			"span_kind":                     "client",
			"span_status_code":              "error",
			"parent_span_id":                "parent-1",
			"destination_service_name":      "payments",
			"destination_service_namespace": "storefront",
			"call_protocol":                 "grpc",
		},
	}

	result := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, observation.ObservedAt.Add(time.Minute))
	if result.TraceCallEdgesCreated != 1 {
		t.Fatalf("TraceCallEdgesCreated = %d, want 1", result.TraceCallEdgesCreated)
	}

	edge := testFindEdge(t, g, "service:storefront/checkout", "service:storefront/payments", graph.EdgeKindCalls)
	if got := edge.Properties["protocol"]; got != "grpc" {
		t.Fatalf("protocol = %#v, want grpc", got)
	}
	if got := edge.Properties["call_count"]; got != int64(1) {
		t.Fatalf("call_count = %#v, want 1", got)
	}
	if got := edge.Properties["error_count"]; got != int64(1) {
		t.Fatalf("error_count = %#v, want 1", got)
	}
	if got := edge.Properties["avg_latency_ms"]; got != float64(5000) {
		t.Fatalf("avg_latency_ms = %#v, want 5000", got)
	}
	if got := edge.Properties["trace_id"]; got != "trace-1" {
		t.Fatalf("trace_id = %#v, want trace-1", got)
	}

	observationNode := mustNode(t, g, "observation:"+observation.ID)
	if got := testMetadataString(observationNode.Properties, "trace_calls_target_id"); got != "service:storefront/payments" {
		t.Fatalf("trace_calls_target_id = %q, want service:storefront/payments", got)
	}
}

func TestMaterializeObservationsIntoGraphAggregatesTraceCallEdges(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "service:storefront/checkout", Kind: graph.NodeKindService, Name: "checkout"})
	g.AddNode(&graph.Node{ID: "service:storefront/payments", Kind: graph.NodeKindService, Name: "payments"})

	first := &runtime.RuntimeObservation{
		ID:         "runtime:trace_link:checkout-payments-1",
		Source:     "otel",
		Kind:       runtime.ObservationKindTraceLink,
		ObservedAt: time.Date(2026, 3, 17, 17, 20, 0, 0, time.UTC),
		RecordedAt: time.Date(2026, 3, 17, 17, 20, 4, 0, time.UTC),
		Trace:      &runtime.TraceContext{TraceID: "trace-1", SpanID: "span-1", ServiceName: "checkout"},
		Metadata: map[string]any{
			"service_namespace":             "storefront",
			"span_kind":                     "client",
			"span_status_code":              "error",
			"destination_service_name":      "payments",
			"destination_service_namespace": "storefront",
			"call_protocol":                 "grpc",
		},
	}
	second := &runtime.RuntimeObservation{
		ID:         "runtime:trace_link:checkout-payments-2",
		Source:     "otel",
		Kind:       runtime.ObservationKindTraceLink,
		ObservedAt: time.Date(2026, 3, 17, 17, 22, 0, 0, time.UTC),
		RecordedAt: time.Date(2026, 3, 17, 17, 22, 2, 0, time.UTC),
		Trace:      &runtime.TraceContext{TraceID: "trace-2", SpanID: "span-2", ServiceName: "checkout"},
		Metadata: map[string]any{
			"service_namespace":             "storefront",
			"span_kind":                     "client",
			"span_status_code":              "ok",
			"destination_service_name":      "payments",
			"destination_service_namespace": "storefront",
			"call_protocol":                 "grpc",
		},
	}

	firstResult := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{first}, first.ObservedAt.Add(time.Minute))
	secondResult := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{second}, second.ObservedAt.Add(time.Minute))
	if firstResult.TraceCallEdgesCreated != 1 {
		t.Fatalf("first TraceCallEdgesCreated = %d, want 1", firstResult.TraceCallEdgesCreated)
	}
	if secondResult.TraceCallEdgesCreated != 0 {
		t.Fatalf("second TraceCallEdgesCreated = %d, want 0", secondResult.TraceCallEdgesCreated)
	}

	edge := testFindEdge(t, g, "service:storefront/checkout", "service:storefront/payments", graph.EdgeKindCalls)
	if got := edge.Properties["call_count"]; got != int64(2) {
		t.Fatalf("call_count = %#v, want 2", got)
	}
	if got := edge.Properties["error_count"]; got != int64(1) {
		t.Fatalf("error_count = %#v, want 1", got)
	}
	if got := edge.Properties["avg_latency_ms"]; got != float64(3000) {
		t.Fatalf("avg_latency_ms = %#v, want 3000", got)
	}
	if got := edge.Properties["error_rate"]; got != 0.5 {
		t.Fatalf("error_rate = %#v, want 0.5", got)
	}
	if got := edge.Properties["call_rate_per_min"]; got != 1.0 {
		t.Fatalf("call_rate_per_min = %#v, want 1.0", got)
	}
}

func TestMaterializeObservationsIntoGraphDoesNotDoubleCountDuplicateTraceCallObservation(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "service:storefront/checkout", Kind: graph.NodeKindService, Name: "checkout"})
	g.AddNode(&graph.Node{ID: "service:storefront/payments", Kind: graph.NodeKindService, Name: "payments"})

	observation := &runtime.RuntimeObservation{
		ID:         "runtime:trace_link:checkout-payments-1",
		Source:     "otel",
		Kind:       runtime.ObservationKindTraceLink,
		ObservedAt: time.Date(2026, 3, 17, 17, 20, 0, 0, time.UTC),
		RecordedAt: time.Date(2026, 3, 17, 17, 20, 4, 0, time.UTC),
		Trace:      &runtime.TraceContext{TraceID: "trace-1", SpanID: "span-1", ServiceName: "checkout"},
		Metadata: map[string]any{
			"service_namespace":             "storefront",
			"span_kind":                     "client",
			"destination_service_name":      "payments",
			"destination_service_namespace": "storefront",
			"call_protocol":                 "grpc",
		},
	}

	first := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, observation.ObservedAt.Add(time.Minute))
	second := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, observation.ObservedAt.Add(2*time.Minute))
	if first.TraceCallEdgesCreated != 1 {
		t.Fatalf("first TraceCallEdgesCreated = %d, want 1", first.TraceCallEdgesCreated)
	}
	if second.TraceCallEdgesCreated != 0 {
		t.Fatalf("second TraceCallEdgesCreated = %d, want 0", second.TraceCallEdgesCreated)
	}

	edge := testFindEdge(t, g, "service:storefront/checkout", "service:storefront/payments", graph.EdgeKindCalls)
	if got := edge.Properties["call_count"]; got != int64(1) {
		t.Fatalf("call_count = %#v, want 1", got)
	}
}

func TestMaterializeObservationsIntoGraphIgnoresUntrustedTraceCallTargetMetadata(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "service:storefront/checkout", Kind: graph.NodeKindService, Name: "checkout"})
	g.AddNode(&graph.Node{ID: "service:storefront/payments", Kind: graph.NodeKindService, Name: "payments"})
	g.AddNode(&graph.Node{ID: "deployment:prod/admin", Kind: graph.NodeKindDeployment, Name: "admin"})

	observation := &runtime.RuntimeObservation{
		ID:         "runtime:trace_link:checkout-payments-untrusted-target",
		Source:     "otel",
		Kind:       runtime.ObservationKindTraceLink,
		ObservedAt: time.Date(2026, 3, 17, 17, 24, 0, 0, time.UTC),
		RecordedAt: time.Date(2026, 3, 17, 17, 24, 2, 0, time.UTC),
		Trace:      &runtime.TraceContext{TraceID: "trace-rogue", SpanID: "span-rogue", ServiceName: "checkout"},
		Metadata: map[string]any{
			"service_namespace":             "storefront",
			"span_kind":                     "client",
			"destination_service_name":      "payments",
			"destination_service_namespace": "storefront",
			"destination_workload_ref":      "deployment:prod/admin",
		},
	}

	result := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, observation.ObservedAt.Add(time.Minute))
	if result.TraceCallEdgesCreated != 1 {
		t.Fatalf("TraceCallEdgesCreated = %d, want 1", result.TraceCallEdgesCreated)
	}

	testFindEdge(t, g, "service:storefront/checkout", "service:storefront/payments", graph.EdgeKindCalls)
	for _, edge := range g.GetOutEdges("service:storefront/checkout") {
		if edge.Kind == graph.EdgeKindCalls && edge.Target == "deployment:prod/admin" {
			t.Fatalf("unexpected forged calls edge = %+v", edge)
		}
	}

	observationNode := mustNode(t, g, "observation:"+observation.ID)
	if got := testMetadataString(observationNode.Properties, "trace_calls_target_id"); got != "service:storefront/payments" {
		t.Fatalf("trace_calls_target_id = %q, want service:storefront/payments", got)
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

func TestMaterializeObservationsIntoGraphCarriesResponseOutcomeTargetMetadata(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "deployment:prod/web",
		Kind: graph.NodeKindDeployment,
		Name: "web",
	})

	observation := &runtime.RuntimeObservation{
		ID:          "runtime:response_outcome:block-ip",
		Source:      "runtime_response",
		Kind:        runtime.ObservationKindResponseOutcome,
		ObservedAt:  time.Date(2026, 3, 16, 20, 45, 0, 0, time.UTC),
		RecordedAt:  time.Date(2026, 3, 16, 20, 45, 1, 0, time.UTC),
		WorkloadRef: "deployment:prod/web",
		Metadata: map[string]any{
			"execution_id":  "exec-1",
			"policy_id":     "policy-1",
			"action_type":   "block_ip",
			"action_status": "completed",
		},
	}

	result := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, time.Date(2026, 3, 16, 20, 46, 0, 0, time.UTC))
	if result.ObservationsMaterialized != 1 {
		t.Fatalf("ObservationsMaterialized = %d, want 1", result.ObservationsMaterialized)
	}

	observationNodeID := "observation:" + observation.ID
	forwardEdges := g.GetOutEdges(observationNodeID)
	if len(forwardEdges) != 1 {
		t.Fatalf("len(forwardEdges) = %d, want 1", len(forwardEdges))
	}
	if got := forwardEdges[0].Properties["response_execution_id"]; got != "exec-1" {
		t.Fatalf("forward response_execution_id = %#v, want exec-1", got)
	}
	if got := forwardEdges[0].Properties["response_policy_id"]; got != "policy-1" {
		t.Fatalf("forward response_policy_id = %#v, want policy-1", got)
	}
	if got := forwardEdges[0].Properties["response_action_type"]; got != "block_ip" {
		t.Fatalf("forward response_action_type = %#v, want block_ip", got)
	}
	if got := forwardEdges[0].Properties["response_action_status"]; got != "completed" {
		t.Fatalf("forward response_action_status = %#v, want completed", got)
	}

	reverseEdges := g.GetOutEdges("deployment:prod/web")
	if len(reverseEdges) != 1 {
		t.Fatalf("len(reverseEdges) = %d, want 1", len(reverseEdges))
	}
	if got := reverseEdges[0].Properties["response_execution_id"]; got != "exec-1" {
		t.Fatalf("reverse response_execution_id = %#v, want exec-1", got)
	}
	if got := reverseEdges[0].Properties["response_action_type"]; got != "block_ip" {
		t.Fatalf("reverse response_action_type = %#v, want block_ip", got)
	}
}

func TestMaterializeObservationsIntoGraphAddsResponseOutcomeBasedOnEvidenceEdge(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "deployment:prod/web",
		Kind: graph.NodeKindDeployment,
		Name: "web",
	})
	g.AddNode(&graph.Node{
		ID:       "evidence:runtime_finding:finding-1",
		Kind:     graph.NodeKindEvidence,
		Name:     "finding-1",
		Provider: runtimeFindingEvidenceSourceSystem,
		Properties: map[string]any{
			"evidence_type": "runtime_finding",
			"source_system": runtimeFindingEvidenceSourceSystem,
			"observed_at":   "2026-03-16T20:44:00Z",
			"valid_from":    "2026-03-16T20:44:00Z",
		},
	})

	observation := &runtime.RuntimeObservation{
		ID:          "runtime:response_outcome:block-ip",
		Source:      "runtime_response",
		Kind:        runtime.ObservationKindResponseOutcome,
		ObservedAt:  time.Date(2026, 3, 16, 20, 45, 0, 0, time.UTC),
		RecordedAt:  time.Date(2026, 3, 16, 20, 45, 1, 0, time.UTC),
		WorkloadRef: "deployment:prod/web",
		Metadata: map[string]any{
			"finding_id":    "finding-1",
			"execution_id":  "exec-1",
			"policy_id":     "policy-1",
			"action_type":   "block_ip",
			"action_status": "completed",
		},
	}

	result := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, time.Date(2026, 3, 16, 20, 46, 0, 0, time.UTC))
	if result.ObservationsMaterialized != 1 {
		t.Fatalf("ObservationsMaterialized = %d, want 1", result.ObservationsMaterialized)
	}
	if result.ResponseBasedOnEdgesCreated != 1 {
		t.Fatalf("ResponseBasedOnEdgesCreated = %d, want 1", result.ResponseBasedOnEdgesCreated)
	}

	observationNodeID := "observation:" + observation.ID
	var found bool
	for _, edge := range g.GetOutEdges(observationNodeID) {
		if edge.Kind != graph.EdgeKindBasedOn {
			continue
		}
		found = true
		if edge.Target != "evidence:runtime_finding:finding-1" {
			t.Fatalf("based_on target = %q, want evidence:runtime_finding:finding-1", edge.Target)
		}
		if got := edge.Properties["finding_id"]; got != "finding-1" {
			t.Fatalf("based_on finding_id = %#v, want finding-1", got)
		}
		if got := edge.Properties["response_execution_id"]; got != "exec-1" {
			t.Fatalf("based_on response_execution_id = %#v, want exec-1", got)
		}
	}
	if !found {
		t.Fatal("expected response outcome based_on edge to evidence")
	}
}

func TestMaterializeObservationsIntoGraphSkipsResponseOutcomeBasedOnEdgeWhenEvidenceMissing(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "deployment:prod/web",
		Kind: graph.NodeKindDeployment,
		Name: "web",
	})

	observation := &runtime.RuntimeObservation{
		ID:          "runtime:response_outcome:block-ip",
		Source:      "runtime_response",
		Kind:        runtime.ObservationKindResponseOutcome,
		ObservedAt:  time.Date(2026, 3, 16, 20, 45, 0, 0, time.UTC),
		RecordedAt:  time.Date(2026, 3, 16, 20, 45, 1, 0, time.UTC),
		WorkloadRef: "deployment:prod/web",
		Metadata: map[string]any{
			"finding_id":    "finding-1",
			"execution_id":  "exec-1",
			"policy_id":     "policy-1",
			"action_type":   "block_ip",
			"action_status": "completed",
		},
	}

	result := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, time.Date(2026, 3, 16, 20, 46, 0, 0, time.UTC))
	if result.ResponseBasedOnEdgesCreated != 0 {
		t.Fatalf("ResponseBasedOnEdgesCreated = %d, want 0", result.ResponseBasedOnEdgesCreated)
	}

	observationNodeID := "observation:" + observation.ID
	if got := len(g.GetOutEdges(observationNodeID)); got != 1 {
		t.Fatalf("len(out edges) = %d, want 1 target edge only", got)
	}
}

func TestMaterializeObservationsIntoGraphDoesNotDuplicateResponseOutcomeBasedOnEdges(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "deployment:prod/web",
		Kind: graph.NodeKindDeployment,
		Name: "web",
	})
	g.AddNode(&graph.Node{
		ID:       "evidence:runtime_finding:finding-1",
		Kind:     graph.NodeKindEvidence,
		Name:     "finding-1",
		Provider: runtimeFindingEvidenceSourceSystem,
		Properties: map[string]any{
			"evidence_type": "runtime_finding",
			"source_system": runtimeFindingEvidenceSourceSystem,
			"observed_at":   "2026-03-16T20:44:00Z",
			"valid_from":    "2026-03-16T20:44:00Z",
		},
	})

	observation := &runtime.RuntimeObservation{
		ID:          "runtime:response_outcome:block-ip",
		Source:      "runtime_response",
		Kind:        runtime.ObservationKindResponseOutcome,
		ObservedAt:  time.Date(2026, 3, 16, 20, 45, 0, 0, time.UTC),
		RecordedAt:  time.Date(2026, 3, 16, 20, 45, 1, 0, time.UTC),
		WorkloadRef: "deployment:prod/web",
		Metadata: map[string]any{
			"finding_id":    "finding-1",
			"execution_id":  "exec-1",
			"policy_id":     "policy-1",
			"action_type":   "block_ip",
			"action_status": "completed",
		},
	}

	first := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, time.Date(2026, 3, 16, 20, 46, 0, 0, time.UTC))
	second := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, time.Date(2026, 3, 16, 20, 47, 0, 0, time.UTC))
	if first.ResponseBasedOnEdgesCreated != 1 {
		t.Fatalf("first ResponseBasedOnEdgesCreated = %d, want 1", first.ResponseBasedOnEdgesCreated)
	}
	if second.ResponseBasedOnEdgesCreated != 0 {
		t.Fatalf("second ResponseBasedOnEdgesCreated = %d, want 0", second.ResponseBasedOnEdgesCreated)
	}

	observationNodeID := "observation:" + observation.ID
	var basedOn int
	for _, edge := range g.GetOutEdges(observationNodeID) {
		if edge.Kind == graph.EdgeKindBasedOn {
			basedOn++
		}
	}
	if basedOn != 1 {
		t.Fatalf("based_on edge count = %d, want 1", basedOn)
	}
}

func TestMaterializeObservationsIntoGraphAddsDeploymentRunBasedOnEdge(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "deployment:storefront/checkout",
		Kind: graph.NodeKindDeployment,
		Name: "checkout",
	})
	g.AddNode(&graph.Node{
		ID:   "service:storefront/checkout",
		Kind: graph.NodeKindService,
		Name: "checkout",
	})
	g.AddNode(&graph.Node{
		ID:       "deployment_run:storefront/checkout:deploy-1",
		Kind:     graph.NodeKindDeploymentRun,
		Name:     "deploy-1",
		Provider: "github_actions",
		Properties: map[string]any{
			"status":      "completed",
			"service_id":  "service:storefront/checkout",
			"observed_at": "2026-03-16T20:30:00Z",
			"valid_from":  "2026-03-16T20:30:00Z",
		},
	})
	g.AddEdge(&graph.Edge{
		ID:     "deployment_run:storefront/checkout:deploy-1->service:storefront/checkout:targets",
		Source: "deployment_run:storefront/checkout:deploy-1",
		Target: "service:storefront/checkout",
		Kind:   graph.EdgeKindTargets,
		Effect: graph.EdgeEffectAllow,
	})

	observation := &runtime.RuntimeObservation{
		ID:          "runtime:process_exec:deploy-linked",
		Source:      "tetragon",
		Kind:        runtime.ObservationKindProcessExec,
		ObservedAt:  time.Date(2026, 3, 16, 20, 45, 0, 0, time.UTC),
		RecordedAt:  time.Date(2026, 3, 16, 20, 45, 1, 0, time.UTC),
		WorkloadRef: "deployment:storefront/checkout",
		Namespace:   "storefront",
		Trace: &runtime.TraceContext{
			ServiceName: "checkout",
		},
		Process: &runtime.ProcessEvent{
			Name: "sh",
			Path: "/bin/sh",
		},
		Metadata: map[string]any{
			"service_namespace": "storefront",
		},
	}

	result := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, time.Date(2026, 3, 16, 20, 46, 0, 0, time.UTC))
	if result.ObservationsMaterialized != 1 {
		t.Fatalf("ObservationsMaterialized = %d, want 1", result.ObservationsMaterialized)
	}
	if result.DeploymentRunBasedOnEdgesCreated != 1 {
		t.Fatalf("DeploymentRunBasedOnEdgesCreated = %d, want 1", result.DeploymentRunBasedOnEdgesCreated)
	}

	observationNodeID := "observation:" + observation.ID
	var found bool
	for _, edge := range g.GetOutEdges(observationNodeID) {
		if edge.Kind != graph.EdgeKindBasedOn {
			continue
		}
		found = true
		if edge.Target != "deployment_run:storefront/checkout:deploy-1" {
			t.Fatalf("based_on target = %q, want deployment_run:storefront/checkout:deploy-1", edge.Target)
		}
		if got := edge.Properties["service_id"]; got != "service:storefront/checkout" {
			t.Fatalf("based_on service_id = %#v, want service:storefront/checkout", got)
		}
		if got := edge.Properties["deployment_gap_seconds"]; got != int64((15 * time.Minute).Seconds()) {
			t.Fatalf("based_on deployment_gap_seconds = %#v, want %d", got, int64((15 * time.Minute).Seconds()))
		}
	}
	if !found {
		t.Fatal("expected deployment_run based_on edge")
	}
}

func TestMaterializeObservationsIntoGraphSkipsDeploymentRunBasedOnEdgeWhenAmbiguous(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "deployment:storefront/checkout",
		Kind: graph.NodeKindDeployment,
		Name: "checkout",
	})
	g.AddNode(&graph.Node{
		ID:   "service:storefront/checkout",
		Kind: graph.NodeKindService,
		Name: "checkout",
	})
	for _, id := range []string{
		"deployment_run:storefront/checkout:deploy-1",
		"deployment_run:storefront/checkout:deploy-2",
	} {
		g.AddNode(&graph.Node{
			ID:       id,
			Kind:     graph.NodeKindDeploymentRun,
			Name:     id,
			Provider: "github_actions",
			Properties: map[string]any{
				"status":      "completed",
				"service_id":  "service:storefront/checkout",
				"observed_at": "2026-03-16T20:30:00Z",
				"valid_from":  "2026-03-16T20:30:00Z",
			},
		})
		g.AddEdge(&graph.Edge{
			ID:     id + "->service:storefront/checkout:targets",
			Source: id,
			Target: "service:storefront/checkout",
			Kind:   graph.EdgeKindTargets,
			Effect: graph.EdgeEffectAllow,
		})
	}

	observation := &runtime.RuntimeObservation{
		ID:          "runtime:process_exec:deploy-ambiguous",
		Source:      "tetragon",
		Kind:        runtime.ObservationKindProcessExec,
		ObservedAt:  time.Date(2026, 3, 16, 20, 45, 0, 0, time.UTC),
		RecordedAt:  time.Date(2026, 3, 16, 20, 45, 1, 0, time.UTC),
		WorkloadRef: "deployment:storefront/checkout",
		Namespace:   "storefront",
		Trace: &runtime.TraceContext{
			ServiceName: "checkout",
		},
		Process: &runtime.ProcessEvent{
			Name: "sh",
			Path: "/bin/sh",
		},
		Metadata: map[string]any{
			"service_namespace": "storefront",
		},
	}

	result := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, time.Date(2026, 3, 16, 20, 46, 0, 0, time.UTC))
	if result.DeploymentRunBasedOnEdgesCreated != 0 {
		t.Fatalf("DeploymentRunBasedOnEdgesCreated = %d, want 0", result.DeploymentRunBasedOnEdgesCreated)
	}

	observationNodeID := "observation:" + observation.ID
	for _, edge := range g.GetOutEdges(observationNodeID) {
		if edge.Kind == graph.EdgeKindBasedOn {
			t.Fatalf("unexpected based_on edge = %+v", edge)
		}
	}
}

func TestMaterializeObservationsIntoGraphDoesNotDuplicateDeploymentRunBasedOnEdges(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "deployment:storefront/checkout",
		Kind: graph.NodeKindDeployment,
		Name: "checkout",
	})
	g.AddNode(&graph.Node{
		ID:   "service:storefront/checkout",
		Kind: graph.NodeKindService,
		Name: "checkout",
	})
	g.AddNode(&graph.Node{
		ID:       "deployment_run:storefront/checkout:deploy-1",
		Kind:     graph.NodeKindDeploymentRun,
		Name:     "deploy-1",
		Provider: "github_actions",
		Properties: map[string]any{
			"status":      "completed",
			"service_id":  "service:storefront/checkout",
			"observed_at": "2026-03-16T20:30:00Z",
			"valid_from":  "2026-03-16T20:30:00Z",
		},
	})
	g.AddEdge(&graph.Edge{
		ID:     "deployment_run:storefront/checkout:deploy-1->service:storefront/checkout:targets",
		Source: "deployment_run:storefront/checkout:deploy-1",
		Target: "service:storefront/checkout",
		Kind:   graph.EdgeKindTargets,
		Effect: graph.EdgeEffectAllow,
	})

	observation := &runtime.RuntimeObservation{
		ID:          "runtime:process_exec:deploy-dedupe",
		Source:      "tetragon",
		Kind:        runtime.ObservationKindProcessExec,
		ObservedAt:  time.Date(2026, 3, 16, 20, 45, 0, 0, time.UTC),
		RecordedAt:  time.Date(2026, 3, 16, 20, 45, 1, 0, time.UTC),
		WorkloadRef: "deployment:storefront/checkout",
		Namespace:   "storefront",
		Trace: &runtime.TraceContext{
			ServiceName: "checkout",
		},
		Process: &runtime.ProcessEvent{
			Name: "sh",
			Path: "/bin/sh",
		},
		Metadata: map[string]any{
			"service_namespace": "storefront",
		},
	}

	first := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, time.Date(2026, 3, 16, 20, 46, 0, 0, time.UTC))
	second := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, time.Date(2026, 3, 16, 20, 47, 0, 0, time.UTC))
	if first.DeploymentRunBasedOnEdgesCreated != 1 {
		t.Fatalf("first DeploymentRunBasedOnEdgesCreated = %d, want 1", first.DeploymentRunBasedOnEdgesCreated)
	}
	if second.DeploymentRunBasedOnEdgesCreated != 0 {
		t.Fatalf("second DeploymentRunBasedOnEdgesCreated = %d, want 0", second.DeploymentRunBasedOnEdgesCreated)
	}

	observationNodeID := "observation:" + observation.ID
	basedOnCount := 0
	for _, edge := range g.GetOutEdges(observationNodeID) {
		if edge.Kind == graph.EdgeKindBasedOn && edge.Target == "deployment_run:storefront/checkout:deploy-1" {
			basedOnCount++
		}
	}
	if basedOnCount != 1 {
		t.Fatalf("deployment_run based_on edge count = %d, want 1", basedOnCount)
	}
}

func TestMaterializeObservationsIntoGraphAddsKubernetesAuditBasedOnEdge(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "deployment:prod/api",
		Kind: graph.NodeKindDeployment,
		Name: "api",
	})

	auditObservation := &runtime.RuntimeObservation{
		ID:          "runtime:k8s_audit:patch-api",
		Source:      "k8s_audit",
		Kind:        runtime.ObservationKindKubernetesAudit,
		ObservedAt:  time.Date(2026, 3, 16, 21, 30, 0, 0, time.UTC),
		RecordedAt:  time.Date(2026, 3, 16, 21, 30, 1, 0, time.UTC),
		WorkloadRef: "deployment:prod/api",
		Namespace:   "prod",
		ControlPlane: &runtime.ControlPlaneContext{
			Verb:      "patch",
			Resource:  "deployments",
			Namespace: "prod",
			Name:      "api",
			User:      "deployer",
		},
	}
	auditResult := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{auditObservation}, time.Date(2026, 3, 16, 21, 31, 0, 0, time.UTC))
	if auditResult.ObservationsMaterialized != 1 {
		t.Fatalf("audit ObservationsMaterialized = %d, want 1", auditResult.ObservationsMaterialized)
	}

	observation := &runtime.RuntimeObservation{
		ID:          "runtime:process_exec:post-deploy",
		Source:      "tetragon",
		Kind:        runtime.ObservationKindProcessExec,
		ObservedAt:  time.Date(2026, 3, 16, 21, 35, 0, 0, time.UTC),
		RecordedAt:  time.Date(2026, 3, 16, 21, 35, 1, 0, time.UTC),
		WorkloadRef: "deployment:prod/api",
		Process: &runtime.ProcessEvent{
			Name: "sh",
			Path: "/bin/sh",
		},
	}

	result := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, time.Date(2026, 3, 16, 21, 36, 0, 0, time.UTC))
	if result.KubernetesAuditBasedOnEdgesCreated != 1 {
		t.Fatalf("KubernetesAuditBasedOnEdgesCreated = %d, want 1", result.KubernetesAuditBasedOnEdgesCreated)
	}

	observationNodeID := "observation:" + observation.ID
	var found bool
	for _, edge := range g.GetOutEdges(observationNodeID) {
		if edge.Kind != graph.EdgeKindBasedOn {
			continue
		}
		found = true
		if edge.Target != "observation:"+auditObservation.ID {
			t.Fatalf("based_on target = %q, want %q", edge.Target, "observation:"+auditObservation.ID)
		}
		if got := edge.Properties["audit_gap_seconds"]; got != int64((5 * time.Minute).Seconds()) {
			t.Fatalf("audit_gap_seconds = %#v, want %d", got, int64((5 * time.Minute).Seconds()))
		}
		if got := edge.Properties["subject_id"]; got != "deployment:prod/api" {
			t.Fatalf("subject_id = %#v, want deployment:prod/api", got)
		}
	}
	if !found {
		t.Fatal("expected kubernetes audit based_on edge")
	}
}

func TestMaterializeObservationsIntoGraphSkipsKubernetesAuditBasedOnEdgeWhenAmbiguous(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "deployment:prod/api",
		Kind: graph.NodeKindDeployment,
		Name: "api",
	})

	for _, suffix := range []string{"patch-a", "patch-b"} {
		auditObservation := &runtime.RuntimeObservation{
			ID:          "runtime:k8s_audit:" + suffix,
			Source:      "k8s_audit",
			Kind:        runtime.ObservationKindKubernetesAudit,
			ObservedAt:  time.Date(2026, 3, 16, 21, 30, 0, 0, time.UTC),
			RecordedAt:  time.Date(2026, 3, 16, 21, 30, 1, 0, time.UTC),
			WorkloadRef: "deployment:prod/api",
			Namespace:   "prod",
			ControlPlane: &runtime.ControlPlaneContext{
				Verb:      "patch",
				Resource:  "deployments",
				Namespace: "prod",
				Name:      "api",
				User:      "deployer",
			},
		}
		MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{auditObservation}, time.Date(2026, 3, 16, 21, 31, 0, 0, time.UTC))
	}

	observation := &runtime.RuntimeObservation{
		ID:          "runtime:process_exec:post-deploy-ambiguous",
		Source:      "tetragon",
		Kind:        runtime.ObservationKindProcessExec,
		ObservedAt:  time.Date(2026, 3, 16, 21, 35, 0, 0, time.UTC),
		RecordedAt:  time.Date(2026, 3, 16, 21, 35, 1, 0, time.UTC),
		WorkloadRef: "deployment:prod/api",
		Process: &runtime.ProcessEvent{
			Name: "sh",
			Path: "/bin/sh",
		},
	}

	result := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, time.Date(2026, 3, 16, 21, 36, 0, 0, time.UTC))
	if result.KubernetesAuditBasedOnEdgesCreated != 0 {
		t.Fatalf("KubernetesAuditBasedOnEdgesCreated = %d, want 0", result.KubernetesAuditBasedOnEdgesCreated)
	}

	observationNodeID := "observation:" + observation.ID
	for _, edge := range g.GetOutEdges(observationNodeID) {
		if edge.Kind == graph.EdgeKindBasedOn {
			t.Fatalf("unexpected based_on edge = %+v", edge)
		}
	}
}

func TestMaterializeObservationsIntoGraphDoesNotDuplicateKubernetesAuditBasedOnEdges(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "deployment:prod/api",
		Kind: graph.NodeKindDeployment,
		Name: "api",
	})

	auditObservation := &runtime.RuntimeObservation{
		ID:          "runtime:k8s_audit:patch-api",
		Source:      "k8s_audit",
		Kind:        runtime.ObservationKindKubernetesAudit,
		ObservedAt:  time.Date(2026, 3, 16, 21, 30, 0, 0, time.UTC),
		RecordedAt:  time.Date(2026, 3, 16, 21, 30, 1, 0, time.UTC),
		WorkloadRef: "deployment:prod/api",
		Namespace:   "prod",
		ControlPlane: &runtime.ControlPlaneContext{
			Verb:      "patch",
			Resource:  "deployments",
			Namespace: "prod",
			Name:      "api",
			User:      "deployer",
		},
	}
	MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{auditObservation}, time.Date(2026, 3, 16, 21, 31, 0, 0, time.UTC))

	observation := &runtime.RuntimeObservation{
		ID:          "runtime:process_exec:post-deploy-dedupe",
		Source:      "tetragon",
		Kind:        runtime.ObservationKindProcessExec,
		ObservedAt:  time.Date(2026, 3, 16, 21, 35, 0, 0, time.UTC),
		RecordedAt:  time.Date(2026, 3, 16, 21, 35, 1, 0, time.UTC),
		WorkloadRef: "deployment:prod/api",
		Process: &runtime.ProcessEvent{
			Name: "sh",
			Path: "/bin/sh",
		},
	}

	first := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, time.Date(2026, 3, 16, 21, 36, 0, 0, time.UTC))
	second := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, time.Date(2026, 3, 16, 21, 37, 0, 0, time.UTC))
	if first.KubernetesAuditBasedOnEdgesCreated != 1 {
		t.Fatalf("first KubernetesAuditBasedOnEdgesCreated = %d, want 1", first.KubernetesAuditBasedOnEdgesCreated)
	}
	if second.KubernetesAuditBasedOnEdgesCreated != 0 {
		t.Fatalf("second KubernetesAuditBasedOnEdgesCreated = %d, want 0", second.KubernetesAuditBasedOnEdgesCreated)
	}

	observationNodeID := "observation:" + observation.ID
	basedOnCount := 0
	for _, edge := range g.GetOutEdges(observationNodeID) {
		if edge.Kind == graph.EdgeKindBasedOn && edge.Target == "observation:"+auditObservation.ID {
			basedOnCount++
		}
	}
	if basedOnCount != 1 {
		t.Fatalf("kubernetes audit based_on edge count = %d, want 1", basedOnCount)
	}
}

func TestMaterializeObservationsIntoGraphDoesNotLinkNormalizedAuditObservationBackToAudit(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "deployment:prod/api",
		Kind: graph.NodeKindDeployment,
		Name: "api",
	})

	priorAuditObservation := &runtime.RuntimeObservation{
		ID:          "runtime:k8s_audit:prior-patch",
		Source:      "k8s_audit",
		Kind:        runtime.ObservationKindKubernetesAudit,
		ObservedAt:  time.Date(2026, 3, 16, 21, 30, 0, 0, time.UTC),
		RecordedAt:  time.Date(2026, 3, 16, 21, 30, 1, 0, time.UTC),
		WorkloadRef: "deployment:prod/api",
		Namespace:   "prod",
		ControlPlane: &runtime.ControlPlaneContext{
			Verb:      "patch",
			Resource:  "deployments",
			Namespace: "prod",
			Name:      "api",
			User:      "deployer",
		},
	}
	MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{priorAuditObservation}, time.Date(2026, 3, 16, 21, 31, 0, 0, time.UTC))

	inferredAuditObservation := &runtime.RuntimeObservation{
		ID:          "runtime:k8s_audit:inferred-delete",
		Source:      "k8s_audit",
		ObservedAt:  time.Date(2026, 3, 16, 21, 35, 0, 0, time.UTC),
		RecordedAt:  time.Date(2026, 3, 16, 21, 35, 1, 0, time.UTC),
		WorkloadRef: "deployment:prod/api",
		Namespace:   "prod",
		ControlPlane: &runtime.ControlPlaneContext{
			Verb:      "delete",
			Resource:  "pods",
			Namespace: "prod",
			Name:      "api-7f9d",
			User:      "deployer",
		},
	}

	result := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{inferredAuditObservation}, time.Date(2026, 3, 16, 21, 36, 0, 0, time.UTC))
	if result.ObservationsMaterialized != 1 {
		t.Fatalf("ObservationsMaterialized = %d, want 1", result.ObservationsMaterialized)
	}
	if result.KubernetesAuditBasedOnEdgesCreated != 0 {
		t.Fatalf("KubernetesAuditBasedOnEdgesCreated = %d, want 0", result.KubernetesAuditBasedOnEdgesCreated)
	}

	observationNodeID := "observation:" + inferredAuditObservation.ID
	for _, edge := range g.GetOutEdges(observationNodeID) {
		if edge.Kind == graph.EdgeKindBasedOn && edge.Target == "observation:"+priorAuditObservation.ID {
			t.Fatalf("unexpected kubernetes audit based_on edge = %+v", edge)
		}
	}

	node := mustNode(t, g, observationNodeID)
	if got := testNodeStringProperty(node, "observation_type"); got != string(runtime.ObservationKindKubernetesAudit) {
		t.Fatalf("observation_type = %q, want %q", got, runtime.ObservationKindKubernetesAudit)
	}
}

func TestMaterializeObservationsIntoGraphKeepsIncrementalIndexesCurrentUntilFinalize(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "deployment:prod/api",
		Kind: graph.NodeKindDeployment,
		Name: "api",
	})
	g.BuildIndex()
	if !g.IsIndexBuilt() {
		t.Fatal("expected initial graph index to be built")
	}

	now := time.Date(2026, 3, 16, 19, 40, 0, 0, time.UTC)
	observation := &runtime.RuntimeObservation{
		ID:          "runtime:process_exec:defer-index",
		Source:      "tetragon",
		Kind:        runtime.ObservationKindProcessExec,
		ObservedAt:  now.Add(-10 * time.Second),
		RecordedAt:  now.Add(-5 * time.Second),
		WorkloadRef: "deployment:prod/api",
		Process: &runtime.ProcessEvent{
			Name: "sh",
			Path: "/bin/sh",
		},
	}

	result := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, now)
	if result.ObservationsMaterialized != 1 {
		t.Fatalf("ObservationsMaterialized = %d, want 1", result.ObservationsMaterialized)
	}
	if !g.IsIndexBuilt() {
		t.Fatal("expected incremental indexes to remain current during materialization")
	}
	if got := len(g.GetNodesByKindIndexed(graph.NodeKindObservation)); got != 1 {
		t.Fatalf("len(GetNodesByKindIndexed(observation)) before finalize = %d, want 1", got)
	}
	if got := g.Metadata().BuiltAt; !got.Equal(now) {
		t.Fatalf("metadata.BuiltAt = %s, want %s", got, now)
	}

	FinalizeMaterializedGraph(g, now.Add(time.Minute))
	if !g.IsIndexBuilt() {
		t.Fatal("expected FinalizeMaterializedGraph to rebuild indexes")
	}
	if got := len(g.GetNodesByKindIndexed(graph.NodeKindObservation)); got != 1 {
		t.Fatalf("len(GetNodesByKindIndexed(observation)) = %d, want 1", got)
	}
	if got := g.Metadata().BuiltAt; !got.Equal(now.Add(time.Minute)) {
		t.Fatalf("metadata.BuiltAt after finalize = %s, want %s", got, now.Add(time.Minute))
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

func testFindEdgeInList(edges []*graph.Edge, kind graph.EdgeKind, target string) *graph.Edge {
	target = strings.TrimSpace(target)
	for _, edge := range edges {
		if edge == nil || edge.Kind != kind {
			continue
		}
		if strings.TrimSpace(edge.Target) == target {
			return edge
		}
	}
	return nil
}

func testStringSliceProperty(properties map[string]any, key string) []string {
	if len(properties) == 0 {
		return nil
	}
	switch typed := properties[key].(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			value, ok := item.(string)
			if !ok {
				continue
			}
			out = append(out, value)
		}
		return out
	default:
		return nil
	}
}

func testNodeProperty(node *graph.Node, key string) any {
	if node == nil {
		return nil
	}
	value, _ := node.PropertyValue(key)
	return value
}

func testNodeStringProperty(node *graph.Node, key string) string {
	value, _ := testNodeProperty(node, key).(string)
	return value
}

func testFindEdge(t *testing.T, g *graph.Graph, sourceID, targetID string, kind graph.EdgeKind) *graph.Edge {
	t.Helper()
	for _, edge := range g.GetOutEdges(sourceID) {
		if edge != nil && edge.Target == targetID && edge.Kind == kind {
			return edge
		}
	}
	t.Fatalf("edge %s -> %s (%s) not found", sourceID, targetID, kind)
	return nil
}
