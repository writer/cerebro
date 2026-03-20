package builders

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestBuilderBuild_ProjectsCloudRunAPIEndpoints(t *testing.T) {
	ctx := context.Background()
	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT name, project_id, location, ingress, uri FROM gcp_cloudrun_services`, &DataQueryResult{
		Rows: []map[string]any{
			{
				"name":       "projects/proj-1/locations/us-central1/services/payments-api",
				"project_id": "proj-1",
				"location":   "us-central1",
				"ingress":    "INGRESS_TRAFFIC_ALL",
				"uri":        "https://payments-api-uc.a.run.app/",
			},
			{
				"name":       "projects/proj-1/locations/us-central1/services/internal-api",
				"project_id": "proj-1",
				"location":   "us-central1",
				"ingress":    "INGRESS_TRAFFIC_INTERNAL_ONLY",
				"uri":        "https://internal-api-uc.a.run.app",
			},
		},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(ctx); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	g := builder.Graph()

	publicEndpointID := apiEndpointNodeID("https://payments-api-uc.a.run.app")
	publicEndpoint, ok := g.GetNode(publicEndpointID)
	if !ok {
		t.Fatalf("expected public API endpoint node %q", publicEndpointID)
	}
	if publicEndpoint.Kind != NodeKindAPIEndpoint {
		t.Fatalf("endpoint kind = %s, want %s", publicEndpoint.Kind, NodeKindAPIEndpoint)
	}
	if got := toString(publicEndpoint.Properties["host"]); got != "payments-api-uc.a.run.app" {
		t.Fatalf("endpoint host = %q, want %q", got, "payments-api-uc.a.run.app")
	}
	if got, _ := publicEndpoint.Properties["public"].(bool); !got {
		t.Fatalf("expected public endpoint node, got %#v", publicEndpoint.Properties["public"])
	}

	assertEdgeExists(t, g, "projects/proj-1/locations/us-central1/services/payments-api", publicEndpointID, EdgeKindServes)
	assertEdgeExists(t, g, "internet", publicEndpointID, EdgeKindExposedTo)

	internalEndpointID := apiEndpointNodeID("https://internal-api-uc.a.run.app")
	internalEndpoint, ok := g.GetNode(internalEndpointID)
	if !ok {
		t.Fatalf("expected internal API endpoint node %q", internalEndpointID)
	}
	if got, _ := internalEndpoint.Properties["public"].(bool); got {
		t.Fatalf("expected internal endpoint node, got public=%#v", internalEndpoint.Properties["public"])
	}
	assertEdgeExists(t, g, "projects/proj-1/locations/us-central1/services/internal-api", internalEndpointID, EdgeKindServes)
	if edge := findEdge(g, "internet", internalEndpointID, EdgeKindExposedTo); edge != nil {
		t.Fatalf("did not expect internet exposure edge for internal endpoint: %#v", edge)
	}
}

func TestBuilderApplyChanges_ProjectsCloudRunAPIEndpoints(t *testing.T) {
	source := newCDCRoutingSource()
	builder := NewBuilder(source, nil)

	builder.Graph().AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Provider: "external", Name: "Internet", Risk: RiskCritical})

	base := time.Now().UTC().Add(-1 * time.Minute)
	source.events = []map[string]any{
		{
			"event_id":    "evt-cloudrun",
			"table_name":  "gcp_cloudrun_services",
			"resource_id": "projects/proj-1/locations/us-central1/services/payments-api",
			"change_type": "added",
			"provider":    "gcp",
			"region":      "us-central1",
			"account_id":  "proj-1",
			"payload": map[string]any{
				"name":       "projects/proj-1/locations/us-central1/services/payments-api",
				"project_id": "proj-1",
				"location":   "us-central1",
				"ingress":    "INGRESS_TRAFFIC_ALL",
				"uri":        "https://payments-api-uc.a.run.app",
			},
			"event_time": base.Add(5 * time.Second),
		},
	}

	if _, err := builder.ApplyChanges(context.Background(), base); err != nil {
		t.Fatalf("ApplyChanges failed: %v", err)
	}

	endpointID := apiEndpointNodeID("https://payments-api-uc.a.run.app")
	if _, ok := builder.Graph().GetNode(endpointID); !ok {
		t.Fatalf("expected projected API endpoint node %q after CDC apply", endpointID)
	}
	assertEdgeExists(t, builder.Graph(), "projects/proj-1/locations/us-central1/services/payments-api", endpointID, EdgeKindServes)
	assertEdgeExists(t, builder.Graph(), "internet", endpointID, EdgeKindExposedTo)
}

func TestBuilderApplyChanges_RemovesOrphanedAPIEndpointsAfterDelete(t *testing.T) {
	source := newCDCRoutingSource()
	builder := NewBuilder(source, nil)

	builder.Graph().AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Provider: "external", Name: "Internet", Risk: RiskCritical})

	base := time.Now().UTC().Add(-2 * time.Minute)
	workloadID := "projects/proj-1/locations/us-central1/services/payments-api"
	endpointID := apiEndpointNodeID("https://payments-api-uc.a.run.app")

	source.events = []map[string]any{
		{
			"event_id":    "evt-cloudrun-added",
			"table_name":  "gcp_cloudrun_services",
			"resource_id": workloadID,
			"change_type": "added",
			"provider":    "gcp",
			"region":      "us-central1",
			"account_id":  "proj-1",
			"payload": map[string]any{
				"name":       workloadID,
				"project_id": "proj-1",
				"location":   "us-central1",
				"ingress":    "INGRESS_TRAFFIC_ALL",
				"uri":        "https://payments-api-uc.a.run.app",
			},
			"event_time": base.Add(5 * time.Second),
		},
	}

	if _, err := builder.ApplyChanges(context.Background(), base); err != nil {
		t.Fatalf("ApplyChanges add failed: %v", err)
	}

	if _, ok := builder.Graph().GetNode(endpointID); !ok {
		t.Fatalf("expected projected API endpoint node %q after add", endpointID)
	}

	source.events = []map[string]any{
		{
			"event_id":    "evt-cloudrun-removed",
			"table_name":  "gcp_cloudrun_services",
			"resource_id": workloadID,
			"change_type": "removed",
			"provider":    "gcp",
			"region":      "us-central1",
			"account_id":  "proj-1",
			"payload": map[string]any{
				"name":       workloadID,
				"project_id": "proj-1",
				"location":   "us-central1",
				"ingress":    "INGRESS_TRAFFIC_ALL",
				"uri":        "https://payments-api-uc.a.run.app",
			},
			"event_time": base.Add(20 * time.Second),
		},
	}

	if _, err := builder.ApplyChanges(context.Background(), base.Add(10*time.Second)); err != nil {
		t.Fatalf("ApplyChanges remove failed: %v", err)
	}

	if _, ok := builder.Graph().GetNode(endpointID); ok {
		t.Fatalf("expected orphaned API endpoint node %q to be removed after workload delete", endpointID)
	}
	if edge := findEdge(builder.Graph(), "internet", endpointID, EdgeKindExposedTo); edge != nil {
		t.Fatalf("expected no internet exposure edge after workload delete, got %#v", edge)
	}
	if deleted, ok := builder.Graph().GetNodeIncludingDeleted(endpointID); !ok || deleted.DeletedAt == nil {
		t.Fatalf("expected endpoint node tombstone after workload delete, got %#v ok=%v", deleted, ok)
	}
}
