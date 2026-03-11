package agentsdk

import (
	"testing"
	"time"

	"github.com/writer/cerebro/internal/agents"
)

func TestBuildToolCatalogUsesReportRuntimeOverride(t *testing.T) {
	catalog := BuildToolCatalog([]agents.Tool{{
		Name:        "cerebro.intelligence_report",
		Description: "report",
		Parameters:  map[string]any{"type": "object"},
	}})
	if len(catalog) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(catalog))
	}
	tool := catalog[0]
	if tool.ID != "cerebro_report" {
		t.Fatalf("expected cerebro_report id, got %q", tool.ID)
	}
	if tool.ExecutionKind != ExecutionKindReportRun {
		t.Fatalf("expected report execution kind, got %q", tool.ExecutionKind)
	}
	if !tool.SupportsAsync || !tool.SupportsProgress {
		t.Fatalf("expected async/progress support, got async=%t progress=%t", tool.SupportsAsync, tool.SupportsProgress)
	}
	if tool.HTTPPath != "/api/v1/agent-sdk/report" {
		t.Fatalf("expected report path, got %q", tool.HTTPPath)
	}
}

func TestCompareCatalogsRequiresVersionBumpOnContractChange(t *testing.T) {
	baseline := Catalog{
		Tools: []ToolDefinition{{
			ID:                 "cerebro_context",
			Version:            "1.0.0",
			ToolName:           "insight_card",
			RequiredPermission: "sdk.context.read",
		}},
	}
	current := Catalog{
		Tools: []ToolDefinition{{
			ID:                 "cerebro_context",
			Version:            "1.0.0",
			ToolName:           "insight_card",
			RequiredPermission: "sdk.schema.read",
		}},
	}
	report := CompareCatalogs(baseline, current, time.Now().UTC())
	if len(report.VersioningViolations) != 1 {
		t.Fatalf("expected 1 versioning violation, got %#v", report.VersioningViolations)
	}
}

func TestBuildCatalogOmitsGeneratedAtWhenZero(t *testing.T) {
	catalog := BuildCatalog(nil, ZeroGeneratedAt())
	if !catalog.GeneratedAt.IsZero() {
		t.Fatalf("expected zero generated_at when zero time is provided, got %v", catalog.GeneratedAt)
	}
}

func TestBuildToolCatalogAssignsDistinctContractIDsForSimulationTools(t *testing.T) {
	catalog := BuildToolCatalog([]agents.Tool{
		{Name: "simulate", Description: "scenario simulate"},
		{Name: "cerebro.simulate", Description: "graph simulate"},
	})
	if len(catalog) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(catalog))
	}
	if catalog[0].ID == catalog[1].ID {
		t.Fatalf("expected distinct tool ids, got duplicate %q", catalog[0].ID)
	}
	if catalog[0].SDKMethod == catalog[1].SDKMethod {
		t.Fatalf("expected distinct sdk methods, got duplicate %q", catalog[0].SDKMethod)
	}
}
