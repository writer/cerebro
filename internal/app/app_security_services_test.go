package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/health"
)

func TestEvaluateGraphOntologySLOStatus(t *testing.T) {
	thresholds := graphOntologySLOThresholds{
		FallbackWarn:        12,
		FallbackCritical:    25,
		SchemaValidWarn:     98,
		SchemaValidCritical: 92,
	}

	healthyStatus, _ := evaluateGraphOntologySLOStatus(graph.GraphOntologySLO{
		FallbackActivityPercent: 4,
		SchemaValidWritePercent: 99.5,
	}, thresholds)
	if healthyStatus != health.StatusHealthy {
		t.Fatalf("expected healthy status, got %s", healthyStatus)
	}

	degradedStatus, degradedMsg := evaluateGraphOntologySLOStatus(graph.GraphOntologySLO{
		FallbackActivityPercent: 15,
		SchemaValidWritePercent: 99.5,
	}, thresholds)
	if degradedStatus != health.StatusDegraded {
		t.Fatalf("expected degraded status, got %s", degradedStatus)
	}
	if !strings.Contains(degradedMsg, "fallback_activity_percent") {
		t.Fatalf("expected fallback degradation message, got %q", degradedMsg)
	}

	unhealthyStatus, unhealthyMsg := evaluateGraphOntologySLOStatus(graph.GraphOntologySLO{
		FallbackActivityPercent: 10,
		SchemaValidWritePercent: 90,
	}, thresholds)
	if unhealthyStatus != health.StatusUnhealthy {
		t.Fatalf("expected unhealthy status, got %s", unhealthyStatus)
	}
	if !strings.Contains(unhealthyMsg, "schema_valid_write_percent") {
		t.Fatalf("expected schema validity unhealthy message, got %q", unhealthyMsg)
	}
}

func TestEvaluateGraphOntologySLOStatus_BurnRateDegraded(t *testing.T) {
	thresholds := graphOntologySLOThresholds{
		FallbackWarn:        12,
		FallbackCritical:    25,
		SchemaValidWarn:     98,
		SchemaValidCritical: 92,
	}
	status, msg := evaluateGraphOntologySLOStatus(graph.GraphOntologySLO{
		FallbackActivityPercent: 10,
		SchemaValidWritePercent: 99,
		Trend: []graph.GraphOntologySLOPoint{
			{Date: "2026-03-07", FallbackActivityPercent: 24, SchemaValidWritePercent: 99, Samples: 20},
			{Date: "2026-03-08", FallbackActivityPercent: 24, SchemaValidWritePercent: 99, Samples: 20},
			{Date: "2026-03-09", FallbackActivityPercent: 24, SchemaValidWritePercent: 99, Samples: 20},
		},
	}, thresholds)
	if status != health.StatusDegraded {
		t.Fatalf("expected degraded due to burn rate, got %s (%s)", status, msg)
	}
	if !strings.Contains(msg, "burn_rate") {
		t.Fatalf("expected burn-rate message, got %q", msg)
	}
}

func TestGraphOntologySLOHealthCheck(t *testing.T) {
	g := graph.New()
	now := time.Date(2026, 3, 9, 10, 0, 0, 0, time.UTC)
	g.AddNode(&graph.Node{
		ID:   "activity:test",
		Kind: graph.NodeKindActivity,
		Name: "Legacy Activity",
		Properties: map[string]any{
			"source_system": "github",
			"observed_at":   now.Format(time.RFC3339),
			"valid_from":    now.Format(time.RFC3339),
		},
	})

	application := &App{
		Config: &Config{
			GraphOntologyFallbackWarnPct:        10,
			GraphOntologyFallbackCriticalPct:    50,
			GraphOntologySchemaValidWarnPct:     98,
			GraphOntologySchemaValidCriticalPct: 92,
		},
		SecurityGraph: g,
	}

	result := application.graphOntologySLOHealthCheck()(context.Background())
	if result.Status != health.StatusUnhealthy {
		t.Fatalf("expected unhealthy status from high fallback activity, got %s (%s)", result.Status, result.Message)
	}
	if !strings.Contains(result.Message, "fallback_activity_percent") {
		t.Fatalf("expected fallback issue in message, got %q", result.Message)
	}
}

func TestGraphOntologySLOHealthCheckWithoutGraph(t *testing.T) {
	application := &App{}
	result := application.graphOntologySLOHealthCheck()(context.Background())
	if result.Status != health.StatusUnknown {
		t.Fatalf("expected unknown when graph is missing, got %s", result.Status)
	}
}

func TestBurnRatesFastWindowUsesCurrentSnapshot(t *testing.T) {
	trend := []graph.GraphOntologySLOPoint{
		{Date: "2026-03-08", FallbackActivityPercent: 12, SchemaValidWritePercent: 97, Samples: 20},
		{Date: "2026-03-09", FallbackActivityPercent: 12, SchemaValidWritePercent: 97, Samples: 20},
	}

	fastHigher, _ := burnRatesForHigherIsWorse(20, 10, 30, trend)
	if fastHigher != 0.5 {
		t.Fatalf("expected higher-is-worse fast burn from current snapshot, got %.4f", fastHigher)
	}

	fastLower, _ := burnRatesForLowerIsWorse(90, 98, 92, trend)
	if fastLower != (8.0 / 6.0) {
		t.Fatalf("expected lower-is-worse fast burn from current snapshot, got %.4f", fastLower)
	}
}
