package builders

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestBuilderBuild_AddsPersonInteractionEdges(t *testing.T) {
	t.Parallel()

	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT id, login, email, status, last_login, mfa_enrolled, is_admin FROM okta_users`, &DataQueryResult{
		Rows: []map[string]any{
			{"id": "okta-a", "login": "alice", "email": "alice@example.com"},
			{"id": "okta-b", "login": "bob", "email": "bob@example.com"},
		},
	})

	source.setResult(`SELECT id, email FROM gong_users`, &DataQueryResult{
		Rows: []map[string]any{
			{"id": "gong-a", "email": "alice@example.com"},
			{"id": "gong-b", "email": "bob@example.com"},
		},
	})

	source.setResult(`
		SELECT a.user_id AS person_a, b.user_id AS person_b,
		       COUNT(*) AS interaction_count,
		       MAX(c.start_time) AS last_interaction,
		       SUM(c.duration_seconds) AS total_duration_seconds
		FROM gong_call_participants a
		JOIN gong_call_participants b ON a.call_id = b.call_id AND a.user_id < b.user_id
		JOIN gong_calls c ON a.call_id = c.id
		WHERE a.user_id IS NOT NULL AND b.user_id IS NOT NULL
		GROUP BY a.user_id, b.user_id
	`, &DataQueryResult{
		Rows: []map[string]any{
			{
				"person_a":               "gong-a",
				"person_b":               "gong-b",
				"interaction_count":      int64(2),
				"last_interaction":       "2026-03-01T12:00:00Z",
				"total_duration_seconds": 1800.0,
			},
		},
	})

	source.setResult(`
		SELECT a.actor_id AS person_a, b.actor_id AS person_b,
		       COUNT(*) AS co_actions,
		       MAX(GREATEST(a.published, b.published)) AS last_interaction
		FROM okta_system_logs a
		JOIN okta_system_logs b ON a.target_id = b.target_id AND a.actor_id < b.actor_id
		WHERE a.actor_id IS NOT NULL AND b.actor_id IS NOT NULL
		  AND a.target_id IS NOT NULL
		  AND a.published BETWEEN b.published - INTERVAL '24 hours' AND b.published + INTERVAL '24 hours'
		GROUP BY a.actor_id, b.actor_id
	`, &DataQueryResult{
		Rows: []map[string]any{
			{
				"person_a":         "okta-a",
				"person_b":         "okta-b",
				"co_actions":       int64(3),
				"last_interaction": time.Date(2026, time.March, 2, 15, 0, 0, 0, time.UTC),
			},
		},
	})

	source.setResult(`
		SELECT a.user_id AS person_a, b.user_id AS person_b,
		       COUNT(DISTINCT a.group_id) AS shared_groups
		FROM okta_group_memberships a
		JOIN okta_group_memberships b ON a.group_id = b.group_id AND a.user_id < b.user_id
		GROUP BY a.user_id, b.user_id
	`, &DataQueryResult{
		Rows: []map[string]any{{"person_a": "okta-a", "person_b": "okta-b", "shared_groups": int64(1)}},
	})

	source.setResult(`
		SELECT a.assignee_id AS person_a, b.assignee_id AS person_b,
		       COUNT(DISTINCT a.app_id) AS shared_apps
		FROM okta_app_assignments a
		JOIN okta_app_assignments b ON a.app_id = b.app_id AND a.assignee_id < b.assignee_id
		WHERE a.assignee_type = 'USER' AND b.assignee_type = 'USER'
		GROUP BY a.assignee_id, b.assignee_id
	`, &DataQueryResult{
		Rows: []map[string]any{{"person_a": "okta-a", "person_b": "okta-b", "shared_apps": int64(2)}},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	g := builder.Graph()
	personA := "person:alice@example.com"
	personB := "person:bob@example.com"
	edge := findEdge(g, personA, personB, EdgeKindInteractedWith)
	if edge == nil {
		t.Fatalf("expected interaction edge between %s and %s", personA, personB)
	}

	if got := int64FromValue(edge.Properties["call_count"]); got != 2 {
		t.Fatalf("expected call_count=2, got %d", got)
	}
	if got := int64FromValue(edge.Properties["co_actions"]); got != 3 {
		t.Fatalf("expected co_actions=3, got %d", got)
	}
	if got := int64FromValue(edge.Properties["shared_groups"]); got != 1 {
		t.Fatalf("expected shared_groups=1, got %d", got)
	}
	if got := int64FromValue(edge.Properties["shared_apps"]); got != 2 {
		t.Fatalf("expected shared_apps=2, got %d", got)
	}
	if got := int64FromValue(edge.Properties["frequency"]); got != 8 {
		t.Fatalf("expected frequency=8, got %d", got)
	}
	if got := float64FromValue(edge.Properties["total_duration_seconds"]); got != 1800 {
		t.Fatalf("expected total_duration_seconds=1800, got %.2f", got)
	}
	if got := float64FromValue(edge.Properties["strength"]); got <= 0 {
		t.Fatalf("expected positive strength, got %.4f", got)
	}

	sources, ok := edge.Properties["interaction_source_types"].([]string)
	if !ok {
		t.Fatalf("expected interaction_source_types []string, got %T", edge.Properties["interaction_source_types"])
	}
	if len(sources) != 4 {
		t.Fatalf("expected 4 interaction source types, got %d (%v)", len(sources), sources)
	}
}

func findEdge(g *Graph, source string, target string, kind EdgeKind) *Edge {
	for _, edge := range g.GetOutEdges(source) {
		if edge.Target == target && edge.Kind == kind {
			return edge
		}
	}
	return nil
}
