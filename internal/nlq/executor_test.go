package nlq

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/policy"
)

func TestExecutorEntityFindingsQuery(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:       "instance:web-1",
		Kind:     graph.NodeKindInstance,
		Name:     "web-1",
		Provider: "aws",
		Properties: map[string]any{
			"internet_exposed": true,
		},
	})
	g.AddNode(&graph.Node{
		ID:       "instance:internal-1",
		Kind:     graph.NodeKindInstance,
		Name:     "internal-1",
		Provider: "aws",
	})

	store := findings.NewStore()
	store.Upsert(context.Background(), policy.Finding{
		ID:           "finding:web-1:cve",
		PolicyID:     "vuln-critical",
		PolicyName:   "Critical Vulnerability",
		Severity:     "critical",
		Description:  "Critical unpatched CVE",
		ResourceID:   "instance:web-1",
		ResourceName: "web-1",
		ResourceType: "instance",
		Resource:     map[string]any{"id": "instance:web-1"},
	})
	store.Upsert(context.Background(), policy.Finding{
		ID:           "finding:internal-1:high",
		PolicyID:     "vuln-high",
		PolicyName:   "High Vulnerability",
		Severity:     "high",
		Description:  "High vulnerability",
		ResourceID:   "instance:internal-1",
		ResourceName: "internal-1",
		ResourceType: "instance",
		Resource:     map[string]any{"id": "instance:internal-1"},
	})
	store.Upsert(context.Background(), policy.Finding{
		ID:           "finding:internal-1:cve",
		PolicyID:     "vuln-critical",
		PolicyName:   "Critical Vulnerability",
		Severity:     "critical",
		Description:  "Critical unpatched CVE",
		ResourceID:   "instance:internal-1",
		ResourceName: "internal-1",
		ResourceType: "instance",
		Resource:     map[string]any{"id": "instance:internal-1"},
	})

	executor := &Executor{Graph: g, Findings: store}
	result, err := executor.Execute(context.Background(), &Plan{
		Question: "Which internet-facing instances have critical unpatched CVEs?",
		Kind:     PlanKindEntityFindingsQuery,
		CompositeQuery: &EntityFindingsQuery{
			Entities: EntityQuery{
				Kinds:        []graph.NodeKind{graph.NodeKindInstance},
				Capabilities: []graph.NodeKindCapability{graph.NodeCapabilityInternetExposable},
				Search:       "web-1",
				Limit:        25,
			},
			Findings: FindingsQuery{
				Severity: "critical",
				Query:    "cve",
				Limit:    50,
			},
			JoinOn: "entity_or_resource_id",
		},
		ReadOnly: true,
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	payload, ok := result.Result.(EntityFindingsResult)
	if !ok {
		t.Fatalf("result type = %T, want EntityFindingsResult", result.Result)
	}
	if payload.MatchingEntities != 1 {
		t.Fatalf("MatchingEntities = %d, want 1", payload.MatchingEntities)
	}
	if payload.MatchingFindings != 1 {
		t.Fatalf("MatchingFindings = %d, want 1", payload.MatchingFindings)
	}
	if len(payload.Matches) != 1 || payload.Matches[0].Entity.ID != "instance:web-1" {
		t.Fatalf("matches = %#v, want instance:web-1 only", payload.Matches)
	}
	if result.Summary != "Matched 1 entities with 1 findings." {
		t.Fatalf("Summary = %q, want matched findings count", result.Summary)
	}
}

func TestExecutorReverseAccessAdminOnly(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "user:alice", Kind: graph.NodeKindUser, Name: "Alice"})
	g.AddNode(&graph.Node{ID: "role:db-admin", Kind: graph.NodeKindRole, Name: "DB Admin", Properties: map[string]any{"role": "admin"}})
	g.AddNode(&graph.Node{ID: "role:readonly", Kind: graph.NodeKindRole, Name: "Read Only"})
	g.AddNode(&graph.Node{ID: "database:prod", Kind: graph.NodeKindDatabase, Name: "prod-payments"})
	g.AddEdge(&graph.Edge{ID: "alice-admin", Source: "user:alice", Target: "role:db-admin", Kind: graph.EdgeKindCanAssume, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "admin-db", Source: "role:db-admin", Target: "database:prod", Kind: graph.EdgeKindCanAdmin, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "readonly-db", Source: "role:readonly", Target: "database:prod", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})

	executor := &Executor{Graph: g}
	result, err := executor.Execute(context.Background(), &Plan{
		Question: "Show me all admin access paths to production databases",
		Kind:     PlanKindReverseAccessQuery,
		ReverseAccess: &ReverseAccessQuery{
			Targets: EntityQuery{
				Kinds:  []graph.NodeKind{graph.NodeKindDatabase},
				Search: "prod",
				Limit:  10,
			},
			MaxDepth:  6,
			AdminOnly: true,
		},
		ReadOnly: true,
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	payload, ok := result.Result.(ReverseAccessCollection)
	if !ok {
		t.Fatalf("result type = %T, want ReverseAccessCollection", result.Result)
	}
	if payload.Count != 1 {
		t.Fatalf("Count = %d, want 1", payload.Count)
	}
	if payload.Results[0].TotalCount != 2 {
		t.Fatalf("TotalCount = %d, want 2", payload.Results[0].TotalCount)
	}
	for _, accessor := range payload.Results[0].AccessibleBy {
		if accessor.Node.ID == "role:readonly" {
			t.Fatalf("did not expect readonly accessor in admin-only results: %#v", payload.Results[0].AccessibleBy)
		}
	}
}

func TestExecutorGraphChangeDiff(t *testing.T) {
	diff := &graph.GraphDiff{
		NodesAdded:    []*graph.Node{{ID: "instance:web-1"}},
		NodesRemoved:  []*graph.Node{{ID: "instance:web-2"}},
		NodesModified: []graph.NodeChange{{NodeID: "database:prod"}},
		EdgesAdded:    []*graph.Edge{{ID: "edge:1"}},
		EdgesRemoved:  []*graph.Edge{{ID: "edge:2"}},
	}
	executor := &Executor{
		Graph: graph.New(),
		Diffs: staticDiffReader{diff: diff},
		Now: func() time.Time {
			return time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC)
		},
	}
	result, err := executor.Execute(context.Background(), &Plan{
		Question: "What changed this week?",
		Kind:     PlanKindGraphChangeDiff,
		ChangeQuery: &ChangeQuery{
			Since: time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC),
			Until: time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC),
		},
		ReadOnly: true,
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !stringsContains(result.Summary, "1 added nodes", "1 removed nodes", "1 modified nodes") {
		t.Fatalf("summary = %q, want diff counts", result.Summary)
	}
}

func TestExecutorRejectsMissingPayloads(t *testing.T) {
	executor := &Executor{Graph: graph.New()}
	testCases := []struct {
		name    string
		plan    *Plan
		wantErr string
	}{
		{
			name:    "entity query",
			plan:    &Plan{Kind: PlanKindEntityQuery, ReadOnly: true},
			wantErr: "entity_query plan missing entity_query payload",
		},
		{
			name:    "findings query",
			plan:    &Plan{Kind: PlanKindFindingsQuery, ReadOnly: true},
			wantErr: "findings_query plan missing findings_query payload",
		},
		{
			name:    "entity findings query",
			plan:    &Plan{Kind: PlanKindEntityFindingsQuery, ReadOnly: true},
			wantErr: "entity_findings_query plan missing composite_query payload",
		},
		{
			name:    "reverse access query",
			plan:    &Plan{Kind: PlanKindReverseAccessQuery, ReadOnly: true},
			wantErr: "reverse_access_query plan missing reverse_access payload",
		},
		{
			name:    "graph change diff query",
			plan:    &Plan{Kind: PlanKindGraphChangeDiff, ReadOnly: true},
			wantErr: "graph_change_diff_query plan missing change_query payload",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("Execute() panicked: %v", recovered)
				}
			}()

			_, err := executor.Execute(context.Background(), testCase.plan)
			if err == nil || err.Error() != testCase.wantErr {
				t.Fatalf("Execute() error = %v, want %q", err, testCase.wantErr)
			}
		})
	}
}

type staticDiffReader struct {
	diff *graph.GraphDiff
}

func (s staticDiffReader) DiffByTime(time.Time, time.Time) (*graph.GraphDiff, error) {
	return s.diff, nil
}

func stringsContains(value string, fragments ...string) bool {
	for _, fragment := range fragments {
		if !strings.Contains(value, fragment) {
			return false
		}
	}
	return true
}
