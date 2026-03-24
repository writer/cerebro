package policy

import (
	"context"
	"slices"
	"sort"
	"strings"
	"testing"
)

func TestListQueryPolicies_Sorted(t *testing.T) {
	engine := NewEngine()
	engine.AddPolicy(&Policy{ID: "z-policy", Name: "Z", Description: "desc", Severity: "high", Query: "SELECT id FROM assets"})
	engine.AddPolicy(&Policy{ID: "a-policy", Name: "A", Description: "desc", Severity: "high", Query: "SELECT id FROM assets"})
	engine.AddPolicy(&Policy{ID: "condition-policy", Name: "C", Description: "desc", Severity: "high", Resource: "aws::s3::bucket", Conditions: []string{"resource.public == true"}})

	policies := engine.ListQueryPolicies()
	if len(policies) != 2 {
		t.Fatalf("expected 2 query policies, got %d", len(policies))
	}
	if policies[0].ID != "a-policy" || policies[1].ID != "z-policy" {
		t.Fatalf("expected sorted query policy IDs [a-policy z-policy], got [%s %s]", policies[0].ID, policies[1].ID)
	}
}

func TestEvaluateQueryPolicies_DeterministicFindingIDs(t *testing.T) {
	engine := NewEngine()
	engine.AddPolicy(&Policy{ID: "query-policy", Name: "Query Policy", Description: "query finding", Severity: "high", Query: "SELECT id FROM assets"})

	executor := func(context.Context, *Policy) ([]map[string]interface{}, error) {
		return []map[string]interface{}{
			{"id": "res-1", "name": "asset-a"},
			{"ID": "res-1", "name": "asset-a-duplicate"},
			{"value": 1, "count": 2},
			{"count": 2, "value": 1},
		}, nil
	}

	findings, errs := engine.EvaluateQueryPolicies(context.Background(), executor)
	if len(errs) != 0 {
		t.Fatalf("expected no query execution errors, got %v", errs)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 deduplicated findings, got %d", len(findings))
	}

	ids := []string{findings[0].ID, findings[1].ID}
	if !slices.Contains(ids, "query-policy:res-1") {
		t.Fatalf("expected deterministic resource ID finding, got %v", ids)
	}

	hashed := ""
	for _, id := range ids {
		if strings.HasPrefix(id, "query-policy:row:") {
			hashed = id
			break
		}
	}
	if hashed == "" {
		t.Fatalf("expected hashed fallback finding ID, got %v", ids)
	}

	findingsSecondRun, errsSecondRun := engine.EvaluateQueryPolicies(context.Background(), executor)
	if len(errsSecondRun) != 0 {
		t.Fatalf("expected no query execution errors on second run, got %v", errsSecondRun)
	}
	idsSecondRun := []string{findingsSecondRun[0].ID, findingsSecondRun[1].ID}
	idCopy := slices.Clone(ids)
	idSecondCopy := slices.Clone(idsSecondRun)
	sort.Strings(idCopy)
	sort.Strings(idSecondCopy)
	if !slices.Equal(idCopy, idSecondCopy) {
		t.Fatalf("expected stable finding IDs across runs, got %v then %v", ids, idsSecondRun)
	}
}

func TestExtractQueryTableReferences(t *testing.T) {
	query := `SELECT a.id
FROM "RAW"."ASSETS" a
JOIN employees e ON a.owner = e.work_email
JOIN prod.security."VULNERABILITIES" v ON v.asset_id = a.id
JOIN employees e2 ON e2.work_email = a.owner`

	tables := ExtractQueryTableReferences(query)
	want := []string{"assets", "employees", "vulnerabilities"}
	if !slices.Equal(tables, want) {
		t.Fatalf("expected table references %v, got %v", want, tables)
	}
}
