package graph

import (
	"context"
	"log/slog"
	"os"
	"testing"
)

func TestBuilderBuild_UnifiesPersonNodesAndProjectsEdges(t *testing.T) {
	t.Parallel()

	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT id, user_principal_name, display_name, mail FROM azure_ad_users`, &QueryResult{
		Rows: []map[string]any{
			{"id": "azure-1", "user_principal_name": "alice@example.com", "display_name": "Alice Azure", "mail": "alice@example.com"},
		},
	})

	source.setResult(`SELECT id, login, email, status, last_login, mfa_enrolled, is_admin FROM okta_users`, &QueryResult{
		Rows: []map[string]any{
			{"id": "okta-1", "login": "alice", "email": "ALICE@example.com", "status": "ACTIVE"},
			{"id": "okta-personal", "login": "alice.personal", "email": "alice.personal@gmail.com", "status": "ACTIVE"},
		},
	})

	source.setResult(`SELECT id, label, name, status, sign_on_mode FROM okta_applications`, &QueryResult{
		Rows: []map[string]any{
			{"id": "app-1", "label": "Payroll", "status": "ACTIVE", "sign_on_mode": "SAML_2_0"},
		},
	})

	source.setResult(`
		SELECT source_id, source_type, target_id, target_type, rel_type, properties
		FROM resource_relationships
	`, &QueryResult{
		Rows: []map[string]any{
			{
				"source_id":   "okta-1",
				"source_type": "okta:user",
				"target_id":   "app-1",
				"target_type": "okta:application",
				"rel_type":    "HAS_PERMISSION",
			},
		},
	})

	source.setResult(`
		SELECT id, work_email, personal_email, display_name, first_name, last_name, employment_status,
		       department, title, manager_id, location, start_date
		FROM rippling_employees
	`, &QueryResult{
		Rows: []map[string]any{
			{
				"id":                "emp-1",
				"work_email":        "alice@example.com",
				"personal_email":    "alice.personal@gmail.com",
				"display_name":      "Alice HR",
				"employment_status": "ACTIVE",
				"department":        "Engineering",
				"title":             "Staff Engineer",
				"manager_id":        "emp-2",
				"location":          "San Francisco",
				"start_date":        "2024-01-01",
			},
			{
				"id":                "emp-2",
				"work_email":        "manager@example.com",
				"display_name":      "Manager HR",
				"employment_status": "ACTIVE",
				"department":        "Engineering",
				"location":          "San Francisco",
			},
		},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	g := builder.Graph()
	personID := "person:alice@example.com"
	person, ok := g.GetNode(personID)
	if !ok {
		t.Fatalf("expected unified person node %q", personID)
	}
	if person.Kind != NodeKindPerson {
		t.Fatalf("expected person node kind, got %s", person.Kind)
	}
	if person.Name != "Alice HR" {
		t.Fatalf("expected HR name to win, got %q", person.Name)
	}
	if external, ok := person.Properties["external"].(bool); !ok || external {
		t.Fatalf("expected person external=false, got %v (ok=%v)", person.Properties["external"], ok)
	}
	if got := queryRowString(person.Properties, "azure_ad_id"); got != "azure-1" {
		t.Fatalf("expected azure_ad_id=azure-1, got %q", got)
	}

	if _, ok := g.GetNode("person:alice.personal@gmail.com"); ok {
		t.Fatal("expected personal email alias to merge into work-email person id")
	}
	if _, ok := g.GetNode("person:manager@example.com"); !ok {
		t.Fatal("expected manager person node from HR enrichment")
	}
	if _, ok := g.GetNode("department:engineering"); !ok {
		t.Fatal("expected department node")
	}
	if _, ok := g.GetNode("location:san-francisco"); !ok {
		t.Fatal("expected location node")
	}

	assertEdgeExists(t, g, "okta-1", personID, EdgeKindResolvesTo)
	assertEdgeExists(t, g, "okta-personal", personID, EdgeKindResolvesTo)
	assertEdgeExists(t, g, "azure-1", personID, EdgeKindResolvesTo)
	assertEdgeExists(t, g, personID, "app-1", EdgeKindCanAdmin)
	assertEdgeExists(t, g, personID, "department:engineering", EdgeKindMemberOf)
	assertEdgeExists(t, g, personID, "location:san-francisco", EdgeKindLocatedIn)
	assertEdgeExists(t, g, personID, "person:manager@example.com", EdgeKindReportsTo)
}

func TestBuilderBuild_PersonResolutionSkipsServiceAccountsAndMarksExternal(t *testing.T) {
	t.Parallel()

	source := newMockDataSource()
	builder := NewBuilder(source, slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})))

	source.setResult(`SELECT id, login, email, status, last_login, mfa_enrolled, is_admin FROM okta_users`, &QueryResult{
		Rows: []map[string]any{
			{"id": "svc-1", "login": "svc-build", "email": "svc-build@example.com"},
			{"id": "contractor-1", "login": "contractor", "email": "contractor@vendor.com"},
		},
	})

	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	g := builder.Graph()
	if _, ok := g.GetNode("person:svc-build@example.com"); ok {
		t.Fatal("expected service-account-like email to be excluded from person resolution")
	}

	contractor, ok := g.GetNode("person:contractor@vendor.com")
	if !ok {
		t.Fatal("expected external contractor person node")
	}
	if external, ok := contractor.Properties["external"].(bool); !ok || !external {
		t.Fatalf("expected contractor external=true, got %v (ok=%v)", contractor.Properties["external"], ok)
	}
}

func assertEdgeExists(t *testing.T, g *Graph, source string, target string, kind EdgeKind) {
	t.Helper()
	for _, edge := range g.GetOutEdges(source) {
		if edge.Target == target && edge.Kind == kind {
			return
		}
	}
	t.Fatalf("expected edge %s --%s--> %s", source, kind, target)
}
