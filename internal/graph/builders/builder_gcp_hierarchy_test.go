package builders

import (
	"context"
	"log/slog"
	"os"
	"testing"
)

func TestBuilder_GCPHierarchyNodesAndEdges(t *testing.T) {
	ctx := context.Background()
	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT DISTINCT resource_name, organization_id, display_name, state, lineage_complete, lineage_error FROM gcp_resource_manager_organizations`, &DataQueryResult{
		Rows: []map[string]any{{
			"resource_name":    "organizations/789",
			"organization_id":  "789",
			"display_name":     "example.com",
			"state":            "ACTIVE",
			"lineage_complete": true,
			"lineage_error":    "",
		}},
	})
	source.setResult(`SELECT DISTINCT resource_name, folder_id, display_name, parent, state, organization_id, depth, lineage_complete, lineage_error FROM gcp_resource_manager_folders`, &DataQueryResult{
		Rows: []map[string]any{
			{
				"resource_name":    "folders/123",
				"folder_id":        "123",
				"display_name":     "Platform",
				"parent":           "organizations/789",
				"state":            "ACTIVE",
				"organization_id":  "789",
				"depth":            1,
				"lineage_complete": true,
				"lineage_error":    "",
			},
			{
				"resource_name":    "folders/456",
				"folder_id":        "456",
				"display_name":     "Engineering",
				"parent":           "folders/123",
				"state":            "ACTIVE",
				"organization_id":  "789",
				"depth":            2,
				"lineage_complete": true,
				"lineage_error":    "",
			},
		},
	})
	source.setResult(`SELECT resource_name, project_id, project_number, display_name, parent, state, labels, organization_id, folder_ids, lineage_complete, lineage_error FROM gcp_resource_manager_projects`, &DataQueryResult{
		Rows: []map[string]any{{
			"resource_name":    "projects/123456789",
			"project_id":       "proj-a",
			"project_number":   "123456789",
			"display_name":     "Project A",
			"parent":           "folders/456",
			"state":            "ACTIVE",
			"labels":           map[string]any{"env": "prod"},
			"organization_id":  "789",
			"folder_ids":       []any{"123", "456"},
			"lineage_complete": true,
			"lineage_error":    "",
		}},
	})
	source.setResult(`SELECT resource_name, parent FROM gcp_resource_manager_projects`, &DataQueryResult{
		Rows: []map[string]any{{
			"resource_name": "projects/123456789",
			"parent":        "folders/456",
		}},
	})
	source.setResult(`SELECT DISTINCT resource_name, parent FROM gcp_resource_manager_folders`, &DataQueryResult{
		Rows: []map[string]any{
			{"resource_name": "folders/123", "parent": "organizations/789"},
			{"resource_name": "folders/456", "parent": "folders/123"},
		},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(ctx); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	project, ok := builder.Graph().GetNode("projects/123456789")
	if !ok || project.Kind != NodeKindProject {
		t.Fatalf("expected project node, got %#v", project)
	}
	folder, ok := builder.Graph().GetNode("folders/456")
	if !ok || folder.Kind != NodeKindFolder {
		t.Fatalf("expected folder node, got %#v", folder)
	}
	org, ok := builder.Graph().GetNode("organizations/789")
	if !ok || org.Kind != NodeKindOrganization {
		t.Fatalf("expected organization node, got %#v", org)
	}

	if !hasEdge(builder.Graph().GetOutEdges("projects/123456789"), "folders/456", EdgeKindLocatedIn) {
		t.Fatal("expected project located_in folder edge")
	}
	if !hasEdge(builder.Graph().GetOutEdges("folders/456"), "folders/123", EdgeKindLocatedIn) {
		t.Fatal("expected child folder located_in parent folder edge")
	}
	if !hasEdge(builder.Graph().GetOutEdges("folders/123"), "organizations/789", EdgeKindLocatedIn) {
		t.Fatal("expected folder located_in organization edge")
	}
}

func TestBuilder_GCPInheritedHierarchyIAMPolicyEdges(t *testing.T) {
	ctx := context.Background()
	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT resource_name, project_id, project_number, display_name, parent, state, labels, organization_id, folder_ids, lineage_complete, lineage_error FROM gcp_resource_manager_projects`, &DataQueryResult{
		Rows: []map[string]any{{
			"resource_name":    "projects/123456789",
			"project_id":       "proj-a",
			"project_number":   "123456789",
			"display_name":     "Project A",
			"parent":           "folders/456",
			"state":            "ACTIVE",
			"organization_id":  "789",
			"folder_ids":       []any{"123", "456"},
			"lineage_complete": true,
			"lineage_error":    "",
		}},
	})
	source.setResult(`SELECT id, name, project_id, zone, status, service_accounts FROM gcp_compute_instances`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":               "instance-1",
			"name":             "instance-1",
			"project_id":       "proj-a",
			"zone":             "us-central1-a",
			"status":           "RUNNING",
			"service_accounts": []any{},
		}},
	})
	source.setResult(`SELECT project_id, resource_name, bindings, ancestor_path, lineage_complete, lineage_error FROM gcp_folder_iam_policies`, &DataQueryResult{
		Rows: []map[string]any{{
			"project_id":       "proj-a",
			"resource_name":    "folders/456",
			"ancestor_path":    []any{"organizations/789", "folders/123", "folders/456"},
			"lineage_complete": false,
			"lineage_error":    "project proj-a lineage incomplete at folders/123: permission denied",
			"bindings": []any{
				map[string]any{
					"role":    "roles/viewer",
					"members": []any{"user:alice@example.com"},
					"condition": map[string]any{
						"title":      "folder-scope",
						"expression": "resource.matchTag('env','prod')",
					},
				},
			},
		}},
	})
	source.setResult(`SELECT project_id, resource_name, bindings, ancestor_path, lineage_complete, lineage_error FROM gcp_organization_iam_policies`, &DataQueryResult{
		Rows: []map[string]any{{
			"project_id":       "proj-a",
			"resource_name":    "organizations/789",
			"ancestor_path":    []any{"organizations/789"},
			"lineage_complete": true,
			"lineage_error":    "",
			"bindings": []any{
				map[string]any{
					"role":    "roles/editor",
					"members": []any{"user:bob@example.com"},
				},
			},
		}},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(ctx); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	foundFolderInherited := false
	for _, edge := range builder.Graph().GetOutEdges("user:alice@example.com") {
		if edge.Target != "instance-1" || edge.Kind != EdgeKindCanRead {
			continue
		}
		foundFolderInherited = true
		if edge.Properties["binding"] != "folder" || edge.Properties["scope"] != "folder" {
			t.Fatalf("expected folder-scoped inherited edge, got %#v", edge.Properties)
		}
		if edge.Properties["inherited"] != true || edge.Properties["mechanism"] != "hierarchy_policy" {
			t.Fatalf("expected hierarchy inheritance markers, got %#v", edge.Properties)
		}
		if edge.Properties["lineage_complete"] != false {
			t.Fatalf("expected inherited folder edge to preserve incomplete lineage, got %#v", edge.Properties)
		}
		condition, ok := edge.Properties["condition"].(map[string]any)
		if !ok || condition["expression"] != "resource.matchTag('env','prod')" {
			t.Fatalf("expected preserved folder condition, got %#v", edge.Properties["condition"])
		}
	}
	if !foundFolderInherited {
		t.Fatal("expected inherited folder IAM edge to descendant project resource")
	}

	foundOrgInherited := false
	for _, edge := range builder.Graph().GetOutEdges("user:bob@example.com") {
		if edge.Target != "projects/123456789" || edge.Kind != EdgeKindCanWrite {
			continue
		}
		foundOrgInherited = true
		if edge.Properties["binding"] != "organization" || edge.Properties["scope_resource"] != "organizations/789" {
			t.Fatalf("expected organization-scoped inherited edge, got %#v", edge.Properties)
		}
		if edge.Properties["lineage_complete"] != true {
			t.Fatalf("expected organization inherited edge to preserve complete lineage, got %#v", edge.Properties)
		}
	}
	if !foundOrgInherited {
		t.Fatal("expected inherited organization IAM edge to descendant project node")
	}
}

func hasEdge(edges []*Edge, target string, kind EdgeKind) bool {
	for _, edge := range edges {
		if edge.Target == target && edge.Kind == kind {
			return true
		}
	}
	return false
}
