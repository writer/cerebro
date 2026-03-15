package builders

import (
	"context"
	"log/slog"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestBuilder_ProjectsVendorNodesFromIdentityIntegrations(t *testing.T) {
	t.Parallel()

	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT id, label, name, status, sign_on_mode FROM okta_applications`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":           "okta-app-slack",
			"label":        "Slack",
			"name":         "slack",
			"status":       "ACTIVE",
			"sign_on_mode": "SAML_2_0",
		}},
	})
	source.setResult(`SELECT id, display_name, app_id, service_principal_type, account_enabled, app_owner_organization_id, app_role_assignment_required, publisher_name, created_date_time, tags, subscription_id FROM azure_graph_service_principals`, &DataQueryResult{
		Rows: []map[string]any{
			{
				"id":                        "sp-slack",
				"display_name":              "Slack Enterprise Grid",
				"app_id":                    "app-slack",
				"service_principal_type":    "Application",
				"account_enabled":           true,
				"app_owner_organization_id": "tenant-vendor",
				"publisher_name":            "Slack",
				"subscription_id":           "sub-1",
			},
			{
				"id":                        "sp-managed",
				"display_name":              "aks-workload-identity",
				"app_id":                    "app-managed",
				"service_principal_type":    "ManagedIdentity",
				"account_enabled":           true,
				"app_owner_organization_id": "tenant-local",
				"publisher_name":            "Microsoft",
				"subscription_id":           "sub-1",
			},
		},
	})
	source.setResult(`
		SELECT source_id, source_type, target_id, target_type, rel_type, properties
		FROM resource_relationships
	`, &DataQueryResult{
		Rows: []map[string]any{
			{
				"source_id":   "sp-slack",
				"source_type": "entra:service_principal",
				"target_id":   "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Storage/storageAccounts/data",
				"target_type": "azure:storage:account",
				"rel_type":    "READS_FROM",
			},
			{
				"source_id":   "sp-slack",
				"source_type": "entra:service_principal",
				"target_id":   "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/prod",
				"target_type": "azure:keyvault:vault",
				"rel_type":    "HAS_PERMISSION",
			},
		},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	g := builder.Graph()
	vendor, ok := g.GetNode("vendor:slack")
	if !ok {
		t.Fatal("expected vendor node for Slack")
	}
	if vendor.Kind != NodeKindVendor {
		t.Fatalf("expected vendor node kind, got %#v", vendor)
	}
	if vendor.Name != "Slack" {
		t.Fatalf("expected canonical vendor name to be preserved, got %q", vendor.Name)
	}
	assertStringSliceProperty(t, vendor.Properties, "source_providers", []string{"azure", "okta"})
	assertStringSliceProperty(t, vendor.Properties, "integration_types", []string{"entra_service_principal", "okta_application"})
	if got := intProperty(t, vendor.Properties, "managed_node_count"); got != 2 {
		t.Fatalf("expected two managed nodes, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "managed_application_count"); got != 1 {
		t.Fatalf("expected one managed application, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "managed_service_account_count"); got != 1 {
		t.Fatalf("expected one managed service account, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "accessible_resource_count"); got != 2 {
		t.Fatalf("expected two accessible resources, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "read_access_count"); got != 1 {
		t.Fatalf("expected one readable resource, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "admin_access_count"); got != 1 {
		t.Fatalf("expected one admin resource, got %d", got)
	}
	if vendor.Risk != RiskHigh {
		t.Fatalf("expected high vendor risk from admin access, got %s", vendor.Risk)
	}

	assertEdgeExists(t, g, "okta-app-slack", "vendor:slack", EdgeKindManagedBy)
	assertEdgeExists(t, g, "sp-slack", "vendor:slack", EdgeKindManagedBy)
	for _, edge := range g.GetOutEdges("sp-managed") {
		if edge.Target == "vendor:microsoft" && edge.Kind == EdgeKindManagedBy {
			t.Fatalf("expected managed identities to avoid vendor projection, got %#v", edge)
		}
	}
	if _, ok := g.GetNode("vendor:microsoft"); ok {
		t.Fatal("expected managed identity publisher to avoid vendor node creation")
	}
}

func TestBuilder_ApplyChangesReprojectsDerivedVendorNodes(t *testing.T) {
	t.Parallel()

	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT id, label, name, status, sign_on_mode FROM okta_applications`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":           "okta-app-1",
			"label":        "Slack",
			"name":         "slack",
			"status":       "ACTIVE",
			"sign_on_mode": "SAML_2_0",
		}},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("initial build failed: %v", err)
	}

	if _, ok := builder.Graph().GetNode("vendor:slack"); !ok {
		t.Fatal("expected initial derived vendor node")
	}

	source.setResult(`SELECT id, label, name, status, sign_on_mode FROM okta_applications`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":           "okta-app-1",
			"label":        "Notion",
			"name":         "notion",
			"status":       "ACTIVE",
			"sign_on_mode": "SAML_2_0",
		}},
	})
	cdcQuery := `
		SELECT event_id, table_name, resource_id, change_type, provider, region, account_id, payload, event_time,
		       COALESCE(ingested_at, event_time) AS ingested_at
		FROM CDC_EVENTS
		WHERE (
			event_time > ?
			OR (event_time = ? AND COALESCE(ingested_at, event_time) > ?)
			OR (event_time = ? AND COALESCE(ingested_at, event_time) = ? AND event_id > ?)
		) ORDER BY event_time ASC, ingested_at ASC, event_id ASC`
	now := time.Now().UTC()
	source.setResult(cdcQuery, &DataQueryResult{
		Rows: []map[string]any{{
			"event_id":    "evt-1",
			"table_name":  "okta_applications",
			"resource_id": "okta-app-1",
			"change_type": "modified",
			"provider":    "okta",
			"payload": map[string]any{
				"id":           "okta-app-1",
				"label":        "Notion",
				"name":         "notion",
				"status":       "ACTIVE",
				"sign_on_mode": "SAML_2_0",
			},
			"event_time":  now,
			"ingested_at": now,
		}},
	})

	if _, err := builder.ApplyChanges(context.Background(), time.Time{}); err != nil {
		t.Fatalf("apply changes failed: %v", err)
	}

	if _, ok := builder.Graph().GetNode("vendor:notion"); !ok {
		t.Fatal("expected renamed vendor node after incremental rebuild")
	}
	if _, ok := builder.Graph().GetNode("vendor:slack"); ok {
		t.Fatal("expected stale derived vendor node to be removed")
	}
}

func assertStringSliceProperty(t *testing.T, properties map[string]any, key string, want []string) {
	t.Helper()

	value, ok := properties[key]
	if !ok {
		t.Fatalf("expected property %q to be present", key)
	}

	var got []string
	switch typed := value.(type) {
	case []string:
		got = append(got, typed...)
	case []any:
		for _, item := range typed {
			if text, ok := item.(string); ok && text != "" {
				got = append(got, text)
			}
		}
	default:
		t.Fatalf("expected property %q to be string slice, got %#v", key, value)
	}

	sort.Strings(got)
	sortedWant := append([]string(nil), want...)
	sort.Strings(sortedWant)
	if !reflect.DeepEqual(got, sortedWant) {
		t.Fatalf("unexpected property %q: got %#v want %#v", key, got, sortedWant)
	}
}

func intProperty(t *testing.T, properties map[string]any, key string) int {
	t.Helper()

	value, ok := properties[key]
	if !ok {
		t.Fatalf("expected property %q to be present", key)
	}
	switch typed := value.(type) {
	case int:
		return typed
	case int32:
		return int(typed)
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		t.Fatalf("expected property %q to be numeric, got %#v", key, value)
		return 0
	}
}
