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
	source.setResult(`SELECT id, display_name, app_id, service_principal_type, account_enabled, app_owner_organization_id, app_role_assignment_required, publisher_name, verified_publisher_display_name, verified_publisher_id, verified_publisher_added_datetime, created_date_time, tags, subscription_id FROM azure_graph_service_principals`, &DataQueryResult{
		Rows: []map[string]any{
			{
				"id":                                "sp-slack",
				"display_name":                      "Slack Enterprise Grid",
				"app_id":                            "app-slack",
				"service_principal_type":            "Application",
				"account_enabled":                   true,
				"app_owner_organization_id":         "tenant-vendor",
				"publisher_name":                    "Slack",
				"verified_publisher_display_name":   "Slack Technologies",
				"verified_publisher_id":             "slack-publisher",
				"verified_publisher_added_datetime": "2026-03-02T00:00:00Z",
				"subscription_id":                   "sub-1",
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
	assertStringSliceProperty(t, vendor.Properties, "owner_organization_ids", []string{"tenant-vendor"})
	assertStringSliceProperty(t, vendor.Properties, "accessible_resource_kinds", []string{"bucket", "secret"})
	assertStringSliceProperty(t, vendor.Properties, "verified_publisher_ids", []string{"slack-publisher"})
	assertStringSliceProperty(t, vendor.Properties, "verified_publisher_names", []string{"Slack Technologies"})
	if got := intProperty(t, vendor.Properties, "managed_node_count"); got != 2 {
		t.Fatalf("expected two managed nodes, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "managed_application_count"); got != 1 {
		t.Fatalf("expected one managed application, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "managed_service_account_count"); got != 1 {
		t.Fatalf("expected one managed service account, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "verified_publisher_count"); got != 1 {
		t.Fatalf("expected one verified integration, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "unverified_integration_count"); got != 0 {
		t.Fatalf("expected no unverified integrations, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "accessible_resource_count"); got != 2 {
		t.Fatalf("expected two accessible resources, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "dependent_principal_count"); got != 0 {
		t.Fatalf("expected no dependent principals in this fixture, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "read_access_count"); got != 1 {
		t.Fatalf("expected one readable resource, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "admin_access_count"); got != 1 {
		t.Fatalf("expected one admin resource, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "app_role_assignment_required_count"); got != 0 {
		t.Fatalf("expected no assignment-required integrations in this fixture, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "app_role_assignment_optional_count"); got != 0 {
		t.Fatalf("expected no assignment-optional integrations in this fixture, got %d", got)
	}
	if got, _ := vendor.Properties["permission_level"].(string); got != "admin" {
		t.Fatalf("expected permission level admin, got %#v", vendor.Properties["permission_level"])
	}
	if got, _ := vendor.Properties["vendor_category"].(string); got != "saas_integration" {
		t.Fatalf("expected saas integration category, got %#v", vendor.Properties["vendor_category"])
	}
	if got, _ := vendor.Properties["verification_status"].(string); got != "verified" {
		t.Fatalf("expected verified status, got %#v", vendor.Properties["verification_status"])
	}
	if got := intProperty(t, vendor.Properties, "vendor_risk_score"); got != 86 {
		t.Fatalf("expected vendor risk score 86, got %d", got)
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

func TestBuilder_CanonicalizesVendorAliasesAndAggregatesProvenance(t *testing.T) {
	t.Parallel()

	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT id, label, name, status, sign_on_mode FROM okta_applications`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":           "okta-app-zoom",
			"label":        "Zoom",
			"name":         "zoom",
			"status":       "ACTIVE",
			"sign_on_mode": "SAML_2_0",
		}},
	})
	source.setResult(`SELECT id, display_name, app_id, service_principal_type, account_enabled, app_owner_organization_id, app_role_assignment_required, publisher_name, verified_publisher_display_name, verified_publisher_id, verified_publisher_added_datetime, created_date_time, tags, subscription_id FROM azure_graph_service_principals`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":                                "sp-zoom",
			"display_name":                      "Zoom for Enterprise",
			"app_id":                            "app-zoom",
			"service_principal_type":            "Application",
			"account_enabled":                   true,
			"app_owner_organization_id":         "tenant-zoom",
			"app_role_assignment_required":      true,
			"publisher_name":                    "Zoom Video Communications, Inc.",
			"verified_publisher_display_name":   "Zoom Video Communications",
			"verified_publisher_id":             "zoom-publisher",
			"verified_publisher_added_datetime": "2026-03-02T00:00:00Z",
			"subscription_id":                   "sub-1",
		}},
	})
	source.setResult(`
		SELECT arn, name, account_id, region
		FROM aws_secretsmanager_secrets
	`, &DataQueryResult{
		Rows: []map[string]any{{
			"arn":        "arn:aws:secretsmanager:us-east-1:111111111111:secret:zoom-api",
			"name":       "zoom-api",
			"account_id": "111111111111",
			"region":     "us-east-1",
		}},
	})
	source.setResult(`
		SELECT source_id, source_type, target_id, target_type, rel_type, properties
		FROM resource_relationships
	`, &DataQueryResult{
		Rows: []map[string]any{{
			"source_id":   "sp-zoom",
			"source_type": "entra:service_principal",
			"target_id":   "arn:aws:secretsmanager:us-east-1:111111111111:secret:zoom-api",
			"target_type": "aws:secretsmanager:secret",
			"rel_type":    "READS_FROM",
		}},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	g := builder.Graph()
	vendor, ok := g.GetNode("vendor:zoom")
	if !ok {
		t.Fatal("expected canonical vendor node for Zoom")
	}
	if _, ok := g.GetNode("vendor:zoom-video-communications"); ok {
		t.Fatal("expected alias form to collapse into canonical vendor node")
	}
	if vendor.Name != "Zoom" {
		t.Fatalf("expected canonical vendor display name Zoom, got %q", vendor.Name)
	}
	assertStringSliceProperty(t, vendor.Properties, "aliases", []string{"Zoom Video Communications"})
	assertStringSliceProperty(t, vendor.Properties, "owner_organization_ids", []string{"tenant-zoom"})
	assertStringSliceProperty(t, vendor.Properties, "accessible_resource_kinds", []string{"secret"})
	assertStringSliceProperty(t, vendor.Properties, "verified_publisher_ids", []string{"zoom-publisher"})
	if got := intProperty(t, vendor.Properties, "sensitive_resource_count"); got != 1 {
		t.Fatalf("expected one sensitive resource, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "app_role_assignment_required_count"); got != 1 {
		t.Fatalf("expected one assignment-required integration, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "vendor_risk_score"); got != 33 {
		t.Fatalf("expected vendor risk score 33, got %d", got)
	}
	if got, _ := vendor.Properties["permission_level"].(string); got != "read" {
		t.Fatalf("expected permission level read, got %#v", vendor.Properties["permission_level"])
	}
	if got, _ := vendor.Properties["verification_status"].(string); got != "verified" {
		t.Fatalf("expected verified status, got %#v", vendor.Properties["verification_status"])
	}
	assertEdgeExists(t, g, "okta-app-zoom", "vendor:zoom", EdgeKindManagedBy)
	assertEdgeExists(t, g, "sp-zoom", "vendor:zoom", EdgeKindManagedBy)
}

func TestBuilder_AggregatesVendorDependencyBreadthFromAssignments(t *testing.T) {
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
	source.setResult(`SELECT id, display_name, app_id, service_principal_type, account_enabled, app_owner_organization_id, app_role_assignment_required, publisher_name, verified_publisher_display_name, verified_publisher_id, verified_publisher_added_datetime, created_date_time, tags, subscription_id FROM azure_graph_service_principals`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":                                "sp-slack",
			"display_name":                      "Slack Enterprise Grid",
			"app_id":                            "app-slack",
			"service_principal_type":            "Application",
			"account_enabled":                   true,
			"app_owner_organization_id":         "tenant-vendor",
			"publisher_name":                    "Slack",
			"verified_publisher_display_name":   "Slack Technologies",
			"verified_publisher_id":             "slack-publisher",
			"verified_publisher_added_datetime": "2026-03-02T00:00:00Z",
			"subscription_id":                   "sub-1",
		}},
	})
	source.setResult(`
		SELECT source_id, source_type, target_id, target_type, rel_type, properties
		FROM resource_relationships
	`, &DataQueryResult{
		Rows: []map[string]any{
			{
				"source_id":   "user-alice",
				"source_type": "okta:user",
				"target_id":   "okta-app-slack",
				"target_type": "okta:application",
				"rel_type":    "CAN_ACCESS",
			},
			{
				"source_id":   "group-ops",
				"source_type": "okta:group",
				"target_id":   "okta-app-slack",
				"target_type": "okta:application",
				"rel_type":    "CAN_ACCESS",
			},
			{
				"source_id":   "user-bob",
				"source_type": "okta:user",
				"target_id":   "group-ops",
				"target_type": "okta:group",
				"rel_type":    "MEMBER_OF",
			},
			{
				"source_id":   "sp-worker",
				"source_type": "entra:service_principal",
				"target_id":   "sp-slack",
				"target_type": "entra:service_principal",
				"rel_type":    "CAN_ACCESS",
			},
		},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	vendor, ok := builder.Graph().GetNode("vendor:slack")
	if !ok {
		t.Fatal("expected vendor node for Slack")
	}
	if got := intProperty(t, vendor.Properties, "dependent_principal_count"); got != 4 {
		t.Fatalf("expected four dependent principals, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "dependent_user_count"); got != 2 {
		t.Fatalf("expected two dependent users, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "dependent_group_count"); got != 1 {
		t.Fatalf("expected one dependent group, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "dependent_service_account_count"); got != 1 {
		t.Fatalf("expected one dependent service account, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "vendor_risk_score"); got != 13 {
		t.Fatalf("expected dependency-only vendor risk score 13, got %d", got)
	}
	if vendor.Risk != RiskLow {
		t.Fatalf("expected dependency breadth to surface low risk, got %s", vendor.Risk)
	}
}

func TestBuilder_MergesVendorProjectionsByVerifiedPublisherID(t *testing.T) {
	t.Parallel()

	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT id, display_name, app_id, service_principal_type, account_enabled, app_owner_organization_id, app_role_assignment_required, publisher_name, verified_publisher_display_name, verified_publisher_id, verified_publisher_added_datetime, created_date_time, tags, subscription_id FROM azure_graph_service_principals`, &DataQueryResult{
		Rows: []map[string]any{
			{
				"id":                                "sp-one",
				"display_name":                      "PagerDuty Operations Cloud",
				"app_id":                            "app-one",
				"service_principal_type":            "Application",
				"account_enabled":                   true,
				"publisher_name":                    "PagerDuty Operations Cloud",
				"verified_publisher_display_name":   "PagerDuty",
				"verified_publisher_id":             "pagerduty-publisher",
				"verified_publisher_added_datetime": "2026-03-02T00:00:00Z",
				"subscription_id":                   "sub-1",
			},
			{
				"id":                                "sp-two",
				"display_name":                      "PagerDuty Incident Response",
				"app_id":                            "app-two",
				"service_principal_type":            "Application",
				"account_enabled":                   true,
				"publisher_name":                    "PagerDuty Inc.",
				"verified_publisher_display_name":   "PagerDuty",
				"verified_publisher_id":             "pagerduty-publisher",
				"verified_publisher_added_datetime": "2026-03-02T00:00:00Z",
				"subscription_id":                   "sub-1",
			},
		},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	g := builder.Graph()
	vendor, ok := g.GetNode("vendor:pagerduty")
	if !ok {
		t.Fatal("expected vendor node to merge on verified publisher id")
	}
	if got := intProperty(t, vendor.Properties, "managed_service_account_count"); got != 2 {
		t.Fatalf("expected two service-principal integrations, got %d", got)
	}
	assertStringSliceProperty(t, vendor.Properties, "verified_publisher_ids", []string{"pagerduty-publisher"})
	if got, _ := vendor.Properties["verification_status"].(string); got != "verified" {
		t.Fatalf("expected verified status, got %#v", vendor.Properties["verification_status"])
	}
}

func TestBuilder_AggregatesVendorSignalsFromDelegatedOAuthGrantRelationships(t *testing.T) {
	t.Parallel()

	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT id, display_name, app_id, service_principal_type, account_enabled, app_owner_organization_id, app_role_assignment_required, publisher_name, verified_publisher_display_name, verified_publisher_id, verified_publisher_added_datetime, created_date_time, tags, subscription_id FROM azure_graph_service_principals`, &DataQueryResult{
		Rows: []map[string]any{
			{
				"id":                                "sp-client",
				"display_name":                      "Slack Enterprise Grid",
				"app_id":                            "app-slack",
				"service_principal_type":            "Application",
				"account_enabled":                   true,
				"app_owner_organization_id":         "tenant-vendor",
				"publisher_name":                    "Slack",
				"verified_publisher_display_name":   "Slack Technologies",
				"verified_publisher_id":             "slack-publisher",
				"verified_publisher_added_datetime": "2026-03-02T00:00:00Z",
				"subscription_id":                   "sub-1",
			},
			{
				"id":                                "sp-resource",
				"display_name":                      "Microsoft Graph",
				"app_id":                            "app-msgraph",
				"service_principal_type":            "Application",
				"account_enabled":                   true,
				"publisher_name":                    "Microsoft",
				"verified_publisher_display_name":   "Microsoft",
				"verified_publisher_id":             "msft-publisher",
				"verified_publisher_added_datetime": "2026-03-02T00:00:00Z",
				"subscription_id":                   "sub-1",
			},
		},
	})
	source.setResult(`
		SELECT source_id, source_type, target_id, target_type, rel_type, properties
		FROM resource_relationships
	`, &DataQueryResult{
		Rows: []map[string]any{
			{
				"source_id":   "sp-client",
				"source_type": "entra:service_principal",
				"target_id":   "sp-resource",
				"target_type": "entra:service_principal",
				"rel_type":    "CAN_ACCESS",
				"properties": map[string]any{
					"grant_id":     "grant-slack-mail-read",
					"grant_type":   "delegated_permission",
					"consent_type": "AllPrincipals",
					"scope":        "Mail.Read Files.Read",
				},
			},
			{
				"source_id":   "user-alice",
				"source_type": "entra:user",
				"target_id":   "sp-client",
				"target_type": "entra:service_principal",
				"rel_type":    "CAN_ACCESS",
				"properties": map[string]any{
					"grant_id":     "grant-slack-mail-read",
					"grant_type":   "delegated_permission_consent",
					"consent_type": "Principal",
					"scope":        "Mail.Read Files.Read",
				},
			},
		},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	vendor, ok := builder.Graph().GetNode("vendor:slack-technologies")
	if !ok {
		t.Fatal("expected vendor node for Slack")
	}
	if got := intProperty(t, vendor.Properties, "dependent_user_count"); got != 1 {
		t.Fatalf("expected delegated consent to count one dependent user, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "delegated_grant_count"); got != 1 {
		t.Fatalf("expected one delegated grant, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "delegated_admin_consent_count"); got != 1 {
		t.Fatalf("expected one admin-consented delegated grant, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "delegated_principal_consent_count"); got != 1 {
		t.Fatalf("expected one principal-consented delegated grant, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "delegated_scope_count"); got != 2 {
		t.Fatalf("expected two delegated scopes, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "accessible_resource_count"); got != 1 {
		t.Fatalf("expected one accessible downstream API resource, got %d", got)
	}
	assertStringSliceProperty(t, vendor.Properties, "accessible_resource_kinds", []string{"service_account"})
	assertStringSliceProperty(t, vendor.Properties, "delegated_scopes", []string{"Files.Read", "Mail.Read"})
	if got := intProperty(t, vendor.Properties, "vendor_risk_score"); got != 44 {
		t.Fatalf("expected delegated grant signals to lift vendor risk score to 44, got %d", got)
	}
	if vendor.Risk != RiskMedium {
		t.Fatalf("expected delegated admin consent to lift vendor risk to medium, got %s", vendor.Risk)
	}
}

func TestBuilder_TenantWideDelegatedGrantElevatesVendorRiskWithoutPrincipalAssignments(t *testing.T) {
	t.Parallel()

	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT id, display_name, app_id, service_principal_type, account_enabled, app_owner_organization_id, app_role_assignment_required, publisher_name, verified_publisher_display_name, verified_publisher_id, verified_publisher_added_datetime, created_date_time, tags, subscription_id FROM azure_graph_service_principals`, &DataQueryResult{
		Rows: []map[string]any{
			{
				"id":                                "sp-client",
				"display_name":                      "Dropbox Enterprise",
				"app_id":                            "app-dropbox",
				"service_principal_type":            "Application",
				"account_enabled":                   true,
				"app_owner_organization_id":         "tenant-vendor",
				"publisher_name":                    "Dropbox",
				"verified_publisher_display_name":   "Dropbox",
				"verified_publisher_id":             "dropbox-publisher",
				"verified_publisher_added_datetime": "2026-03-02T00:00:00Z",
				"subscription_id":                   "sub-1",
			},
			{
				"id":                                "sp-resource",
				"display_name":                      "Microsoft Graph",
				"app_id":                            "app-msgraph",
				"service_principal_type":            "Application",
				"account_enabled":                   true,
				"publisher_name":                    "Microsoft",
				"verified_publisher_display_name":   "Microsoft",
				"verified_publisher_id":             "msft-publisher",
				"verified_publisher_added_datetime": "2026-03-02T00:00:00Z",
				"subscription_id":                   "sub-1",
			},
		},
	})
	source.setResult(`
		SELECT source_id, source_type, target_id, target_type, rel_type, properties
		FROM resource_relationships
	`, &DataQueryResult{
		Rows: []map[string]any{
			{
				"source_id":   "sp-client",
				"source_type": "entra:service_principal",
				"target_id":   "sp-resource",
				"target_type": "entra:service_principal",
				"rel_type":    "CAN_ACCESS",
				"properties": map[string]any{
					"grant_id":     "grant-dropbox-tenant",
					"grant_type":   "delegated_permission",
					"consent_type": "AllPrincipals",
					"scope":        "Files.Read Sites.Read.All User.Read",
				},
			},
		},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	vendor, ok := builder.Graph().GetNode("vendor:dropbox")
	if !ok {
		t.Fatal("expected vendor node for Dropbox")
	}
	if got := intProperty(t, vendor.Properties, "dependent_principal_count"); got != 0 {
		t.Fatalf("expected no explicit dependent principals for tenant-wide admin consent, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "delegated_grant_count"); got != 1 {
		t.Fatalf("expected one delegated grant, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "delegated_admin_consent_count"); got != 1 {
		t.Fatalf("expected one tenant-wide admin consent, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "delegated_principal_consent_count"); got != 0 {
		t.Fatalf("expected no principal-specific delegated consents, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "delegated_scope_count"); got != 3 {
		t.Fatalf("expected three delegated scopes, got %d", got)
	}
	assertStringSliceProperty(t, vendor.Properties, "delegated_scopes", []string{"Files.Read", "Sites.Read.All", "User.Read"})
	if got := intProperty(t, vendor.Properties, "vendor_risk_score"); got != 44 {
		t.Fatalf("expected tenant-wide delegated admin consent to elevate vendor risk score to 44, got %d", got)
	}
	if vendor.Risk != RiskMedium {
		t.Fatalf("expected tenant-wide delegated admin consent to elevate vendor risk to medium, got %s", vendor.Risk)
	}
}

func TestBuilder_ProjectsGoogleWorkspaceOAuthAppsIntoVendorRisk(t *testing.T) {
	t.Parallel()

	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT id, primary_email, name, given_name, family_name, is_admin, is_delegated_admin, suspended, archived, is_enrolled_in_2sv, is_enforced_in_2sv, creation_time, last_login_time, org_unit_path FROM google_workspace_users`, &DataQueryResult{
		Rows: []map[string]any{
			{
				"id":            "user-1",
				"primary_email": "user-1@example.com",
				"name":          "Alice Example",
			},
		},
	})
	source.setResult(`SELECT id, email, name, description, direct_members_count, admin_created FROM google_workspace_groups`, &DataQueryResult{Rows: []map[string]any{}})
	source.setResult(`SELECT client_id, display_text, anonymous, native_app, app_type FROM google_workspace_tokens`, &DataQueryResult{
		Rows: []map[string]any{
			{
				"client_id":    "client-1",
				"display_text": "Slack",
				"anonymous":    false,
				"native_app":   true,
				"app_type":     "native",
			},
		},
	})
	source.setResult(`
		SELECT source_id, source_type, target_id, target_type, rel_type, properties
		FROM resource_relationships
	`, &DataQueryResult{
		Rows: []map[string]any{
			{
				"source_id":   "user-1",
				"source_type": "google_workspace:user",
				"target_id":   "client-1",
				"target_type": "google_workspace:application",
				"rel_type":    "CAN_ACCESS",
				"properties": map[string]any{
					"grant_id":     "user-1|client-1",
					"grant_type":   "delegated_permission_consent",
					"consent_type": "Principal",
					"scope":        "https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/calendar.readonly",
				},
			},
			{
				"source_id":   "client-1",
				"source_type": "google_workspace:application",
				"target_id":   "google_workspace_scope:https://www.googleapis.com/auth/admin.directory.user.readonly",
				"target_type": "google_workspace:scope",
				"rel_type":    "CAN_ACCESS",
				"properties": map[string]any{
					"grant_id":   "user-1|client-1",
					"grant_type": "delegated_permission",
					"scope":      "https://www.googleapis.com/auth/admin.directory.user.readonly",
				},
			},
			{
				"source_id":   "client-1",
				"source_type": "google_workspace:application",
				"target_id":   "google_workspace_scope:https://www.googleapis.com/auth/calendar.readonly",
				"target_type": "google_workspace:scope",
				"rel_type":    "CAN_ACCESS",
				"properties": map[string]any{
					"grant_id":   "user-1|client-1",
					"grant_type": "delegated_permission",
					"scope":      "https://www.googleapis.com/auth/calendar.readonly",
				},
			},
		},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	vendor, ok := builder.Graph().GetNode("vendor:slack")
	if !ok {
		t.Fatal("expected vendor node for Slack")
	}
	if got := intProperty(t, vendor.Properties, "managed_application_count"); got != 1 {
		t.Fatalf("expected one managed application, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "dependent_user_count"); got != 1 {
		t.Fatalf("expected one dependent user, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "delegated_grant_count"); got != 1 {
		t.Fatalf("expected one delegated grant, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "delegated_scope_count"); got != 2 {
		t.Fatalf("expected two delegated scopes, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "anonymous_application_count"); got != 0 {
		t.Fatalf("expected no anonymous applications, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "native_application_count"); got != 1 {
		t.Fatalf("expected one native application, got %d", got)
	}
	assertStringSliceProperty(t, vendor.Properties, "integration_types", []string{"google_workspace_application"})
}

func TestBuilder_AnonymousGoogleWorkspaceOAuthAppsRaiseVendorRisk(t *testing.T) {
	t.Parallel()

	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT id, primary_email, name, given_name, family_name, is_admin, is_delegated_admin, suspended, archived, is_enrolled_in_2sv, is_enforced_in_2sv, creation_time, last_login_time, org_unit_path FROM google_workspace_users`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":            "user-1",
			"primary_email": "user-1@example.com",
			"name":          "Alice Example",
		}},
	})
	source.setResult(`SELECT id, email, name, description, direct_members_count, admin_created FROM google_workspace_groups`, &DataQueryResult{Rows: []map[string]any{}})
	source.setResult(`SELECT client_id, display_text, anonymous, native_app, app_type FROM google_workspace_tokens`, &DataQueryResult{
		Rows: []map[string]any{{
			"client_id":    "client-2",
			"display_text": "Shadow AI",
			"anonymous":    true,
			"native_app":   true,
			"app_type":     "anonymous",
		}},
	})
	source.setResult(`
		SELECT source_id, source_type, target_id, target_type, rel_type, properties
		FROM resource_relationships
	`, &DataQueryResult{
		Rows: []map[string]any{
			{
				"source_id":   "user-1",
				"source_type": "google_workspace:user",
				"target_id":   "client-2",
				"target_type": "google_workspace:application",
				"rel_type":    "CAN_ACCESS",
				"properties": map[string]any{
					"grant_id":     "user-1|client-2",
					"grant_type":   "delegated_permission_consent",
					"consent_type": "Principal",
					"scope":        "https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/calendar.readonly",
				},
			},
			{
				"source_id":   "client-2",
				"source_type": "google_workspace:application",
				"target_id":   "google_workspace_scope:https://www.googleapis.com/auth/admin.directory.user.readonly",
				"target_type": "google_workspace:scope",
				"rel_type":    "CAN_ACCESS",
				"properties": map[string]any{
					"grant_id":   "user-1|client-2",
					"grant_type": "delegated_permission",
					"scope":      "https://www.googleapis.com/auth/admin.directory.user.readonly",
				},
			},
			{
				"source_id":   "client-2",
				"source_type": "google_workspace:application",
				"target_id":   "google_workspace_scope:https://www.googleapis.com/auth/calendar.readonly",
				"target_type": "google_workspace:scope",
				"rel_type":    "CAN_ACCESS",
				"properties": map[string]any{
					"grant_id":   "user-1|client-2",
					"grant_type": "delegated_permission",
					"scope":      "https://www.googleapis.com/auth/calendar.readonly",
				},
			},
		},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	vendor, ok := builder.Graph().GetNode("vendor:shadow-ai")
	if !ok {
		t.Fatal("expected vendor node for Shadow AI")
	}
	if got := intProperty(t, vendor.Properties, "anonymous_application_count"); got != 1 {
		t.Fatalf("expected one anonymous application, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "native_application_count"); got != 1 {
		t.Fatalf("expected one native application, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "vendor_risk_score"); got != 42 {
		t.Fatalf("expected anonymous/native delegated app risk score 42, got %d", got)
	}
	if vendor.Risk != RiskMedium {
		t.Fatalf("expected anonymous delegated app to reach medium risk, got %v", vendor.Risk)
	}
}

func TestBuilder_ProjectsOktaAppGrantScopesIntoVendorRisk(t *testing.T) {
	t.Parallel()

	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT id, login, email, status, last_login, mfa_enrolled, is_admin FROM okta_users`, &DataQueryResult{
		Rows: []map[string]any{
			{
				"id":    "user-1",
				"login": "alice@example.com",
				"email": "alice@example.com",
			},
		},
	})
	source.setResult(`SELECT id, label, name, status, sign_on_mode FROM okta_applications`, &DataQueryResult{
		Rows: []map[string]any{
			{
				"id":           "okta-app-slack",
				"label":        "Slack",
				"name":         "slack",
				"status":       "ACTIVE",
				"sign_on_mode": "OPENID_CONNECT",
			},
		},
	})
	source.setResult(`
		SELECT source_id, source_type, target_id, target_type, rel_type, properties
		FROM resource_relationships
	`, &DataQueryResult{
		Rows: []map[string]any{
			{
				"source_id":   "user-1",
				"source_type": "okta:user",
				"target_id":   "okta-app-slack",
				"target_type": "okta:application",
				"rel_type":    "CAN_ACCESS",
				"properties": map[string]any{
					"grant_id":     "grant-2",
					"grant_type":   "delegated_permission_consent",
					"consent_type": "Principal",
					"scope":        "okta.apps.manage",
				},
			},
			{
				"source_id":   "okta-app-slack",
				"source_type": "okta:application",
				"target_id":   "okta_scope:okta.users.read",
				"target_type": "okta:scope",
				"rel_type":    "CAN_ACCESS",
				"properties": map[string]any{
					"grant_id":     "grant-1",
					"grant_type":   "delegated_permission",
					"consent_type": "AllPrincipals",
					"scope":        "okta.users.read",
				},
			},
			{
				"source_id":   "okta-app-slack",
				"source_type": "okta:application",
				"target_id":   "okta_scope:okta.apps.manage",
				"target_type": "okta:scope",
				"rel_type":    "HAS_PERMISSION",
				"properties": map[string]any{
					"grant_id":     "grant-2",
					"grant_type":   "delegated_permission",
					"consent_type": "Principal",
					"scope":        "okta.apps.manage",
				},
			},
		},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	vendor, ok := builder.Graph().GetNode("vendor:slack")
	if !ok {
		t.Fatal("expected vendor node for Slack")
	}
	if got := intProperty(t, vendor.Properties, "read_access_count"); got != 1 {
		t.Fatalf("expected one read-granted Okta scope, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "admin_access_count"); got != 1 {
		t.Fatalf("expected one manage-granted Okta scope, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "delegated_grant_count"); got != 2 {
		t.Fatalf("expected two Okta grant records, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "delegated_admin_consent_count"); got != 1 {
		t.Fatalf("expected one admin-consented Okta grant, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "delegated_principal_consent_count"); got != 1 {
		t.Fatalf("expected one principal-consented Okta grant, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "delegated_scope_count"); got != 2 {
		t.Fatalf("expected two delegated Okta scopes, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "dependent_user_count"); got != 1 {
		t.Fatalf("expected one dependent user from principal grant, got %d", got)
	}
	if got := intProperty(t, vendor.Properties, "vendor_risk_score"); got != 97 {
		t.Fatalf("expected Okta grant signals to raise vendor risk score to 97, got %d", got)
	}
	if got, _ := vendor.Properties["permission_level"].(string); got != "admin" {
		t.Fatalf("expected admin permission level from Okta manage scope, got %#v", vendor.Properties["permission_level"])
	}
	if vendor.Risk != RiskHigh {
		t.Fatalf("expected Okta grant signals to produce high risk, got %v", vendor.Risk)
	}
}

func TestBuilder_KeepsDistinctVendorProductAliasesSeparate(t *testing.T) {
	t.Parallel()

	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT id, label, name, status, sign_on_mode FROM okta_applications`, &DataQueryResult{
		Rows: []map[string]any{
			{
				"id":           "okta-app-google",
				"label":        "Google",
				"name":         "google",
				"status":       "ACTIVE",
				"sign_on_mode": "SAML_2_0",
			},
			{
				"id":           "okta-app-google-analytics",
				"label":        "Google Analytics",
				"name":         "google_analytics",
				"status":       "ACTIVE",
				"sign_on_mode": "SAML_2_0",
			},
		},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	g := builder.Graph()
	assertEdgeExists(t, g, "okta-app-google", "vendor:google", EdgeKindManagedBy)
	assertEdgeExists(t, g, "okta-app-google-analytics", "vendor:google-analytics", EdgeKindManagedBy)
	if _, ok := g.GetNode("vendor:google"); !ok {
		t.Fatal("expected vendor node for Google")
	}
	if _, ok := g.GetNode("vendor:google-analytics"); !ok {
		t.Fatal("expected separate vendor node for Google Analytics")
	}
}

func TestVendorAliasKey_TrimsCorporateSuffixesConservatively(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"Zoom Video Communications, Inc.": "zoom",
		"Slack Technologies, LLC":         "slack",
		"Google Analytics":                "google analytics",
		"Palo Alto Networks, Inc.":        "palo alto networks",
	}

	for input, want := range cases {
		if got := vendorAliasKey(input); got != want {
			t.Fatalf("vendorAliasKey(%q) = %q, want %q", input, got, want)
		}
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
