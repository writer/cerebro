package builders

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
)

func TestBuilder_AzureBuildsScopesRBACPoliciesAndVaultEdges(t *testing.T) {
	t.Parallel()

	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT id, display_name, app_id, service_principal_type, account_enabled, app_owner_organization_id, app_role_assignment_required, publisher_name, verified_publisher_display_name, verified_publisher_id, verified_publisher_added_datetime, created_date_time, tags, subscription_id FROM azure_graph_service_principals`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":                                "sp-managed",
			"display_name":                      "vm-managed-identity",
			"app_id":                            "app-1",
			"service_principal_type":            "ManagedIdentity",
			"app_owner_organization_id":         "tenant-local",
			"app_role_assignment_required":      true,
			"publisher_name":                    "Microsoft",
			"verified_publisher_display_name":   "Microsoft",
			"verified_publisher_id":             "msft-publisher",
			"verified_publisher_added_datetime": "2026-03-01T00:00:00Z",
			"subscription_id":                   "sub-1",
		}},
	})
	source.setResult(`SELECT id, user_principal_name, display_name, mail, department, job_title, account_enabled, user_type, last_sign_in_datetime FROM entra_users`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":                  "user-1",
			"user_principal_name": "alice@example.com",
			"display_name":        "Alice",
			"mail":                "alice@example.com",
		}},
	})
	source.setResult(`SELECT id, name, subscription_id, resource_group, location, vm_size, os_type, provisioning_state, identity FROM azure_compute_virtual_machines`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":                 "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-1",
			"name":               "vm-1",
			"subscription_id":    "sub-1",
			"resource_group":     "rg-app",
			"location":           "eastus",
			"identity":           map[string]any{"principal_id": "sp-managed"},
			"vm_size":            "Standard_D2s_v5",
			"os_type":            "Linux",
			"provisioning_state": "Succeeded",
		}},
	})
	source.setResult(`SELECT id, name, subscription_id, resource_group, location, security_rules, default_security_rules FROM azure_network_security_groups`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":              "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/nsg-1",
			"name":            "nsg-1",
			"subscription_id": "sub-1",
			"resource_group":  "rg-app",
			"location":        "eastus",
			"security_rules": []any{
				map[string]any{
					"direction":             "Inbound",
					"access":                "Allow",
					"source_address_prefix": "0.0.0.0/0",
				},
			},
		}},
	})
	source.setResult(`SELECT id, name, subscription_id, resource_group, location, tenant_id, vault_uri, access_policies, enable_purge_protection, enable_soft_delete FROM azure_keyvault_vaults`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":              "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/vault-1",
			"name":            "vault-1",
			"subscription_id": "sub-1",
			"resource_group":  "rg-app",
			"location":        "eastus",
			"tenant_id":       "tenant-1",
			"vault_uri":       "https://vault-1.vault.azure.net/",
			"access_policies": []any{
				map[string]any{
					"object_id": "sp-managed",
					"permissions": map[string]any{
						"secrets": []any{"get", "set"},
					},
				},
			},
		}},
	})
	source.setResult(`SELECT id, name, subscription_id, vault_uri, managed, attributes FROM azure_keyvault_keys`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":              "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/vault-1/keys/key-1",
			"name":            "key-1",
			"subscription_id": "sub-1",
			"vault_uri":       "https://vault-1.vault.azure.net/",
		}},
	})
	source.setResult(`SELECT id, name, subscription_id, location, display_name, scope, policy_definition_id, enforcement_mode, identity, metadata, parameters FROM azure_policy_assignments`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":                   "/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/pa-1",
			"name":                 "pa-1",
			"display_name":         "Require Tags",
			"subscription_id":      "sub-1",
			"location":             "eastus",
			"scope":                "/subscriptions/sub-1",
			"policy_definition_id": "/providers/Microsoft.Authorization/policyDefinitions/pd-1",
			"identity":             map[string]any{"principal_id": "sp-managed"},
		}},
	})
	source.setResult(`SELECT id, scope, subscription_id FROM azure_policy_assignments`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":              "/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/pa-1",
			"scope":           "/subscriptions/sub-1",
			"subscription_id": "sub-1",
		}},
	})
	source.setResult(`SELECT id, principal_id, principal_type, role_definition_id, scope, condition, can_delegate, delegated_managed_identity_id, description, subscription_id FROM azure_rbac_role_assignments`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":                 "ra-1",
			"principal_id":       "sp-managed",
			"principal_type":     "ServicePrincipal",
			"role_definition_id": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
			"scope":              "/subscriptions/sub-1",
			"subscription_id":    "sub-1",
		}},
	})
	source.setResult(`SELECT id, vault_uri, access_policies FROM azure_keyvault_vaults`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":        "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/vault-1",
			"vault_uri": "https://vault-1.vault.azure.net/",
			"access_policies": []any{
				map[string]any{
					"object_id": "sp-managed",
					"permissions": map[string]any{
						"secrets": []any{"get", "set"},
					},
				},
			},
		}},
	})
	source.setResult(`SELECT id, principal_id, role_definition_id, directory_scope_id FROM entra_role_assignments`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":                 "entra-ra-1",
			"principal_id":       "user-1",
			"role_definition_id": "role-global-admin",
			"directory_scope_id": "/",
		}},
	})
	source.setResult(`SELECT id, display_name FROM entra_directory_roles`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":           "role-global-admin",
			"display_name": "Global Administrator",
		}},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	g := builder.Graph()
	vmID := "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-1"
	rgID := "/subscriptions/sub-1/resourceGroups/rg-app"
	subscriptionID := "/subscriptions/sub-1"
	vaultID := "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/vault-1"
	keyID := "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/vault-1/keys/key-1"
	policyID := "/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/pa-1"
	roleNodeID := "azure_rbac_role:8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
	directoryRoleNodeID := "azure_directory_role:role-global-admin"
	nsgID := "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/nsg-1"

	if node, ok := g.GetNode(subscriptionID); !ok || node.Kind != NodeKindProject {
		t.Fatalf("expected Azure subscription scope node, got %#v", node)
	}
	if node, ok := g.GetNode(rgID); !ok || node.Kind != NodeKindFolder {
		t.Fatalf("expected Azure resource group scope node, got %#v", node)
	}
	if node, ok := g.GetNode(roleNodeID); !ok || node.Kind != NodeKindRole {
		t.Fatalf("expected Azure RBAC role node, got %#v", node)
	}
	if node, ok := g.GetNode(directoryRoleNodeID); !ok || node.Kind != NodeKindRole {
		t.Fatalf("expected Entra directory role node, got %#v", node)
	}

	assertEdgeExists(t, g, vmID, "sp-managed", EdgeKindCanAssume)
	assertEdgeExists(t, g, vmID, rgID, EdgeKindLocatedIn)
	assertEdgeExists(t, g, rgID, subscriptionID, EdgeKindLocatedIn)
	assertEdgeExists(t, g, "sp-managed", roleNodeID, EdgeKindMemberOf)
	assertEdgeExists(t, g, roleNodeID, subscriptionID, EdgeKindLocatedIn)
	assertEdgeExists(t, g, "sp-managed", vmID, EdgeKindCanAdmin)
	assertEdgeExists(t, g, policyID, subscriptionID, EdgeKindLocatedIn)
	assertEdgeExists(t, g, policyID, "sp-managed", EdgeKindCanAssume)
	assertEdgeExists(t, g, "sp-managed", vaultID, EdgeKindCanWrite)
	assertEdgeExists(t, g, "sp-managed", keyID, EdgeKindCanWrite)
	assertEdgeExists(t, g, "user-1", directoryRoleNodeID, EdgeKindMemberOf)
	assertEdgeExists(t, g, directoryRoleNodeID, azureTenantRootNodeID, EdgeKindLocatedIn)
	assertEdgeExists(t, g, "internet", nsgID, EdgeKindExposedTo)

	spNode, ok := g.GetNode("sp-managed")
	if !ok {
		t.Fatal("expected managed identity service principal node")
	}
	assignments, _ := spNode.Properties["role_assignments"].([]any)
	if len(assignments) != 1 {
		t.Fatalf("expected one RBAC role assignment on managed identity, got %#v", spNode.Properties["role_assignments"])
	}
	if got := queryRowString(spNode.Properties, "app_owner_organization_id"); got != "tenant-local" {
		t.Fatalf("expected app owner organization to be preserved, got %#v", spNode.Properties)
	}
	if got, _ := spNode.Properties["app_role_assignment_required"].(bool); !got {
		t.Fatalf("expected app role assignment requirement to be preserved, got %#v", spNode.Properties)
	}
}

func TestBuilder_AzureRelationshipEdgesCreatePlaceholderNodes(t *testing.T) {
	t.Parallel()

	source := newMockDataSource()
	builder := NewBuilder(source, nil)

	source.setResult(`
		SELECT source_id, source_type, target_id, target_type, rel_type, properties
		FROM resource_relationships
	`, &DataQueryResult{
		Rows: []map[string]any{{
			"source_id":   "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Network/publicIPAddresses/pip-1",
			"source_type": "azure:network:public_ip",
			"target_id":   "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-1",
			"target_type": "azure:network:interface",
			"rel_type":    "ATTACHED_TO",
		}},
	})

	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	publicIP, ok := builder.Graph().GetNode("/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Network/publicIPAddresses/pip-1")
	if !ok || publicIP.Kind != NodeKindNetwork || publicIP.Provider != "azure" {
		t.Fatalf("expected placeholder Azure public IP node, got %#v", publicIP)
	}
	nic, ok := builder.Graph().GetNode("/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-1")
	if !ok || nic.Kind != NodeKindNetwork || nic.Provider != "azure" {
		t.Fatalf("expected placeholder Azure NIC node, got %#v", nic)
	}
	assertEdgeExists(t, builder.Graph(), publicIP.ID, nic.ID, EdgeKindConnectsTo)
}

func TestCDCEventToNode_AzureModernTables(t *testing.T) {
	t.Parallel()

	spNode := cdcEventToNode("azure_graph_service_principals", cdcEvent{
		ResourceID: "sp-managed",
		Payload: map[string]any{
			"id":                                "sp-managed",
			"display_name":                      "vm-managed-identity",
			"service_principal_type":            "ManagedIdentity",
			"app_owner_organization_id":         "tenant-local",
			"app_role_assignment_required":      true,
			"publisher_name":                    "Microsoft",
			"verified_publisher_display_name":   "Microsoft",
			"verified_publisher_id":             "msft-publisher",
			"verified_publisher_added_datetime": "2026-03-01T00:00:00Z",
			"subscription_id":                   "sub-1",
		},
	})
	if spNode == nil || spNode.Kind != NodeKindServiceAccount {
		t.Fatalf("expected service account node from Azure graph service principal, got %#v", spNode)
	}
	if got := queryRowString(spNode.Properties, "identity_type"); got != "ManagedIdentity" {
		t.Fatalf("expected managed identity marker on service principal, got %#v", spNode.Properties)
	}
	if got := queryRowString(spNode.Properties, "app_owner_organization_id"); got != "tenant-local" {
		t.Fatalf("expected app owner organization to be preserved, got %#v", spNode.Properties)
	}
	if got, _ := spNode.Properties["app_role_assignment_required"].(bool); !got {
		t.Fatalf("expected app role assignment requirement to be preserved, got %#v", spNode.Properties)
	}
	if got := queryRowString(spNode.Properties, "verified_publisher_id"); got != "msft-publisher" {
		t.Fatalf("expected verified publisher id to be preserved, got %#v", spNode.Properties)
	}

	entraNode := cdcEventToNode("entra_service_principals", cdcEvent{
		ResourceID: "sp-app",
		Payload: map[string]any{
			"id":                                "sp-app",
			"display_name":                      "Slack Enterprise Grid",
			"service_principal_type":            "Application",
			"app_owner_organization_id":         "tenant-vendor",
			"app_role_assignment_required":      false,
			"publisher_name":                    "Slack",
			"verified_publisher_display_name":   "Slack Technologies",
			"verified_publisher_id":             "slack-publisher",
			"verified_publisher_added_datetime": "2026-03-02T00:00:00Z",
		},
	})
	if entraNode == nil || entraNode.Kind != NodeKindServiceAccount {
		t.Fatalf("expected service account node from Entra service principal, got %#v", entraNode)
	}
	if got := queryRowString(entraNode.Properties, "app_owner_organization_id"); got != "tenant-vendor" {
		t.Fatalf("expected Entra owner organization to be preserved, got %#v", entraNode.Properties)
	}
	if got := queryRowString(entraNode.Properties, "publisher_name"); got != "Slack" {
		t.Fatalf("expected Entra publisher name to be preserved, got %#v", entraNode.Properties)
	}
	if got := queryRowString(entraNode.Properties, "verified_publisher_id"); got != "slack-publisher" {
		t.Fatalf("expected Entra verified publisher id to be preserved, got %#v", entraNode.Properties)
	}

	policyNode := cdcEventToNode("azure_policy_assignments", cdcEvent{
		ResourceID: "/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/pa-1",
		Payload: map[string]any{
			"id":                   "/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/pa-1",
			"display_name":         "Require Tags",
			"subscription_id":      "sub-1",
			"scope":                "/subscriptions/sub-1",
			"policy_definition_id": "/providers/Microsoft.Authorization/policyDefinitions/pd-1",
		},
	})
	if policyNode == nil || policyNode.Kind != NodeKindService {
		t.Fatalf("expected policy assignment service node, got %#v", policyNode)
	}
	if got := queryRowString(policyNode.Properties, "scope"); got != "/subscriptions/sub-1" {
		t.Fatalf("expected policy assignment scope to be preserved, got %#v", policyNode.Properties)
	}
}

func TestBuilder_AzureIdentityFallsBackToEntraServicePrincipalsWithVendorMetadata(t *testing.T) {
	t.Parallel()

	source := newMockDataSource()
	builder := NewBuilder(source, nil)

	source.setResult(`SELECT id, display_name, app_id, service_principal_type, account_enabled, app_owner_organization_id, app_role_assignment_required, publisher_name, verified_publisher_display_name, verified_publisher_id, verified_publisher_added_datetime, created_datetime, tags FROM entra_service_principals`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":                                "sp-slack",
			"display_name":                      "Slack Enterprise Grid",
			"app_id":                            "app-slack",
			"service_principal_type":            "Application",
			"account_enabled":                   true,
			"app_owner_organization_id":         "tenant-vendor",
			"app_role_assignment_required":      true,
			"publisher_name":                    "Slack",
			"verified_publisher_display_name":   "Slack Technologies",
			"verified_publisher_id":             "slack-publisher",
			"verified_publisher_added_datetime": "2026-03-02T00:00:00Z",
			"created_datetime":                  "2026-03-01T00:00:00Z",
		}},
	})

	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	spNode, ok := builder.Graph().GetNode("sp-slack")
	if !ok || spNode.Kind != NodeKindServiceAccount {
		t.Fatalf("expected service principal node from Entra fallback query, got %#v", spNode)
	}
	if got := queryRowString(spNode.Properties, "app_owner_organization_id"); got != "tenant-vendor" {
		t.Fatalf("expected Entra owner organization to be preserved, got %#v", spNode.Properties)
	}
	if got, _ := spNode.Properties["app_role_assignment_required"].(bool); !got {
		t.Fatalf("expected Entra app role assignment requirement to be preserved, got %#v", spNode.Properties)
	}
	if got := queryRowString(spNode.Properties, "publisher_name"); got != "Slack" {
		t.Fatalf("expected Entra publisher name to be preserved, got %#v", spNode.Properties)
	}
	if got := queryRowString(spNode.Properties, "verified_publisher_id"); got != "slack-publisher" {
		t.Fatalf("expected Entra verified publisher id to be preserved, got %#v", spNode.Properties)
	}
}

func TestBuilder_AzureRBACResourceScopeDoesNotOvergrantResourceGroup(t *testing.T) {
	t.Parallel()

	source := newMockDataSource()
	builder := NewBuilder(source, nil)

	vaultID := "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/vault-1"
	keyID := vaultID + "/keys/key-1"
	vmID := "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-1"

	source.setResult(`SELECT id, display_name, app_id, service_principal_type, account_enabled, app_owner_organization_id, app_role_assignment_required, publisher_name, verified_publisher_display_name, verified_publisher_id, verified_publisher_added_datetime, created_date_time, tags, subscription_id FROM azure_graph_service_principals`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":                     "sp-managed",
			"display_name":           "vm-managed-identity",
			"service_principal_type": "ManagedIdentity",
			"subscription_id":        "sub-1",
		}},
	})
	source.setResult(`SELECT id, name, subscription_id, resource_group, location, vm_size, os_type, provisioning_state, identity FROM azure_compute_virtual_machines`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":              vmID,
			"name":            "vm-1",
			"subscription_id": "sub-1",
			"resource_group":  "rg-app",
			"location":        "eastus",
		}},
	})
	source.setResult(`SELECT id, name, subscription_id, resource_group, location, tenant_id, vault_uri, access_policies, enable_purge_protection, enable_soft_delete FROM azure_keyvault_vaults`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":              vaultID,
			"name":            "vault-1",
			"subscription_id": "sub-1",
			"resource_group":  "rg-app",
			"location":        "eastus",
			"vault_uri":       "https://vault-1.vault.azure.net/",
		}},
	})
	source.setResult(`SELECT id, name, subscription_id, vault_uri, managed, attributes FROM azure_keyvault_keys`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":              keyID,
			"name":            "key-1",
			"subscription_id": "sub-1",
			"vault_uri":       "https://vault-1.vault.azure.net/",
		}},
	})
	source.setResult(`SELECT id, principal_id, principal_type, role_definition_id, scope, condition, can_delegate, delegated_managed_identity_id, description, subscription_id FROM azure_rbac_role_assignments`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":                 "ra-1",
			"principal_id":       "sp-managed",
			"principal_type":     "ServicePrincipal",
			"role_definition_id": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
			"scope":              vaultID,
			"subscription_id":    "sub-1",
		}},
	})

	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	g := builder.Graph()
	assertEdgeExists(t, g, "sp-managed", vaultID, EdgeKindCanAdmin)
	assertEdgeExists(t, g, "sp-managed", keyID, EdgeKindCanAdmin)
	assertEdgeAbsent(t, g, "sp-managed", vmID, EdgeKindCanAdmin)
}

func TestBuilder_AzureKeyVaultAccessPoliciesLinkKeysByVaultID(t *testing.T) {
	t.Parallel()

	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	vaultID := "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/vault-1"
	keyID := vaultID + "/keys/key-1"

	source.setResult(`SELECT id, name, subscription_id, resource_group, location, tenant_id, vault_uri, access_policies, enable_purge_protection, enable_soft_delete FROM azure_keyvault_vaults`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":              vaultID,
			"name":            "vault-1",
			"subscription_id": "sub-1",
			"resource_group":  "rg-app",
			"location":        "eastus",
			"vault_uri":       "https://vault-1.vault.azure.net/",
			"access_policies": []any{
				map[string]any{
					"object_id": "sp-managed",
					"permissions": map[string]any{
						"keys": []any{"get"},
					},
				},
			},
		}},
	})
	source.setResult(`SELECT id, name, subscription_id, vault_uri, managed, attributes FROM azure_keyvault_keys`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":              keyID,
			"name":            "key-1",
			"subscription_id": "sub-1",
			"vault_uri":       "",
		}},
	})
	source.setResult(`SELECT id, principal_id, principal_type, role_definition_id, scope, condition, can_delegate, delegated_managed_identity_id, description, subscription_id FROM azure_rbac_role_assignments`, &DataQueryResult{Rows: []map[string]any{}})
	source.setResult(`SELECT id, scope, subscription_id FROM azure_policy_assignments`, &DataQueryResult{Rows: []map[string]any{}})
	source.setResult(`SELECT id, vault_uri, access_policies FROM azure_keyvault_vaults`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":        vaultID,
			"vault_uri": "https://vault-1.vault.azure.net/",
			"access_policies": []any{
				map[string]any{
					"object_id": "sp-managed",
					"permissions": map[string]any{
						"keys": []any{"get"},
					},
				},
			},
		}},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	g := builder.Graph()
	keyNode, ok := g.GetNode(keyID)
	if !ok {
		t.Fatalf("expected key node %q to exist", keyID)
	}
	if got := queryRowString(keyNode.Properties, "vault_id"); got != vaultID {
		t.Fatalf("expected key node vault_id %q, got %q", vaultID, got)
	}
	assertEdgeExists(t, g, "sp-managed", keyID, EdgeKindCanRead)
}

func TestBuilder_LoadAzurePreferredIdentityNodesContinuesAfterEmptyDiscoveredTable(t *testing.T) {
	t.Parallel()

	source := newMockDataSource()
	builder := NewBuilder(source, nil)
	builder.availableTables = map[string]bool{
		"ENTRA_USERS":    true,
		"AZURE_AD_USERS": true,
	}

	source.setResult(`SELECT id, user_principal_name, display_name, mail, department, job_title, account_enabled, user_type, last_sign_in_datetime FROM entra_users`, &DataQueryResult{
		Rows: []map[string]any{},
	})
	source.setResult(`SELECT id, user_principal_name, display_name, mail FROM azure_ad_users`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":                  "user-1",
			"user_principal_name": "alice@example.com",
			"display_name":        "Alice",
			"mail":                "alice@example.com",
		}},
	})

	builder.loadAzurePreferredIdentityNodes(context.Background(), []nodeQuery{
		{
			table: "entra_users",
			query: `SELECT id, user_principal_name, display_name, mail, department, job_title, account_enabled, user_type, last_sign_in_datetime FROM entra_users`,
			parse: parseAzureUserNodes,
		},
		{
			table: "azure_ad_users",
			query: `SELECT id, user_principal_name, display_name, mail FROM azure_ad_users`,
			parse: parseAzureUserNodes,
		},
	})

	if node, ok := builder.Graph().GetNode("user-1"); !ok || node == nil {
		t.Fatal("expected fallback identity table rows to be loaded")
	}
}

func TestBuilder_QueryAzureRBACRoleAssignmentsFallsBackWithoutDiscovery(t *testing.T) {
	t.Parallel()

	source := &azureQueryErrorSource{
		results: map[string]*DataQueryResult{
			`SELECT id, principal_id, principal_type, role_definition_id, role_definition_name, scope, condition, can_delegate, delegated_managed_identity_id, description, subscription_id FROM azure_authorization_role_assignments`: {
				Rows: []map[string]any{{
					"id":                   "ra-legacy",
					"principal_id":         "sp-managed",
					"principal_type":       "ServicePrincipal",
					"role_definition_id":   "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
					"role_definition_name": "Owner",
					"scope":                "/subscriptions/sub-1",
					"subscription_id":      "sub-1",
				}},
			},
		},
		errors: map[string]error{
			`SELECT id, principal_id, principal_type, role_definition_id, scope, condition, can_delegate, delegated_managed_identity_id, description, subscription_id FROM azure_rbac_role_assignments`: errors.New("table not found"),
		},
	}
	builder := NewBuilder(source, nil)

	rows, err := builder.queryAzureRBACRoleAssignments(context.Background())
	if err != nil {
		t.Fatalf("expected legacy fallback rows, got error %v", err)
	}
	if len(rows) != 1 || queryRowString(rows[0], "id") != "ra-legacy" {
		t.Fatalf("expected legacy RBAC fallback rows, got %#v", rows)
	}
}

func TestAzureNodeWithinScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		node  *Node
		scope string
		want  bool
	}{
		{
			name: "resource scope does not match sibling resource in same group",
			node: &Node{
				ID:         "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-1",
				Kind:       NodeKindInstance,
				Provider:   "azure",
				Account:    "sub-1",
				Properties: map[string]any{"resource_group": "rg-app"},
			},
			scope: "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/vault-1",
			want:  false,
		},
		{
			name: "subscription scope does not match similar subscription identifier",
			node: &Node{
				ID:         "/subscriptions/sub-10/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-1",
				Kind:       NodeKindInstance,
				Provider:   "azure",
				Account:    "sub-10",
				Properties: map[string]any{"resource_group": "rg-app"},
			},
			scope: "/subscriptions/sub-1",
			want:  false,
		},
		{
			name: "resource scope still matches descendants",
			node: &Node{
				ID:         "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/vault-1/keys/key-1",
				Kind:       NodeKindSecret,
				Provider:   "azure",
				Account:    "sub-1",
				Properties: map[string]any{"resource_group": "rg-app"},
			},
			scope: "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/vault-1",
			want:  true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := azureNodeWithinScope(tc.node, tc.scope); got != tc.want {
				t.Fatalf("azureNodeWithinScope(%q, %q) = %v, want %v", tc.node.ID, tc.scope, got, tc.want)
			}
		})
	}
}

func TestAzurePermissionsToEdgeKindUsesHighestPermissionScore(t *testing.T) {
	t.Parallel()

	if got := azurePermissionsToEdgeKind(map[string]any{
		"keys": []any{"get", "backup"},
	}); got != EdgeKindCanAdmin {
		t.Fatalf("expected admin edge kind, got %s", got)
	}

	if got := azurePermissionsToEdgeKind(map[string]any{
		"secrets": []any{"get", "set"},
	}); got != EdgeKindCanWrite {
		t.Fatalf("expected write edge kind, got %s", got)
	}
}

func TestAzureVaultResourceIDFromKeyID(t *testing.T) {
	t.Parallel()

	keyID := "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/vault-1/keys/key-1"
	want := "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/vault-1"
	if got := azureVaultResourceIDFromKeyID(keyID); got != want {
		t.Fatalf("azureVaultResourceIDFromKeyID(%q) = %q, want %q", keyID, got, want)
	}

	if got := azureVaultResourceIDFromKeyID("/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/vault-1"); got != "" {
		t.Fatalf("expected empty vault id for non-key resource, got %q", got)
	}
}

type azureQueryErrorSource struct {
	results map[string]*DataQueryResult
	errors  map[string]error
}

func (s *azureQueryErrorSource) Query(ctx context.Context, query string, args ...any) (*DataQueryResult, error) {
	_ = ctx
	_ = args
	if err := s.errors[query]; err != nil {
		return nil, err
	}
	if result := s.results[query]; result != nil {
		return result, nil
	}
	return &DataQueryResult{Rows: []map[string]any{}}, nil
}

func assertEdgeAbsent(t *testing.T, g *Graph, source string, target string, kind EdgeKind) {
	t.Helper()
	for _, edge := range g.GetOutEdges(source) {
		if edge.Target == target && edge.Kind == kind {
			t.Fatalf("did not expect edge %s --%s--> %s", source, kind, target)
		}
	}
}
