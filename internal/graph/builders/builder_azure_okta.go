package builders

import (
	"context"
	"strings"
)

// Azure + Okta Builder Methods

func (b *Builder) buildAzureNodes(ctx context.Context) {
	queries := []nodeQuery{
		{
			table: "azure_ad_service_principals",
			query: `SELECT id, display_name, app_id, service_principal_type FROM azure_ad_service_principals`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, sp := range rows {
					nodes = append(nodes, &Node{
						ID: toString(sp["id"]), Kind: NodeKindServiceAccount, Name: toString(sp["display_name"]),
						Provider: "azure", Properties: map[string]any{"app_id": sp["app_id"], "type": sp["service_principal_type"]},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_ad_users",
			query: `SELECT id, user_principal_name, display_name, mail FROM azure_ad_users`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, u := range rows {
					nodes = append(nodes, &Node{
						ID: toString(u["id"]), Kind: NodeKindUser, Name: toString(u["display_name"]),
						Provider: "azure", Properties: map[string]any{"upn": u["user_principal_name"], "mail": u["mail"]},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_compute_virtual_machines",
			query: `SELECT id, name, subscription_id, resource_group, location, identity FROM azure_compute_virtual_machines`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, vm := range rows {
					nodes = append(nodes, &Node{
						ID: toString(vm["id"]), Kind: NodeKindInstance, Name: toString(vm["name"]),
						Provider: "azure", Account: toString(vm["subscription_id"]), Region: toString(vm["location"]),
						Properties: map[string]any{"resource_group": vm["resource_group"], "identity": vm["identity"]},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_network_security_groups",
			query: `SELECT id, name, subscription_id, resource_group, location, security_rules, default_security_rules FROM azure_network_security_groups`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, nsg := range rows {
					node := azureNetworkSecurityGroupNodeFromRecord(nsg, "azure", "", "")
					if node == nil {
						continue
					}
					nodes = append(nodes, node)
				}
				return nodes
			},
		},
		{
			table: "azure_storage_accounts",
			query: `SELECT id, name, subscription_id, resource_group, location, allow_blob_public_access FROM azure_storage_accounts`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, sa := range rows {
					isPublic := toBool(sa["allow_blob_public_access"])
					risk := RiskNone
					if isPublic {
						risk = RiskHigh
					}
					nodes = append(nodes, &Node{
						ID: toString(sa["id"]), Kind: NodeKindBucket, Name: toString(sa["name"]),
						Provider: "azure", Account: toString(sa["subscription_id"]), Region: toString(sa["location"]),
						Risk: risk, Properties: map[string]any{"resource_group": sa["resource_group"], "public": isPublic},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_sql_databases",
			query: `SELECT id, name, subscription_id, resource_group, location, server_name FROM azure_sql_databases`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, db := range rows {
					nodes = append(nodes, &Node{
						ID: toString(db["id"]), Kind: NodeKindDatabase, Name: toString(db["name"]),
						Provider: "azure", Account: toString(db["subscription_id"]), Region: toString(db["location"]),
						Properties: map[string]any{"resource_group": db["resource_group"], "server": db["server_name"]},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_keyvault_vaults",
			query: `SELECT id, name, subscription_id, resource_group, location FROM azure_keyvault_vaults`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, kv := range rows {
					nodes = append(nodes, &Node{
						ID: toString(kv["id"]), Kind: NodeKindSecret, Name: toString(kv["name"]),
						Provider: "azure", Account: toString(kv["subscription_id"]), Region: toString(kv["location"]),
						Risk: RiskHigh, Properties: map[string]any{"resource_group": kv["resource_group"]},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_functions_apps",
			query: `SELECT id, name, subscription_id, resource_group, location, identity FROM azure_functions_apps`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, fn := range rows {
					nodes = append(nodes, &Node{
						ID: toString(fn["id"]), Kind: NodeKindFunction, Name: toString(fn["name"]),
						Provider: "azure", Account: toString(fn["subscription_id"]), Region: toString(fn["location"]),
						Properties: map[string]any{"resource_group": fn["resource_group"], "identity": fn["identity"]},
					})
				}
				return nodes
			},
		},
	}

	b.runNodeQueries(ctx, queries)
}

func (b *Builder) buildOktaNodes(ctx context.Context) {
	queries := []nodeQuery{
		{
			table: "okta_users",
			query: `SELECT id, login, email, status, last_login, mfa_enrolled, is_admin FROM okta_users`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, u := range rows {
					id := toString(u["id"])
					if id == "" {
						continue
					}
					name := toString(u["login"])
					if name == "" {
						name = toString(u["email"])
					}
					if name == "" {
						name = id
					}
					nodes = append(nodes, &Node{
						ID: id, Kind: NodeKindUser, Name: name,
						Provider: "okta",
						Properties: map[string]any{
							"email":        u["email"],
							"status":       u["status"],
							"last_login":   u["last_login"],
							"mfa_enrolled": u["mfa_enrolled"],
							"is_admin":     u["is_admin"],
						},
					})
				}
				return nodes
			},
		},
		{
			table: "okta_groups",
			query: `SELECT id, name, description, type FROM okta_groups`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, g := range rows {
					id := toString(g["id"])
					if id == "" {
						continue
					}
					name := toString(g["name"])
					if name == "" {
						name = id
					}
					nodes = append(nodes, &Node{
						ID: id, Kind: NodeKindGroup, Name: name,
						Provider: "okta",
						Properties: map[string]any{
							"description": g["description"],
							"type":        g["type"],
						},
					})
				}
				return nodes
			},
		},
		{
			table: "okta_applications",
			query: `SELECT id, label, name, status, sign_on_mode FROM okta_applications`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, app := range rows {
					id := toString(app["id"])
					if id == "" {
						continue
					}
					name := toString(app["label"])
					if name == "" {
						name = toString(app["name"])
					}
					if name == "" {
						name = id
					}
					nodes = append(nodes, &Node{
						ID: id, Kind: NodeKindApplication, Name: name,
						Provider: "okta",
						Properties: map[string]any{
							"status":       app["status"],
							"sign_on_mode": app["sign_on_mode"],
						},
					})
				}
				return nodes
			},
		},
		{
			table: "okta_admin_roles",
			query: `SELECT DISTINCT role_type, role_label FROM okta_admin_roles WHERE role_type IS NOT NULL`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, role := range rows {
					roleType := strings.TrimSpace(toString(role["role_type"]))
					if roleType == "" {
						continue
					}
					roleID := "okta_admin_role:" + strings.ToLower(roleType)
					name := toString(role["role_label"])
					if name == "" {
						name = roleType
					}
					nodes = append(nodes, &Node{
						ID: roleID, Kind: NodeKindRole, Name: name,
						Provider:   "okta",
						Properties: map[string]any{"role_type": roleType},
					})
				}
				return nodes
			},
		},
	}

	b.runNodeQueries(ctx, queries)
}

func (b *Builder) buildAzureEdges(ctx context.Context) {
	roleAssignments, err := b.queryIfExists(ctx, "azure_authorization_role_assignments",
		`SELECT id, principal_id, role_definition_name, scope FROM azure_authorization_role_assignments`)
	if err != nil {
		b.logger.Debug("failed to query Azure role assignments", "error", err)
		return
	}

	// Use indexed provider lookup instead of GetAllNodes scan
	azureNodes := b.graph.GetNodesByKindIndexed(NodeKindBucket, NodeKindInstance, NodeKindDatabase, NodeKindSecret, NodeKindFunction)

	for _, ra := range roleAssignments.Rows {
		principalID := toString(ra["principal_id"])
		roleName := toString(ra["role_definition_name"])
		scope := toString(ra["scope"])
		edgeKind := azureRoleToEdgeKind(roleName)

		for _, node := range azureNodes {
			if node.Provider != "azure" {
				continue
			}
			if contains(node.ID, scope) || scope == "/" {
				b.graph.AddEdge(&Edge{
					ID:     principalID + "->" + node.ID + ":" + roleName,
					Source: principalID,
					Target: node.ID,
					Kind:   edgeKind,
					Effect: EdgeEffectAllow,
					Properties: map[string]any{
						"role":  roleName,
						"scope": scope,
					},
				})
			}
		}
	}
	b.logger.Debug("processed Azure role assignments", "count", len(roleAssignments.Rows))

	b.buildAzureManagedIdentityEdges(ctx)
}

func (b *Builder) buildAzureManagedIdentityEdges(_ context.Context) {
	// Link VMs and Functions to their managed identities
	for _, node := range b.graph.GetAllNodes() {
		if node.Provider != "azure" {
			continue
		}
		if node.Kind != NodeKindInstance && node.Kind != NodeKindFunction {
			continue
		}

		identity, ok := node.Properties["identity"].(map[string]any)
		if !ok {
			continue
		}

		// System-assigned managed identity
		if principalID, ok := identity["principal_id"].(string); ok && principalID != "" {
			b.graph.AddEdge(&Edge{
				ID:     node.ID + "->identity->" + principalID,
				Source: node.ID,
				Target: principalID,
				Kind:   EdgeKindCanAssume,
				Effect: EdgeEffectAllow,
				Properties: map[string]any{
					"mechanism": "system_assigned_identity",
				},
			})
		}

		// User-assigned managed identities
		if userIdentities, ok := identity["user_assigned_identities"].(map[string]any); ok {
			for identityID := range userIdentities {
				b.graph.AddEdge(&Edge{
					ID:     node.ID + "->identity->" + identityID,
					Source: node.ID,
					Target: identityID,
					Kind:   EdgeKindCanAssume,
					Effect: EdgeEffectAllow,
					Properties: map[string]any{
						"mechanism": "user_assigned_identity",
					},
				})
			}
		}
	}
}

func azureRoleToEdgeKind(role string) EdgeKind {
	switch {
	case contains(role, "Owner"), contains(role, "Contributor"):
		return EdgeKindCanAdmin
	case contains(role, "Writer"):
		return EdgeKindCanWrite
	case contains(role, "Delete"):
		return EdgeKindCanDelete
	default:
		return EdgeKindCanRead
	}
}
