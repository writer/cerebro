package builders

import (
	"context"
	"strings"
)

const azureTenantRootNodeID = "azure://tenant"

var azureBuiltInRoleNames = map[string]string{
	"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
	"b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
	"acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
	"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
	"ba92f5b4-2d11-453d-a403-e96b0029c9fe": "Storage Blob Data Contributor",
	"2a2b9908-6ea1-4ae2-8e65-a410df84e7d1": "Storage Blob Data Reader",
	"00482a5a-887f-4fb3-b363-3b7fe8e74483": "Key Vault Administrator",
	"4633458b-17de-408a-b874-0445c86b69e6": "Key Vault Secrets User",
	"21090545-7ca7-4776-b22c-e363652d74d2": "Key Vault Reader",
	"7ca78c08-252a-4471-8644-bb5ff32d4ba0": "Key Vault Crypto Officer",
	"12338af0-0e69-4776-bea7-57ae8d297424": "Key Vault Certificates Officer",
}

// Azure Builder Methods

func (b *Builder) buildAzureNodes(ctx context.Context) {
	b.buildAzureIdentityNodes(ctx)

	queries := []nodeQuery{
		{
			table: "azure_compute_virtual_machines",
			query: `SELECT id, name, subscription_id, resource_group, location, vm_size, os_type, provisioning_state, identity FROM azure_compute_virtual_machines`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, vm := range rows {
					id := toString(vm["id"])
					if id == "" {
						continue
					}
					nodes = append(nodes, &Node{
						ID:       id,
						Kind:     NodeKindInstance,
						Name:     firstNonEmpty(queryRowString(vm, "name"), azureResourceDisplayName(id), id),
						Provider: "azure",
						Account:  queryRowString(vm, "subscription_id"),
						Region:   queryRowString(vm, "location"),
						Properties: map[string]any{
							"resource_group":      queryRow(vm, "resource_group"),
							"identity":            queryRow(vm, "identity"),
							"vm_size":             queryRow(vm, "vm_size"),
							"os_type":             queryRow(vm, "os_type"),
							"provisioning_state":  queryRow(vm, "provisioning_state"),
							"azure_resource_type": "virtual_machine",
						},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_aks_clusters",
			query: `SELECT id, name, subscription_id, resource_group, location, private_cluster_enabled, authorized_ip_ranges, identity, kubernetes_version, fqdn FROM azure_aks_clusters`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, cluster := range rows {
					id := toString(cluster["id"])
					if id == "" {
						continue
					}
					public := azureAuthorizedIPRangesPublic(queryRow(cluster, "authorized_ip_ranges"))
					risk := RiskNone
					if public {
						risk = RiskMedium
					}
					nodes = append(nodes, &Node{
						ID:       id,
						Kind:     NodeKindService,
						Name:     firstNonEmpty(queryRowString(cluster, "name"), azureResourceDisplayName(id), id),
						Provider: "azure",
						Account:  queryRowString(cluster, "subscription_id"),
						Region:   queryRowString(cluster, "location"),
						Risk:     risk,
						Properties: map[string]any{
							"resource_group":          queryRow(cluster, "resource_group"),
							"identity":                queryRow(cluster, "identity"),
							"kubernetes_version":      queryRow(cluster, "kubernetes_version"),
							"fqdn":                    queryRow(cluster, "fqdn"),
							"private_cluster_enabled": queryRow(cluster, "private_cluster_enabled"),
							"authorized_ip_ranges":    queryRow(cluster, "authorized_ip_ranges"),
							"public":                  public,
							"azure_resource_type":     "aks_cluster",
						},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_storage_accounts",
			query: `SELECT id, name, subscription_id, resource_group, location, allow_blob_public_access, network_acls, minimum_tls_version, https_only FROM azure_storage_accounts`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, sa := range rows {
					id := toString(sa["id"])
					if id == "" {
						continue
					}
					isPublic := toBool(sa["allow_blob_public_access"])
					risk := RiskNone
					if isPublic {
						risk = RiskHigh
					}
					nodes = append(nodes, &Node{
						ID:       id,
						Kind:     NodeKindBucket,
						Name:     firstNonEmpty(queryRowString(sa, "name"), azureResourceDisplayName(id), id),
						Provider: "azure",
						Account:  queryRowString(sa, "subscription_id"),
						Region:   queryRowString(sa, "location"),
						Risk:     risk,
						Properties: map[string]any{
							"resource_group":           queryRow(sa, "resource_group"),
							"public":                   isPublic,
							"allow_blob_public_access": queryRow(sa, "allow_blob_public_access"),
							"network_acls":             queryRow(sa, "network_acls"),
							"minimum_tls_version":      queryRow(sa, "minimum_tls_version"),
							"https_only":               queryRow(sa, "https_only"),
							"azure_resource_type":      "storage_account",
						},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_storage_containers",
			query: `SELECT id, name, account_name, resource_group, subscription_id, public_access, has_immutability_policy, legal_hold FROM azure_storage_containers`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, container := range rows {
					id := toString(container["id"])
					if id == "" {
						continue
					}
					publicAccess := queryRowString(container, "public_access")
					isPublic := publicAccess != "" && !strings.EqualFold(publicAccess, "none")
					risk := RiskNone
					if isPublic {
						risk = RiskCritical
					}
					nodes = append(nodes, &Node{
						ID:       id,
						Kind:     NodeKindBucket,
						Name:     firstNonEmpty(queryRowString(container, "name"), azureResourceDisplayName(id), id),
						Provider: "azure",
						Account:  queryRowString(container, "subscription_id"),
						Risk:     risk,
						Properties: map[string]any{
							"resource_group":          queryRow(container, "resource_group"),
							"account_name":            queryRow(container, "account_name"),
							"public":                  isPublic,
							"public_access":           publicAccess,
							"has_immutability_policy": queryRow(container, "has_immutability_policy"),
							"legal_hold":              queryRow(container, "legal_hold"),
							"azure_resource_type":     "storage_container",
						},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_storage_blobs",
			query: `SELECT id, name, account_name, container_name, resource_group, subscription_id, content_length, content_type FROM azure_storage_blobs`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, blob := range rows {
					id := toString(blob["id"])
					if id == "" {
						continue
					}
					nodes = append(nodes, &Node{
						ID:       id,
						Kind:     NodeKindBucket,
						Name:     firstNonEmpty(queryRowString(blob, "name"), azureResourceDisplayName(id), id),
						Provider: "azure",
						Account:  queryRowString(blob, "subscription_id"),
						Properties: map[string]any{
							"resource_group":      queryRow(blob, "resource_group"),
							"account_name":        queryRow(blob, "account_name"),
							"container_name":      queryRow(blob, "container_name"),
							"content_length":      queryRow(blob, "content_length"),
							"content_type":        queryRow(blob, "content_type"),
							"azure_resource_type": "storage_blob",
						},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_sql_servers",
			query: `SELECT id, name, subscription_id, resource_group, location, version, state, public_network_access, administrator_login FROM azure_sql_servers`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, server := range rows {
					id := toString(server["id"])
					if id == "" {
						continue
					}
					isPublic := strings.EqualFold(strings.TrimSpace(queryRowString(server, "public_network_access")), "enabled")
					risk := RiskNone
					if isPublic {
						risk = RiskHigh
					}
					nodes = append(nodes, &Node{
						ID:       id,
						Kind:     NodeKindDatabase,
						Name:     firstNonEmpty(queryRowString(server, "name"), azureResourceDisplayName(id), id),
						Provider: "azure",
						Account:  queryRowString(server, "subscription_id"),
						Region:   queryRowString(server, "location"),
						Risk:     risk,
						Properties: map[string]any{
							"resource_group":        queryRow(server, "resource_group"),
							"version":               queryRow(server, "version"),
							"state":                 queryRow(server, "state"),
							"administrator_login":   queryRow(server, "administrator_login"),
							"public_network_access": queryRow(server, "public_network_access"),
							"public":                isPublic,
							"azure_resource_type":   "sql_server",
						},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_sql_databases",
			query: `SELECT id, name, subscription_id, resource_group, location, server_name, status FROM azure_sql_databases`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, db := range rows {
					id := toString(db["id"])
					if id == "" {
						continue
					}
					nodes = append(nodes, &Node{
						ID:       id,
						Kind:     NodeKindDatabase,
						Name:     firstNonEmpty(queryRowString(db, "name"), azureResourceDisplayName(id), id),
						Provider: "azure",
						Account:  queryRowString(db, "subscription_id"),
						Region:   queryRowString(db, "location"),
						Properties: map[string]any{
							"resource_group":      queryRow(db, "resource_group"),
							"server":              queryRow(db, "server_name"),
							"status":              queryRow(db, "status"),
							"azure_resource_type": "sql_database",
						},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_keyvault_vaults",
			query: `SELECT id, name, subscription_id, resource_group, location, tenant_id, vault_uri, access_policies, enable_purge_protection, enable_soft_delete FROM azure_keyvault_vaults`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, kv := range rows {
					id := toString(kv["id"])
					if id == "" {
						continue
					}
					nodes = append(nodes, &Node{
						ID:       id,
						Kind:     NodeKindSecret,
						Name:     firstNonEmpty(queryRowString(kv, "name"), azureResourceDisplayName(id), id),
						Provider: "azure",
						Account:  queryRowString(kv, "subscription_id"),
						Region:   queryRowString(kv, "location"),
						Risk:     RiskHigh,
						Properties: map[string]any{
							"resource_group":          queryRow(kv, "resource_group"),
							"tenant_id":               queryRow(kv, "tenant_id"),
							"vault_uri":               queryRow(kv, "vault_uri"),
							"access_policies":         queryRow(kv, "access_policies"),
							"enable_purge_protection": queryRow(kv, "enable_purge_protection"),
							"enable_soft_delete":      queryRow(kv, "enable_soft_delete"),
							"azure_resource_type":     "key_vault",
						},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_keyvault_keys",
			query: `SELECT id, name, subscription_id, vault_uri, managed, attributes FROM azure_keyvault_keys`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, key := range rows {
					id := toString(key["id"])
					if id == "" {
						continue
					}
					nodes = append(nodes, &Node{
						ID:       id,
						Kind:     NodeKindSecret,
						Name:     firstNonEmpty(queryRowString(key, "name"), azureResourceDisplayName(id), id),
						Provider: "azure",
						Account:  queryRowString(key, "subscription_id"),
						Risk:     RiskHigh,
						Properties: map[string]any{
							"vault_id":            azureVaultResourceIDFromKeyID(id),
							"vault_uri":           queryRow(key, "vault_uri"),
							"managed":             queryRow(key, "managed"),
							"attributes":          queryRow(key, "attributes"),
							"azure_resource_type": "key_vault_key",
						},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_functions_apps",
			query: `SELECT id, name, subscription_id, resource_group, location, identity, auth_level, http_trigger, https_only FROM azure_functions_apps`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, fn := range rows {
					id := toString(fn["id"])
					if id == "" {
						continue
					}
					public := toBool(fn["http_trigger"]) && !strings.EqualFold(queryRowString(fn, "auth_level"), "admin")
					risk := RiskNone
					if public {
						risk = RiskMedium
					}
					nodes = append(nodes, &Node{
						ID:       id,
						Kind:     NodeKindFunction,
						Name:     firstNonEmpty(queryRowString(fn, "name"), azureResourceDisplayName(id), id),
						Provider: "azure",
						Account:  queryRowString(fn, "subscription_id"),
						Region:   queryRowString(fn, "location"),
						Risk:     risk,
						Properties: map[string]any{
							"resource_group":      queryRow(fn, "resource_group"),
							"identity":            queryRow(fn, "identity"),
							"auth_level":          queryRow(fn, "auth_level"),
							"http_trigger":        queryRow(fn, "http_trigger"),
							"https_only":          queryRow(fn, "https_only"),
							"public":              public,
							"azure_resource_type": "function_app",
						},
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
					id := toString(nsg["id"])
					if id == "" {
						continue
					}
					public := azureNSGAllowsInternet(queryRow(nsg, "security_rules"), queryRow(nsg, "default_security_rules"))
					risk := RiskNone
					if public {
						risk = RiskHigh
					}
					nodes = append(nodes, &Node{
						ID:       id,
						Kind:     NodeKindNetwork,
						Name:     firstNonEmpty(queryRowString(nsg, "name"), azureResourceDisplayName(id), id),
						Provider: "azure",
						Account:  queryRowString(nsg, "subscription_id"),
						Region:   queryRowString(nsg, "location"),
						Risk:     risk,
						Properties: map[string]any{
							"resource_group":         queryRow(nsg, "resource_group"),
							"security_rules":         queryRow(nsg, "security_rules"),
							"default_security_rules": queryRow(nsg, "default_security_rules"),
							"public":                 public,
							"azure_resource_type":    "network_security_group",
						},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_network_virtual_networks",
			query: `SELECT id, name, subscription_id, resource_group, location, address_space, subnets, peerings, enable_ddos_protection FROM azure_network_virtual_networks`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, vnet := range rows {
					id := toString(vnet["id"])
					if id == "" {
						continue
					}
					nodes = append(nodes, &Node{
						ID:       id,
						Kind:     NodeKindNetwork,
						Name:     firstNonEmpty(queryRowString(vnet, "name"), azureResourceDisplayName(id), id),
						Provider: "azure",
						Account:  queryRowString(vnet, "subscription_id"),
						Region:   queryRowString(vnet, "location"),
						Properties: map[string]any{
							"resource_group":         queryRow(vnet, "resource_group"),
							"address_space":          queryRow(vnet, "address_space"),
							"subnets":                queryRow(vnet, "subnets"),
							"peerings":               queryRow(vnet, "peerings"),
							"enable_ddos_protection": queryRow(vnet, "enable_ddos_protection"),
							"azure_resource_type":    "virtual_network",
						},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_network_public_ip_addresses",
			query: `SELECT id, name, subscription_id, resource_group, location, ip_address, public_ip_allocation_method, ip_configuration FROM azure_network_public_ip_addresses`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, publicIP := range rows {
					id := toString(publicIP["id"])
					if id == "" {
						continue
					}
					ipAddress := queryRowString(publicIP, "ip_address")
					public := strings.TrimSpace(ipAddress) != ""
					risk := RiskNone
					if public {
						risk = RiskMedium
					}
					nodes = append(nodes, &Node{
						ID:       id,
						Kind:     NodeKindNetwork,
						Name:     firstNonEmpty(queryRowString(publicIP, "name"), azureResourceDisplayName(id), id),
						Provider: "azure",
						Account:  queryRowString(publicIP, "subscription_id"),
						Region:   queryRowString(publicIP, "location"),
						Risk:     risk,
						Properties: map[string]any{
							"resource_group":              queryRow(publicIP, "resource_group"),
							"public_ip":                   ipAddress,
							"public":                      public,
							"public_ip_allocation_method": queryRow(publicIP, "public_ip_allocation_method"),
							"ip_configuration":            queryRow(publicIP, "ip_configuration"),
							"azure_resource_type":         "public_ip",
						},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_network_load_balancers",
			query: `SELECT id, name, subscription_id, resource_group, location, sku, frontend_ip_configurations FROM azure_network_load_balancers`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, lb := range rows {
					id := toString(lb["id"])
					if id == "" {
						continue
					}
					public := azureLoadBalancerHasPublicFrontend(queryRow(lb, "frontend_ip_configurations"))
					risk := RiskNone
					if public {
						risk = RiskMedium
					}
					nodes = append(nodes, &Node{
						ID:       id,
						Kind:     NodeKindNetwork,
						Name:     firstNonEmpty(queryRowString(lb, "name"), azureResourceDisplayName(id), id),
						Provider: "azure",
						Account:  queryRowString(lb, "subscription_id"),
						Region:   queryRowString(lb, "location"),
						Risk:     risk,
						Properties: map[string]any{
							"resource_group":             queryRow(lb, "resource_group"),
							"sku":                        queryRow(lb, "sku"),
							"frontend_ip_configurations": queryRow(lb, "frontend_ip_configurations"),
							"public":                     public,
							"azure_resource_type":        "load_balancer",
						},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_network_interfaces",
			query: `SELECT id, name, subscription_id, resource_group, location, ip_configurations, network_security_group, virtual_machine FROM azure_network_interfaces`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, nic := range rows {
					id := toString(nic["id"])
					if id == "" {
						continue
					}
					public := azureNICHasPublicFrontend(queryRow(nic, "ip_configurations"))
					risk := RiskNone
					if public {
						risk = RiskMedium
					}
					nodes = append(nodes, &Node{
						ID:       id,
						Kind:     NodeKindNetwork,
						Name:     firstNonEmpty(queryRowString(nic, "name"), azureResourceDisplayName(id), id),
						Provider: "azure",
						Account:  queryRowString(nic, "subscription_id"),
						Region:   queryRowString(nic, "location"),
						Risk:     risk,
						Properties: map[string]any{
							"resource_group":         queryRow(nic, "resource_group"),
							"ip_configurations":      queryRow(nic, "ip_configurations"),
							"network_security_group": queryRow(nic, "network_security_group"),
							"virtual_machine":        queryRow(nic, "virtual_machine"),
							"public":                 public,
							"azure_resource_type":    "network_interface",
						},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_compute_disks",
			query: `SELECT id, name, subscription_id, resource_group, location, disk_size_gb, disk_state, managed_by FROM azure_compute_disks`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, disk := range rows {
					id := toString(disk["id"])
					if id == "" {
						continue
					}
					nodes = append(nodes, &Node{
						ID:       id,
						Kind:     NodeKindService,
						Name:     firstNonEmpty(queryRowString(disk, "name"), azureResourceDisplayName(id), id),
						Provider: "azure",
						Account:  queryRowString(disk, "subscription_id"),
						Region:   queryRowString(disk, "location"),
						Properties: map[string]any{
							"resource_group":      queryRow(disk, "resource_group"),
							"disk_size_gb":        queryRow(disk, "disk_size_gb"),
							"disk_state":          queryRow(disk, "disk_state"),
							"managed_by":          queryRow(disk, "managed_by"),
							"azure_resource_type": "disk",
						},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_policy_assignments",
			query: `SELECT id, name, subscription_id, location, display_name, scope, policy_definition_id, enforcement_mode, identity, metadata, parameters FROM azure_policy_assignments`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, assignment := range rows {
					id := toString(assignment["id"])
					if id == "" {
						continue
					}
					nodes = append(nodes, &Node{
						ID:       id,
						Kind:     NodeKindService,
						Name:     firstNonEmpty(queryRowString(assignment, "display_name"), queryRowString(assignment, "name"), azureResourceDisplayName(id), id),
						Provider: "azure",
						Account:  queryRowString(assignment, "subscription_id"),
						Region:   queryRowString(assignment, "location"),
						Properties: map[string]any{
							"scope":                queryRow(assignment, "scope"),
							"policy_definition_id": queryRow(assignment, "policy_definition_id"),
							"enforcement_mode":     queryRow(assignment, "enforcement_mode"),
							"identity":             queryRow(assignment, "identity"),
							"metadata":             queryRow(assignment, "metadata"),
							"parameters":           queryRow(assignment, "parameters"),
							"azure_resource_type":  "policy_assignment",
						},
					})
				}
				return nodes
			},
		},
	}

	b.runNodeQueries(ctx, queries)
}

func (b *Builder) buildAzureIdentityNodes(ctx context.Context) {
	b.loadAzurePreferredIdentityNodes(ctx, []nodeQuery{
		{
			table: "azure_graph_service_principals",
			query: `SELECT id, display_name, app_id, service_principal_type, account_enabled, app_owner_organization_id, publisher_name, created_date_time, tags, subscription_id FROM azure_graph_service_principals`,
			parse: parseAzureServicePrincipalNodes,
		},
		{
			table: "entra_service_principals",
			query: `SELECT id, display_name, app_id, service_principal_type, account_enabled, app_role_assignment_required, created_datetime, tags FROM entra_service_principals`,
			parse: parseAzureServicePrincipalNodes,
		},
		{
			table: "azure_ad_service_principals",
			query: `SELECT id, display_name, app_id, service_principal_type FROM azure_ad_service_principals`,
			parse: parseAzureServicePrincipalNodes,
		},
	})

	b.loadAzurePreferredIdentityNodes(ctx, []nodeQuery{
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

	b.runAzureNodeQuery(ctx, nodeQuery{
		table: "entra_groups",
		query: `SELECT id, display_name, description, mail, security_enabled, group_types FROM entra_groups`,
		parse: func(rows []map[string]any) []*Node {
			nodes := make([]*Node, 0, len(rows))
			for _, group := range rows {
				id := toString(group["id"])
				if id == "" {
					continue
				}
				nodes = append(nodes, &Node{
					ID:       id,
					Kind:     NodeKindGroup,
					Name:     firstNonEmpty(queryRowString(group, "display_name"), id),
					Provider: "azure",
					Properties: map[string]any{
						"description":         queryRow(group, "description"),
						"mail":                queryRow(group, "mail"),
						"security_enabled":    queryRow(group, "security_enabled"),
						"group_types":         queryRow(group, "group_types"),
						"azure_resource_type": "entra_group",
					},
				})
			}
			return nodes
		},
	})

	b.runAzureNodeQuery(ctx, nodeQuery{
		table: "entra_directory_roles",
		query: `SELECT id, display_name, description, is_built_in, is_enabled FROM entra_directory_roles`,
		parse: func(rows []map[string]any) []*Node {
			nodes := make([]*Node, 0, len(rows))
			for _, role := range rows {
				rawID := toString(role["id"])
				if rawID == "" {
					continue
				}
				roleID := azureDirectoryRoleNodeID(rawID)
				nodes = append(nodes, &Node{
					ID:       roleID,
					Kind:     NodeKindRole,
					Name:     firstNonEmpty(queryRowString(role, "display_name"), rawID),
					Provider: "azure",
					Properties: map[string]any{
						"directory_role_id":   rawID,
						"description":         queryRow(role, "description"),
						"is_built_in":         queryRow(role, "is_built_in"),
						"is_enabled":          queryRow(role, "is_enabled"),
						"azure_resource_type": "entra_directory_role",
					},
				})
			}
			return nodes
		},
	})
}

func (b *Builder) buildAzureEdges(ctx context.Context) {
	b.buildAzureScopeHierarchy()
	b.buildAzureRBACEdges(ctx)
	b.buildAzureEntraDirectoryRoleEdges(ctx)
	b.buildAzurePolicyAssignmentEdges(ctx)
	b.buildAzureKeyVaultAccessPolicyEdges(ctx)
	b.buildAzureManagedIdentityEdges(ctx)
}

func (b *Builder) buildAzureScopeHierarchy() {
	for _, node := range b.graph.GetAllNodes() {
		if node == nil || node.Provider != "azure" {
			continue
		}
		b.ensureAzureScopeAncestry(node.ID, node.Account, queryRowString(node.Properties, "resource_group"))
		if scope := queryRowString(node.Properties, "scope"); scope != "" {
			scopeNodeID := b.ensureAzureScopeNode(scope, node.Account)
			if scopeNodeID != "" && scopeNodeID != node.ID {
				b.addEdgeIfMissing(&Edge{
					ID:     node.ID + "->located_in->" + scopeNodeID,
					Source: node.ID,
					Target: scopeNodeID,
					Kind:   EdgeKindLocatedIn,
					Effect: EdgeEffectAllow,
					Properties: map[string]any{
						"provider": "azure",
						"scope":    scope,
					},
				})
			}
		}
	}
}

func (b *Builder) buildAzureRBACEdges(ctx context.Context) {
	rows, err := b.queryAzureRBACRoleAssignments(ctx)
	if err != nil {
		b.logger.Debug("failed to query Azure RBAC role assignments", "error", err)
		return
	}

	count := 0
	for _, row := range rows {
		principalID := strings.TrimSpace(queryRowString(row, "principal_id"))
		if principalID == "" {
			continue
		}
		b.ensureAzurePrincipalNode(principalID, queryRowString(row, "principal_type"))

		scope := firstNonEmpty(queryRowString(row, "scope"), azureSubscriptionScopeID(queryRowString(row, "subscription_id")))
		scopeNodeID := b.ensureAzureScopeNode(scope, queryRowString(row, "subscription_id"))

		roleDefinitionID := normalizeAzureRoleDefinitionID(queryRowString(row, "role_definition_id"))
		roleName := firstNonEmpty(queryRowString(row, "role_definition_name"), azureRBACRoleDisplayName(roleDefinitionID), roleDefinitionID)
		roleNodeID := b.ensureAzureRoleNode(azureRBACRoleNodeID(roleDefinitionID), roleName, "azure_rbac", queryRowString(row, "subscription_id"))

		if roleNodeID != "" {
			b.addEdgeIfMissing(&Edge{
				ID:     principalID + "->member_of->" + roleNodeID + ":" + queryRowString(row, "id"),
				Source: principalID,
				Target: roleNodeID,
				Kind:   EdgeKindMemberOf,
				Effect: EdgeEffectAllow,
				Properties: map[string]any{
					"assignment_id":         queryRow(row, "id"),
					"assignment_type":       "azure_rbac",
					"scope":                 scope,
					"role_definition_id":    roleDefinitionID,
					"role_definition_name":  roleName,
					"condition":             queryRow(row, "condition"),
					"can_delegate":          queryRow(row, "can_delegate"),
					"delegated_identity_id": queryRow(row, "delegated_managed_identity_id"),
				},
			})
		}
		if roleNodeID != "" && scopeNodeID != "" {
			b.addEdgeIfMissing(&Edge{
				ID:     roleNodeID + "->located_in->" + scopeNodeID,
				Source: roleNodeID,
				Target: scopeNodeID,
				Kind:   EdgeKindLocatedIn,
				Effect: EdgeEffectAllow,
				Properties: map[string]any{
					"assignment_type":      "azure_rbac",
					"role_definition_id":   roleDefinitionID,
					"role_definition_name": roleName,
					"scope":                scope,
				},
			})
		}

		assignmentMeta := map[string]any{
			"id":                   queryRow(row, "id"),
			"scope":                scope,
			"role_definition_id":   roleDefinitionID,
			"role_definition_name": roleName,
			"principal_type":       queryRow(row, "principal_type"),
			"condition":            queryRow(row, "condition"),
		}
		b.appendAzureRoleAssignment(principalID, assignmentMeta)

		edgeKind := azureRoleToEdgeKind(roleName)
		for _, target := range b.azureScopeTargets(scope) {
			if target == nil || target.ID == "" || target.ID == principalID {
				continue
			}
			b.addEdgeIfMissing(&Edge{
				ID:     principalID + "->" + target.ID + ":" + roleName,
				Source: principalID,
				Target: target.ID,
				Kind:   edgeKind,
				Effect: EdgeEffectAllow,
				Properties: map[string]any{
					"assignment_id":         queryRow(row, "id"),
					"assignment_type":       "azure_rbac",
					"scope":                 scope,
					"role_definition_id":    roleDefinitionID,
					"role_definition_name":  roleName,
					"condition":             queryRow(row, "condition"),
					"can_delegate":          queryRow(row, "can_delegate"),
					"delegated_identity_id": queryRow(row, "delegated_managed_identity_id"),
				},
			})
			count++
		}
	}

	b.logger.Debug("processed Azure RBAC role assignments", "count", count)
}

func (b *Builder) buildAzureEntraDirectoryRoleEdges(ctx context.Context) {
	assignments, err := b.queryIfExists(ctx, "entra_role_assignments",
		`SELECT id, principal_id, role_definition_id, directory_scope_id FROM entra_role_assignments`)
	if err != nil {
		b.logger.Debug("failed to query Entra role assignments", "error", err)
		return
	}

	roleNames := make(map[string]string)
	roles, err := b.queryIfExists(ctx, "entra_directory_roles",
		`SELECT id, display_name FROM entra_directory_roles`)
	if err == nil {
		for _, row := range roles.Rows {
			rawID := queryRowString(row, "id")
			if rawID == "" {
				continue
			}
			roleNames[rawID] = firstNonEmpty(queryRowString(row, "display_name"), rawID)
		}
	}

	for _, row := range assignments.Rows {
		principalID := strings.TrimSpace(queryRowString(row, "principal_id"))
		if principalID == "" {
			continue
		}
		roleDefinitionID := strings.TrimSpace(queryRowString(row, "role_definition_id"))
		if roleDefinitionID == "" {
			continue
		}

		b.ensureAzurePrincipalNode(principalID, "")
		scope := firstNonEmpty(queryRowString(row, "directory_scope_id"), "/")
		scopeNodeID := b.ensureAzureScopeNode(scope, "")
		roleName := firstNonEmpty(roleNames[roleDefinitionID], roleDefinitionID)
		roleNodeID := b.ensureAzureRoleNode(azureDirectoryRoleNodeID(roleDefinitionID), roleName, "entra_directory_role", "")

		b.addEdgeIfMissing(&Edge{
			ID:     principalID + "->member_of->" + roleNodeID + ":" + queryRowString(row, "id"),
			Source: principalID,
			Target: roleNodeID,
			Kind:   EdgeKindMemberOf,
			Effect: EdgeEffectAllow,
			Properties: map[string]any{
				"assignment_id":        queryRow(row, "id"),
				"assignment_type":      "entra_directory_role",
				"directory_scope_id":   scope,
				"role_definition_id":   roleDefinitionID,
				"role_definition_name": roleName,
			},
		})
		if scopeNodeID != "" {
			b.addEdgeIfMissing(&Edge{
				ID:     roleNodeID + "->located_in->" + scopeNodeID,
				Source: roleNodeID,
				Target: scopeNodeID,
				Kind:   EdgeKindLocatedIn,
				Effect: EdgeEffectAllow,
				Properties: map[string]any{
					"assignment_type":      "entra_directory_role",
					"directory_scope_id":   scope,
					"role_definition_id":   roleDefinitionID,
					"role_definition_name": roleName,
				},
			})
			b.addEdgeIfMissing(&Edge{
				ID:     principalID + "->" + scopeNodeID + ":" + roleName,
				Source: principalID,
				Target: scopeNodeID,
				Kind:   azureRoleToEdgeKind(roleName),
				Effect: EdgeEffectAllow,
				Properties: map[string]any{
					"assignment_id":        queryRow(row, "id"),
					"assignment_type":      "entra_directory_role",
					"directory_scope_id":   scope,
					"role_definition_id":   roleDefinitionID,
					"role_definition_name": roleName,
				},
			})
		}
	}
}

func (b *Builder) buildAzurePolicyAssignmentEdges(ctx context.Context) {
	assignments, err := b.queryIfExists(ctx, "azure_policy_assignments",
		`SELECT id, scope, subscription_id FROM azure_policy_assignments`)
	if err != nil {
		b.logger.Debug("failed to query Azure policy assignments", "error", err)
		return
	}

	for _, row := range assignments.Rows {
		policyID := strings.TrimSpace(queryRowString(row, "id"))
		if policyID == "" {
			continue
		}
		scope := firstNonEmpty(queryRowString(row, "scope"), azureParentScope(policyID, queryRowString(row, "subscription_id"), ""))
		if scope == "" {
			continue
		}
		scopeNodeID := b.ensureAzureScopeNode(scope, queryRowString(row, "subscription_id"))
		if scopeNodeID == "" {
			continue
		}
		b.addEdgeIfMissing(&Edge{
			ID:     policyID + "->located_in->" + scopeNodeID,
			Source: policyID,
			Target: scopeNodeID,
			Kind:   EdgeKindLocatedIn,
			Effect: EdgeEffectAllow,
			Properties: map[string]any{
				"assignment_type": "azure_policy",
				"scope":           scope,
			},
		})
	}
}

func (b *Builder) buildAzureKeyVaultAccessPolicyEdges(ctx context.Context) {
	vaults, err := b.queryIfExists(ctx, "azure_keyvault_vaults",
		`SELECT id, vault_uri, access_policies FROM azure_keyvault_vaults`)
	if err != nil {
		b.logger.Debug("failed to query Azure Key Vault access policies", "error", err)
		return
	}

	for _, row := range vaults.Rows {
		vaultID := strings.TrimSpace(queryRowString(row, "id"))
		if vaultID == "" {
			continue
		}
		vaultURI := normalizeAzureVaultURI(queryRowString(row, "vault_uri"))
		keys := b.azureKeyNodesForVault(vaultID, vaultURI)

		for _, rawPolicy := range azureSlice(queryRow(row, "access_policies")) {
			policy := azureMap(rawPolicy)
			if policy == nil {
				continue
			}
			principalID := firstNonEmpty(queryRowString(policy, "object_id"), queryRowString(policy, "objectId"), queryRowString(policy, "principal_id"))
			if principalID == "" {
				continue
			}
			b.ensureAzurePrincipalNode(principalID, "")
			kind := azurePermissionsToEdgeKind(queryRow(policy, "permissions"))
			props := map[string]any{
				"mechanism": "key_vault_access_policy",
				"vault_uri": vaultURI,
			}
			if appID := firstNonEmpty(queryRowString(policy, "application_id"), queryRowString(policy, "applicationId")); appID != "" {
				props["application_id"] = appID
			}
			b.addEdgeIfMissing(&Edge{
				ID:         principalID + "->" + vaultID + ":key_vault_access_policy",
				Source:     principalID,
				Target:     vaultID,
				Kind:       kind,
				Effect:     EdgeEffectAllow,
				Properties: cloneAnyMap(props),
			})
			for _, keyNode := range keys {
				if keyNode == nil {
					continue
				}
				b.addEdgeIfMissing(&Edge{
					ID:         principalID + "->" + keyNode.ID + ":key_vault_access_policy",
					Source:     principalID,
					Target:     keyNode.ID,
					Kind:       kind,
					Effect:     EdgeEffectAllow,
					Properties: cloneAnyMap(props),
				})
			}
		}
	}
}

func (b *Builder) buildAzureManagedIdentityEdges(_ context.Context) {
	for _, node := range b.graph.GetAllNodes() {
		if node == nil || node.Provider != "azure" || node.Properties == nil {
			continue
		}

		identity := azureMap(node.Properties["identity"])
		if identity == nil {
			continue
		}

		if principalID := firstNonEmpty(
			queryRowString(identity, "principal_id"),
			queryRowString(identity, "principalId"),
		); principalID != "" {
			b.ensureAzurePrincipalNode(principalID, "ServicePrincipal")
			b.addEdgeIfMissing(&Edge{
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

		for _, targetID := range azureUserAssignedIdentityTargets(identity) {
			if targetID == "" {
				continue
			}
			b.ensureAzurePrincipalNode(targetID, "ServicePrincipal")
			b.addEdgeIfMissing(&Edge{
				ID:     node.ID + "->identity->" + targetID,
				Source: node.ID,
				Target: targetID,
				Kind:   EdgeKindCanAssume,
				Effect: EdgeEffectAllow,
				Properties: map[string]any{
					"mechanism": "user_assigned_identity",
				},
			})
		}
	}
}

func (b *Builder) loadAzurePreferredIdentityNodes(ctx context.Context, candidates []nodeQuery) {
	discoveryAvailable := b.availableTables != nil
	for _, candidate := range candidates {
		if discoveryAvailable && !b.hasTable(candidate.table) {
			continue
		}
		rows, err := b.queryIfExists(ctx, candidate.table, candidate.query)
		if err != nil {
			b.logger.Warn("failed to query "+candidate.table, "error", err)
			continue
		}
		if len(rows.Rows) == 0 {
			continue
		}
		nodes := candidate.parse(rows.Rows)
		b.graph.AddNodesBatch(nodes)
		b.logger.Debug("added "+candidate.table, "count", len(nodes))
		return
	}
}

func (b *Builder) runAzureNodeQuery(ctx context.Context, query nodeQuery) {
	rows, err := b.queryIfExists(ctx, query.table, query.query)
	if err != nil {
		b.logger.Warn("failed to query "+query.table, "error", err)
		return
	}
	if len(rows.Rows) == 0 {
		return
	}
	nodes := query.parse(rows.Rows)
	b.graph.AddNodesBatch(nodes)
	b.logger.Debug("added "+query.table, "count", len(nodes))
}

func parseAzureServicePrincipalNodes(rows []map[string]any) []*Node {
	nodes := make([]*Node, 0, len(rows))
	for _, sp := range rows {
		id := toString(sp["id"])
		if id == "" {
			continue
		}
		servicePrincipalType := firstNonEmpty(queryRowString(sp, "service_principal_type"), queryRowString(sp, "type"))
		properties := map[string]any{
			"app_id":              queryRow(sp, "app_id"),
			"type":                servicePrincipalType,
			"account_enabled":     queryRow(sp, "account_enabled"),
			"tags":                queryRow(sp, "tags"),
			"publisher_name":      queryRow(sp, "publisher_name"),
			"created_datetime":    firstNonEmpty(queryRowString(sp, "created_datetime"), queryRowString(sp, "created_date_time")),
			"azure_resource_type": "service_principal",
		}
		if strings.Contains(strings.ToLower(servicePrincipalType), "managed") {
			properties["identity_type"] = servicePrincipalType
		}
		nodes = append(nodes, &Node{
			ID:         id,
			Kind:       NodeKindServiceAccount,
			Name:       firstNonEmpty(queryRowString(sp, "display_name"), id),
			Provider:   "azure",
			Account:    queryRowString(sp, "subscription_id"),
			Properties: properties,
		})
	}
	return nodes
}

func parseAzureUserNodes(rows []map[string]any) []*Node {
	nodes := make([]*Node, 0, len(rows))
	for _, user := range rows {
		id := toString(user["id"])
		if id == "" {
			continue
		}
		nodes = append(nodes, &Node{
			ID:       id,
			Kind:     NodeKindUser,
			Name:     firstNonEmpty(queryRowString(user, "display_name"), queryRowString(user, "user_principal_name"), id),
			Provider: "azure",
			Properties: map[string]any{
				"upn":                 queryRow(user, "user_principal_name"),
				"mail":                queryRow(user, "mail"),
				"department":          queryRow(user, "department"),
				"job_title":           queryRow(user, "job_title"),
				"account_enabled":     queryRow(user, "account_enabled"),
				"user_type":           queryRow(user, "user_type"),
				"last_sign_in":        queryRow(user, "last_sign_in_datetime"),
				"azure_resource_type": "user",
			},
		})
	}
	return nodes
}

func (b *Builder) queryAzureRBACRoleAssignments(ctx context.Context) ([]map[string]any, error) {
	candidates := []struct {
		table string
		query string
	}{
		{
			table: "azure_rbac_role_assignments",
			query: `SELECT id, principal_id, principal_type, role_definition_id, scope, condition, can_delegate, delegated_managed_identity_id, description, subscription_id FROM azure_rbac_role_assignments`,
		},
		{
			table: "azure_authorization_role_assignments",
			query: `SELECT id, principal_id, principal_type, role_definition_id, role_definition_name, scope, condition, can_delegate, delegated_managed_identity_id, description, subscription_id FROM azure_authorization_role_assignments`,
		},
	}

	var lastErr error
	discoveryAvailable := b.availableTables != nil
	for _, candidate := range candidates {
		if discoveryAvailable && !b.hasTable(candidate.table) {
			continue
		}
		result, err := b.queryIfExists(ctx, candidate.table, candidate.query)
		if err != nil {
			lastErr = err
			b.logger.Warn("failed to query "+candidate.table, "error", err)
			continue
		}
		if len(result.Rows) == 0 {
			continue
		}
		return result.Rows, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, nil
}

func (b *Builder) ensureAzurePrincipalNode(principalID, principalType string) {
	if principalID == "" {
		return
	}
	if _, ok := b.graph.GetNode(principalID); ok {
		return
	}

	kind := NodeKindServiceAccount
	switch strings.ToLower(strings.TrimSpace(principalType)) {
	case "user":
		kind = NodeKindUser
	case "group":
		kind = NodeKindGroup
	case "serviceprincipal", "service_principal", "managedidentity", "managed_identity":
		kind = NodeKindServiceAccount
	}

	properties := map[string]any{
		"principal_type": principalType,
	}
	if strings.Contains(strings.ToLower(principalType), "managed") {
		properties["identity_type"] = principalType
	}

	b.graph.AddNode(&Node{
		ID:         principalID,
		Kind:       kind,
		Name:       principalID,
		Provider:   "azure",
		Properties: properties,
	})
}

func (b *Builder) ensureAzureRoleNode(roleNodeID, roleName, roleType, account string) string {
	if roleNodeID == "" {
		return ""
	}
	if _, ok := b.graph.GetNode(roleNodeID); ok {
		return roleNodeID
	}

	b.graph.AddNode(&Node{
		ID:       roleNodeID,
		Kind:     NodeKindRole,
		Name:     firstNonEmpty(roleName, roleNodeID),
		Provider: "azure",
		Account:  account,
		Properties: map[string]any{
			"role_type":           roleType,
			"azure_resource_type": roleType,
		},
	})
	return roleNodeID
}

func (b *Builder) appendAzureRoleAssignment(principalID string, assignment map[string]any) {
	node, ok := b.graph.GetNode(principalID)
	if !ok || node == nil {
		return
	}
	if node.Properties == nil {
		node.Properties = make(map[string]any)
	}
	existing, _ := node.Properties["role_assignments"].([]any)
	node.Properties["role_assignments"] = append(existing, cloneAnyMap(assignment))
}

func (b *Builder) ensureAzureScopeNode(scope, account string) string {
	normalized := strings.TrimSpace(scope)
	if normalized == "" {
		return ""
	}

	nodeID := normalized
	switch {
	case normalized == "/" || strings.EqualFold(normalized, "tenant"):
		nodeID = azureTenantRootNodeID
	case strings.HasPrefix(strings.ToLower(normalized), "/tenants/"):
		nodeID = normalized
	}

	if _, ok := b.graph.GetNode(nodeID); !ok {
		node := &Node{
			ID:       nodeID,
			Kind:     azureNodeKindFromID(nodeID),
			Name:     azureResourceDisplayName(nodeID),
			Provider: "azure",
			Account:  account,
			Properties: map[string]any{
				"scope_type":          azureScopeType(nodeID),
				"azure_resource_type": azureScopeType(nodeID),
			},
		}
		if node.Kind == "" {
			node.Kind = NodeKindService
		}
		if node.Name == "" {
			node.Name = nodeID
		}
		if node.ID == azureTenantRootNodeID {
			node.Kind = NodeKindOrganization
			node.Name = "Azure Tenant"
		}
		if subscriptionID := azureIDSegment(nodeID, "subscriptions"); subscriptionID != "" && node.Account == "" {
			node.Account = subscriptionID
		}
		b.graph.AddNode(node)
	}

	b.ensureAzureScopeAncestry(nodeID, account, "")
	return nodeID
}

func (b *Builder) ensureAzureScopeAncestry(nodeID, account, resourceGroup string) {
	parent := azureParentScope(nodeID, account, resourceGroup)
	if parent == "" || parent == nodeID {
		return
	}
	parentID := b.ensureAzureScopeNode(parent, firstNonEmpty(account, azureIDSegment(nodeID, "subscriptions")))
	if parentID == "" || parentID == nodeID {
		return
	}
	b.addEdgeIfMissing(&Edge{
		ID:     nodeID + "->located_in->" + parentID,
		Source: nodeID,
		Target: parentID,
		Kind:   EdgeKindLocatedIn,
		Effect: EdgeEffectAllow,
		Properties: map[string]any{
			"provider": "azure",
		},
	})
}

func (b *Builder) azureScopeTargets(scope string) []*Node {
	targets := make([]*Node, 0)
	seen := make(map[string]struct{})

	scope = strings.TrimSpace(scope)
	if scope == "" {
		return targets
	}
	scopeNodeID := b.ensureAzureScopeNode(scope, "")
	if scopeNodeID != "" {
		if node, ok := b.graph.GetNode(scopeNodeID); ok && node != nil {
			targets = append(targets, node)
			seen[node.ID] = struct{}{}
		}
	}

	for _, node := range b.graph.GetAllNodes() {
		if node == nil || node.Provider != "azure" || !node.IsResource() {
			continue
		}
		if !azureNodeWithinScope(node, scope) {
			continue
		}
		if _, ok := seen[node.ID]; ok {
			continue
		}
		seen[node.ID] = struct{}{}
		targets = append(targets, node)
	}

	return targets
}

func (b *Builder) azureKeyNodesForVault(vaultID, vaultURI string) []*Node {
	keys := make([]*Node, 0)
	for _, node := range b.graph.GetAllNodes() {
		if node == nil || node.Provider != "azure" || node.Kind != NodeKindSecret || node.ID == vaultID {
			continue
		}
		if queryRowString(node.Properties, "azure_resource_type") != "key_vault_key" {
			continue
		}
		if queryRowString(node.Properties, "vault_id") == vaultID {
			keys = append(keys, node)
			continue
		}
		if vaultURI != "" && normalizeAzureVaultURI(queryRowString(node.Properties, "vault_uri")) == vaultURI {
			keys = append(keys, node)
		}
	}
	return keys
}

func azureRoleToEdgeKind(role string) EdgeKind {
	role = strings.TrimSpace(role)
	switch {
	case contains(role, "Owner"), contains(role, "Contributor"), contains(role, "Administrator"), contains(role, "Officer"):
		return EdgeKindCanAdmin
	case contains(role, "Writer"), contains(role, "Write"), contains(role, "Editor"):
		return EdgeKindCanWrite
	case contains(role, "Delete"), contains(role, "Purge"):
		return EdgeKindCanDelete
	default:
		return EdgeKindCanRead
	}
}

func azureRBACRoleNodeID(roleDefinitionID string) string {
	if roleDefinitionID == "" {
		return ""
	}
	return "azure_rbac_role:" + normalizeAzureRoleDefinitionID(roleDefinitionID)
}

func azureDirectoryRoleNodeID(roleDefinitionID string) string {
	if roleDefinitionID == "" {
		return ""
	}
	return "azure_directory_role:" + strings.TrimSpace(roleDefinitionID)
}

func normalizeAzureRoleDefinitionID(roleDefinitionID string) string {
	roleDefinitionID = strings.TrimSpace(roleDefinitionID)
	if roleDefinitionID == "" {
		return ""
	}
	parts := strings.Split(roleDefinitionID, "/")
	return parts[len(parts)-1]
}

func azureRBACRoleDisplayName(roleDefinitionID string) string {
	roleDefinitionID = normalizeAzureRoleDefinitionID(roleDefinitionID)
	if roleDefinitionID == "" {
		return ""
	}
	return azureBuiltInRoleNames[strings.ToLower(roleDefinitionID)]
}

func azureScopeType(scope string) string {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return ""
	}
	lower := strings.ToLower(scope)
	switch {
	case scope == azureTenantRootNodeID || scope == "/" || strings.HasPrefix(lower, "/tenants/"):
		return "tenant"
	case strings.HasPrefix(lower, "/providers/microsoft.management/managementgroups/"):
		return "management_group"
	case strings.HasPrefix(lower, "/administrativeunits/"):
		return "directory_scope"
	case strings.HasPrefix(lower, "/subscriptions/") && !strings.Contains(lower, "/resourcegroups/") && strings.Count(lower, "/") == 2:
		return "subscription"
	case strings.HasPrefix(lower, "/subscriptions/") && strings.Contains(lower, "/resourcegroups/") && !strings.Contains(lower, "/providers/"):
		return "resource_group"
	default:
		return "resource"
	}
}

func azureParentScope(scope, account, resourceGroup string) string {
	scope = strings.TrimSpace(scope)
	if scope == "" || scope == azureTenantRootNodeID || scope == "/" || strings.HasPrefix(strings.ToLower(scope), "/tenants/") {
		return ""
	}

	lower := strings.ToLower(scope)
	switch azureScopeType(scope) {
	case "management_group", "subscription", "directory_scope":
		return azureTenantRootNodeID
	case "resource_group":
		subscriptionID := firstNonEmpty(azureIDSegment(scope, "subscriptions"), account)
		if subscriptionID == "" {
			return ""
		}
		return azureSubscriptionScopeID(subscriptionID)
	case "resource":
		subscriptionID := firstNonEmpty(azureIDSegment(scope, "subscriptions"), account)
		resourceGroup = firstNonEmpty(resourceGroup, azureIDSegment(scope, "resourceGroups"))
		if subscriptionID != "" && resourceGroup != "" {
			return azureResourceGroupScopeID(subscriptionID, resourceGroup)
		}
		if subscriptionID != "" && strings.HasPrefix(lower, "/subscriptions/") {
			return azureSubscriptionScopeID(subscriptionID)
		}
	}
	return ""
}

func azureSubscriptionScopeID(subscriptionID string) string {
	subscriptionID = strings.TrimSpace(subscriptionID)
	if subscriptionID == "" {
		return ""
	}
	return "/subscriptions/" + subscriptionID
}

func azureResourceGroupScopeID(subscriptionID, resourceGroup string) string {
	subscriptionID = strings.TrimSpace(subscriptionID)
	resourceGroup = strings.TrimSpace(resourceGroup)
	if subscriptionID == "" || resourceGroup == "" {
		return ""
	}
	return "/subscriptions/" + subscriptionID + "/resourceGroups/" + resourceGroup
}

func azureNodeKindFromID(id string) NodeKind {
	switch azureScopeType(id) {
	case "tenant":
		return NodeKindOrganization
	case "management_group", "resource_group", "directory_scope":
		return NodeKindFolder
	case "subscription":
		return NodeKindProject
	}

	lower := strings.ToLower(id)
	switch {
	case strings.Contains(lower, "/providers/microsoft.compute/virtualmachines/"):
		return NodeKindInstance
	case strings.Contains(lower, "/providers/microsoft.compute/disks/"), strings.Contains(lower, "/providers/microsoft.compute/availabilitysets/"):
		return NodeKindService
	case strings.Contains(lower, "/providers/microsoft.network/"):
		return NodeKindNetwork
	case strings.Contains(lower, "/providers/microsoft.storage/storageaccounts/"):
		return NodeKindBucket
	case strings.Contains(lower, "/providers/microsoft.sql/servers/"):
		return NodeKindDatabase
	case strings.Contains(lower, "/providers/microsoft.keyvault/vaults/"):
		return NodeKindSecret
	case strings.Contains(lower, "/providers/microsoft.web/sites/"):
		return NodeKindFunction
	case strings.Contains(lower, "/providers/microsoft.authorization/policyassignments/"):
		return NodeKindService
	default:
		return NodeKindService
	}
}

func azureNodeWithinScope(node *Node, scope string) bool {
	if node == nil || node.Provider != "azure" || !node.IsResource() {
		return false
	}

	scope = strings.TrimRight(strings.TrimSpace(scope), "/")
	if scope == "" {
		return false
	}
	if scope == "/" || scope == azureTenantRootNodeID {
		return true
	}
	if strings.EqualFold(node.ID, scope) {
		return true
	}

	scopeLower := strings.ToLower(scope)
	nodeIDLower := strings.ToLower(node.ID)
	if strings.HasPrefix(nodeIDLower, scopeLower+"/") {
		return true
	}

	scopeType := azureScopeType(scope)
	subscriptionID := azureIDSegment(scope, "subscriptions")
	if subscriptionID == "" {
		return false
	}
	if node.Account != subscriptionID && !strings.EqualFold(azureIDSegment(node.ID, "subscriptions"), subscriptionID) {
		return false
	}
	switch scopeType {
	case "subscription":
		return true
	case "resource_group":
		resourceGroup := azureIDSegment(scope, "resourceGroups")
		if resourceGroup == "" {
			return false
		}
		return strings.EqualFold(queryRowString(node.Properties, "resource_group"), resourceGroup) ||
			strings.EqualFold(azureIDSegment(node.ID, "resourceGroups"), resourceGroup)
	}
	return false
}

func azureResourceDisplayName(id string) string {
	if id == azureTenantRootNodeID {
		return "Azure Tenant"
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	parts := strings.Split(strings.Trim(id, "/"), "/")
	if len(parts) == 0 {
		return id
	}
	return parts[len(parts)-1]
}

func azureIDSegment(id, segment string) string {
	if id == "" || segment == "" {
		return ""
	}
	parts := strings.Split(strings.Trim(id, "/"), "/")
	for idx := 0; idx < len(parts)-1; idx++ {
		if strings.EqualFold(parts[idx], segment) {
			return parts[idx+1]
		}
	}
	return ""
}

func azureAuthorizedIPRangesPublic(value any) bool {
	for _, entry := range azureStringSlice(value) {
		if azureInternetCIDR(entry) {
			return true
		}
	}
	return false
}

func azureNSGAllowsInternet(values ...any) bool {
	for _, value := range values {
		for _, rule := range azureSlice(value) {
			if azureNSGRuleAllowsInternet(rule) {
				return true
			}
		}
	}
	return false
}

func azureNSGRuleAllowsInternet(value any) bool {
	rule := azureMap(value)
	if rule == nil {
		return false
	}
	properties := azureMap(queryRow(rule, "properties"))
	if properties == nil {
		properties = rule
	}

	if !strings.EqualFold(firstNonEmpty(queryRowString(properties, "direction"), queryRowString(rule, "direction")), "inbound") {
		return false
	}
	if !strings.EqualFold(firstNonEmpty(queryRowString(properties, "access"), queryRowString(rule, "access")), "allow") {
		return false
	}

	for _, prefix := range append(
		azureStringSlice(queryRow(properties, "source_address_prefixes")),
		firstNonEmpty(queryRowString(properties, "source_address_prefix"), queryRowString(rule, "source_address_prefix"), queryRowString(rule, "sourceAddressPrefix")),
	) {
		if azureInternetCIDR(prefix) {
			return true
		}
	}
	return false
}

func azureLoadBalancerHasPublicFrontend(value any) bool {
	for _, frontend := range azureSlice(value) {
		if azureNestedReferenceID(frontend, "public_ip_address", "publicIPAddress", "PublicIPAddress") != "" {
			return true
		}
	}
	return false
}

func azureNICHasPublicFrontend(value any) bool {
	for _, ipConfig := range azureSlice(value) {
		if azureNestedReferenceID(ipConfig, "public_ip_address", "publicIPAddress", "PublicIPAddress") != "" {
			return true
		}
	}
	return false
}

func azurePermissionsToEdgeKind(value any) EdgeKind {
	permissions := azureMap(value)
	if permissions == nil {
		return EdgeKindCanRead
	}

	score := 0
	for _, key := range []string{"keys", "secrets", "certificates", "storage"} {
		for _, permission := range azureStringSlice(queryRow(permissions, key)) {
			score = max(score, azurePermissionScore(permission))
		}
	}

	switch score {
	case 4:
		return EdgeKindCanAdmin
	case 3:
		return EdgeKindCanDelete
	case 2:
		return EdgeKindCanWrite
	default:
		return EdgeKindCanRead
	}
}

func azurePermissionScore(permission string) int {
	permission = strings.ToLower(strings.TrimSpace(permission))
	switch {
	case permission == "", permission == "get", permission == "list", permission == "read":
		return 1
	case contains(permission, "all"), contains(permission, "manage"), contains(permission, "admin"), contains(permission, "recover"), contains(permission, "restore"), contains(permission, "backup"):
		return 4
	case contains(permission, "delete"), contains(permission, "purge"):
		return 3
	case contains(permission, "set"), contains(permission, "write"), contains(permission, "create"), contains(permission, "import"), contains(permission, "update"), contains(permission, "sign"), contains(permission, "verify"), contains(permission, "encrypt"), contains(permission, "decrypt"), contains(permission, "wrap"), contains(permission, "unwrap"):
		return 2
	default:
		return 1
	}
}

func azureUserAssignedIdentityTargets(identity map[string]any) []string {
	targets := make([]string, 0)
	userAssigned := azureMap(queryRow(identity, "user_assigned_identities"))
	if userAssigned == nil {
		userAssigned = azureMap(queryRow(identity, "userAssignedIdentities"))
	}
	if userAssigned == nil {
		return targets
	}
	for resourceID, value := range userAssigned {
		entry := azureMap(value)
		targetID := firstNonEmpty(
			queryRowString(entry, "principal_id"),
			queryRowString(entry, "principalId"),
			strings.TrimSpace(resourceID),
		)
		if targetID == "" {
			continue
		}
		targets = append(targets, targetID)
	}
	return targets
}

func azureInternetCIDR(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	switch value {
	case "*", "internet", "0.0.0.0/0", "::/0", "any":
		return true
	default:
		return false
	}
}

func normalizeAzureVaultURI(uri string) string {
	uri = strings.TrimSpace(strings.ToLower(uri))
	return strings.TrimRight(uri, "/")
}

func azureVaultResourceIDFromKeyID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}

	lower := strings.ToLower(id)
	const needle = "/keys/"
	idx := strings.Index(lower, needle)
	if idx == -1 {
		return ""
	}

	vaultID := strings.TrimRight(id[:idx], "/")
	if !strings.Contains(strings.ToLower(vaultID), "/providers/microsoft.keyvault/vaults/") {
		return ""
	}
	return vaultID
}

func azureNestedReferenceID(value any, keys ...string) string {
	root := azureMap(value)
	if root == nil {
		return ""
	}
	for _, key := range keys {
		if ref := azureReferenceID(queryRow(root, key)); ref != "" {
			return ref
		}
	}
	properties := azureMap(queryRow(root, "properties"))
	if properties == nil {
		properties = azureMap(queryRow(root, "Properties"))
	}
	if properties == nil {
		return ""
	}
	for _, key := range keys {
		if ref := azureReferenceID(queryRow(properties, key)); ref != "" {
			return ref
		}
	}
	return ""
}

func azureReferenceID(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	case map[string]any:
		return firstNonEmpty(queryRowString(typed, "id"), queryRowString(typed, "Id"), queryRowString(typed, "ID"))
	default:
		return ""
	}
}

func azureMap(value any) map[string]any {
	if value == nil {
		return nil
	}
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return nil
}

func azureSlice(value any) []any {
	switch typed := value.(type) {
	case nil:
		return nil
	case []any:
		return typed
	case []string:
		out := make([]any, 0, len(typed))
		for _, entry := range typed {
			out = append(out, entry)
		}
		return out
	default:
		return nil
	}
}

func azureStringSlice(value any) []string {
	switch typed := value.(type) {
	case nil:
		return nil
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, entry := range typed {
			if s := strings.TrimSpace(toString(entry)); s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if trimmed := strings.TrimSpace(typed); trimmed != "" {
			return []string{trimmed}
		}
	}
	return nil
}
