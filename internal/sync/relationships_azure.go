package sync

import (
	"context"
	"strings"
)

// extractAzureRelationships extracts Azure resource relationships.
func (r *RelationshipExtractor) extractAzureRelationships(ctx context.Context) (int, error) {
	var rels []Relationship
	extractNestedRef := func(value interface{}, directKeys []string, objectKeys []string) string {
		root := asMap(value)
		if root == nil {
			return ""
		}

		candidates := []map[string]interface{}{root}
		if props := asMap(root["properties"]); props != nil {
			candidates = append(candidates, props)
		}
		if props := asMap(root["Properties"]); props != nil {
			candidates = append(candidates, props)
		}

		for _, candidate := range candidates {
			for _, key := range directKeys {
				if id := normalizeRelationshipID(getStringAny(candidate, key)); id != "" {
					return id
				}
			}
			for _, key := range objectKeys {
				if ref := extractReferenceID(candidate[key]); ref != "" {
					return ref
				}
			}
		}

		return ""
	}

	query := `SELECT ID, NETWORK_INTERFACES, AVAILABILITY_SET, OS_DISK, DATA_DISKS
	          FROM AZURE_COMPUTE_VIRTUAL_MACHINES WHERE ID IS NOT NULL`

	if result, ok, err := r.queryRowsForTable(ctx, "AZURE_COMPUTE_VIRTUAL_MACHINES", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			vmID := toString(queryRow(row, "id"))
			if vmID == "" {
				continue
			}

			if nicList := asSlice(queryRow(row, "network_interfaces")); len(nicList) > 0 {
				for _, nic := range nicList {
					if nicID := extractReferenceID(nic); nicID != "" {
						rels = append(rels, Relationship{
							SourceID:   vmID,
							SourceType: "azure:compute:virtual_machine",
							TargetID:   nicID,
							TargetType: "azure:network:interface",
							RelType:    RelAttachedTo,
						})
					}
				}
			}

			if availabilitySetID := normalizeRelationshipID(toString(queryRow(row, "availability_set"))); availabilitySetID != "" {
				rels = append(rels, Relationship{
					SourceID:   vmID,
					SourceType: "azure:compute:virtual_machine",
					TargetID:   availabilitySetID,
					TargetType: "azure:compute:availability_set",
					RelType:    RelBelongsTo,
				})
			}

			if osDiskID := extractManagedDiskID(queryRow(row, "os_disk")); osDiskID != "" {
				rels = append(rels, Relationship{
					SourceID:   vmID,
					SourceType: "azure:compute:virtual_machine",
					TargetID:   osDiskID,
					TargetType: "azure:compute:disk",
					RelType:    RelAttachedTo,
				})
			}

			if dataDisks := asSlice(queryRow(row, "data_disks")); len(dataDisks) > 0 {
				for _, disk := range dataDisks {
					if diskID := extractManagedDiskID(disk); diskID != "" {
						rels = append(rels, Relationship{
							SourceID:   vmID,
							SourceType: "azure:compute:virtual_machine",
							TargetID:   diskID,
							TargetType: "azure:compute:disk",
							RelType:    RelAttachedTo,
						})
					}
				}
			}
		}
	}

	query = `SELECT ID, NETWORK_SECURITY_GROUP, VIRTUAL_MACHINE, IP_CONFIGURATIONS
	         FROM AZURE_NETWORK_INTERFACES WHERE ID IS NOT NULL`
	if result, ok, err := r.queryRowsForTable(ctx, "AZURE_NETWORK_INTERFACES", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			nicID := toString(queryRow(row, "id"))
			if nicID == "" {
				continue
			}

			if vmID := normalizeRelationshipID(toString(queryRow(row, "virtual_machine"))); vmID != "" {
				rels = append(rels, Relationship{
					SourceID:   nicID,
					SourceType: "azure:network:interface",
					TargetID:   vmID,
					TargetType: "azure:compute:virtual_machine",
					RelType:    RelAttachedTo,
				})
			}

			if nsgID := normalizeRelationshipID(toString(queryRow(row, "network_security_group"))); nsgID != "" {
				rels = append(rels, Relationship{
					SourceID:   nicID,
					SourceType: "azure:network:interface",
					TargetID:   nsgID,
					TargetType: "azure:network:security_group",
					RelType:    RelMemberOf,
				})
			}

			if ipConfigs := asSlice(queryRow(row, "ip_configurations")); len(ipConfigs) > 0 {
				for _, ipCfg := range ipConfigs {
					if subnetID := extractSubnetReferenceID(ipCfg); subnetID != "" {
						rels = append(rels, Relationship{
							SourceID:   nicID,
							SourceType: "azure:network:interface",
							TargetID:   subnetID,
							TargetType: "azure:network:subnet",
							RelType:    RelInSubnet,
						})
					}
				}
			}
		}
	}

	query = `SELECT ID, NETWORK_INTERFACES, SUBNETS
	         FROM AZURE_NETWORK_SECURITY_GROUPS WHERE ID IS NOT NULL`
	if result, ok, err := r.queryRowsForTable(ctx, "AZURE_NETWORK_SECURITY_GROUPS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			nsgID := toString(queryRow(row, "id"))
			if nsgID == "" {
				continue
			}

			for _, nic := range asSlice(queryRow(row, "network_interfaces")) {
				if nicID := extractReferenceID(nic); nicID != "" {
					rels = append(rels, Relationship{
						SourceID:   nsgID,
						SourceType: "azure:network:security_group",
						TargetID:   nicID,
						TargetType: "azure:network:interface",
						RelType:    RelAttachedTo,
					})
				}
			}

			for _, subnet := range asSlice(queryRow(row, "subnets")) {
				if subnetID := extractReferenceID(subnet); subnetID != "" {
					rels = append(rels, Relationship{
						SourceID:   nsgID,
						SourceType: "azure:network:security_group",
						TargetID:   subnetID,
						TargetType: "azure:network:subnet",
						RelType:    RelAttachedTo,
					})
				}
			}
		}
	}

	query = `SELECT ID, SUBNETS, PEERINGS
	         FROM AZURE_NETWORK_VIRTUAL_NETWORKS WHERE ID IS NOT NULL`
	if result, ok, err := r.queryRowsForTable(ctx, "AZURE_NETWORK_VIRTUAL_NETWORKS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			vnetID := toString(queryRow(row, "id"))
			if vnetID == "" {
				continue
			}

			for _, subnet := range asSlice(queryRow(row, "subnets")) {
				if subnetID := extractReferenceID(subnet); subnetID != "" {
					rels = append(rels, Relationship{
						SourceID:   subnetID,
						SourceType: "azure:network:subnet",
						TargetID:   vnetID,
						TargetType: "azure:network:virtual_network",
						RelType:    RelBelongsTo,
					})
				}
			}

			for _, peering := range asSlice(queryRow(row, "peerings")) {
				peerVNetID := extractNestedRef(
					peering,
					[]string{"remote_virtual_network_id", "remoteVirtualNetworkId", "RemoteVirtualNetworkID"},
					[]string{"remote_virtual_network", "remoteVirtualNetwork", "RemoteVirtualNetwork"},
				)
				if peerVNetID == "" || peerVNetID == vnetID {
					continue
				}

				rels = append(rels, Relationship{
					SourceID:   vnetID,
					SourceType: "azure:network:virtual_network",
					TargetID:   peerVNetID,
					TargetType: "azure:network:virtual_network",
					RelType:    RelRoutes,
				})
			}
		}
	}

	query = `SELECT ID, MANAGED_BY FROM AZURE_COMPUTE_DISKS WHERE ID IS NOT NULL`
	if result, ok, err := r.queryRowsForTable(ctx, "AZURE_COMPUTE_DISKS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			diskID := toString(queryRow(row, "id"))
			if diskID == "" {
				continue
			}
			if managedBy := normalizeRelationshipID(toString(queryRow(row, "managed_by"))); managedBy != "" {
				rels = append(rels, Relationship{
					SourceID:   diskID,
					SourceType: "azure:compute:disk",
					TargetID:   managedBy,
					TargetType: "azure:compute:virtual_machine",
					RelType:    RelAttachedTo,
				})
			}
		}
	}

	query = `SELECT ID, PUBLIC_NETWORK_ACCESS
	         FROM AZURE_SQL_SERVERS WHERE ID IS NOT NULL`
	if result, ok, err := r.queryRowsForTable(ctx, "AZURE_SQL_SERVERS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			serverID := toString(queryRow(row, "id"))
			if serverID == "" {
				continue
			}

			if strings.EqualFold(strings.TrimSpace(toString(queryRow(row, "public_network_access"))), "Enabled") {
				rels = append(rels, Relationship{
					SourceID:   serverID,
					SourceType: "azure:sql:server",
					TargetID:   "internet",
					TargetType: "network:internet",
					RelType:    RelExposedTo,
				})
			}
		}
	}

	query = `SELECT ID, SERVER_NAME, RESOURCE_GROUP, SUBSCRIPTION_ID
	         FROM AZURE_SQL_DATABASES WHERE ID IS NOT NULL`
	if result, ok, err := r.queryRowsForTable(ctx, "AZURE_SQL_DATABASES", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			dbID := toString(queryRow(row, "id"))
			if dbID == "" {
				continue
			}

			serverName := toString(queryRow(row, "server_name"))
			if serverName == "" {
				serverName = azureIDSegment(dbID, "servers")
			}
			serverID := azureSQLServerID(toString(queryRow(row, "subscription_id")), toString(queryRow(row, "resource_group")), serverName)
			if serverID == "" {
				continue
			}

			rels = append(rels, Relationship{
				SourceID:   dbID,
				SourceType: "azure:sql:database",
				TargetID:   serverID,
				TargetType: "azure:sql:server",
				RelType:    RelBelongsTo,
			})
		}
	}

	query = `SELECT ID, NETWORK_ACLS, ALLOW_BLOB_PUBLIC_ACCESS
	         FROM AZURE_STORAGE_ACCOUNTS WHERE ID IS NOT NULL`
	if result, ok, err := r.queryRowsForTable(ctx, "AZURE_STORAGE_ACCOUNTS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			accountID := toString(queryRow(row, "id"))
			if accountID == "" {
				continue
			}

			if networkACLs := asMap(queryRow(row, "network_acls")); networkACLs != nil {
				for _, rule := range getSliceAny(networkACLs, "virtual_network_rules", "virtualNetworkRules", "VirtualNetworkRules") {
					ruleMap := asMap(rule)
					if ruleMap == nil {
						continue
					}

					subnetID := normalizeRelationshipID(getStringAny(ruleMap, "virtual_network_resource_id", "virtualNetworkResourceId", "VirtualNetworkResourceID"))
					if subnetID == "" {
						if properties := asMap(ruleMap["properties"]); properties != nil {
							subnetID = normalizeRelationshipID(getStringAny(properties, "virtual_network_resource_id", "virtualNetworkResourceId", "VirtualNetworkResourceID"))
						}
					}
					if subnetID == "" {
						subnetID = extractReferenceID(rule)
					}
					if subnetID == "" {
						continue
					}

					rels = append(rels, Relationship{
						SourceID:   accountID,
						SourceType: "azure:storage:account",
						TargetID:   subnetID,
						TargetType: "azure:network:subnet",
						RelType:    RelInSubnet,
					})
				}
			}

			if strings.EqualFold(strings.TrimSpace(toString(queryRow(row, "allow_blob_public_access"))), "true") {
				rels = append(rels, Relationship{
					SourceID:   accountID,
					SourceType: "azure:storage:account",
					TargetID:   "internet",
					TargetType: "network:internet",
					RelType:    RelExposedTo,
				})
			}
		}
	}

	query = `SELECT ID, ACCOUNT_NAME, RESOURCE_GROUP, SUBSCRIPTION_ID
	         FROM AZURE_STORAGE_CONTAINERS WHERE ID IS NOT NULL`
	if result, ok, err := r.queryRowsForTable(ctx, "AZURE_STORAGE_CONTAINERS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			containerID := toString(queryRow(row, "id"))
			if containerID == "" {
				continue
			}

			accountID := azureStorageAccountID(toString(queryRow(row, "subscription_id")), toString(queryRow(row, "resource_group")), toString(queryRow(row, "account_name")))
			if accountID == "" {
				continue
			}

			rels = append(rels, Relationship{
				SourceID:   containerID,
				SourceType: "azure:storage:container",
				TargetID:   accountID,
				TargetType: "azure:storage:account",
				RelType:    RelBelongsTo,
			})
		}
	}

	query = `SELECT ID, ACCOUNT_NAME, CONTAINER_NAME, RESOURCE_GROUP, SUBSCRIPTION_ID
	         FROM AZURE_STORAGE_BLOBS WHERE ID IS NOT NULL`
	if result, ok, err := r.queryRowsForTable(ctx, "AZURE_STORAGE_BLOBS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			blobID := toString(queryRow(row, "id"))
			if blobID == "" {
				continue
			}

			containerID := azureStorageContainerID(
				toString(queryRow(row, "subscription_id")),
				toString(queryRow(row, "resource_group")),
				toString(queryRow(row, "account_name")),
				toString(queryRow(row, "container_name")),
			)
			if containerID == "" {
				continue
			}

			rels = append(rels, Relationship{
				SourceID:   blobID,
				SourceType: "azure:storage:blob",
				TargetID:   containerID,
				TargetType: "azure:storage:container",
				RelType:    RelBelongsTo,
			})
		}
	}

	query = `SELECT ID, FRONTEND_IP_CONFIGURATIONS
	         FROM AZURE_NETWORK_LOAD_BALANCERS WHERE ID IS NOT NULL`
	if result, ok, err := r.queryRowsForTable(ctx, "AZURE_NETWORK_LOAD_BALANCERS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			lbID := toString(queryRow(row, "id"))
			if lbID == "" {
				continue
			}

			for _, frontend := range asSlice(queryRow(row, "frontend_ip_configurations")) {
				publicIPID := extractNestedRef(
					frontend,
					nil,
					[]string{"public_ip_address", "publicIPAddress", "PublicIPAddress"},
				)
				if publicIPID != "" {
					rels = append(rels, Relationship{
						SourceID:   lbID,
						SourceType: "azure:network:load_balancer",
						TargetID:   publicIPID,
						TargetType: "azure:network:public_ip",
						RelType:    RelAttachedTo,
					})
				}

				subnetID := extractNestedRef(
					frontend,
					nil,
					[]string{"subnet", "Subnet"},
				)
				if subnetID != "" {
					rels = append(rels, Relationship{
						SourceID:   lbID,
						SourceType: "azure:network:load_balancer",
						TargetID:   subnetID,
						TargetType: "azure:network:subnet",
						RelType:    RelInSubnet,
					})
				}
			}
		}
	}

	query = `SELECT ID, IP_CONFIGURATION, IP_ADDRESS
	         FROM AZURE_NETWORK_PUBLIC_IP_ADDRESSES WHERE ID IS NOT NULL`
	if result, ok, err := r.queryRowsForTable(ctx, "AZURE_NETWORK_PUBLIC_IP_ADDRESSES", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			publicIPID := toString(queryRow(row, "id"))
			if publicIPID == "" {
				continue
			}

			if strings.TrimSpace(toString(queryRow(row, "ip_address"))) != "" {
				rels = append(rels, Relationship{
					SourceID:   publicIPID,
					SourceType: "azure:network:public_ip",
					TargetID:   "internet",
					TargetType: "network:internet",
					RelType:    RelExposedTo,
				})
			}

			ipConfigID := extractReferenceID(queryRow(row, "ip_configuration"))
			if ipConfigID == "" {
				continue
			}

			lowerIPConfigID := strings.ToLower(ipConfigID)
			switch {
			case strings.Contains(lowerIPConfigID, "/networkinterfaces/"):
				if nicID := azureParentResourceID(ipConfigID, "ipConfigurations"); nicID != "" {
					rels = append(rels, Relationship{
						SourceID:   publicIPID,
						SourceType: "azure:network:public_ip",
						TargetID:   nicID,
						TargetType: "azure:network:interface",
						RelType:    RelAttachedTo,
					})
				}
			case strings.Contains(lowerIPConfigID, "/loadbalancers/"):
				if lbID := azureParentResourceID(ipConfigID, "frontendIPConfigurations"); lbID != "" {
					rels = append(rels, Relationship{
						SourceID:   publicIPID,
						SourceType: "azure:network:public_ip",
						TargetID:   lbID,
						TargetType: "azure:network:load_balancer",
						RelType:    RelAttachedTo,
					})
				}
			}
		}
	}

	vaultByURI := make(map[string]string)
	query = `SELECT ID, VAULT_URI FROM AZURE_KEYVAULT_VAULTS WHERE ID IS NOT NULL`
	if result, ok, err := r.queryRowsForTable(ctx, "AZURE_KEYVAULT_VAULTS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			vaultID := toString(queryRow(row, "id"))
			vaultURI := normalizeVaultURI(toString(queryRow(row, "vault_uri")))
			if vaultID != "" && vaultURI != "" {
				vaultByURI[vaultURI] = vaultID
			}
		}
	}

	query = `SELECT ID, VAULT_URI FROM AZURE_KEYVAULT_KEYS WHERE ID IS NOT NULL`
	if result, ok, err := r.queryRowsForTable(ctx, "AZURE_KEYVAULT_KEYS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			keyID := toString(queryRow(row, "id"))
			if keyID == "" {
				continue
			}
			vaultURI := normalizeVaultURI(toString(queryRow(row, "vault_uri")))
			if vaultURI == "" {
				continue
			}
			targetID := vaultByURI[vaultURI]
			if targetID == "" {
				targetID = vaultURI
			}

			rels = append(rels, Relationship{
				SourceID:   keyID,
				SourceType: "azure:keyvault:key",
				TargetID:   targetID,
				TargetType: "azure:keyvault:vault",
				RelType:    RelBelongsTo,
			})
		}
	}

	return r.persistRelationships(ctx, rels)
}
