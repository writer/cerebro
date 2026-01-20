package sync

import (
	"context"
	"fmt"

	container "cloud.google.com/go/container/apiv1"
	"cloud.google.com/go/container/apiv1/containerpb"
)

func (e *GCPSyncEngine) gcpGKEClusterTable() GCPTableSpec {
	return GCPTableSpec{
		Name:    "gcp_container_clusters",
		Columns: []string{"project_id", "name", "location", "description", "initial_node_count", "node_config", "master_auth", "logging_service", "monitoring_service", "network", "cluster_ipv4_cidr", "subnetwork", "node_pools", "locations", "enable_kubernetes_alpha", "resource_labels", "label_fingerprint", "legacy_abac", "network_policy", "ip_allocation_policy", "master_authorized_networks_config", "maintenance_policy", "binary_authorization", "autoscaling", "network_config", "private_cluster_config", "database_encryption", "vertical_pod_autoscaling", "shielded_nodes", "release_channel", "workload_identity_config", "mesh_certificates", "notification_config", "confidential_nodes", "identity_service_config", "status", "status_message", "node_ipv4_cidr_size", "services_ipv4_cidr", "current_master_version", "current_node_version", "create_time", "endpoint", "self_link"},
		Fetch:   e.fetchGCPGKEClusters,
	}
}

func (e *GCPSyncEngine) fetchGCPGKEClusters(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	client, err := container.NewClusterManagerClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create container client: %w", err)
	}
	defer func() { _ = client.Close() }()

	req := &containerpb.ListClustersRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectID),
	}

	resp, err := client.ListClusters(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("list clusters: %w", err)
	}

	rows := make([]map[string]interface{}, 0, len(resp.Clusters))

	for _, cluster := range resp.Clusters {
		selfLink := cluster.SelfLink
		if selfLink == "" {
			selfLink = fmt.Sprintf("https://container.googleapis.com/v1/projects/%s/locations/%s/clusters/%s",
				projectID, cluster.Location, cluster.Name)
		}

		row := map[string]interface{}{
			"_cq_id":                  selfLink,
			"project_id":              projectID,
			"name":                    cluster.Name,
			"location":                cluster.Location,
			"description":             cluster.Description,
			"logging_service":         cluster.LoggingService,
			"monitoring_service":      cluster.MonitoringService,
			"network":                 cluster.Network,
			"cluster_ipv4_cidr":       cluster.ClusterIpv4Cidr,
			"subnetwork":              cluster.Subnetwork,
			"locations":               cluster.Locations,
			"enable_kubernetes_alpha": cluster.EnableKubernetesAlpha,
			"resource_labels":         cluster.ResourceLabels,
			"label_fingerprint":       cluster.LabelFingerprint,
			"status":                  cluster.Status.String(),
			"node_ipv4_cidr_size":     cluster.NodeIpv4CidrSize,
			"services_ipv4_cidr":      cluster.ServicesIpv4Cidr,
			"current_master_version":  cluster.CurrentMasterVersion,
			"create_time":             cluster.CreateTime,
			"endpoint":                cluster.Endpoint,
			"self_link":               selfLink,
		}

		// Get initial_node_count, current_node_version, and node_config from first node pool
		// (replaces deprecated cluster-level fields)
		if len(cluster.NodePools) > 0 {
			firstPool := cluster.NodePools[0]
			row["initial_node_count"] = firstPool.InitialNodeCount
			row["current_node_version"] = firstPool.Version
			if firstPool.Config != nil {
				row["node_config"] = serializeNodeConfig(firstPool.Config)
			}
		}

		// Master auth (username field removed as deprecated)
		if cluster.MasterAuth != nil {
			row["master_auth"] = map[string]interface{}{
				"cluster_ca_certificate":    cluster.MasterAuth.ClusterCaCertificate,
				"client_certificate":        cluster.MasterAuth.ClientCertificate,
				"client_certificate_config": cluster.MasterAuth.ClientCertificateConfig,
			}
		}

		// Node pools (status_message removed as deprecated)
		if len(cluster.NodePools) > 0 {
			var nodePools []map[string]interface{}
			for _, np := range cluster.NodePools {
				pool := map[string]interface{}{
					"name":               np.Name,
					"initial_node_count": np.InitialNodeCount,
					"locations":          np.Locations,
					"self_link":          np.SelfLink,
					"version":            np.Version,
					"status":             np.Status.String(),
				}
				if np.Config != nil {
					pool["config"] = serializeNodeConfig(np.Config)
				}
				if np.Autoscaling != nil {
					pool["autoscaling"] = map[string]interface{}{
						"enabled":        np.Autoscaling.Enabled,
						"min_node_count": np.Autoscaling.MinNodeCount,
						"max_node_count": np.Autoscaling.MaxNodeCount,
					}
				}
				if np.Management != nil {
					pool["management"] = map[string]interface{}{
						"auto_upgrade": np.Management.AutoUpgrade,
						"auto_repair":  np.Management.AutoRepair,
					}
				}
				nodePools = append(nodePools, pool)
			}
			row["node_pools"] = nodePools
		}

		// Legacy ABAC
		if cluster.LegacyAbac != nil {
			row["legacy_abac"] = map[string]interface{}{
				"enabled": cluster.LegacyAbac.Enabled,
			}
		}

		// Network policy
		if cluster.NetworkPolicy != nil {
			row["network_policy"] = map[string]interface{}{
				"provider": cluster.NetworkPolicy.Provider.String(),
				"enabled":  cluster.NetworkPolicy.Enabled,
			}
		}

		// IP allocation policy
		if cluster.IpAllocationPolicy != nil {
			row["ip_allocation_policy"] = map[string]interface{}{
				"use_ip_aliases":                cluster.IpAllocationPolicy.UseIpAliases,
				"cluster_secondary_range_name":  cluster.IpAllocationPolicy.ClusterSecondaryRangeName,
				"services_secondary_range_name": cluster.IpAllocationPolicy.ServicesSecondaryRangeName,
				"cluster_ipv4_cidr_block":       cluster.IpAllocationPolicy.ClusterIpv4CidrBlock,
				"services_ipv4_cidr_block":      cluster.IpAllocationPolicy.ServicesIpv4CidrBlock,
			}
		}

		// Master authorized networks (use new ControlPlaneEndpointsConfig)
		if cluster.ControlPlaneEndpointsConfig != nil &&
			cluster.ControlPlaneEndpointsConfig.IpEndpointsConfig != nil &&
			cluster.ControlPlaneEndpointsConfig.IpEndpointsConfig.AuthorizedNetworksConfig != nil {
			anc := cluster.ControlPlaneEndpointsConfig.IpEndpointsConfig.AuthorizedNetworksConfig
			config := map[string]interface{}{
				"enabled": anc.Enabled,
			}
			if len(anc.CidrBlocks) > 0 {
				var blocks []map[string]interface{}
				for _, b := range anc.CidrBlocks {
					blocks = append(blocks, map[string]interface{}{
						"display_name": b.DisplayName,
						"cidr_block":   b.CidrBlock,
					})
				}
				config["cidr_blocks"] = blocks
			}
			row["master_authorized_networks_config"] = config
		}

		// Private cluster config (use new NetworkConfig and ControlPlaneEndpointsConfig)
		privateClusterConfig := map[string]interface{}{}
		if cluster.NetworkConfig != nil {
			privateClusterConfig["enable_private_nodes"] = cluster.NetworkConfig.DefaultEnablePrivateNodes
		}
		if cluster.ControlPlaneEndpointsConfig != nil &&
			cluster.ControlPlaneEndpointsConfig.IpEndpointsConfig != nil {
			ipConfig := cluster.ControlPlaneEndpointsConfig.IpEndpointsConfig
			if ipConfig.EnablePublicEndpoint != nil {
				privateClusterConfig["enable_private_endpoint"] = !*ipConfig.EnablePublicEndpoint
			}
			privateClusterConfig["private_endpoint"] = ipConfig.PrivateEndpoint
		}
		if cluster.PrivateClusterConfig != nil {
			privateClusterConfig["master_ipv4_cidr_block"] = cluster.PrivateClusterConfig.MasterIpv4CidrBlock
		}
		if len(privateClusterConfig) > 0 {
			row["private_cluster_config"] = privateClusterConfig
		}

		// Database encryption
		if cluster.DatabaseEncryption != nil {
			row["database_encryption"] = map[string]interface{}{
				"state":    cluster.DatabaseEncryption.State.String(),
				"key_name": cluster.DatabaseEncryption.KeyName,
			}
		}

		// Shielded nodes
		if cluster.ShieldedNodes != nil {
			row["shielded_nodes"] = map[string]interface{}{
				"enabled": cluster.ShieldedNodes.Enabled,
			}
		}

		// Release channel
		if cluster.ReleaseChannel != nil {
			row["release_channel"] = map[string]interface{}{
				"channel": cluster.ReleaseChannel.Channel.String(),
			}
		}

		// Workload identity
		if cluster.WorkloadIdentityConfig != nil {
			row["workload_identity_config"] = map[string]interface{}{
				"workload_pool": cluster.WorkloadIdentityConfig.WorkloadPool,
			}
		}

		// Binary authorization (use EvaluationMode instead of deprecated Enabled field)
		if cluster.BinaryAuthorization != nil {
			evalMode := cluster.BinaryAuthorization.EvaluationMode.String()
			enabled := evalMode != "DISABLED" && evalMode != "EVALUATION_MODE_UNSPECIFIED"
			row["binary_authorization"] = map[string]interface{}{
				"enabled":         enabled,
				"evaluation_mode": evalMode,
			}
		}

		rows = append(rows, row)
	}

	return rows, nil
}

func serializeNodeConfig(nc *containerpb.NodeConfig) map[string]interface{} {
	config := map[string]interface{}{
		"machine_type":    nc.MachineType,
		"disk_size_gb":    nc.DiskSizeGb,
		"disk_type":       nc.DiskType,
		"oauth_scopes":    nc.OauthScopes,
		"service_account": nc.ServiceAccount,
		"metadata":        nc.Metadata,
		"image_type":      nc.ImageType,
		"labels":          nc.Labels,
		"local_ssd_count": nc.LocalSsdCount,
		"tags":            nc.Tags,
		"preemptible":     nc.Preemptible,
		"spot":            nc.Spot,
	}

	if nc.ShieldedInstanceConfig != nil {
		config["shielded_instance_config"] = map[string]interface{}{
			"enable_secure_boot":          nc.ShieldedInstanceConfig.EnableSecureBoot,
			"enable_integrity_monitoring": nc.ShieldedInstanceConfig.EnableIntegrityMonitoring,
		}
	}

	if nc.WorkloadMetadataConfig != nil {
		config["workload_metadata_config"] = map[string]interface{}{
			"mode": nc.WorkloadMetadataConfig.Mode.String(),
		}
	}

	return config
}
