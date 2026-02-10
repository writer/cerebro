package sync

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	container "cloud.google.com/go/container/apiv1"
	"cloud.google.com/go/container/apiv1/containerpb"
)

type gkeClusterManagerClient interface {
	ListClusters(ctx context.Context, req *containerpb.ListClustersRequest) (*containerpb.ListClustersResponse, error)
	Close() error
}

type gkeClusterManagerClientWrapper struct {
	client *container.ClusterManagerClient
}

func (w gkeClusterManagerClientWrapper) ListClusters(ctx context.Context, req *containerpb.ListClustersRequest) (*containerpb.ListClustersResponse, error) {
	return w.client.ListClusters(ctx, req)
}

func (w gkeClusterManagerClientWrapper) Close() error {
	return w.client.Close()
}

var newGKEClusterManagerClient = func(ctx context.Context) (gkeClusterManagerClient, error) {
	client, err := container.NewClusterManagerClient(ctx)
	if err != nil {
		return nil, err
	}
	return gkeClusterManagerClientWrapper{client: client}, nil
}

func (e *GCPSyncEngine) gcpGKEClusterTable() GCPTableSpec {
	return GCPTableSpec{
		Name:    "gcp_container_clusters",
		Columns: []string{"project_id", "name", "location", "description", "initial_node_count", "node_config", "master_auth", "logging_service", "monitoring_service", "network", "cluster_ipv4_cidr", "subnetwork", "node_pools", "locations", "enable_kubernetes_alpha", "resource_labels", "label_fingerprint", "legacy_abac", "network_policy", "ip_allocation_policy", "master_authorized_networks_config", "maintenance_policy", "binary_authorization", "autoscaling", "network_config", "private_cluster_config", "database_encryption", "vertical_pod_autoscaling", "shielded_nodes", "release_channel", "workload_identity_config", "mesh_certificates", "notification_config", "confidential_nodes", "identity_service_config", "status", "status_message", "node_ipv4_cidr_size", "services_ipv4_cidr", "current_master_version", "current_node_version", "create_time", "endpoint", "self_link"},
		Fetch:   e.fetchGCPGKEClusters,
	}
}

func (e *GCPSyncEngine) gcpGKENodePoolTable() GCPTableSpec {
	return GCPTableSpec{
		Name:    "gcp_container_node_pools",
		Columns: []string{"project_id", "cluster_name", "location", "name", "initial_node_count", "locations", "version", "status", "status_message", "config", "autoscaling", "management", "instance_group_urls", "max_pods_constraint", "upgrade_settings", "self_link"},
		Fetch:   e.fetchGCPGKENodePools,
	}
}

func (e *GCPSyncEngine) fetchGCPGKEClusters(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	client, err := newGKEClusterManagerClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create container client: %w", err)
	}
	defer func() { _ = client.Close() }()

	return fetchGCPGKEClustersWithClient(ctx, projectID, client)
}

func (e *GCPSyncEngine) fetchGCPGKENodePools(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	client, err := newGKEClusterManagerClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create container client: %w", err)
	}
	defer func() { _ = client.Close() }()

	return fetchGCPGKENodePoolsWithClient(ctx, projectID, client)
}

func fetchGCPGKENodePoolsWithClient(ctx context.Context, projectID string, client gkeClusterManagerClient) ([]map[string]interface{}, error) {
	req := &containerpb.ListClustersRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectID),
	}

	resp, err := client.ListClusters(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("list clusters: %w", err)
	}

	rows := make([]map[string]interface{}, 0, len(resp.Clusters))
	for _, cluster := range resp.Clusters {
		for _, np := range cluster.NodePools {
			statusMessage := statusMessageFromConditions(np.Conditions)
			selfLink := np.SelfLink
			if selfLink == "" {
				selfLink = fmt.Sprintf("https://container.googleapis.com/v1/projects/%s/locations/%s/clusters/%s/nodePools/%s",
					projectID, cluster.Location, cluster.Name, np.Name)
			}

			row := map[string]interface{}{
				"_cq_id":              selfLink,
				"project_id":          projectID,
				"cluster_name":        cluster.Name,
				"location":            cluster.Location,
				"name":                np.Name,
				"initial_node_count":  np.InitialNodeCount,
				"locations":           np.Locations,
				"version":             np.Version,
				"status":              np.Status.String(),
				"status_message":      statusMessage,
				"instance_group_urls": np.InstanceGroupUrls,
				"self_link":           selfLink,
			}

			if np.Config != nil {
				row["config"] = serializeNodeConfig(np.Config)
			}
			if np.Autoscaling != nil {
				row["autoscaling"] = map[string]interface{}{
					"enabled":              np.Autoscaling.Enabled,
					"min_node_count":       np.Autoscaling.MinNodeCount,
					"max_node_count":       np.Autoscaling.MaxNodeCount,
					"total_min_node_count": np.Autoscaling.TotalMinNodeCount,
					"total_max_node_count": np.Autoscaling.TotalMaxNodeCount,
				}
			}
			if np.Management != nil {
				row["management"] = map[string]interface{}{
					"auto_upgrade": np.Management.AutoUpgrade,
					"auto_repair":  np.Management.AutoRepair,
				}
			}
			if np.MaxPodsConstraint != nil {
				row["max_pods_constraint"] = map[string]interface{}{
					"max_pods_per_node": np.MaxPodsConstraint.MaxPodsPerNode,
				}
			}
			if np.UpgradeSettings != nil {
				row["upgrade_settings"] = map[string]interface{}{
					"strategy":        np.UpgradeSettings.Strategy.String(),
					"max_surge":       np.UpgradeSettings.MaxSurge,
					"max_unavailable": np.UpgradeSettings.MaxUnavailable,
				}
			}

			rows = append(rows, row)
		}
	}

	return rows, nil
}

func fetchGCPGKEClustersWithClient(ctx context.Context, projectID string, client gkeClusterManagerClient) ([]map[string]interface{}, error) {

	// List clusters across all locations
	req := &containerpb.ListClustersRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectID),
	}

	resp, err := client.ListClusters(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("list clusters: %w", err)
	}

	rows := make([]map[string]interface{}, 0, len(resp.Clusters))

	for _, cluster := range resp.Clusters {
		defaultPool := defaultNodePool(cluster.NodePools)
		statusMessage := statusMessageFromConditions(cluster.Conditions)
		currentNodeVersion := minNodePoolVersion(cluster.NodePools)
		if currentNodeVersion == "" && defaultPool != nil {
			currentNodeVersion = defaultPool.Version
		}

		initialNodeCount := int32(0)
		if defaultPool != nil {
			initialNodeCount = defaultPool.InitialNodeCount
		}

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
			"initial_node_count":      initialNodeCount,
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
			"status_message":          statusMessage,
			"node_ipv4_cidr_size":     cluster.NodeIpv4CidrSize,
			"services_ipv4_cidr":      cluster.ServicesIpv4Cidr,
			"current_master_version":  cluster.CurrentMasterVersion,
			"current_node_version":    currentNodeVersion,
			"create_time":             cluster.CreateTime,
			"endpoint":                cluster.Endpoint,
			"self_link":               selfLink,
		}

		// Node config (default pool)
		if defaultPool != nil && defaultPool.Config != nil {
			row["node_config"] = serializeNodeConfig(defaultPool.Config)
		}

		// Master auth
		if cluster.MasterAuth != nil {
			row["master_auth"] = map[string]interface{}{
				"cluster_ca_certificate":    cluster.MasterAuth.ClusterCaCertificate,
				"client_certificate":        cluster.MasterAuth.ClientCertificate,
				"client_certificate_config": cluster.MasterAuth.ClientCertificateConfig,
			}
		}

		// Node pools
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
				poolStatusMessage := statusMessageFromConditions(np.Conditions)
				if poolStatusMessage != "" {
					pool["status_message"] = poolStatusMessage
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

		var ipEndpointsConfig *containerpb.ControlPlaneEndpointsConfig_IPEndpointsConfig
		if cluster.ControlPlaneEndpointsConfig != nil {
			ipEndpointsConfig = cluster.ControlPlaneEndpointsConfig.GetIpEndpointsConfig()
		}
		if ipEndpointsConfig != nil {
			if authorizedConfig := ipEndpointsConfig.GetAuthorizedNetworksConfig(); authorizedConfig != nil {
				config := map[string]interface{}{
					"enabled": authorizedConfig.Enabled,
				}
				if len(authorizedConfig.CidrBlocks) > 0 {
					var blocks []map[string]interface{}
					for _, b := range authorizedConfig.CidrBlocks {
						blocks = append(blocks, map[string]interface{}{
							"display_name": b.DisplayName,
							"cidr_block":   b.CidrBlock,
						})
					}
					config["cidr_blocks"] = blocks
				}
				row["master_authorized_networks_config"] = config
			}
		}

		// Private cluster config
		privateConfig := map[string]interface{}{}
		if cluster.NetworkConfig != nil && cluster.NetworkConfig.DefaultEnablePrivateNodes != nil {
			privateConfig["enable_private_nodes"] = cluster.NetworkConfig.GetDefaultEnablePrivateNodes()
		}
		if ipEndpointsConfig != nil {
			if ipEndpointsConfig.EnablePublicEndpoint != nil {
				privateConfig["enable_private_endpoint"] = !ipEndpointsConfig.GetEnablePublicEndpoint()
			}
			if ipEndpointsConfig.PrivateEndpoint != "" {
				privateConfig["private_endpoint"] = ipEndpointsConfig.PrivateEndpoint
			}
			if ipEndpointsConfig.PublicEndpoint != "" {
				privateConfig["public_endpoint"] = ipEndpointsConfig.PublicEndpoint
			}
		}
		if cluster.PrivateClusterConfig != nil && cluster.PrivateClusterConfig.MasterIpv4CidrBlock != "" {
			privateConfig["master_ipv4_cidr_block"] = cluster.PrivateClusterConfig.MasterIpv4CidrBlock
		}
		if len(privateConfig) > 0 {
			row["private_cluster_config"] = privateConfig
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

		// Binary authorization
		if cluster.BinaryAuthorization != nil {
			row["binary_authorization"] = map[string]interface{}{
				"enabled":         cluster.BinaryAuthorization.EvaluationMode == containerpb.BinaryAuthorization_PROJECT_SINGLETON_POLICY_ENFORCE,
				"evaluation_mode": cluster.BinaryAuthorization.EvaluationMode.String(),
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

func defaultNodePool(pools []*containerpb.NodePool) *containerpb.NodePool {
	for _, pool := range pools {
		if pool.Name == "default-pool" {
			return pool
		}
	}
	if len(pools) > 0 {
		return pools[0]
	}
	return nil
}

func statusMessageFromConditions(conditions []*containerpb.StatusCondition) string {
	if len(conditions) == 0 {
		return ""
	}

	messages := make([]string, 0, len(conditions))
	for _, condition := range conditions {
		if condition == nil {
			continue
		}
		if condition.Message != "" {
			messages = append(messages, condition.Message)
		}
	}

	return strings.Join(messages, "; ")
}

func minNodePoolVersion(pools []*containerpb.NodePool) string {
	minVersion := ""
	for _, pool := range pools {
		if pool.Version == "" {
			continue
		}
		if minVersion == "" || compareNodeVersions(pool.Version, minVersion) < 0 {
			minVersion = pool.Version
		}
	}
	return minVersion
}

func compareNodeVersions(left, right string) int {
	leftVersion, leftOK := parseNodeVersion(left)
	rightVersion, rightOK := parseNodeVersion(right)
	if leftOK && rightOK {
		if leftVersion.major != rightVersion.major {
			return compareInts(leftVersion.major, rightVersion.major)
		}
		if leftVersion.minor != rightVersion.minor {
			return compareInts(leftVersion.minor, rightVersion.minor)
		}
		if leftVersion.patch != rightVersion.patch {
			return compareInts(leftVersion.patch, rightVersion.patch)
		}
		return 0
	}
	if left == right {
		return 0
	}
	if left < right {
		return -1
	}
	return 1
}

func compareInts(left, right int) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

type nodeVersion struct {
	major int
	minor int
	patch int
}

func parseNodeVersion(version string) (nodeVersion, bool) {
	base := strings.SplitN(version, "-", 2)[0]
	parts := strings.Split(base, ".")
	if len(parts) < 2 {
		return nodeVersion{}, false
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return nodeVersion{}, false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return nodeVersion{}, false
	}
	patch := 0
	if len(parts) > 2 {
		patch, err = strconv.Atoi(parts[2])
		if err != nil {
			return nodeVersion{}, false
		}
	}

	return nodeVersion{major: major, minor: minor, patch: patch}, true
}
