package sync

import (
	"context"
	"testing"

	"cloud.google.com/go/container/apiv1/containerpb"
)

type fakeGKEClusterClient struct {
	response *containerpb.ListClustersResponse
	err      error
	request  *containerpb.ListClustersRequest
}

func (f *fakeGKEClusterClient) ListClusters(ctx context.Context, req *containerpb.ListClustersRequest) (*containerpb.ListClustersResponse, error) {
	f.request = req
	return f.response, f.err
}

func (f *fakeGKEClusterClient) Close() error {
	return nil
}

func TestDefaultNodePool(t *testing.T) {
	primary := &containerpb.NodePool{Name: "default-pool"}
	secondary := &containerpb.NodePool{Name: "secondary"}

	if got := defaultNodePool([]*containerpb.NodePool{secondary, primary}); got != primary {
		t.Fatalf("expected default pool, got %v", got)
	}
	if got := defaultNodePool([]*containerpb.NodePool{secondary}); got != secondary {
		t.Fatalf("expected fallback pool, got %v", got)
	}
	if got := defaultNodePool(nil); got != nil {
		t.Fatalf("expected nil pool, got %v", got)
	}
}

func TestStatusMessageFromConditions(t *testing.T) {
	conditions := []*containerpb.StatusCondition{
		{Message: "ready"},
		{Message: "healthy"},
		{},
	}

	message := statusMessageFromConditions(conditions)
	if message != "ready; healthy" {
		t.Fatalf("unexpected status message: %q", message)
	}
}

func TestParseNodeVersion(t *testing.T) {
	version, ok := parseNodeVersion("1.27.3-gke.100")
	if !ok {
		t.Fatal("expected version to parse")
	}
	if version.major != 1 || version.minor != 27 || version.patch != 3 {
		t.Fatalf("unexpected parsed version: %+v", version)
	}

	version, ok = parseNodeVersion("1.27")
	if !ok {
		t.Fatal("expected version to parse")
	}
	if version.patch != 0 {
		t.Fatalf("expected patch 0, got %d", version.patch)
	}

	if _, ok := parseNodeVersion("not-a-version"); ok {
		t.Fatal("expected parse to fail")
	}
}

func TestCompareNodeVersions(t *testing.T) {
	if compareNodeVersions("1.27.3-gke.1", "1.27.10-gke.1") >= 0 {
		t.Fatal("expected 1.27.3 to be less than 1.27.10")
	}
	if compareNodeVersions("1.28.0", "1.27.10") <= 0 {
		t.Fatal("expected 1.28.0 to be greater than 1.27.10")
	}
}

func TestMinNodePoolVersion(t *testing.T) {
	pools := []*containerpb.NodePool{
		{Name: "default-pool", Version: "1.28.1-gke.100"},
		{Name: "secondary", Version: "1.27.5-gke.200"},
	}

	if got := minNodePoolVersion(pools); got != "1.27.5-gke.200" {
		t.Fatalf("unexpected min version: %s", got)
	}
}

func TestFetchGCPGKEClustersWithClient(t *testing.T) {
	privateNodes := true
	publicEndpoint := false

	cluster := &containerpb.Cluster{
		Name:        "cluster-1",
		Location:    "us-central1",
		Description: "test cluster",
		NodePools: []*containerpb.NodePool{
			{
				Name:             "default-pool",
				InitialNodeCount: 3,
				Version:          "1.28.1-gke.100",
				Config: &containerpb.NodeConfig{
					MachineType: "e2-medium",
				},
			},
			{
				Name:             "secondary",
				InitialNodeCount: 1,
				Version:          "1.27.5-gke.200",
			},
		},
		Conditions: []*containerpb.StatusCondition{
			{Message: "ready"},
			{Message: "healthy"},
		},
		ControlPlaneEndpointsConfig: &containerpb.ControlPlaneEndpointsConfig{
			IpEndpointsConfig: &containerpb.ControlPlaneEndpointsConfig_IPEndpointsConfig{
				EnablePublicEndpoint: &publicEndpoint,
				PublicEndpoint:       "35.1.1.1",
				PrivateEndpoint:      "10.0.0.1",
				AuthorizedNetworksConfig: &containerpb.MasterAuthorizedNetworksConfig{
					Enabled: true,
					CidrBlocks: []*containerpb.MasterAuthorizedNetworksConfig_CidrBlock{
						{DisplayName: "office", CidrBlock: "1.2.3.4/32"},
					},
				},
			},
		},
		NetworkConfig: &containerpb.NetworkConfig{
			DefaultEnablePrivateNodes: &privateNodes,
		},
		PrivateClusterConfig: &containerpb.PrivateClusterConfig{
			MasterIpv4CidrBlock: "10.0.0.0/28",
		},
		BinaryAuthorization: &containerpb.BinaryAuthorization{
			EvaluationMode: containerpb.BinaryAuthorization_PROJECT_SINGLETON_POLICY_ENFORCE,
		},
	}

	client := &fakeGKEClusterClient{
		response: &containerpb.ListClustersResponse{Clusters: []*containerpb.Cluster{cluster}},
	}

	rows, err := fetchGCPGKEClustersWithClient(context.Background(), "my-project", client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.request == nil || client.request.Parent != "projects/my-project/locations/-" {
		t.Fatalf("unexpected request: %+v", client.request)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}

	row := rows[0]
	if row["current_node_version"] != "1.27.5-gke.200" {
		t.Fatalf("unexpected node version: %v", row["current_node_version"])
	}
	if row["status_message"] != "ready; healthy" {
		t.Fatalf("unexpected status message: %v", row["status_message"])
	}
	if value, ok := row["initial_node_count"].(int32); !ok || value != 3 {
		t.Fatalf("unexpected initial node count: %v", row["initial_node_count"])
	}

	nodeConfig, ok := row["node_config"].(map[string]interface{})
	if !ok || nodeConfig["machine_type"] != "e2-medium" {
		t.Fatalf("unexpected node config: %v", row["node_config"])
	}

	authorized, ok := row["master_authorized_networks_config"].(map[string]interface{})
	if !ok || authorized["enabled"] != true {
		t.Fatalf("unexpected authorized networks config: %v", row["master_authorized_networks_config"])
	}

	privateConfig, ok := row["private_cluster_config"].(map[string]interface{})
	if !ok || privateConfig["enable_private_nodes"] != true || privateConfig["enable_private_endpoint"] != true {
		t.Fatalf("unexpected private cluster config: %v", row["private_cluster_config"])
	}

	binaryAuth, ok := row["binary_authorization"].(map[string]interface{})
	if !ok || binaryAuth["enabled"] != true {
		t.Fatalf("unexpected binary authorization config: %v", row["binary_authorization"])
	}
}
