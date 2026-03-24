package scanner

import (
	"context"
	"testing"
)

type fakeAWSRegistryDiscovery struct {
	regions   []string
	accountID string
}

func (d fakeAWSRegistryDiscovery) Regions(context.Context) ([]string, error) {
	return append([]string(nil), d.regions...), nil
}

func (d fakeAWSRegistryDiscovery) AccountID(context.Context) (string, error) {
	return d.accountID, nil
}

type fakeGCPRegistryDiscovery struct {
	hostsByProject map[string][]string
	token          string
}

func (d fakeGCPRegistryDiscovery) RegistryHosts(_ context.Context, projectID string) ([]string, error) {
	return append([]string(nil), d.hostsByProject[projectID]...), nil
}

func (d fakeGCPRegistryDiscovery) AccessToken(context.Context) (string, error) {
	return d.token, nil
}

type fakeAzureRegistryDiscovery struct {
	namesBySubscription map[string][]string
}

func (d fakeAzureRegistryDiscovery) RegistryNames(_ context.Context, subscriptionID string) ([]string, error) {
	return append([]string(nil), d.namesBySubscription[subscriptionID]...), nil
}

func TestDiscoverRegistryClientsWithDependenciesBuildsCloudAndDockerHubClients(t *testing.T) {
	clients, err := DiscoverRegistryClientsWithDependencies(context.Background(), RegistryDiscoveryOptions{
		DockerHubNamespaces:   []string{"library"},
		GCPProjects:           []string{"proj-a"},
		AzureSubscriptionIDs:  []string{"sub-123"},
		DiscoverAWSRegistries: true,
	}, RegistryDiscoveryDependencies{
		AWS: fakeAWSRegistryDiscovery{
			regions:   []string{"us-east-1", "us-west-2"},
			accountID: "123456789012",
		},
		GCP: fakeGCPRegistryDiscovery{
			hostsByProject: map[string][]string{
				"proj-a": {"gcr.io", "us-docker.pkg.dev"},
			},
			token: "gcp-token",
		},
		Azure: fakeAzureRegistryDiscovery{
			namesBySubscription: map[string][]string{
				"sub-123": {"team-registry"},
			},
		},
	})
	if err != nil {
		t.Fatalf("DiscoverRegistryClientsWithDependencies: %v", err)
	}
	if len(clients) != 6 {
		t.Fatalf("expected 6 discovered clients, got %d", len(clients))
	}

	hosts := map[string]bool{}
	for _, client := range clients {
		hosts[client.RegistryHost()] = true
	}
	for _, expected := range []string{
		"docker.io",
		"123456789012.dkr.ecr.us-east-1.amazonaws.com",
		"123456789012.dkr.ecr.us-west-2.amazonaws.com",
		"gcr.io",
		"us-docker.pkg.dev",
		"team-registry.azurecr.io",
	} {
		if !hosts[expected] {
			t.Fatalf("expected discovered host %q, got %#v", expected, hosts)
		}
	}
}
