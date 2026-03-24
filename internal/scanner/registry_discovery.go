package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	artifactregistry "cloud.google.com/go/artifactregistry/apiv1"
	"cloud.google.com/go/artifactregistry/apiv1/artifactregistrypb"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
)

type RegistryDiscoveryOptions struct {
	DockerHubNamespaces   []string
	AWSRegions            []string
	DiscoverAWSRegistries bool
	GCPProjects           []string
	IncludeLegacyGCR      bool
	AzureSubscriptionIDs  []string
}

type RegistryDiscoveryDependencies struct {
	AWS   awsRegistryDiscovery
	GCP   gcpRegistryDiscovery
	Azure azureRegistryDiscovery
}

type awsRegistryDiscovery interface {
	Regions(ctx context.Context) ([]string, error)
	AccountID(ctx context.Context) (string, error)
}

type gcpRegistryDiscovery interface {
	RegistryHosts(ctx context.Context, projectID string) ([]string, error)
	AccessToken(ctx context.Context) (string, error)
}

type azureRegistryDiscovery interface {
	RegistryNames(ctx context.Context, subscriptionID string) ([]string, error)
}

func DiscoverRegistryClients(ctx context.Context, opts RegistryDiscoveryOptions) ([]RegistryClient, error) {
	return DiscoverRegistryClientsWithDependencies(ctx, opts, RegistryDiscoveryDependencies{
		AWS:   defaultAWSRegistryDiscovery{},
		GCP:   defaultGCPRegistryDiscovery{},
		Azure: defaultAzureRegistryDiscovery{client: &http.Client{Timeout: 60 * time.Second}},
	})
}

func DiscoverRegistryClientsWithDependencies(ctx context.Context, opts RegistryDiscoveryOptions, deps RegistryDiscoveryDependencies) ([]RegistryClient, error) {
	clients := make([]RegistryClient, 0)
	seen := make(map[string]struct{})
	addClient := func(client RegistryClient) {
		if client == nil {
			return
		}
		key := client.Name() + "|" + strings.ToLower(strings.TrimSpace(client.RegistryHost()))
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		clients = append(clients, client)
	}

	if len(opts.DockerHubNamespaces) > 0 {
		addClient(NewDockerHubClient(opts.DockerHubNamespaces...))
	}

	awsRegions := normalizeStringList(opts.AWSRegions)
	if deps.AWS != nil && (opts.DiscoverAWSRegistries || len(awsRegions) > 0) {
		accountID, err := deps.AWS.AccountID(ctx)
		if err != nil {
			return nil, err
		}
		if len(awsRegions) == 0 {
			awsRegions, err = deps.AWS.Regions(ctx)
			if err != nil {
				return nil, err
			}
		}
		for _, region := range awsRegions {
			addClient(NewECRClient(region, accountID))
		}
	}

	if deps.GCP != nil {
		token := ""
		if len(opts.GCPProjects) > 0 {
			var err error
			token, err = deps.GCP.AccessToken(ctx)
			if err != nil {
				return nil, err
			}
		}
		for _, projectID := range normalizeStringList(opts.GCPProjects) {
			hosts, err := deps.GCP.RegistryHosts(ctx, projectID)
			if err != nil {
				return nil, err
			}
			if opts.IncludeLegacyGCR {
				hosts = append(hosts, "gcr.io", "us.gcr.io", "eu.gcr.io", "asia.gcr.io")
			}
			for _, host := range normalizeStringList(hosts) {
				client := NewGCRClient(projectID)
				client.SetRegistryHost(host)
				client.SetAccessToken(token)
				addClient(client)
			}
		}
	}

	if deps.Azure != nil {
		for _, subscriptionID := range normalizeStringList(opts.AzureSubscriptionIDs) {
			names, err := deps.Azure.RegistryNames(ctx, subscriptionID)
			if err != nil {
				return nil, err
			}
			for _, name := range normalizeStringList(names) {
				addClient(NewACRClient(name, subscriptionID))
			}
		}
	}

	return clients, nil
}

type defaultAWSRegistryDiscovery struct{}

func (d defaultAWSRegistryDiscovery) Regions(ctx context.Context) ([]string, error) {
	region := firstNonEmptyString(os.Getenv("AWS_REGION"), os.Getenv("AWS_DEFAULT_REGION"), "us-east-1")
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	client := ec2.NewFromConfig(cfg)
	out, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, fmt.Errorf("describe aws regions: %w", err)
	}
	regions := make([]string, 0, len(out.Regions))
	for _, item := range out.Regions {
		if item.RegionName != nil && strings.TrimSpace(*item.RegionName) != "" {
			regions = append(regions, strings.TrimSpace(*item.RegionName))
		}
	}
	return normalizeStringList(regions), nil
}

func (d defaultAWSRegistryDiscovery) AccountID(ctx context.Context) (string, error) {
	region := firstNonEmptyString(os.Getenv("AWS_REGION"), os.Getenv("AWS_DEFAULT_REGION"), "us-east-1")
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return "", fmt.Errorf("load aws config: %w", err)
	}
	client := sts.NewFromConfig(cfg)
	out, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("get aws caller identity: %w", err)
	}
	if out.Account == nil || strings.TrimSpace(*out.Account) == "" {
		return "", fmt.Errorf("aws caller identity missing account id")
	}
	return strings.TrimSpace(*out.Account), nil
}

type defaultGCPRegistryDiscovery struct{}

func (d defaultGCPRegistryDiscovery) RegistryHosts(ctx context.Context, projectID string) ([]string, error) {
	client, err := artifactregistry.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create artifact registry client: %w", err)
	}
	defer func() { _ = client.Close() }()

	seen := make(map[string]struct{})
	hosts := make([]string, 0)
	for _, location := range []string{"us", "us-central1", "us-east1", "us-west1", "europe-west1", "asia-east1"} {
		req := &artifactregistrypb.ListRepositoriesRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", strings.TrimSpace(projectID), location),
		}
		it := client.ListRepositories(ctx, req)
		for {
			repo, err := it.Next()
			if errors.Is(err, iterator.Done) {
				break
			}
			if err != nil {
				break
			}
			if repo.GetFormat() != artifactregistrypb.Repository_DOCKER {
				continue
			}
			host := strings.TrimSpace(location) + "-docker.pkg.dev"
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			hosts = append(hosts, host)
		}
	}
	return hosts, nil
}

func (d defaultGCPRegistryDiscovery) AccessToken(ctx context.Context) (string, error) {
	tokenSource, err := google.DefaultTokenSource(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return "", fmt.Errorf("resolve gcp access token source: %w", err)
	}
	token, err := tokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("resolve gcp access token: %w", err)
	}
	return strings.TrimSpace(token.AccessToken), nil
}

type defaultAzureRegistryDiscovery struct {
	client *http.Client
}

func (d defaultAzureRegistryDiscovery) RegistryNames(ctx context.Context, subscriptionID string) ([]string, error) {
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("create azure credential: %w", err)
	}
	token, err := credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{"https://management.azure.com/.default"}})
	if err != nil {
		return nil, fmt.Errorf("request azure management token: %w", err)
	}
	client := d.client
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}

	reqURL, err := azureRegistryListURL(subscriptionID, "")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0)
	for reqURL != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token.Token))
		resp, err := client.Do(req)
		if err != nil {
			return nil, sanitizeTransportError(err)
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("azure registry discovery error %d: %s", resp.StatusCode, string(body))
		}
		var payload struct {
			Value []struct {
				Name string `json:"name"`
			} `json:"value"`
			NextLink string `json:"nextLink"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, err
		}
		for _, item := range payload.Value {
			if name := strings.TrimSpace(item.Name); name != "" {
				names = append(names, name)
			}
		}
		reqURL, err = azureRegistryListURL(subscriptionID, payload.NextLink)
		if err != nil {
			return nil, err
		}
	}
	return normalizeStringList(names), nil
}

func azureRegistryListURL(subscriptionID, nextLink string) (string, error) {
	if strings.TrimSpace(nextLink) != "" {
		parsed, err := url.Parse(strings.TrimSpace(nextLink))
		if err != nil {
			return "", err
		}
		if !strings.EqualFold(parsed.Host, "management.azure.com") {
			return "", fmt.Errorf("unexpected azure registry next link host %q", parsed.Host)
		}
		return parsed.String(), nil
	}
	subscriptionID = strings.TrimSpace(subscriptionID)
	if subscriptionID == "" {
		return "", nil
	}
	return (&url.URL{
		Scheme: "https",
		Host:   "management.azure.com",
		Path:   "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.ContainerRegistry/registries",
		RawQuery: url.Values{
			"api-version": []string{"2023-07-01"},
		}.Encode(),
	}).String(), nil
}

func normalizeStringList(values []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
