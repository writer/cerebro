package cloudidentitysource

import (
	"context"
	"fmt"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	ci "github.com/writer/cerebro/internal/cloudidentity"
	"github.com/writer/cerebro/internal/cloudidentity/iac"
	"github.com/writer/cerebro/internal/graphagent"
	"github.com/writer/cerebro/internal/sourcehttp"
	"golang.org/x/oauth2"
)

// DefaultFactory is the source composition root. Standard task credentials are
// resolved by the AWS SDK; all business logic receives narrow read-only ports.
func DefaultFactory(ctx context.Context, settings Settings) (ci.CollectionPorts, error) {
	apps := make(map[string]sourcehttp.GitHubAppAuthConfig, len(settings.GitHubInstallations))
	for owner, installation := range settings.GitHubInstallations {
		apps[owner] = sourcehttp.GitHubAppAuthConfig{AppID: settings.GitHubAppID, InstallationID: installation, PrivateKeyBase64: settings.GitHubPrivateKeyBase64}
	}
	repositories, err := NewRepositoryReader(RepositoryOptions{Apps: apps, AllowedRepositories: settings.AllowedRepositories, AllowedModules: settings.AllowedModules, RegistryModules: settings.RegistryModules})
	if err != nil {
		return ci.CollectionPorts{}, err
	}
	modules, err := AsModuleReader(repositories)
	if err != nil {
		return ci.CollectionPorts{}, err
	}
	charts, err := NewChartReader(ChartReaderOptions{AllowedRepositories: settings.AllowedChartRepositories})
	if err != nil {
		return ci.CollectionPorts{}, err
	}
	manifests, err := NewManifestRenderer(ManifestRendererOptions{Repositories: repositories, Charts: charts, AllowedChartRepositories: settings.AllowedChartRepositories})
	if err != nil {
		return ci.CollectionPorts{}, err
	}
	awsConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(settings.AWSRegion))
	if err != nil {
		return ci.CollectionPorts{}, fmt.Errorf("cloud_identity AWS task credential configuration failed")
	}
	clouds := make(map[ci.Provider]ci.CloudReader)
	var googleTokens oauth2.TokenSource
	if planUsesProvider(settings.Plan, ci.GCP) {
		googleTokens, err = NewGCPCredentialSource(ctx, awsConfig, settings.GCPWIFAudience, settings.GCPWIFServiceAccount)
		if err != nil {
			return ci.CollectionPorts{}, err
		}
		clouds[ci.GCP], err = NewGCPReader(GCPOptions{TokenSource: googleTokens, Organization: settings.GCPOrganization, QuotaProject: settings.GCPQuotaProject})
		if err != nil {
			return ci.CollectionPorts{}, err
		}
	}
	if planUsesProvider(settings.Plan, ci.AWS) {
		clouds[ci.AWS], err = NewAWSReader(ctx, AWSOptions{Config: awsConfig, RoleName: settings.AWSRoleName, Region: settings.AWSRegion})
		if err != nil {
			return ci.CollectionPorts{}, err
		}
	}
	registry, err := NewRegistryReader(RegistryOptions{AWSConfig: awsConfig, AWSRoleName: settings.AWSRoleName, GoogleTokenSource: googleTokens})
	if err != nil {
		return ci.CollectionPorts{}, err
	}
	model, err := graphagent.NewLLMClientWithSecrets(ctx, graphagent.LLMConfigWithSecrets{LLMConfig: graphagent.LLMConfig{Provider: settings.LLMProvider, Model: settings.LLMModel, Region: settings.LLMRegion, MaxTokens: 8192, Temperature: 0, TemperatureSet: true}, OpenRouterAPIKey: settings.LLMAPIKey})
	if err != nil {
		return ci.CollectionPorts{}, fmt.Errorf("cloud_identity model provider configuration failed")
	}
	structured, ok := model.(graphagent.StructuredJSONClient)
	if !ok {
		return ci.CollectionPorts{}, fmt.Errorf("cloud_identity model provider must support schema-bound investigation")
	}
	investigator, err := NewRequirementInvestigator(InvestigatorOptions{Client: structured, Model: graphagent.DefaultModel, TenantID: settings.TenantID})
	if err != nil {
		return ci.CollectionPorts{}, err
	}
	return ci.CollectionPorts{Repositories: repositories, Registry: registry, Manifests: manifests, Declarations: iac.NewDeclarationReader(modules), Clouds: clouds, Investigator: investigator}, nil
}

func planUsesProvider(plan ci.ScanPlan, provider ci.Provider) bool {
	for _, target := range plan.Targets {
		if target.Provider == provider {
			return true
		}
	}
	return false
}
