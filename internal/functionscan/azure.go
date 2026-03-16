package functionscan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
)

type azureWebAppsAPI interface {
	Get(ctx context.Context, resourceGroupName string, name string, options *armappservice.WebAppsClientGetOptions) (armappservice.WebAppsClientGetResponse, error)
	ListApplicationSettings(ctx context.Context, resourceGroupName string, name string, options *armappservice.WebAppsClientListApplicationSettingsOptions) (armappservice.WebAppsClientListApplicationSettingsResponse, error)
}

type AzureProvider struct {
	client     azureWebAppsAPI
	httpClient *http.Client
}

func NewAzureProvider(subscriptionID string) (*AzureProvider, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("create azure credential: %w", err)
	}
	return NewAzureProviderWithCredential(subscriptionID, cred)
}

func NewAzureProviderWithCredential(subscriptionID string, cred azcore.TokenCredential) (*AzureProvider, error) {
	client, err := armappservice.NewWebAppsClient(strings.TrimSpace(subscriptionID), cred, nil)
	if err != nil {
		return nil, fmt.Errorf("create azure webapps client: %w", err)
	}
	return NewAzureProviderWithClient(client), nil
}

func NewAzureProviderWithClient(client azureWebAppsAPI) *AzureProvider {
	return &AzureProvider{client: client, httpClient: &http.Client{Timeout: 2 * time.Minute}}
}

func (p *AzureProvider) Kind() ProviderKind { return ProviderAzure }

func (p *AzureProvider) DescribeFunction(ctx context.Context, target FunctionTarget) (*FunctionDescriptor, error) {
	if p == nil || p.client == nil {
		return nil, fmt.Errorf("azure function scan provider is not configured")
	}
	name := strings.TrimSpace(target.AppName)
	if name == "" {
		return nil, fmt.Errorf("azure function app name is required")
	}
	resourceGroup := strings.TrimSpace(target.ResourceGroup)
	if resourceGroup == "" {
		return nil, fmt.Errorf("azure resource group is required")
	}
	site, err := p.client.Get(ctx, resourceGroup, name, nil)
	if err != nil {
		return nil, fmt.Errorf("get azure function app %s: %w", name, err)
	}
	settings, err := p.client.ListApplicationSettings(ctx, resourceGroup, name, nil)
	if err != nil {
		return nil, fmt.Errorf("list azure function app settings %s: %w", name, err)
	}
	env := map[string]string{}
	for key, value := range settings.Properties {
		if strings.TrimSpace(key) == "" || value == nil {
			continue
		}
		env[key] = strings.TrimSpace(*value)
	}
	descriptor := &FunctionDescriptor{
		ID:                 target.Identity(),
		Name:               name,
		Runtime:            azureRuntimeFromSettings(env),
		EntryPoint:         firstNonEmpty(env["FUNCTIONS_WORKER_RUNTIME"], env["FUNCTIONS_EXTENSION_VERSION"]),
		ServiceAccount:     managedIdentityFromSite(site),
		Environment:        env,
		RuntimeEnvironment: firstNonEmpty(env["FUNCTIONS_EXTENSION_VERSION"], ptrString(site.Kind)),
		Metadata:           map[string]any{},
	}
	if site.Properties != nil {
		descriptor.Metadata["state"] = ptrString(site.Properties.State)
		descriptor.Metadata["https_only"] = boolPtr(site.Properties.HTTPSOnly)
		descriptor.EventSources = azureEventSources(site)
	}
	if packageURL := firstNonEmpty(env["WEBSITE_RUN_FROM_PACKAGE"], env["SCM_RUN_FROM_PACKAGE"]); strings.HasPrefix(packageURL, "https://") || strings.HasPrefix(packageURL, "http://") {
		descriptor.Artifacts = append(descriptor.Artifacts, ArtifactRef{
			ID:     "run_from_package",
			Kind:   ArtifactFunctionCode,
			Format: ArchiveFormatZIP,
			Name:   name + ".zip",
			Metadata: map[string]any{
				"app_setting_key": packageURLSettingKey(env),
			},
		})
	}
	return descriptor, nil
}

func (p *AzureProvider) OpenArtifact(ctx context.Context, target FunctionTarget, artifact ArtifactRef) (io.ReadCloser, error) {
	if p == nil || p.client == nil {
		return nil, fmt.Errorf("azure function scan provider is not configured")
	}
	settings, err := p.client.ListApplicationSettings(ctx, strings.TrimSpace(target.ResourceGroup), strings.TrimSpace(target.AppName), nil)
	if err != nil {
		return nil, fmt.Errorf("list azure function app settings %s: %w", target.AppName, err)
	}
	packageURL := firstNonEmpty(stringDictionaryValue(settings.Properties, "WEBSITE_RUN_FROM_PACKAGE"), stringDictionaryValue(settings.Properties, "SCM_RUN_FROM_PACKAGE"))
	if !strings.HasPrefix(packageURL, "https://") && !strings.HasPrefix(packageURL, "http://") {
		return nil, fmt.Errorf("azure function app %s does not expose a downloadable package url", target.AppName)
	}
	return openHTTPArtifact(ctx, p.httpClient, packageURL)
}

func packageURLSettingKey(values map[string]string) string {
	if value := strings.TrimSpace(values["WEBSITE_RUN_FROM_PACKAGE"]); strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "http://") {
		return "WEBSITE_RUN_FROM_PACKAGE"
	}
	if value := strings.TrimSpace(values["SCM_RUN_FROM_PACKAGE"]); strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "http://") {
		return "SCM_RUN_FROM_PACKAGE"
	}
	return ""
}

func stringDictionaryValue(values map[string]*string, key string) string {
	if values == nil {
		return ""
	}
	value := values[key]
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func azureRuntimeFromSettings(env map[string]string) string {
	worker := strings.TrimSpace(env["FUNCTIONS_WORKER_RUNTIME"])
	joinRuntime := func(version string) string {
		version = strings.TrimSpace(version)
		if version == "" {
			return worker
		}
		return worker + "|" + version
	}
	switch strings.ToLower(worker) {
	case "node":
		return joinRuntime(env["WEBSITE_NODE_DEFAULT_VERSION"])
	case "python":
		return joinRuntime(env["PYTHON_VERSION"])
	case "java":
		return joinRuntime(env["JAVA_VERSION"])
	case "dotnet", "dotnet-isolated":
		return joinRuntime(env["FUNCTIONS_EXTENSION_VERSION"])
	default:
		return worker
	}
}

func managedIdentityFromSite(site armappservice.WebAppsClientGetResponse) string {
	if site.Identity == nil || site.Identity.PrincipalID == nil {
		return ""
	}
	return strings.TrimSpace(*site.Identity.PrincipalID)
}

func azureEventSources(site armappservice.WebAppsClientGetResponse) []string {
	if site.Properties == nil {
		return nil
	}
	sources := []string{}
	if site.Properties.HostNamesDisabled != nil && !*site.Properties.HostNamesDisabled {
		sources = append(sources, "http")
	}
	return sources
}

func ptrString(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func boolPtr(value *bool) bool {
	return value != nil && *value
}
