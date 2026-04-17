package providers

import "sort"

// AllProviderTableNames returns sorted table names from all provider schemas.
func AllProviderTableNames() []string {
	providers := []Provider{
		NewAtlassianProvider(),
		NewAuth0Provider(),
		NewAzureProvider(),
		NewBambooHRProvider(),
		NewCloudflareProvider(),
		NewCloudTrailProvider(),
		NewCrowdStrikeProvider(),
		NewCyberArkProvider(),
		NewDatadogProvider(),
		NewDuoProvider(),
		NewEntraIDProvider(),
		NewFigmaProvider(),
		NewForgeRockProvider(),
		NewGitHubProvider(),
		NewGitLabProvider(),
		NewGongProvider(),
		NewGoogleWorkspaceProvider(),
		NewIntuneProvider(),
		NewJamfProvider(),
		NewJumpCloudProvider(),
		NewKandjiProvider(),
		NewKolideProvider(),
		NewOktaProvider(),
		NewOneLoginProvider(),
		NewOracleIDCSProvider(),
		NewPantherProvider(),
		NewPingIdentityProvider(),
		NewQualysProvider(),
		NewRampProvider(),
		NewRipplingProvider(),
		NewS3Provider(),
		NewSailPointProvider(),
		NewSalesforceProvider(),
		NewSaviyntProvider(),
		NewSeCheckProvider(),
		NewSemgrepProvider(),
		NewSentinelOneProvider(),
		NewServiceNowProvider(),
		NewSlackProvider(),
		NewSnykProvider(),
		NewSocketProvider(),
		NewSplunkProvider(),
		NewTailscaleProvider(),
		NewTenableProvider(),
		NewTerraformCloudProvider(),
		NewVantaProvider(),
		NewVaultProvider(),
		NewWizProvider(),
		NewWorkdayProvider(),
		NewZoomProvider(),
	}

	seen := make(map[string]struct{})
	var names []string
	for _, p := range providers {
		for _, schema := range p.Schema() {
			if _, ok := seen[schema.Name]; ok {
				continue
			}
			seen[schema.Name] = struct{}{}
			names = append(names, schema.Name)
		}
	}
	sort.Strings(names)
	return names
}
