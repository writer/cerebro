package providers

import "testing"

func TestPreviouslyUntestedProviders_BasicCoverage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		constructor func() Provider
	}{
		{name: "azure", constructor: func() Provider { return NewAzureProvider() }},
		{name: "cloudflare", constructor: func() Provider { return NewCloudflareProvider() }},
		{name: "cloudtrail", constructor: func() Provider { return NewCloudTrailProvider() }},
		{name: "crowdstrike", constructor: func() Provider { return NewCrowdStrikeProvider() }},
		{name: "datadog", constructor: func() Provider { return NewDatadogProvider() }},
		{name: "entra_id", constructor: func() Provider { return NewEntraIDProvider() }},
		{name: "github", constructor: func() Provider { return NewGitHubProvider() }},
		{name: "gitlab", constructor: func() Provider { return NewGitLabProvider() }},
		{name: "intune", constructor: func() Provider { return NewIntuneProvider() }},
		{name: "jamf", constructor: func() Provider { return NewJamfProvider() }},
		{name: "qualys", constructor: func() Provider { return NewQualysProvider() }},
		{name: "rippling", constructor: func() Provider { return NewRipplingProvider() }},
		{name: "s3", constructor: func() Provider { return NewS3Provider() }},
		{name: "salesforce", constructor: func() Provider { return NewSalesforceProvider() }},
		{name: "slack", constructor: func() Provider { return NewSlackProvider() }},
		{name: "tailscale", constructor: func() Provider { return NewTailscaleProvider() }},
		{name: "tenable", constructor: func() Provider { return NewTenableProvider() }},
		{name: "vault", constructor: func() Provider { return NewVaultProvider() }},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider := tt.constructor()
			if provider == nil {
				t.Fatalf("provider constructor returned nil")
				return
			}

			if got := provider.Name(); got != tt.name {
				t.Fatalf("unexpected provider name: got %q want %q", got, tt.name)
			}

			if provider.Type() == "" {
				t.Fatal("provider type must not be empty")
			}

			if len(provider.Schema()) == 0 {
				t.Fatal("provider schema must define at least one table")
			}
		})
	}
}
