package main

import "testing"

func TestCatalogImportRejectionBlocksProviderAPIFragments(t *testing.T) {
	tests := []struct {
		sourceID string
		want     string
	}{
		{sourceID: "azure_com_security_alerts", want: "provider_api_fragment"},
		{sourceID: "googleapis_com_compute", want: "provider_api_fragment"},
		{sourceID: "twilio_com_twilio_voice_v1", want: "provider_api_fragment"},
		{sourceID: "xero_com_xero_assets", want: "api_surface_shard"},
	}
	for _, test := range tests {
		t.Run(test.sourceID, func(t *testing.T) {
			got := catalogImportRejection(manifestTarget{SourceID: test.sourceID})
			if got != test.want {
				t.Fatalf("catalogImportRejection(%q) = %q, want %q", test.sourceID, got, test.want)
			}
		})
	}
}

func TestCatalogImportRejectionBlocksNonSaaSDataAPIs(t *testing.T) {
	tests := []struct {
		sourceID string
		want     string
	}{
		{sourceID: "parliament_uk_bills", want: "public_or_open_data_api"},
		{sourceID: "sportsdata_io_nfl_v3", want: "consumer_media_or_games_api"},
		{sourceID: "weatherbit_io", want: "consumer_or_iot_api"},
	}
	for _, test := range tests {
		t.Run(test.sourceID, func(t *testing.T) {
			got := catalogImportRejection(manifestTarget{SourceID: test.sourceID})
			if got != test.want {
				t.Fatalf("catalogImportRejection(%q) = %q, want %q", test.sourceID, got, test.want)
			}
		})
	}
}

func TestCatalogImportRejectionAllowsProductLevelSaaS(t *testing.T) {
	for _, sourceID := range []string{"akeneo_com", "files_com", "zuora_com"} {
		t.Run(sourceID, func(t *testing.T) {
			if got := catalogImportRejection(manifestTarget{SourceID: sourceID}); got != "" {
				t.Fatalf("catalogImportRejection(%q) = %q, want allowed", sourceID, got)
			}
		})
	}
}
