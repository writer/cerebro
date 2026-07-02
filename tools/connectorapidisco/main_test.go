package main

import (
	"encoding/json"
	"testing"

	"github.com/writer/cerebro/internal/connectorcatalog"
)

func TestAPIsGuruSuggestionsPreferSourceIDConfidence(t *testing.T) {
	var registry apisGuruRegistry
	if err := json.Unmarshal([]byte(`{
		"acmeplatform:v1": {
			"preferred": "v1",
			"versions": {
				"v1": {
					"info": {"title": "Acme Platform"},
					"swaggerUrl": "https://example.test/acme-platform.json"
				}
			}
		},
		"acmecloud:v1": {
			"preferred": "v1",
			"versions": {
				"v1": {
					"info": {"title": "Other API", "x-providerName": "Acme Cloud"},
					"swaggerUrl": "https://example.test/acme-cloud.json"
				}
			}
		}
	}`), &registry); err != nil {
		t.Fatalf("unmarshal registry: %v", err)
	}

	suggestions := apisGuruSuggestions(registry, connectorcatalog.APIDiscoveryCandidate{
		SourceID:    "acme_cloud",
		DisplayName: "Acme Platform",
	})
	if len(suggestions) != 2 {
		t.Fatalf("suggestions = %#v, want 2", suggestions)
	}
	if suggestions[0].Confidence != "source_id" || suggestions[0].Key != "acmecloud:v1" {
		t.Fatalf("first suggestion = %#v, want source_id acmecloud:v1", suggestions[0])
	}
	if suggestions[1].Confidence != "display_name" || suggestions[1].Key != "acmeplatform:v1" {
		t.Fatalf("second suggestion = %#v, want display_name acmeplatform:v1", suggestions[1])
	}
}

func TestNormalizedTokenRemovesNonAlphanumericCharacters(t *testing.T) {
	if got := normalizedToken(" _Acme-Cloud_ "); got != "acmecloud" {
		t.Fatalf("normalizedToken() = %q, want acmecloud", got)
	}
}
