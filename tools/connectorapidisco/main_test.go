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

func TestBuildWorklistPrioritizesHighValueSecuritySources(t *testing.T) {
	worklist := buildWorklist([]connectorcatalog.APIDiscoveryCandidate{
		{
			SourceID:        "generic_records",
			DisplayName:     "Generic Records",
			Path:            "internal/connectorcatalog/catalog/business-data-grc/generic_records.yaml",
			MissingFamilies: []string{"records"},
			Auth:            "api_key",
		},
		{
			SourceID:        "priority_idp",
			DisplayName:     "Priority IDP",
			Path:            "internal/connectorcatalog/catalog/identity-access-secrets/priority_idp.yaml",
			MissingFamilies: []string{"users", "audit_events", "roles"},
			Auth:            "oauth_authorization_code",
			BaseURL:         "https://api.priority.example",
		},
	}, nil)

	if len(worklist.Items) != 2 {
		t.Fatalf("items = %#v, want 2", worklist.Items)
	}
	first := worklist.Items[0]
	if first.SourceID != "priority_idp" {
		t.Fatalf("first source = %q, want priority_idp", first.SourceID)
	}
	if first.PriorityTier != "urgent" {
		t.Fatalf("priority tier = %q, want urgent", first.PriorityTier)
	}
	for _, want := range []string{"identity_access_source", "identity_family", "audit_trail_family", "privilege_family", "oauth_scope_docs_needed"} {
		if !containsString(first.PriorityReasons, want) {
			t.Fatalf("priority reasons = %#v, missing %q", first.PriorityReasons, want)
		}
	}
	if worklist.Summary.ByPriorityTier["urgent"] != 1 || worklist.Summary.ByPriorityTier["backlog"] != 1 {
		t.Fatalf("tier summary = %#v, want one urgent and one backlog", worklist.Summary.ByPriorityTier)
	}
}

func TestDiscoveryQueriesAddProviderDocsAndHostHints(t *testing.T) {
	queries := discoveryQueries(connectorcatalog.APIDiscoveryCandidate{
		SourceID:        "acme",
		DisplayName:     "Acme",
		Auth:            "oauth_client_credentials",
		BaseURL:         "https://api.acme.example/v1",
		SearchQueries:   []string{"web search: Acme API reference"},
		MissingFamilies: []string{"users"},
	})

	for _, want := range []string{
		"web search: Acme API reference",
		"web search: Acme developer API reference",
		"web search: Acme OpenAPI spec",
		"web search: Acme OAuth scopes API",
		"web search: api.acme.example openapi",
		"web search: api.acme.example swagger",
	} {
		if !containsString(queries, want) {
			t.Fatalf("queries = %#v, missing %q", queries, want)
		}
	}
}

func TestNormalizedTokenRemovesNonAlphanumericCharacters(t *testing.T) {
	if got := normalizedToken(" _Acme-Cloud_ "); got != "acmecloud" {
		t.Fatalf("normalizedToken() = %q, want acmecloud", got)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
