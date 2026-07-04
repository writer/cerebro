package connectorcatalog

import (
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions"
)

func TestProviderAPIProofScoreRequiresGroundedEvidence(t *testing.T) {
	api := runtimeProviderAPIFields{
		Status:        "verified",
		Basis:         "detected",
		VerifiedAt:    "2026-07-02T00:00:00Z",
		Transport:     "rest",
		Auth:          "oauth_client_credentials",
		AuthMechanics: "oauth_client_credentials",
		BaseURL:       "https://api.provider.io",
		SpecURL:       "https://developer.provider.io/openapi.yaml",
		SpecKind:      "openapi",
		References: []string{
			"https://developer.provider.io/reference",
			"https://developer.provider.io/openapi.yaml",
		},
		AuthEvidence:  []string{"https://developer.provider.io/authentication"},
		ScopeEvidence: []string{"https://developer.provider.io/scopes"},
		Families: []struct {
			ID        string `yaml:"id"`
			Method    string `yaml:"method"`
			Path      string `yaml:"path"`
			Operation string `yaml:"operation"`
		}{{
			ID:     "users",
			Method: "GET",
			Path:   "/v1/users",
		}},
	}

	proof := providerAPIProofScore(api, nil)
	if !proof.HasProof || proof.Score != providerAPIProofThreshold || proof.Level != "verified" {
		t.Fatalf("proof = %#v, want verified score", proof)
	}
	if len(proof.Gaps) != 0 {
		t.Fatalf("proof gaps = %v, want none", proof.Gaps)
	}
}

func TestProviderAPIProofScoreRejectsPlaceholderSurface(t *testing.T) {
	api := runtimeProviderAPIFields{
		Status:        "verified",
		Transport:     "rest",
		Auth:          "oauth_client_credentials",
		AuthMechanics: "unknown",
		BaseURL:       "//api.provider.io",
		SpecURL:       "https://developer.provider.io/reference",
		References: []string{
			"https://api.provider.io/oauth/token",
		},
		Families: []struct {
			ID        string `yaml:"id"`
			Method    string `yaml:"method"`
			Path      string `yaml:"path"`
			Operation string `yaml:"operation"`
		}{{
			ID:     "users",
			Method: "GET",
			Path:   "/v1/users",
		}},
	}

	proof := providerAPIProofScore(api, []string{"groups"})
	if proof.HasProof || proof.Level != "needs_proof" {
		t.Fatalf("proof = %#v, want needs_proof", proof)
	}
	for _, want := range []string{
		"provider_api:basis",
		"provider_api:verified_at",
		"provider_api:locator",
		"provider_api:reference_oauth_endpoint",
		"provider_api:machine_readable_spec",
		"provider_api:auth_mechanics",
		"provider_api:family_mapping",
		"provider_api:family:groups",
	} {
		if !containsString(proof.Gaps, want) {
			t.Fatalf("proof gaps = %v, want %s", proof.Gaps, want)
		}
	}
}

func TestProviderAPISpecPointerAcceptsExplicitPostmanCollection(t *testing.T) {
	specURL := "https://raw.githubusercontent.com/duosecurity/duo_postman_collection/main/duo-admin-api/Duo%20Admin%20API%20v4.1.0.postman_collection.json"
	if !providerAPISpecPointerOK(specURL, "postman_collection", "rest") {
		t.Fatalf("providerAPISpecPointerOK(%q, postman_collection) = false, want true", specURL)
	}
	if providerAPISpecPointerOK(specURL, "", "rest") {
		t.Fatalf("providerAPISpecPointerOK(%q, empty kind) = true, want false", specURL)
	}
}

func TestProviderAPIURLIsOAuthEndpointRequiresAuthPathSegment(t *testing.T) {
	for _, value := range []string{
		"https://api.provider.io/oauth/token",
		"https://api.provider.io/oauth2/authorize",
		"https://api.provider.io/connect/token",
		"https://api.provider.io/token",
	} {
		if !providerAPIURLIsOAuthEndpoint(value) {
			t.Fatalf("providerAPIURLIsOAuthEndpoint(%q) = false, want true", value)
		}
	}
	for _, value := range []string{
		"https://api.provider.io/v1/tokens",
		"https://api.provider.io/api/token-management",
		"https://api.provider.io/service-account-tokens",
	} {
		if providerAPIURLIsOAuthEndpoint(value) {
			t.Fatalf("providerAPIURLIsOAuthEndpoint(%q) = true, want false", value)
		}
	}
}

func TestProviderAPIDepthForDefinitionSummarizesCatalogProof(t *testing.T) {
	depth := ProviderAPIDepthForDefinition(connectordefinitions.Definition{
		ResourceFamilies: []connectordefinitions.ResourceFamily{{ID: "users"}},
		ProviderAPI: &connectordefinitions.ProviderAPISpec{
			Status:        "verified",
			Basis:         "declared",
			VerifiedAt:    "2026-07-03T00:00:00Z",
			Transport:     "rest",
			Auth:          "api_key",
			AuthMechanics: "header token",
			BaseURL:       "https://api.provider.io",
			SpecURL:       "https://developer.provider.io/openapi.yaml",
			SpecKind:      "openapi",
			References:    []string{"https://developer.provider.io/reference"},
			Families: []connectordefinitions.ProviderAPIFamilySpec{{
				ID:     "users",
				Method: "GET",
				Path:   "/v1/users",
			}},
		},
	})

	if !depth.HasContract || !depth.HasMapping || !depth.HasProof {
		t.Fatalf("depth flags = %#v, want contract, mapping, and proof", depth)
	}
	if depth.ProofScore != providerAPIProofThreshold || depth.ProofLevel != "verified" {
		t.Fatalf("proof = %d/%q, want verified threshold", depth.ProofScore, depth.ProofLevel)
	}
	if len(depth.ProofGaps) != 0 || !containsString(depth.MappedFamilies, "users") {
		t.Fatalf("depth families/gaps = %#v/%#v, want users and no gaps", depth.MappedFamilies, depth.ProofGaps)
	}
}
