package connectorcatalog

import (
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcecdk"
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

func TestProviderAPIProofScoreAcceptsRuntimeURLConfigLocator(t *testing.T) {
	api := runtimeProviderAPIFields{
		Status:        "verified",
		Basis:         "declared",
		VerifiedAt:    "2026-07-04T00:00:00Z",
		Transport:     "rest",
		Auth:          "bearer_token",
		AuthMechanics: "authorization_bearer_token",
		BaseURL:       "${config.base_url}/api/v3",
		SpecURL:       "https://developer.provider.io/openapi.yaml",
		SpecKind:      "openapi",
		References:    []string{"https://developer.provider.io/openapi.yaml"},
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
	if !proof.HasProof || proof.Score != providerAPIProofThreshold {
		t.Fatalf("proof = %#v, want verified runtime URL locator", proof)
	}
	if providerAPIURLLooksGrounded("${config.tenant}/api/v3") {
		t.Fatal("providerAPIURLLooksGrounded(${config.tenant}/api/v3) = true, want false")
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

func TestProviderAPISpecPointerAcceptsGoogleDiscovery(t *testing.T) {
	specURL := "https://generativelanguage.googleapis.com/$discovery/rest?version=v1beta&alt=json"
	if !providerAPISpecPointerOK(specURL, "google_discovery", "rest") {
		t.Fatalf("providerAPISpecPointerOK(%q, google_discovery) = false, want true", specURL)
	}
	if providerAPISpecPointerOK("https://generativelanguage.googleapis.com/v1beta/models", "google_discovery", "rest") {
		t.Fatal("providerAPISpecPointerOK(non-discovery Google API URL, google_discovery) = true, want false")
	}
}

func TestProviderAPISpecPointerAcceptsEmbeddedOpenAPIHTML(t *testing.T) {
	specURL := "https://bitwarden.com/help/api/"
	if !providerAPISpecPointerOK(specURL, "openapi_embedded_html", "rest") {
		t.Fatalf("providerAPISpecPointerOK(%q, openapi_embedded_html) = false, want true", specURL)
	}
	if providerAPISpecPointerOK(specURL, "", "rest") {
		t.Fatalf("providerAPISpecPointerOK(%q, empty kind) = true, want false", specURL)
	}
	if providerAPISpecPointerOK("https://developer.provider.io/docs/security", "openapi_embedded_html", "rest") {
		t.Fatal("providerAPISpecPointerOK(generic docs page, openapi_embedded_html) = true, want false")
	}
}

func TestProviderAPISpecPointerAcceptsExplicitProviderMarkdownReference(t *testing.T) {
	specURL := "https://platform.provider.io/docs/en/api/admin.md"
	if !providerAPISpecPointerOK(specURL, "api_reference_markdown", "rest") {
		t.Fatalf("providerAPISpecPointerOK(%q, api_reference_markdown) = false, want true", specURL)
	}
	if providerAPISpecPointerOK(specURL, "", "rest") {
		t.Fatalf("providerAPISpecPointerOK(%q, empty kind) = true, want false", specURL)
	}
	if providerAPISpecPointerOK("https://platform.provider.io/docs/en/api/admin", "api_reference_markdown", "rest") {
		t.Fatal("providerAPISpecPointerOK(markdown reference without .md) = true, want false")
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

func TestProviderAPIDepthForSourceCatalogPropagatesDisproof(t *testing.T) {
	depth := ProviderAPIDepthForSourceCatalog(sourcecdk.CatalogProviderAPI{
		Disproof: sourcecdk.CatalogProviderAPIDisproof{
			Status:           "invalidated",
			Reason:           "runtime_families_not_in_provider_spec",
			CheckedAt:        "2026-07-04T00:00:00Z",
			References:       []string{"https://developer.provider.io/openapi.yaml"},
			AffectedFamilies: []string{"teams"},
			MissingPaths:     []string{"/v1/teams"},
			Notes:            []string{"provider API does not expose team inventory"},
		},
	}, []string{"teams"})

	if !depth.HasDisproof {
		t.Fatalf("depth.HasDisproof = false, want true: %#v", depth)
	}
	if depth.DisproofReason != "runtime_families_not_in_provider_spec" || !containsString(depth.DisproofFamilies, "teams") {
		t.Fatalf("depth disproof = %#v, want teams invalidation", depth.RuntimeProviderAPIDisproofDepth)
	}
	view, present := ProviderAPIViewForDepth(depth)
	if !present || !view.HasProviderAPIDisproof {
		t.Fatalf("provider API view = %#v, present=%v, want disproof view", view, present)
	}
	if view.ProviderAPIDisproofMissingPaths[0] != "/v1/teams" {
		t.Fatalf("provider API view missing paths = %v, want /v1/teams", view.ProviderAPIDisproofMissingPaths)
	}
}
