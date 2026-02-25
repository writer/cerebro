package providers

import (
	"slices"
	"testing"
)

func TestProviderMetadataFor_KnownProvider(t *testing.T) {
	metadata := ProviderMetadataFor("github")
	if metadata.Maturity != ProviderMaturityProductionReady {
		t.Fatalf("expected github maturity %q, got %q", ProviderMaturityProductionReady, metadata.Maturity)
	}
	if !metadata.Public {
		t.Fatal("expected github to be public")
	}
}

func TestProviderMetadataFor_StubProvider(t *testing.T) {
	metadata := ProviderMetadataFor("duo")
	if metadata.Maturity != ProviderMaturityStub {
		t.Fatalf("expected duo maturity %q, got %q", ProviderMaturityStub, metadata.Maturity)
	}
	if metadata.Public {
		t.Fatal("expected duo to be non-public")
	}
	if !IsProviderIncomplete("duo") {
		t.Fatal("expected duo to be incomplete")
	}
}

func TestProviderMetadataFor_UnknownDefaultsToPublicProductionReady(t *testing.T) {
	metadata := ProviderMetadataFor("custom-provider")
	if metadata.Maturity != ProviderMaturityProductionReady {
		t.Fatalf("expected default maturity %q, got %q", ProviderMaturityProductionReady, metadata.Maturity)
	}
	if !metadata.Public {
		t.Fatal("expected unknown providers to default to public")
	}
	if IsProviderIncomplete("custom-provider") {
		t.Fatal("did not expect unknown provider to be incomplete")
	}
}

func TestPublicProviderNames_ExcludesStubProviders(t *testing.T) {
	names := PublicProviderNames()
	if slices.Contains(names, "duo") {
		t.Fatal("did not expect stub provider duo in public provider names")
	}
	if !slices.Contains(names, "jumpcloud") {
		t.Fatal("expected jumpcloud in public provider names")
	}
	if !slices.Contains(names, "onelogin") {
		t.Fatal("expected onelogin in public provider names")
	}
	if !slices.Contains(names, "bamboohr") {
		t.Fatal("expected bamboohr in public provider names")
	}
	if !slices.Contains(names, "servicenow") {
		t.Fatal("expected servicenow in public provider names")
	}
	if !slices.Contains(names, "workday") {
		t.Fatal("expected workday in public provider names")
	}
	if !slices.Contains(names, "auth0") {
		t.Fatal("expected auth0 in public provider names")
	}
	if !slices.Contains(names, "semgrep") {
		t.Fatal("expected semgrep in public provider names")
	}
	if !slices.Contains(names, "terraform_cloud") {
		t.Fatal("expected terraform_cloud in public provider names")
	}
	if !slices.Contains(names, "splunk") {
		t.Fatal("expected splunk in public provider names")
	}
	if !slices.Contains(names, "github") {
		t.Fatal("expected github in public provider names")
	}
	if !slices.Contains(names, "wiz") {
		t.Fatal("expected wiz in public provider names")
	}
}

func TestImplementedProviderNames_ExcludesStubProviders(t *testing.T) {
	names := ImplementedProviderNames()
	if slices.Contains(names, "duo") {
		t.Fatal("did not expect stub provider duo in implemented provider names")
	}
	if !slices.Contains(names, "jumpcloud") {
		t.Fatal("expected jumpcloud in implemented provider names")
	}
	if !slices.Contains(names, "onelogin") {
		t.Fatal("expected onelogin in implemented provider names")
	}
	if !slices.Contains(names, "bamboohr") {
		t.Fatal("expected bamboohr in implemented provider names")
	}
	if !slices.Contains(names, "servicenow") {
		t.Fatal("expected servicenow in implemented provider names")
	}
	if !slices.Contains(names, "workday") {
		t.Fatal("expected workday in implemented provider names")
	}
	if !slices.Contains(names, "auth0") {
		t.Fatal("expected auth0 in implemented provider names")
	}
	if !slices.Contains(names, "semgrep") {
		t.Fatal("expected semgrep in implemented provider names")
	}
	if !slices.Contains(names, "terraform_cloud") {
		t.Fatal("expected terraform_cloud in implemented provider names")
	}
	if !slices.Contains(names, "splunk") {
		t.Fatal("expected splunk in implemented provider names")
	}
	if !slices.Contains(names, "github") {
		t.Fatal("expected github in implemented provider names")
	}
	if !slices.Contains(names, "wiz") {
		t.Fatal("expected wiz in implemented provider names")
	}
}
