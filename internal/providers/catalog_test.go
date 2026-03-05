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

func TestProviderMetadataFor_OracleIDCSProvider(t *testing.T) {
	metadata := ProviderMetadataFor("oracle_idcs")
	if metadata.Maturity != ProviderMaturityProductionReady {
		t.Fatalf("expected oracle_idcs maturity %q, got %q", ProviderMaturityProductionReady, metadata.Maturity)
	}
	if !metadata.Public {
		t.Fatal("expected oracle_idcs to be public")
	}
	if IsProviderIncomplete("oracle_idcs") {
		t.Fatal("did not expect oracle_idcs to be incomplete")
	}
}

func TestProviderMetadataFor_CyberArkProvider(t *testing.T) {
	metadata := ProviderMetadataFor("cyberark")
	if metadata.Maturity != ProviderMaturityProductionReady {
		t.Fatalf("expected cyberark maturity %q, got %q", ProviderMaturityProductionReady, metadata.Maturity)
	}
	if !metadata.Public {
		t.Fatal("expected cyberark to be public")
	}
	if IsProviderIncomplete("cyberark") {
		t.Fatal("did not expect cyberark to be incomplete")
	}
}

func TestProviderMetadataFor_SailPointProvider(t *testing.T) {
	metadata := ProviderMetadataFor("sailpoint")
	if metadata.Maturity != ProviderMaturityProductionReady {
		t.Fatalf("expected sailpoint maturity %q, got %q", ProviderMaturityProductionReady, metadata.Maturity)
	}
	if !metadata.Public {
		t.Fatal("expected sailpoint to be public")
	}
	if IsProviderIncomplete("sailpoint") {
		t.Fatal("did not expect sailpoint to be incomplete")
	}
}

func TestProviderMetadataFor_SaviyntProvider(t *testing.T) {
	metadata := ProviderMetadataFor("saviynt")
	if metadata.Maturity != ProviderMaturityProductionReady {
		t.Fatalf("expected saviynt maturity %q, got %q", ProviderMaturityProductionReady, metadata.Maturity)
	}
	if !metadata.Public {
		t.Fatal("expected saviynt to be public")
	}
	if IsProviderIncomplete("saviynt") {
		t.Fatal("did not expect saviynt to be incomplete")
	}
}

func TestProviderMetadataFor_ForgeRockProvider(t *testing.T) {
	metadata := ProviderMetadataFor("forgerock")
	if metadata.Maturity != ProviderMaturityProductionReady {
		t.Fatalf("expected forgerock maturity %q, got %q", ProviderMaturityProductionReady, metadata.Maturity)
	}
	if !metadata.Public {
		t.Fatal("expected forgerock to be public")
	}
	if IsProviderIncomplete("forgerock") {
		t.Fatal("did not expect forgerock to be incomplete")
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
	if !slices.Contains(names, "oracle_idcs") {
		t.Fatal("expected oracle_idcs in public provider names")
	}
	if !slices.Contains(names, "cyberark") {
		t.Fatal("expected cyberark in public provider names")
	}
	if !slices.Contains(names, "sailpoint") {
		t.Fatal("expected sailpoint in public provider names")
	}
	if !slices.Contains(names, "saviynt") {
		t.Fatal("expected saviynt in public provider names")
	}
	if !slices.Contains(names, "forgerock") {
		t.Fatal("expected forgerock in public provider names")
	}
	if !slices.Contains(names, "pingidentity") {
		t.Fatal("expected pingidentity in public provider names")
	}
	if !slices.Contains(names, "duo") {
		t.Fatal("expected duo in public provider names")
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
	if !slices.Contains(names, "s3") {
		t.Fatal("expected s3 in public provider names")
	}
}

func TestImplementedProviderNames_ExcludesStubProviders(t *testing.T) {
	names := ImplementedProviderNames()
	if !slices.Contains(names, "oracle_idcs") {
		t.Fatal("expected oracle_idcs in implemented provider names")
	}
	if !slices.Contains(names, "cyberark") {
		t.Fatal("expected cyberark in implemented provider names")
	}
	if !slices.Contains(names, "sailpoint") {
		t.Fatal("expected sailpoint in implemented provider names")
	}
	if !slices.Contains(names, "saviynt") {
		t.Fatal("expected saviynt in implemented provider names")
	}
	if !slices.Contains(names, "forgerock") {
		t.Fatal("expected forgerock in implemented provider names")
	}
	if !slices.Contains(names, "pingidentity") {
		t.Fatal("expected pingidentity in implemented provider names")
	}
	if !slices.Contains(names, "duo") {
		t.Fatal("expected duo in implemented provider names")
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
	if !slices.Contains(names, "s3") {
		t.Fatal("expected s3 in implemented provider names")
	}
}
