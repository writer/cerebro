package providers

import "testing"

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
	metadata := ProviderMetadataFor("auth0")
	if metadata.Maturity != ProviderMaturityStub {
		t.Fatalf("expected auth0 maturity %q, got %q", ProviderMaturityStub, metadata.Maturity)
	}
	if metadata.Public {
		t.Fatal("expected auth0 to be non-public")
	}
	if !IsProviderIncomplete("auth0") {
		t.Fatal("expected auth0 to be incomplete")
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
