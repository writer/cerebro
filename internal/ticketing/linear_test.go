package ticketing

import (
	"context"
	"testing"
)

func TestLinearProviderValidate(t *testing.T) {
	valid := NewLinearProvider(LinearConfig{
		APIKey: "lin_api_key",
		TeamID: "team_123",
	})
	if err := valid.Validate(context.Background()); err != nil {
		t.Fatalf("expected valid provider config, got %v", err)
	}

	invalidAPIKey := NewLinearProvider(LinearConfig{
		APIKey: "",
		TeamID: "team_123",
	})
	if err := invalidAPIKey.Validate(context.Background()); err == nil {
		t.Fatal("expected missing API key to fail validation")
	}

	invalidTeam := NewLinearProvider(LinearConfig{
		APIKey: "lin_api_key",
		TeamID: "",
	})
	if err := invalidTeam.Validate(context.Background()); err == nil {
		t.Fatal("expected missing team ID to fail validation")
	}
}
