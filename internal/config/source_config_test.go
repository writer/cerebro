package config

import (
	"context"
	"testing"
)

func TestResolveSourceConfigSecretReferencesResolvesEnvValues(t *testing.T) {
	t.Setenv("CEREBRO_TEST_TOKEN", "secret-token")
	config := map[string]string{
		"owner": "writer",
		"token": "env:CEREBRO_TEST_TOKEN",
	}

	resolved, err := ResolveSourceConfigSecretReferences(context.Background(), "github", config)
	if err != nil {
		t.Fatalf("ResolveSourceConfigSecretReferences() error = %v", err)
	}
	if got := resolved["token"]; got != "secret-token" {
		t.Fatalf("resolved token = %q, want secret-token", got)
	}
	if got := config["token"]; got != "env:CEREBRO_TEST_TOKEN" {
		t.Fatalf("input token mutated to %q", got)
	}
}

func TestResolveSourceConfigSecretReferencesRejectsUnsetEnv(t *testing.T) {
	_, err := ResolveSourceConfigSecretReferences(context.Background(), "github", map[string]string{
		"token": "env:CEREBRO_TEST_MISSING",
	})
	if err == nil {
		t.Fatal("ResolveSourceConfigSecretReferences() error = nil, want error")
	}
}
