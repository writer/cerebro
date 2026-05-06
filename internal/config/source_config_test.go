package config

import (
	"context"
	"testing"
)

func TestResolveSourceConfigSecretReferencesResolvesEnvValues(t *testing.T) {
	t.Setenv("CEREBRO_SOURCE_GITHUB_TOKEN", "secret-token")
	config := map[string]string{
		"owner": "writer",
		"token": "env:CEREBRO_SOURCE_GITHUB_TOKEN",
	}

	resolved, err := ResolveSourceConfigSecretReferences(context.Background(), "github", config)
	if err != nil {
		t.Fatalf("ResolveSourceConfigSecretReferences() error = %v", err)
	}
	if got := resolved["token"]; got != "secret-token" {
		t.Fatalf("resolved token = %q, want secret-token", got)
	}
	if got := config["token"]; got != "env:CEREBRO_SOURCE_GITHUB_TOKEN" {
		t.Fatalf("input token mutated to %q", got)
	}
}

func TestResolveSourceConfigSecretReferencesRejectsUnsetEnv(t *testing.T) {
	_, err := ResolveSourceConfigSecretReferences(context.Background(), "github", map[string]string{
		"token": "env:CEREBRO_SOURCE_GITHUB_TOKEN",
	})
	if err == nil {
		t.Fatal("ResolveSourceConfigSecretReferences() error = nil, want error")
	}
}

func TestResolveSourceConfigSecretReferencesRejectsDisallowedEnv(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "deployment-secret")
	_, err := ResolveSourceConfigSecretReferences(context.Background(), "github", map[string]string{
		"token": "env:AWS_SECRET_ACCESS_KEY",
	})
	if err == nil {
		t.Fatal("ResolveSourceConfigSecretReferences() error = nil, want error")
	}
}

func TestResolveSourceConfigSecretReferencesAllowsExplicitEnvAllowlist(t *testing.T) {
	t.Setenv("CEREBRO_SOURCE_CONFIG_ENV_ALLOWLIST", "SHARED_GITHUB_TOKEN")
	t.Setenv("SHARED_GITHUB_TOKEN", "secret-token")
	resolved, err := ResolveSourceConfigSecretReferences(context.Background(), "github", map[string]string{
		"token": "env:SHARED_GITHUB_TOKEN",
	})
	if err != nil {
		t.Fatalf("ResolveSourceConfigSecretReferences() error = %v", err)
	}
	if got := resolved["token"]; got != "secret-token" {
		t.Fatalf("resolved token = %q, want secret-token", got)
	}
}

func TestResolveSourceConfigSecretReferencesPreservesLiteralEnvQueryValues(t *testing.T) {
	t.Setenv("prod", "from-env")
	resolved, err := ResolveSourceConfigSecretReferences(context.Background(), "github", map[string]string{
		"phrase": "env:prod",
	})
	if err != nil {
		t.Fatalf("ResolveSourceConfigSecretReferences() error = %v", err)
	}
	if got := resolved["phrase"]; got != "env:prod" {
		t.Fatalf("resolved phrase = %q, want literal env:prod", got)
	}
}

func TestResolveSourceConfigSecretReferencesResolvesAllowedQueryEnvValues(t *testing.T) {
	t.Setenv("CEREBRO_SOURCE_GITHUB_PHRASE", "archived:false")
	resolved, err := ResolveSourceConfigSecretReferences(context.Background(), "github", map[string]string{
		"phrase": "env:CEREBRO_SOURCE_GITHUB_PHRASE",
	})
	if err != nil {
		t.Fatalf("ResolveSourceConfigSecretReferences() error = %v", err)
	}
	if got := resolved["phrase"]; got != "archived:false" {
		t.Fatalf("resolved phrase = %q, want archived:false", got)
	}
}

func TestResolveSourceRuntimeConfigSecretReferencesResolvesQuerySelectors(t *testing.T) {
	t.Setenv("CEREBRO_SOURCE_GITHUB_PHRASE", "archived:false")
	resolved, err := ResolveSourceRuntimeConfigSecretReferences(context.Background(), "github", map[string]string{
		"phrase": "env:CEREBRO_SOURCE_GITHUB_PHRASE",
	})
	if err != nil {
		t.Fatalf("ResolveSourceRuntimeConfigSecretReferences() error = %v", err)
	}
	if got := resolved["phrase"]; got != "archived:false" {
		t.Fatalf("resolved phrase = %q, want archived:false", got)
	}
}
