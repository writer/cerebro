package app

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

func testAppLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestAPIKeysSnapshotReturnsClone(t *testing.T) {
	application := &App{
		Config: &Config{},
		Logger: testAppLogger(),
	}
	application.setAPIKeys(map[string]string{"key-a": "user-a"})

	snapshot := application.APIKeysSnapshot()
	snapshot["key-a"] = "tampered"

	secondSnapshot := application.APIKeysSnapshot()
	if secondSnapshot["key-a"] != "user-a" {
		t.Fatalf("expected stored API key mapping to remain unchanged, got %q", secondSnapshot["key-a"])
	}
}

func TestReloadSecretsUpdatesAPIKeys(t *testing.T) {
	previousLoad := loadConfigForSecretsReload
	t.Cleanup(func() { loadConfigForSecretsReload = previousLoad })

	current := &Config{
		APIAuthEnabled: true,
		APIKeys:        map[string]string{"old-key": "old-user"},
	}
	current.RefreshProviderAwareConfig()

	next := &Config{
		APIAuthEnabled: true,
		APIKeys:        map[string]string{"new-key": "new-user"},
	}
	next.RefreshProviderAwareConfig()

	loadConfigForSecretsReload = func() *Config {
		return next
	}

	application := &App{
		Config: current,
		Logger: testAppLogger(),
	}
	application.setAPIKeys(current.APIKeys)

	if err := application.ReloadSecrets(context.Background()); err != nil {
		t.Fatalf("ReloadSecrets failed: %v", err)
	}

	keys := application.APIKeysSnapshot()
	if len(keys) != 1 || keys["new-key"] != "new-user" {
		t.Fatalf("expected API keys to be rotated, got %#v", keys)
	}
	if application.Config == nil || application.Config.APIKeys["new-key"] != "new-user" {
		t.Fatalf("expected app config to include rotated API keys, got %#v", application.Config)
	}
}

func TestReloadSecretsRebuildsProvidersWhenCredentialsChange(t *testing.T) {
	previousLoad := loadConfigForSecretsReload
	t.Cleanup(func() { loadConfigForSecretsReload = previousLoad })

	current := &Config{
		APIAuthEnabled: true,
		APIKeys:        map[string]string{"key": "user"},
	}
	current.RefreshProviderAwareConfig()

	next := &Config{
		APIAuthEnabled: true,
		APIKeys:        map[string]string{"key": "user"},
		GitHubToken:    "ghp_test_token",
		GitHubOrg:      "acme-security",
	}
	next.RefreshProviderAwareConfig()

	loadConfigForSecretsReload = func() *Config {
		return next
	}

	application := &App{
		Config:    current,
		Logger:    testAppLogger(),
		Providers: nil,
	}
	application.setAPIKeys(current.APIKeys)

	if err := application.ReloadSecrets(context.Background()); err != nil {
		t.Fatalf("ReloadSecrets failed: %v", err)
	}

	if application.Providers == nil {
		t.Fatal("expected providers registry to be rebuilt")
	}
	if _, ok := application.Providers.Get("github"); !ok {
		t.Fatalf("expected github provider to be registered after credential reload")
	}
}
