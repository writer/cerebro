package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/writer/cerebro/internal/agents"
	"github.com/writer/cerebro/internal/appstate"
	"github.com/writer/cerebro/internal/snowflake"
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

	current := LoadConfig()
	current.APIAuthEnabled = true
	current.APIKeys = map[string]string{"old-key": "old-user"}
	current.RefreshProviderAwareConfig()

	next := LoadConfig()
	next.APIAuthEnabled = true
	next.APIKeys = map[string]string{"new-key": "new-user"}
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

	current := LoadConfig()
	current.APIAuthEnabled = true
	current.APIKeys = map[string]string{"key": "user"}
	current.RefreshProviderAwareConfig()

	next := LoadConfig()
	next.APIAuthEnabled = true
	next.APIKeys = map[string]string{"key": "user"}
	next.GitHubToken = "ghp_test_token"
	next.GitHubOrg = "acme-security"
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
		return
	}
	if _, ok := application.Providers.Get("github"); !ok {
		t.Fatalf("expected github provider to be registered after credential reload")
	}
}

func TestReloadSecretsRefreshesConfiguredAgentToolsWhenSCMCredentialsChange(t *testing.T) {
	previousLoad := loadConfigForSecretsReload
	t.Cleanup(func() { loadConfigForSecretsReload = previousLoad })

	current := LoadConfig()
	current.AnthropicAPIKey = "anthropic-key"
	current.RefreshProviderAwareConfig()

	next := LoadConfig()
	next.AnthropicAPIKey = "anthropic-key"
	next.GitHubToken = "github-token"
	next.RefreshProviderAwareConfig()

	loadConfigForSecretsReload = func() *Config {
		return next
	}

	staleHandlerCalled := false
	memory := agents.NewMemory(10)
	registry := agents.NewAgentRegistry()
	registry.RegisterAgent(&agents.Agent{
		ID:   "security-analyst",
		Name: "Security Analyst",
		Tools: []agents.Tool{
			{
				Name:        "analyze_repo",
				Description: "stale",
				Handler: func(context.Context, json.RawMessage) (string, error) {
					staleHandlerCalled = true
					return "stale", nil
				},
			},
			{Name: "remote_tool", Description: "remote"},
		},
		Memory: memory,
	})

	application := &App{
		Config: current,
		Logger: testAppLogger(),
		Agents: registry,
	}

	if err := application.ReloadSecrets(context.Background()); err != nil {
		t.Fatalf("ReloadSecrets failed: %v", err)
	}

	agent, ok := application.Agents.GetAgent("security-analyst")
	if !ok {
		t.Fatal("expected security-analyst agent to remain registered")
	}
	if agent.Memory != memory {
		t.Fatal("expected agent memory to be preserved across SCM credential reload")
	}
	analyzeRepo := findRegisteredAgentTool(agent.Tools, "analyze_repo")
	if analyzeRepo == nil {
		t.Fatal("expected analyze_repo tool after credential reload")
		return
	}
	if analyzeRepo.Description == "stale" {
		t.Fatal("expected analyze_repo tool definition to refresh after SCM credential reload")
	}
	if _, err := analyzeRepo.Handler(context.Background(), json.RawMessage(`{`)); err == nil {
		t.Fatal("expected refreshed analyze_repo handler to reject invalid arguments")
		return
	}
	if staleHandlerCalled {
		t.Fatal("expected stale analyze_repo handler to be replaced")
	}
	if remote := findRegisteredAgentTool(agent.Tools, "remote_tool"); remote == nil || remote.Description != "remote" {
		t.Fatalf("expected remote_tool to be preserved, got %#v", remote)
	}
}

func TestReloadSecretsSyncsConfiguredAIAgentsWhenLLMCredentialsChange(t *testing.T) {
	previousLoad := loadConfigForSecretsReload
	t.Cleanup(func() { loadConfigForSecretsReload = previousLoad })

	current := LoadConfig()
	current.AnthropicAPIKey = "anthropic-old"
	current.RefreshProviderAwareConfig()

	next := LoadConfig()
	next.AnthropicAPIKey = "anthropic-new"
	next.RefreshProviderAwareConfig()

	loadConfigForSecretsReload = func() *Config {
		return next
	}

	memory := agents.NewMemory(10)
	registry := agents.NewAgentRegistry()
	registry.RegisterAgent(&agents.Agent{
		ID:     "security-analyst",
		Name:   "Security Analyst",
		Tools:  []agents.Tool{{Name: "remote_tool", Description: "remote"}},
		Memory: memory,
	})

	application := &App{
		Config: current,
		Logger: testAppLogger(),
		Agents: registry,
	}

	if err := application.ReloadSecrets(context.Background()); err != nil {
		t.Fatalf("ReloadSecrets failed: %v", err)
	}

	agent, ok := application.Agents.GetAgent("security-analyst")
	if !ok {
		t.Fatal("expected security-analyst agent to remain registered")
	}
	if agent.Memory != memory {
		t.Fatal("expected security-analyst memory to be preserved across LLM credential reload")
	}
	if agent.Provider == nil {
		t.Fatal("expected security-analyst provider to be refreshed during LLM credential reload")
		return
	}
	if remote := findRegisteredAgentTool(agent.Tools, "remote_tool"); remote == nil || remote.Description != "remote" {
		t.Fatalf("expected remote_tool to be preserved, got %#v", remote)
	}
	if _, ok := application.Agents.GetAgent("incident-responder"); ok {
		t.Fatal("did not expect incident-responder to be registered without an OpenAI key")
	}
}

func TestReloadSecretsRebuildsAgentToolingWhenRemoteConfigChanges(t *testing.T) {
	previousLoad := loadConfigForSecretsReload
	t.Cleanup(func() { loadConfigForSecretsReload = previousLoad })

	current := LoadConfig()
	current.AgentRemoteToolsEnabled = false
	current.AgentRemoteToolsManifestSubject = "ensemble.old"
	current.RefreshProviderAwareConfig()

	next := LoadConfig()
	next.AgentRemoteToolsEnabled = false
	next.AgentRemoteToolsManifestSubject = "ensemble.new"
	next.RefreshProviderAwareConfig()

	loadConfigForSecretsReload = func() *Config {
		return next
	}

	application := &App{
		Config:           current,
		Logger:           testAppLogger(),
		Agents:           agents.NewAgentRegistry(),
		remoteAgentTools: []agents.Tool{{Name: "remote_tool", Description: "remote"}},
	}

	if err := application.ReloadSecrets(context.Background()); err != nil {
		t.Fatalf("ReloadSecrets failed: %v", err)
	}
	if application.Config == nil || application.Config.AgentRemoteToolsManifestSubject != "ensemble.new" {
		t.Fatalf("expected remote tool config to be reloaded, got %#v", application.Config)
	}
	if len(application.remoteAgentTools) != 0 {
		t.Fatalf("expected cached remote tools to be rebuilt/cleared, got %#v", application.remoteAgentTools)
	}
}

func TestReloadSecretsRemovesDisabledRemoteToolsFromConfiguredAgents(t *testing.T) {
	previousLoad := loadConfigForSecretsReload
	t.Cleanup(func() { loadConfigForSecretsReload = previousLoad })

	current := LoadConfig()
	current.AnthropicAPIKey = "anthropic-key"
	current.AgentRemoteToolsEnabled = true
	current.RefreshProviderAwareConfig()

	next := LoadConfig()
	next.AnthropicAPIKey = "anthropic-key"
	next.AgentRemoteToolsEnabled = false
	next.RefreshProviderAwareConfig()

	loadConfigForSecretsReload = func() *Config {
		return next
	}

	memory := agents.NewMemory(10)
	registry := agents.NewAgentRegistry()
	registry.RegisterAgent(&agents.Agent{
		ID:     "security-analyst",
		Name:   "Security Analyst",
		Tools:  []agents.Tool{{Name: "query_assets", Description: "stale"}, {Name: "remote_tool", Description: "remote"}, {Name: "custom_tool", Description: "custom"}},
		Memory: memory,
	})

	application := &App{
		Config:           current,
		Logger:           testAppLogger(),
		Agents:           registry,
		remoteAgentTools: []agents.Tool{{Name: "remote_tool", Description: "remote"}},
	}

	if err := application.ReloadSecrets(context.Background()); err != nil {
		t.Fatalf("ReloadSecrets failed: %v", err)
	}

	agent, ok := application.Agents.GetAgent("security-analyst")
	if !ok {
		t.Fatal("expected configured AI agent to remain registered")
	}
	if agent.Memory != memory {
		t.Fatal("expected agent memory to be preserved")
	}
	if findRegisteredAgentTool(agent.Tools, "remote_tool") != nil {
		t.Fatal("expected disabled remote tool to be removed from configured agent")
	}
	if findRegisteredAgentTool(agent.Tools, "custom_tool") == nil {
		t.Fatal("expected non-managed extra tool to be preserved")
	}
	if findRegisteredAgentTool(agent.Tools, "query_assets") == nil {
		t.Fatal("expected refreshed security tools to remain available")
	}
}

func TestReloadSecretsRejectsInvalidConfig(t *testing.T) {
	previousLoad := loadConfigForSecretsReload
	t.Cleanup(func() { loadConfigForSecretsReload = previousLoad })

	current := LoadConfig()
	current.APIAuthEnabled = true
	current.APIKeys = map[string]string{"key": "user"}
	current.RefreshProviderAwareConfig()

	next := LoadConfig()
	next.NATSConsumerEnabled = true
	next.NATSJetStreamEnabled = false
	next.RefreshProviderAwareConfig()

	loadConfigForSecretsReload = func() *Config {
		return next
	}

	application := &App{
		Config: current,
		Logger: testAppLogger(),
	}
	application.setAPIKeys(current.APIKeys)

	err := application.ReloadSecrets(context.Background())
	if err == nil {
		t.Fatal("expected ReloadSecrets to reject invalid config")
		return
	}
	if !strings.Contains(err.Error(), "NATS_JETSTREAM_ENABLED must be true when NATS_CONSUMER_ENABLED=true") {
		t.Fatalf("unexpected error: %v", err)
	}
	if application.Config != current {
		t.Fatal("expected current config to remain in place after validation failure")
	}
}

func TestReloadSecretsAllowsDroppingSnowflakeCredentialsOnPostgresBackend(t *testing.T) {
	previousLoad := loadConfigForSecretsReload
	t.Cleanup(func() { loadConfigForSecretsReload = previousLoad })

	current := LoadConfig()
	current.WarehouseBackend = "postgres"
	current.WarehousePostgresDSN = "postgres://warehouse"
	current.SnowflakeAccount = "acct"
	current.SnowflakeUser = "user"
	current.SnowflakePrivateKey = "key"
	current.AnthropicAPIKey = "anthropic-key"
	current.GraphRetentionDays = 0
	current.AccessReviewRetentionDays = 0
	current.RefreshProviderAwareConfig()

	next := LoadConfig()
	next.WarehouseBackend = "postgres"
	next.WarehousePostgresDSN = "postgres://warehouse"
	next.SnowflakeAccount = ""
	next.SnowflakeUser = ""
	next.SnowflakePrivateKey = ""
	next.AnthropicAPIKey = "anthropic-key"
	next.GraphRetentionDays = 0
	next.AccessReviewRetentionDays = 0
	next.RefreshProviderAwareConfig()

	loadConfigForSecretsReload = func() *Config {
		return next
	}

	memory := agents.NewMemory(10)
	staleHandlerCalled := false
	registry := agents.NewAgentRegistry()
	registry.RegisterAgent(&agents.Agent{
		ID:   "security-analyst",
		Name: "Security Analyst",
		Tools: []agents.Tool{{
			Name:        "query_assets",
			Description: "stale",
			Handler: func(context.Context, json.RawMessage) (string, error) {
				staleHandlerCalled = true
				return "stale", nil
			},
		}},
		Memory: memory,
	})

	application := &App{
		Config:          current,
		Logger:          testAppLogger(),
		Snowflake:       new(snowflake.Client),
		LegacySnowflake: new(snowflake.Client),
		Agents:          registry,
	}

	if err := application.ReloadSecrets(context.Background()); err != nil {
		t.Fatalf("ReloadSecrets failed: %v", err)
	}
	if application.Config == nil {
		t.Fatal("expected config to remain set after reload")
		return
	}
	if application.Config.WarehouseBackend != "postgres" {
		t.Fatalf("expected postgres warehouse backend after reload, got %q", application.Config.WarehouseBackend)
	}
	if application.Config.SnowflakeAccount != "" || application.Config.SnowflakeUser != "" || application.Config.SnowflakePrivateKey != "" {
		t.Fatalf("expected Snowflake credentials to be removable on postgres backend, got %#v", application.Config)
	}
	if application.Snowflake != nil {
		t.Fatalf("expected active snowflake client to be cleared, got %T", application.Snowflake)
	}
	if application.LegacySnowflake != nil {
		t.Fatalf("expected legacy snowflake client to be cleared, got %T", application.LegacySnowflake)
	}
	sfClient := application.Snowflake
	if sfClient == nil {
		sfClient = application.LegacySnowflake
	}
	if sfClient != nil {
		t.Fatalf("expected no remaining snowflake client selection after reload, got %T", sfClient)
	}

	agent, ok := application.Agents.GetAgent("security-analyst")
	if !ok {
		t.Fatal("expected security-analyst agent to remain registered")
	}
	if agent.Memory != memory {
		t.Fatal("expected agent memory to be preserved across secret reload")
	}
	queryAssets := findRegisteredAgentTool(agent.Tools, "query_assets")
	if queryAssets == nil {
		t.Fatal("expected query_assets tool after secret reload")
		return
	}
	if queryAssets.Description == "stale" {
		t.Fatal("expected query_assets tool definition to refresh after secret reload")
	}
	_, err := queryAssets.Handler(context.Background(), json.RawMessage(`{"query":"SELECT 1"}`))
	if staleHandlerCalled {
		t.Fatal("expected stale query_assets handler to be replaced")
	}
	if err == nil || err.Error() != "snowflake not configured" {
		t.Fatalf("expected refreshed query_assets handler to reject missing snowflake, got %v", err)
	}
}

func TestReloadSecretsRejectsDroppingSnowflakeCredentialsWhenLegacyRetentionRemainsEnabled(t *testing.T) {
	previousLoad := loadConfigForSecretsReload
	t.Cleanup(func() { loadConfigForSecretsReload = previousLoad })

	current := LoadConfig()
	current.WarehouseBackend = "postgres"
	current.WarehousePostgresDSN = "postgres://warehouse"
	current.SnowflakeAccount = "acct"
	current.SnowflakeUser = "user"
	current.SnowflakePrivateKey = "key"
	current.GraphRetentionDays = 14
	current.AccessReviewRetentionDays = 30
	current.RefreshProviderAwareConfig()

	next := LoadConfig()
	next.WarehouseBackend = "postgres"
	next.WarehousePostgresDSN = "postgres://warehouse"
	next.GraphRetentionDays = 14
	next.AccessReviewRetentionDays = 30
	next.RefreshProviderAwareConfig()

	loadConfigForSecretsReload = func() *Config {
		return next
	}

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	application := &App{
		Config:          current,
		Logger:          testAppLogger(),
		appStateDB:      db,
		LegacySnowflake: new(snowflake.Client),
	}

	err = application.ReloadSecrets(context.Background())
	if err == nil {
		t.Fatal("expected ReloadSecrets to reject dropping snowflake credentials while legacy retention remains enabled")
		return
	}
	if !strings.Contains(err.Error(), "legacy snowflake source is required while graph or access-review retention remains enabled") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRotateSnowflakeClientReinitializesCutoverRetentionRepoWhenLegacySourceRemoved(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	oldLegacy := new(snowflake.Client)
	oldLegacyCleaner := snowflake.NewRetentionRepository(oldLegacy)
	application := &App{
		Config:          &Config{WarehouseBackend: "postgres"},
		Logger:          testAppLogger(),
		appStateDB:      db,
		LegacySnowflake: oldLegacy,
		RetentionRepo: appStateCutoverRetentionCleaner{
			appState: appstate.NewRetentionRepository(db),
			legacy:   oldLegacyCleaner,
		},
	}

	if err := application.rotateSnowflakeClient(context.Background(), &Config{WarehouseBackend: "postgres"}); err != nil {
		t.Fatalf("rotateSnowflakeClient() error = %v", err)
	}

	cutover, ok := application.RetentionRepo.(appStateCutoverRetentionCleaner)
	if !ok {
		t.Fatalf("expected cutover retention cleaner, got %T", application.RetentionRepo)
	}
	if cutover.appState == nil {
		t.Fatal("expected app-state retention cleaner to remain configured")
	}
	if cutover.legacy != nil {
		t.Fatalf("expected legacy retention cleaner to be cleared, got %#v", cutover.legacy)
	}
}

func TestRotateSnowflakeClientReinitializesCutoverRetentionRepoWhenLegacySourceRotates(t *testing.T) {
	originalNewSnowflakeClient := newSnowflakeClient
	originalPingSnowflake := pingSnowflake
	t.Cleanup(func() {
		newSnowflakeClient = originalNewSnowflakeClient
		pingSnowflake = originalPingSnowflake
	})

	newSnowflakeClient = func(snowflake.ClientConfig) (*snowflake.Client, error) {
		return new(snowflake.Client), nil
	}
	pingSnowflake = func(context.Context, *snowflake.Client) error { return nil }

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	oldLegacy := new(snowflake.Client)
	oldLegacyCleaner := snowflake.NewRetentionRepository(oldLegacy)
	application := &App{
		Config:          &Config{WarehouseBackend: "postgres"},
		Logger:          testAppLogger(),
		appStateDB:      db,
		LegacySnowflake: oldLegacy,
		RetentionRepo: appStateCutoverRetentionCleaner{
			appState: appstate.NewRetentionRepository(db),
			legacy:   oldLegacyCleaner,
		},
	}

	if err := application.rotateSnowflakeClient(context.Background(), &Config{
		WarehouseBackend:    "postgres",
		SnowflakeAccount:    "acct",
		SnowflakeUser:       "user",
		SnowflakePrivateKey: "key",
	}); err != nil {
		t.Fatalf("rotateSnowflakeClient() error = %v", err)
	}

	cutover, ok := application.RetentionRepo.(appStateCutoverRetentionCleaner)
	if !ok {
		t.Fatalf("expected cutover retention cleaner, got %T", application.RetentionRepo)
	}
	if cutover.appState == nil {
		t.Fatal("expected app-state retention cleaner to remain configured")
	}
	if cutover.legacy == nil {
		t.Fatal("expected legacy retention cleaner to be refreshed")
	}
	if cutover.legacy == oldLegacyCleaner {
		t.Fatal("expected legacy retention cleaner to be rebuilt with the rotated client")
	}
}

func TestReloadSecretsReadsUpdatedCredentialFileSource(t *testing.T) {
	previousLoad := loadConfigForSecretsReload
	t.Cleanup(func() { loadConfigForSecretsReload = previousLoad })
	loadConfigForSecretsReload = LoadConfig

	dir := t.TempDir()
	writeSecret := func(name, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	t.Setenv("CEREBRO_CREDENTIAL_SOURCE", "file")
	t.Setenv("CEREBRO_CREDENTIAL_FILE_DIR", dir)
	t.Setenv("API_AUTH_ENABLED", "true")

	writeSecret("API_KEYS", "old-key:old-user\n")
	current := LoadConfig()
	current.RefreshProviderAwareConfig()

	application := &App{
		Config: current,
		Logger: testAppLogger(),
	}
	application.setAPIKeys(current.APIKeys)

	writeSecret("API_KEYS", "new-key:new-user\n")
	if err := application.ReloadSecrets(context.Background()); err != nil {
		t.Fatalf("ReloadSecrets failed: %v", err)
	}

	keys := application.APIKeysSnapshot()
	if len(keys) != 1 || keys["new-key"] != "new-user" {
		t.Fatalf("expected updated file-backed API keys, got %#v", keys)
	}
}
