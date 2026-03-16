package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/agents"
	"github.com/writer/cerebro/internal/apiauth"
	"github.com/writer/cerebro/internal/snowflake"
)

type secretsLoader interface {
	LoadConfig() *Config
}

type envSecretsLoader struct{}

func (envSecretsLoader) LoadConfig() *Config {
	return LoadConfig()
}

var loadConfigForSecretsReload = LoadConfig

func cloneStringMap(values map[string]string) map[string]string {
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func credentialsFromAPIKeys(keys map[string]string) map[string]apiauth.Credential {
	credentials := make(map[string]apiauth.Credential, len(keys))
	for key, userID := range keys {
		credentials[key] = apiauth.DefaultCredentialForAPIKey(key, userID)
	}
	return credentials
}

func (a *App) setAPICredentials(credentials map[string]apiauth.Credential) {
	cloned := apiauth.CloneCredentials(credentials)
	derivedKeys := apiauth.CredentialsToUserMap(cloned)
	a.apiCredentials.Store(cloned)
	a.apiKeys.Store(cloneStringMap(derivedKeys))
	if a.Config != nil {
		a.Config.APICredentials = cloned
		a.Config.APIKeys = cloneStringMap(derivedKeys)
	}
}

func (a *App) setAPIKeys(keys map[string]string) {
	a.setAPICredentials(credentialsFromAPIKeys(keys))
}

// APIKeysSnapshot returns the current API key map used by auth middleware.
func (a *App) APIKeysSnapshot() map[string]string {
	if a == nil {
		return map[string]string{}
	}
	current := a.apiKeys.Load()
	if current == nil {
		if a.Config != nil {
			return cloneStringMap(a.Config.APIKeys)
		}
		return map[string]string{}
	}
	keys, ok := current.(map[string]string)
	if !ok {
		return map[string]string{}
	}
	return cloneStringMap(keys)
}

// APICredentialsSnapshot returns the current structured API credential map.
func (a *App) APICredentialsSnapshot() map[string]apiauth.Credential {
	if a == nil {
		return map[string]apiauth.Credential{}
	}
	current := a.apiCredentials.Load()
	if current == nil {
		if a.Config != nil {
			return apiauth.CloneCredentials(a.Config.APICredentials)
		}
		return map[string]apiauth.Credential{}
	}
	credentials, ok := current.(map[string]apiauth.Credential)
	if !ok {
		return map[string]apiauth.Credential{}
	}
	return apiauth.CloneCredentials(credentials)
}

func (a *App) startSecretsReloader(parent context.Context) {
	if a == nil || a.Config == nil || a.Config.SecretsReloadInterval <= 0 {
		return
	}
	if parent == nil {
		parent = context.Background()
	}

	ctx, cancel := context.WithCancel(parent)
	a.secretsReloadCancel = cancel
	a.secretsReloadWG.Add(1)

	interval := a.Config.SecretsReloadInterval
	go func() {
		defer a.secretsReloadWG.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := a.ReloadSecrets(ctx); err != nil && a.Logger != nil {
					a.Logger.Warn("periodic secret reload failed", "error", err)
				}
			}
		}
	}()

	if a.Logger != nil {
		a.Logger.Info("secrets reload scheduler enabled", "interval", interval)
	}
}

func (a *App) stopSecretsReloader() {
	if a == nil {
		return
	}
	if a.secretsReloadCancel != nil {
		a.secretsReloadCancel()
	}
	a.secretsReloadWG.Wait()
}

// ReloadSecrets reloads runtime credentials from the current configuration source.
func (a *App) ReloadSecrets(ctx context.Context) error {
	if a == nil {
		return fmt.Errorf("app is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	a.reloadMu.Lock()
	defer a.reloadMu.Unlock()

	next := loadConfigForSecretsReload()
	if a.secretsLoader != nil {
		next = a.secretsLoader.LoadConfig()
	}
	if next == nil {
		return fmt.Errorf("reload config is nil")
	}
	if err := next.Validate(); err != nil {
		return err
	}
	if len(next.APICredentials) == 0 && len(next.APIKeys) > 0 {
		next.APICredentials = credentialsFromAPIKeys(next.APIKeys)
		next.APIKeys = apiauth.CredentialsToUserMap(next.APICredentials)
	}

	current := a.Config
	if current == nil {
		a.setAPICredentials(next.APICredentials)
		a.Config = next
		return nil
	}

	apiCredentialsChanged := !apiauth.EqualCredentials(a.APICredentialsSnapshot(), next.APICredentials)
	snowflakeChanged := snowflakeCredentialsChanged(current, next)
	providersChanged := providerConfigsChanged(current, next)

	if !apiCredentialsChanged && !snowflakeChanged && !providersChanged {
		return nil
	}

	if snowflakeChanged {
		if err := a.rotateSnowflakeClient(ctx, next); err != nil {
			return fmt.Errorf("rotate snowflake credentials: %w", err)
		}
		a.logSecretRotation(ctx, "snowflake_credentials_rotated", map[string]interface{}{
			"account":   strings.TrimSpace(next.SnowflakeAccount),
			"warehouse": strings.TrimSpace(next.SnowflakeWarehouse),
		})
	}

	if providersChanged || snowflakeChanged {
		a.rebuildProviders(ctx, next)
		a.logSecretRotation(ctx, "provider_credentials_reloaded", map[string]interface{}{
			"provider_count": len(a.Providers.List()),
		})
	}

	if apiCredentialsChanged {
		a.setAPICredentials(next.APICredentials)
		next.APICredentials = a.APICredentialsSnapshot()
		next.APIKeys = a.APIKeysSnapshot()
		a.logSecretRotation(ctx, "api_keys_reloaded", map[string]interface{}{
			"key_count":        len(next.APIKeys),
			"credential_count": len(next.APICredentials),
		})
	} else {
		next.APICredentials = a.APICredentialsSnapshot()
		next.APIKeys = a.APIKeysSnapshot()
	}

	a.Config = next
	if a.Logger != nil {
		a.Logger.Info("secret reload completed",
			"api_credentials_changed", apiCredentialsChanged,
			"snowflake_changed", snowflakeChanged,
			"providers_changed", providersChanged,
		)
	}
	return nil
}

func snowflakeCredentialsChanged(current, next *Config) bool {
	if current == nil || next == nil {
		return current != next
	}
	return current.SnowflakeAccount != next.SnowflakeAccount ||
		current.SnowflakeUser != next.SnowflakeUser ||
		current.SnowflakePrivateKey != next.SnowflakePrivateKey ||
		current.SnowflakeDatabase != next.SnowflakeDatabase ||
		current.SnowflakeSchema != next.SnowflakeSchema ||
		current.SnowflakeWarehouse != next.SnowflakeWarehouse ||
		current.SnowflakeRole != next.SnowflakeRole
}

func (a *App) rotateSnowflakeClient(ctx context.Context, cfg *Config) error {
	if a == nil || cfg == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if strings.TrimSpace(cfg.SnowflakePrivateKey) == "" ||
		strings.TrimSpace(cfg.SnowflakeAccount) == "" ||
		strings.TrimSpace(cfg.SnowflakeUser) == "" {
		return fmt.Errorf("snowflake rotation requires SNOWFLAKE_PRIVATE_KEY, SNOWFLAKE_ACCOUNT, and SNOWFLAKE_USER")
	}

	newClient, err := snowflake.NewClient(snowflake.ClientConfig{
		Account:    cfg.SnowflakeAccount,
		User:       cfg.SnowflakeUser,
		PrivateKey: cfg.SnowflakePrivateKey,
		Database:   cfg.SnowflakeDatabase,
		Schema:     cfg.SnowflakeSchema,
		Warehouse:  cfg.SnowflakeWarehouse,
		Role:       cfg.SnowflakeRole,
	})
	if err != nil {
		return err
	}
	if err := newClient.Ping(ctx); err != nil {
		_ = newClient.Close()
		return err
	}

	oldClient := a.Snowflake
	a.Snowflake = newClient
	a.Warehouse = newClient
	a.initRepositories()

	if a.ScanWatermarks != nil {
		a.ScanWatermarks.SetDB(newClient.DB())
		if err := a.ScanWatermarks.LoadWatermarks(ctx); err != nil && a.Logger != nil {
			a.Logger.Warn("failed to reload scan watermarks after snowflake rotation", "error", err)
		}
	}

	if a.SnowflakeFindings != nil {
		a.SnowflakeFindings.SetConnection(newClient.DB(), newClient.Database(), newClient.Schema())
		if err := a.SnowflakeFindings.Load(ctx); err != nil && a.Logger != nil {
			a.Logger.Warn("failed to reload findings after snowflake rotation", "error", err)
		}
	}

	if a.Agents != nil {
		store, err := agents.NewSnowflakeSessionStore(newClient)
		if err != nil {
			if a.Logger != nil {
				a.Logger.Warn("failed to rotate agent session store", "error", err)
			}
		} else {
			a.Agents.SetSessionStore(store)
		}
	}

	if a.graphCancel != nil {
		a.graphCancel()
		a.graphCancel = nil
	}
	a.initSecurityGraph(ctx)

	if oldClient != nil {
		if err := oldClient.Close(); err != nil && a.Logger != nil {
			a.Logger.Warn("failed to close previous snowflake client after rotation", "error", err)
		}
	}

	return nil
}

func (a *App) logSecretRotation(ctx context.Context, action string, details map[string]interface{}) {
	if a == nil {
		return
	}
	if a.Logger != nil {
		a.Logger.Info("secret rotation event", "action", action, "details", details)
	}
	if a.AuditRepo == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	entry := &snowflake.AuditEntry{
		Action:       action,
		ActorID:      "system:secrets-reloader",
		ActorType:    "system",
		ResourceType: "secrets",
		ResourceID:   action,
		Details:      details,
		IPAddress:    "internal",
		UserAgent:    "cerebro-secrets-reloader",
	}
	if err := a.AuditRepo.Log(ctx, entry); err != nil && a.Logger != nil {
		a.Logger.Warn("failed to persist secret rotation audit log", "action", action, "error", err)
	}
}
