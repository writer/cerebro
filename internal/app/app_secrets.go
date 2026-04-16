package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/agents"
	"github.com/writer/cerebro/internal/apiauth"
	appsecrets "github.com/writer/cerebro/internal/app/secrets"
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
	return appsecrets.CloneStringMap(values)
}

func credentialsFromAPIKeys(keys map[string]string) map[string]apiauth.Credential {
	return appsecrets.CredentialsFromAPIKeys(keys)
}

func (a *App) secretsRuntime() *appsecrets.Runtime {
	if a == nil {
		return nil
	}
	if a.Secrets == nil {
		a.Secrets = appsecrets.NewRuntime()
	}
	return a.Secrets
}

func (a *App) setAPICredentials(credentials map[string]apiauth.Credential) {
	if a == nil {
		return
	}
	runtime := a.secretsRuntime()
	cloned, derivedKeys := runtime.SetAPICredentials(credentials)
	if a.Config != nil {
		a.Config.APICredentials = cloned
		a.Config.APIKeys = derivedKeys
	}
}

func (a *App) setAPIKeys(keys map[string]string) {
	if a == nil {
		return
	}
	a.setAPICredentials(credentialsFromAPIKeys(keys))
}

// APIKeysSnapshot returns the current API key map used by auth middleware.
func (a *App) APIKeysSnapshot() map[string]string {
	var fallback map[string]string
	if a != nil && a.Config != nil {
		fallback = a.Config.APIKeys
	}
	runtime := a.secretsRuntime()
	if runtime == nil {
		return cloneStringMap(fallback)
	}
	return runtime.APIKeysSnapshot(fallback)
}

// APICredentialsSnapshot returns the current structured API credential map.
func (a *App) APICredentialsSnapshot() map[string]apiauth.Credential {
	var fallback map[string]apiauth.Credential
	if a != nil && a.Config != nil {
		fallback = a.Config.APICredentials
	}
	runtime := a.secretsRuntime()
	if runtime == nil {
		return apiauth.CloneCredentials(fallback)
	}
	return runtime.APICredentialsSnapshot(fallback)
}

func (a *App) startSecretsReloader(parent context.Context) {
	if a == nil || a.Config == nil || a.Config.SecretsReloadInterval <= 0 {
		return
	}
	a.secretsRuntime().StartReloader(parent, a.Config.SecretsReloadInterval, a.Logger, a.ReloadSecrets)
}

func (a *App) stopSecretsReloader() {
	a.secretsRuntime().StopReloader()
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

	if !hasSnowflakeCredentials(cfg) {
		return fmt.Errorf("snowflake rotation requires SNOWFLAKE_PRIVATE_KEY, SNOWFLAKE_ACCOUNT, and SNOWFLAKE_USER")
	}

	newClient, err := openConfiguredSnowflakeClient(ctx, cfg)
	if err != nil {
		return err
	}

	oldClient := a.Snowflake
	oldLegacyClient := a.LegacySnowflake
	if strings.EqualFold(strings.TrimSpace(cfg.WarehouseBackend), "snowflake") {
		a.Snowflake = newClient
		a.LegacySnowflake = nil
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
			if db := a.appStateDB(); db != nil {
				a.Agents.SetSessionStore(agents.NewPostgresSessionStore(db))
			} else {
				store, err := agents.NewSnowflakeSessionStore(newClient)
				if err != nil {
					if a.Logger != nil {
						a.Logger.Warn("failed to rotate agent session store", "error", err)
					}
				} else {
					a.Agents.SetSessionStore(store)
				}
			}
		}

		if a.graphCancel != nil {
			a.graphCancel()
			a.graphCancel = nil
		}
		a.initSecurityGraph(ctx)
	} else {
		a.LegacySnowflake = newClient
	}

	if oldClient != nil && oldClient != newClient {
		if err := oldClient.Close(); err != nil && a.Logger != nil {
			a.Logger.Warn("failed to close previous snowflake client after rotation", "error", err)
		}
	}
	if oldLegacyClient != nil && oldLegacyClient != newClient && oldLegacyClient != oldClient {
		if err := oldLegacyClient.Close(); err != nil && a.Logger != nil {
			a.Logger.Warn("failed to close previous legacy snowflake client after rotation", "error", err)
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
