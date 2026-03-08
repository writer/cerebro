package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/agents"
	"github.com/evalops/cerebro/internal/snowflake"
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

func equalStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, valueA := range a {
		if valueB, ok := b[key]; !ok || valueA != valueB {
			return false
		}
	}
	return true
}

func (a *App) setAPIKeys(keys map[string]string) {
	cloned := cloneStringMap(keys)
	a.apiKeys.Store(cloned)
	if a.Config != nil {
		a.Config.APIKeys = cloned
	}
}

// APIKeysSnapshot returns the current API key map used by auth middleware.
func (a *App) APIKeysSnapshot() map[string]string {
	if a == nil {
		return map[string]string{}
	}
	current := a.apiKeys.Load()
	if current == nil {
		return map[string]string{}
	}
	keys, ok := current.(map[string]string)
	if !ok {
		return map[string]string{}
	}
	return cloneStringMap(keys)
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
				if err := a.ReloadSecrets(context.Background()); err != nil && a.Logger != nil {
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

	current := a.Config
	if current == nil {
		a.setAPIKeys(next.APIKeys)
		a.Config = next
		return nil
	}

	apiKeysChanged := !equalStringMap(a.APIKeysSnapshot(), next.APIKeys)
	snowflakeChanged := snowflakeCredentialsChanged(current, next)
	providersChanged := providerConfigsChanged(current, next)

	if !apiKeysChanged && !snowflakeChanged && !providersChanged {
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

	if apiKeysChanged {
		a.setAPIKeys(next.APIKeys)
		next.APIKeys = a.APIKeysSnapshot()
		a.logSecretRotation(ctx, "api_keys_reloaded", map[string]interface{}{
			"key_count": len(next.APIKeys),
		})
	} else {
		next.APIKeys = a.APIKeysSnapshot()
	}

	a.Config = next
	if a.Logger != nil {
		a.Logger.Info("secret reload completed",
			"api_keys_changed", apiKeysChanged,
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
