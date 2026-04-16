package secrets

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/writer/cerebro/internal/apiauth"
)

type Runtime struct {
	apiKeys        atomic.Value
	apiCredentials atomic.Value
	reloadCancel   context.CancelFunc
	reloadWG       sync.WaitGroup
}

func NewRuntime() *Runtime {
	return &Runtime{}
}

func CloneStringMap(values map[string]string) map[string]string {
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func CredentialsFromAPIKeys(keys map[string]string) map[string]apiauth.Credential {
	credentials := make(map[string]apiauth.Credential, len(keys))
	for key, userID := range keys {
		credentials[key] = apiauth.DefaultCredentialForAPIKey(key, userID)
	}
	return credentials
}

func (r *Runtime) SetAPICredentials(credentials map[string]apiauth.Credential) (map[string]apiauth.Credential, map[string]string) {
	cloned := apiauth.CloneCredentials(credentials)
	derivedKeys := apiauth.CredentialsToUserMap(cloned)
	keyClone := CloneStringMap(derivedKeys)
	if r != nil {
		r.apiCredentials.Store(cloned)
		r.apiKeys.Store(keyClone)
	}
	return cloned, keyClone
}

func (r *Runtime) SetAPIKeys(keys map[string]string) (map[string]apiauth.Credential, map[string]string) {
	return r.SetAPICredentials(CredentialsFromAPIKeys(keys))
}

func (r *Runtime) APIKeysSnapshot(fallback map[string]string) map[string]string {
	if r == nil {
		return CloneStringMap(fallback)
	}
	current := r.apiKeys.Load()
	if current == nil {
		return CloneStringMap(fallback)
	}
	keys, ok := current.(map[string]string)
	if !ok {
		return CloneStringMap(fallback)
	}
	return CloneStringMap(keys)
}

func (r *Runtime) APICredentialsSnapshot(fallback map[string]apiauth.Credential) map[string]apiauth.Credential {
	if r == nil {
		return apiauth.CloneCredentials(fallback)
	}
	current := r.apiCredentials.Load()
	if current == nil {
		return apiauth.CloneCredentials(fallback)
	}
	credentials, ok := current.(map[string]apiauth.Credential)
	if !ok {
		return apiauth.CloneCredentials(fallback)
	}
	return apiauth.CloneCredentials(credentials)
}

func (r *Runtime) StartReloader(parent context.Context, interval time.Duration, logger *slog.Logger, reload func(context.Context) error) {
	if r == nil || interval <= 0 || reload == nil {
		return
	}
	if parent == nil {
		parent = context.Background()
	}

	ctx, cancel := context.WithCancel(parent)
	r.reloadCancel = cancel
	r.reloadWG.Add(1)

	go func() {
		defer r.reloadWG.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := reload(ctx); err != nil && logger != nil {
					logger.Warn("periodic secret reload failed", "error", err)
				}
			}
		}
	}()

	if logger != nil {
		logger.Info("secrets reload scheduler enabled", "interval", interval)
	}
}

func (r *Runtime) StopReloader() {
	if r == nil {
		return
	}
	if r.reloadCancel != nil {
		r.reloadCancel()
	}
	r.reloadWG.Wait()
}
