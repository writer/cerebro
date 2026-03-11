package app

import (
	"fmt"
	"time"

	"github.com/writer/cerebro/internal/apiauth"
)

func (a *App) LookupAPICredential(key string) (apiauth.Credential, bool) {
	if credential, ok := apiauth.LookupCredential(a.APICredentialsSnapshot(), key); ok {
		return credential, true
	}
	if a == nil || a.apiCredentialStore == nil {
		return apiauth.Credential{}, false
	}
	return a.apiCredentialStore.Lookup(key)
}

func (a *App) ConfigureManagedAPICredentialStore(path string) error {
	if a == nil {
		return fmt.Errorf("app is nil")
	}
	store := apiauth.NewManagedCredentialStore(path)
	if err := store.Load(); err != nil {
		return err
	}
	a.apiCredentialStore = store
	if a.Config != nil {
		a.Config.APICredentialStateFile = path
	}
	return nil
}

func (a *App) ManagedAPICredentials() []apiauth.ManagedCredentialRecord {
	if a == nil || a.apiCredentialStore == nil {
		return nil
	}
	return a.apiCredentialStore.List()
}

func (a *App) GetManagedAPICredential(id string) (apiauth.ManagedCredentialRecord, bool) {
	if a == nil || a.apiCredentialStore == nil {
		return apiauth.ManagedCredentialRecord{}, false
	}
	return a.apiCredentialStore.Get(id)
}

func (a *App) CreateManagedAPICredential(spec apiauth.ManagedCredentialSpec, now time.Time) (apiauth.ManagedCredentialRecord, string, error) {
	if a == nil || a.apiCredentialStore == nil {
		return apiauth.ManagedCredentialRecord{}, "", fmt.Errorf("managed api credential store is not configured")
	}
	return a.apiCredentialStore.Create(spec, now)
}

func (a *App) RotateManagedAPICredential(id string, now time.Time) (apiauth.ManagedCredentialRecord, string, error) {
	if a == nil || a.apiCredentialStore == nil {
		return apiauth.ManagedCredentialRecord{}, "", fmt.Errorf("managed api credential store is not configured")
	}
	return a.apiCredentialStore.Rotate(id, now)
}

func (a *App) RevokeManagedAPICredential(id, reason string, now time.Time) (apiauth.ManagedCredentialRecord, error) {
	if a == nil || a.apiCredentialStore == nil {
		return apiauth.ManagedCredentialRecord{}, fmt.Errorf("managed api credential store is not configured")
	}
	return a.apiCredentialStore.Revoke(id, reason, now)
}
