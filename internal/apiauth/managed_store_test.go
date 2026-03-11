package apiauth

import (
	"path/filepath"
	"testing"
	"time"
)

func TestManagedCredentialStoreLifecycle(t *testing.T) {
	store := NewManagedCredentialStore(filepath.Join(t.TempDir(), "credentials.json"))
	now := time.Date(2026, 3, 9, 23, 0, 0, 0, time.UTC)

	record, secret, err := store.Create(ManagedCredentialSpec{
		Name:     "SDK client",
		UserID:   "sdk-user",
		ClientID: "sdk-client-1",
		Scopes:   []string{"sdk.context.read", "sdk.invoke"},
	}, now)
	if err != nil {
		t.Fatalf("create managed credential: %v", err)
	}
	if secret == "" {
		t.Fatal("expected raw secret on create")
	}
	if credential, ok := store.Lookup(secret); !ok || credential.ID != record.Credential.ID {
		t.Fatalf("expected lookup by newly created secret to succeed, got credential=%#v ok=%v", credential, ok)
	}

	reloaded := NewManagedCredentialStore(store.Path())
	if err := reloaded.Load(); err != nil {
		t.Fatalf("reload managed credential store: %v", err)
	}
	if credential, ok := reloaded.Lookup(secret); !ok || credential.ID != record.Credential.ID {
		t.Fatalf("expected lookup after reload to succeed, got credential=%#v ok=%v", credential, ok)
	}

	rotated, rotatedSecret, err := reloaded.Rotate(record.Credential.ID, now.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("rotate managed credential: %v", err)
	}
	if rotatedSecret == "" || rotatedSecret == secret {
		t.Fatalf("expected new secret after rotate, got %q", rotatedSecret)
	}
	if _, ok := reloaded.Lookup(secret); ok {
		t.Fatal("expected original secret to stop working after rotate")
	}
	if credential, ok := reloaded.Lookup(rotatedSecret); !ok || credential.ID != rotated.Credential.ID {
		t.Fatalf("expected rotated secret lookup to succeed, got credential=%#v ok=%v", credential, ok)
	}

	revoked, err := reloaded.Revoke(record.Credential.ID, "no longer needed", now.Add(20*time.Minute))
	if err != nil {
		t.Fatalf("revoke managed credential: %v", err)
	}
	if revoked.RevokedAt == nil {
		t.Fatal("expected revoked_at to be recorded")
	}
	if _, ok := reloaded.Lookup(rotatedSecret); ok {
		t.Fatal("expected revoked credential secret to be rejected")
	}
}
