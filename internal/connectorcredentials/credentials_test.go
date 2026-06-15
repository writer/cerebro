package connectorcredentials

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

type memoryStore struct {
	records map[string]*ports.ConnectorCredentialRecord
}

func (s *memoryStore) Ping(context.Context) error { return nil }

func (s *memoryStore) PutConnectorCredential(_ context.Context, record *ports.ConnectorCredentialRecord) error {
	if s.records == nil {
		s.records = map[string]*ports.ConnectorCredentialRecord{}
	}
	cloned := *record
	cloned.Sealed = append([]byte{}, record.Sealed...)
	s.records[record.ID] = &cloned
	return nil
}

func (s *memoryStore) GetConnectorCredential(_ context.Context, id string) (*ports.ConnectorCredentialRecord, error) {
	record, ok := s.records[id]
	if !ok {
		return nil, ports.ErrConnectorCredentialNotFound
	}
	cloned := *record
	cloned.Sealed = append([]byte{}, record.Sealed...)
	return &cloned, nil
}

func TestVaultStoresEncryptedCredentialReferences(t *testing.T) {
	store := &memoryStore{}
	vault, err := NewVault(store, "test-vault-key")
	if err != nil {
		t.Fatalf("NewVault() error = %v", err)
	}
	record, err := vault.Put(context.Background(), PlainCredential{
		TenantID:  "tenant-a",
		SourceID:  "github",
		RuntimeID: "runtime-a",
		Fields:    map[string]string{"token": "secret-token"},
	})
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if string(record.Sealed) == "" || string(record.Sealed) == "secret-token" {
		t.Fatalf("sealed payload = %q, want encrypted envelope", string(record.Sealed))
	}
	resolved, err := vault.ResolveReferences(context.Background(), "github", "tenant-a", "runtime-a", map[string]string{
		"token": Reference(record.ID, "token"),
	})
	if err != nil {
		t.Fatalf("ResolveReferences() error = %v", err)
	}
	if got := resolved["token"]; got != "secret-token" {
		t.Fatalf("resolved token = %q, want secret-token", got)
	}
	if _, err := vault.ResolveReferences(context.Background(), "github", "tenant-b", "runtime-a", map[string]string{"token": Reference(record.ID, "token")}); err == nil {
		t.Fatal("ResolveReferences() tenant mismatch error = nil, want error")
	}
	if _, err := vault.ResolveReferences(context.Background(), "github", "tenant-a", "runtime-b", map[string]string{"token": Reference(record.ID, "token")}); err == nil {
		t.Fatal("ResolveReferences() runtime mismatch error = nil, want error")
	}
}

func TestTransitKeyDecryptsHybridPayload(t *testing.T) {
	transit, err := NewTransitKey()
	if err != nil {
		t.Fatalf("NewTransitKey() error = %v", err)
	}
	additionalData := []byte("connector-credential-test-context")
	payload, err := encryptForTransit(transit, []byte(`{"token":"secret-token"}`), additionalData)
	if err != nil {
		t.Fatalf("encryptForTransit() error = %v", err)
	}
	plaintext, err := transit.DecryptWithExactAdditionalData(payload, additionalData)
	if err != nil {
		t.Fatalf("DecryptWithExactAdditionalData() error = %v", err)
	}
	if string(plaintext) != `{"token":"secret-token"}` {
		t.Fatalf("plaintext = %s", plaintext)
	}
	if _, err := transit.Decrypt(payload); err == nil {
		t.Fatal("Decrypt() with implicit context error = nil, want error")
	}
}

func encryptForTransit(transit *TransitKey, plaintext []byte, additionalData []byte) (EncryptedPayload, error) {
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return EncryptedPayload{}, err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return EncryptedPayload{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedPayload{}, err
	}
	public := transit.private.Public().(*rsa.PublicKey)
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, public, aesKey, nil)
	if err != nil {
		return EncryptedPayload{}, err
	}
	key := transit.PublicKey()
	ciphertext := gcm.Seal(nil, nonce, plaintext, additionalData)
	return EncryptedPayload{
		KeyID:      key.KeyID,
		Algorithm:  key.Algorithm,
		WrappedKey: base64.StdEncoding.EncodeToString(wrapped),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}
