package connectorcredentials

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"sort"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

type memoryStore struct {
	records         map[string]*ports.ConnectorCredentialRecord
	audit           []*ports.ConnectorCredentialAuditRecord
	metadataUpdates int
	putErr          error
	putErrRecord    *ports.ConnectorCredentialRecord
}

func (s *memoryStore) Ping(context.Context) error { return nil }

func (s *memoryStore) PutConnectorCredential(_ context.Context, record *ports.ConnectorCredentialRecord) error {
	if s.records == nil {
		s.records = map[string]*ports.ConnectorCredentialRecord{}
	}
	if s.putErr != nil {
		if s.putErrRecord != nil {
			cloned := cloneMemoryCredential(s.putErrRecord)
			s.records[cloned.ID] = &cloned
		}
		return s.putErr
	}
	cloned := cloneMemoryCredential(record)
	s.records[record.ID] = &cloned
	return nil
}

func (s *memoryStore) GetConnectorCredential(_ context.Context, id string) (*ports.ConnectorCredentialRecord, error) {
	record, ok := s.records[id]
	if !ok {
		return nil, ports.ErrConnectorCredentialNotFound
	}
	cloned := cloneMemoryCredential(record)
	return &cloned, nil
}

func (s *memoryStore) ListConnectorCredentials(_ context.Context, filter ports.ConnectorCredentialFilter) ([]*ports.ConnectorCredentialRecord, error) {
	records := []*ports.ConnectorCredentialRecord{}
	for _, record := range s.records {
		if !memoryCredentialMatches(record, filter) {
			continue
		}
		cloned := cloneMemoryCredential(record)
		records = append(records, &cloned)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].UpdatedAt.After(records[j].UpdatedAt)
	})
	if filter.Limit > 0 && len(records) > filter.Limit {
		records = records[:filter.Limit]
	}
	return records, nil
}

func (s *memoryStore) UpdateConnectorCredentialMetadata(_ context.Context, id string, update ports.ConnectorCredentialMetadataUpdate) (*ports.ConnectorCredentialRecord, error) {
	record, ok := s.records[id]
	if !ok {
		return nil, ports.ErrConnectorCredentialNotFound
	}
	s.metadataUpdates++
	if update.Status != "" {
		record.Status = update.Status
	}
	if update.Fields != nil {
		record.Fields = append([]string{}, update.Fields...)
	}
	if update.UpdatedBy != "" {
		record.UpdatedBy = update.UpdatedBy
	}
	if update.RevokedBy != "" {
		record.RevokedBy = update.RevokedBy
	}
	if update.PreviousCredentialID != "" {
		record.PreviousCredentialID = update.PreviousCredentialID
	}
	if update.RevokedAt != nil {
		record.RevokedAt = *update.RevokedAt
	}
	if update.LastUsedAt != nil {
		record.LastUsedAt = *update.LastUsedAt
	}
	if update.LastValidatedAt != nil {
		record.LastValidatedAt = *update.LastValidatedAt
	}
	record.UpdatedAt = time.Now().UTC()
	cloned := cloneMemoryCredential(record)
	return &cloned, nil
}

func (s *memoryStore) MarkConnectorCredentialUsed(_ context.Context, id string, usedAt time.Time, staleBefore time.Time) (*ports.ConnectorCredentialRecord, bool, error) {
	record, ok := s.records[id]
	if !ok {
		return nil, false, ports.ErrConnectorCredentialNotFound
	}
	if usedAt.IsZero() {
		usedAt = time.Now().UTC()
	}
	if staleBefore.IsZero() {
		staleBefore = usedAt.Add(-credentialUseTrackingInterval)
	}
	if !record.LastUsedAt.IsZero() && record.LastUsedAt.After(staleBefore) {
		cloned := cloneMemoryCredential(record)
		return &cloned, false, nil
	}
	s.metadataUpdates++
	record.LastUsedAt = usedAt.UTC()
	record.UpdatedAt = usedAt.UTC()
	cloned := cloneMemoryCredential(record)
	return &cloned, true, nil
}

func (s *memoryStore) AppendConnectorCredentialAuditEvent(_ context.Context, event *ports.ConnectorCredentialAuditRecord) error {
	if event == nil {
		return nil
	}
	cloned := *event
	s.audit = append(s.audit, &cloned)
	return nil
}

func (s *memoryStore) ListConnectorCredentialAuditEvents(_ context.Context, credentialID string, limit int) ([]*ports.ConnectorCredentialAuditRecord, error) {
	events := []*ports.ConnectorCredentialAuditRecord{}
	for _, event := range s.audit {
		if event.CredentialID != credentialID {
			continue
		}
		cloned := *event
		events = append(events, &cloned)
	}
	sort.Slice(events, func(i, j int) bool {
		return events[i].CreatedAt.After(events[j].CreatedAt)
	})
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

func cloneMemoryCredential(record *ports.ConnectorCredentialRecord) ports.ConnectorCredentialRecord {
	cloned := *record
	cloned.Sealed = append([]byte{}, record.Sealed...)
	cloned.Fields = append([]string{}, record.Fields...)
	return cloned
}

func memoryCredentialMatches(record *ports.ConnectorCredentialRecord, filter ports.ConnectorCredentialFilter) bool {
	if record == nil {
		return false
	}
	if filter.ID != "" && record.ID != filter.ID {
		return false
	}
	if filter.TenantID != "" && record.TenantID != filter.TenantID {
		return false
	}
	if filter.SourceID != "" && record.SourceID != filter.SourceID {
		return false
	}
	if filter.RuntimeID != "" && record.RuntimeID != filter.RuntimeID {
		return false
	}
	if filter.Status != "" && record.Status != filter.Status {
		return false
	}
	if filter.IdempotencyKey != "" && record.IdempotencyKey != filter.IdempotencyKey {
		return false
	}
	return true
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

func TestBrokerStoreEncryptedReplaysConcurrentIdempotencyConflict(t *testing.T) {
	transit, err := NewTransitKey()
	if err != nil {
		t.Fatalf("NewTransitKey() error = %v", err)
	}
	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	winner := &ports.ConnectorCredentialRecord{
		ID:                   "credential-winner",
		TenantID:             "tenant-a",
		SourceID:             "github",
		RuntimeID:            "runtime-a",
		CredentialStoreID:    "cerebro_vault",
		AuthMethod:           "encrypted_submission",
		Status:               StatusValid,
		KeyID:                "test-vault-key",
		Fields:               []string{"token"},
		Sealed:               []byte("sealed"),
		CreatedBy:            "alice",
		UpdatedBy:            "alice",
		IdempotencyKey:       "request-1",
		CreatedAt:            now,
		UpdatedAt:            now,
		PreviousCredentialID: "",
	}
	store := &memoryStore{
		putErr:       ports.ErrConnectorCredentialIdempotencyConflict,
		putErrRecord: winner,
	}
	vault, err := NewVault(store, "test-vault-key")
	if err != nil {
		t.Fatalf("NewVault() error = %v", err)
	}
	broker := NewBroker(vault, transit)
	payload, err := encryptForTransit(
		transit,
		[]byte(`{"token":"secret-token"}`),
		TransitAdditionalData(transit.PublicKey().KeyID, "github", "tenant-a", "runtime-a", "cerebro_vault"),
	)
	if err != nil {
		t.Fatalf("encryptForTransit() error = %v", err)
	}
	result, err := broker.StoreEncrypted(context.Background(), StoreEncryptedRequest{
		SourceID:             "github",
		TenantID:             "tenant-a",
		RuntimeID:            "runtime-a",
		CredentialStoreID:    "cerebro_vault",
		Actor:                "alice",
		IdempotencyKey:       "request-1",
		EncryptedCredentials: payload,
	})
	if err != nil {
		t.Fatalf("StoreEncrypted() error = %v", err)
	}
	if result.Created {
		t.Fatal("StoreEncrypted() Created = true, want replayed result")
	}
	if result.Record == nil || result.Record.ID != winner.ID {
		t.Fatalf("StoreEncrypted() record ID = %v, want %s", result.Record, winner.ID)
	}
	if got := result.References["token"]; got != Reference(winner.ID, "token") {
		t.Fatalf("replayed token reference = %q, want %q", got, Reference(winner.ID, "token"))
	}
	if got := len(store.audit); got != 0 {
		t.Fatalf("audit rows after replay = %d, want 0", got)
	}
}

func TestBrokerResolveReferencesThrottlesUsedAudit(t *testing.T) {
	store := &memoryStore{}
	vault, err := NewVault(store, "test-vault-key")
	if err != nil {
		t.Fatalf("NewVault() error = %v", err)
	}
	broker := NewBroker(vault, nil)
	record, err := vault.Put(context.Background(), PlainCredential{
		TenantID:  "tenant-a",
		SourceID:  "github",
		RuntimeID: "runtime-a",
		Fields:    map[string]string{"token": "secret-token"},
	})
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	values := map[string]string{
		"token":      Reference(record.ID, "token"),
		"token_copy": Reference(record.ID, "token"),
	}
	if _, err := broker.ResolveReferences(context.Background(), "github", "tenant-a", "runtime-a", values); err != nil {
		t.Fatalf("ResolveReferences() error = %v", err)
	}
	if got := len(store.audit); got != 1 {
		t.Fatalf("used audit count after first resolve = %d, want 1", got)
	}
	if store.metadataUpdates != 1 {
		t.Fatalf("metadata updates after first resolve = %d, want 1", store.metadataUpdates)
	}
	lastUsedAt := store.records[record.ID].LastUsedAt
	if lastUsedAt.IsZero() {
		t.Fatal("last_used_at was not recorded on first broker resolve")
	}
	if _, err := broker.ResolveReferences(context.Background(), "github", "tenant-a", "runtime-a", values); err != nil {
		t.Fatalf("second ResolveReferences() error = %v", err)
	}
	if got := len(store.audit); got != 1 {
		t.Fatalf("used audit count after throttled resolve = %d, want 1", got)
	}
	if store.metadataUpdates != 1 {
		t.Fatalf("metadata updates after throttled resolve = %d, want 1", store.metadataUpdates)
	}
	if got := store.records[record.ID].LastUsedAt; !got.Equal(lastUsedAt) {
		t.Fatalf("throttled resolve changed last_used_at = %s, want %s", got, lastUsedAt)
	}
	store.records[record.ID].LastUsedAt = time.Now().UTC().Add(-credentialUseTrackingInterval - time.Minute)
	if _, err := broker.ResolveReferences(context.Background(), "github", "tenant-a", "runtime-a", map[string]string{"missing": Reference(record.ID, "missing")}); err == nil {
		t.Fatal("missing field ResolveReferences() error = nil, want error")
	}
	if got := len(store.audit); got != 1 {
		t.Fatalf("used audit count after failed resolve = %d, want 1", got)
	}
	if store.metadataUpdates != 1 {
		t.Fatalf("metadata updates after failed resolve = %d, want 1", store.metadataUpdates)
	}
	if _, err := broker.ResolveReferences(context.Background(), "github", "tenant-a", "runtime-a", values); err != nil {
		t.Fatalf("stale ResolveReferences() error = %v", err)
	}
	if got := len(store.audit); got != 2 {
		t.Fatalf("used audit count after stale resolve = %d, want 2", got)
	}
	if store.metadataUpdates != 2 {
		t.Fatalf("metadata updates after stale resolve = %d, want 2", store.metadataUpdates)
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
