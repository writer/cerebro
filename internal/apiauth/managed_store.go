package apiauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const managedCredentialSecretPrefix = "csk_"

type ManagedCredentialSpec struct {
	ID              string
	Name            string
	UserID          string
	Kind            string
	Surface         string
	ClientID        string
	Scopes          []string
	RateLimitBucket string
	TenantID        string
	Metadata        map[string]string
	ExpiresAt       *time.Time
}

type ManagedCredentialRecord struct {
	Credential       Credential        `json:"credential"`
	SecretHash       string            `json:"secret_hash"`
	SecretPrefix     string            `json:"secret_prefix"`
	CreatedAt        time.Time         `json:"created_at"`
	RotatedAt        *time.Time        `json:"rotated_at,omitempty"`
	RevokedAt        *time.Time        `json:"revoked_at,omitempty"`
	ExpiresAt        *time.Time        `json:"expires_at,omitempty"`
	RevocationReason string            `json:"revocation_reason,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

type managedCredentialState struct {
	APIVersion  string                    `json:"api_version"`
	GeneratedAt time.Time                 `json:"generated_at"`
	Credentials []ManagedCredentialRecord `json:"credentials"`
}

type ManagedCredentialStore struct {
	path    string
	mu      sync.RWMutex
	records map[string]ManagedCredentialRecord
}

func NewManagedCredentialStore(path string) *ManagedCredentialStore {
	return &ManagedCredentialStore{
		path:    strings.TrimSpace(path),
		records: make(map[string]ManagedCredentialRecord),
	}
}

func (s *ManagedCredentialStore) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

func (s *ManagedCredentialStore) Load() error {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return nil
	}
	payload, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read managed credential state: %w", err)
	}
	var state managedCredentialState
	if err := json.Unmarshal(payload, &state); err != nil {
		return fmt.Errorf("decode managed credential state: %w", err)
	}
	records := make(map[string]ManagedCredentialRecord, len(state.Credentials))
	for _, record := range state.Credentials {
		record = normalizeManagedCredentialRecord(record)
		if strings.TrimSpace(record.Credential.ID) == "" {
			return fmt.Errorf("managed credential state contains record without credential id")
		}
		records[record.Credential.ID] = record
	}
	s.mu.Lock()
	s.records = records
	s.mu.Unlock()
	return nil
}

func (s *ManagedCredentialStore) Lookup(key string) (Credential, bool) {
	if s == nil {
		return Credential{}, false
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return Credential{}, false
	}
	hash := credentialSecretHash(key)
	now := time.Now().UTC()

	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, record := range s.records {
		if !record.Credential.Enabled || record.RevokedAt != nil {
			continue
		}
		if record.ExpiresAt != nil && !record.ExpiresAt.IsZero() && now.After(record.ExpiresAt.UTC()) {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(record.SecretHash), []byte(hash)) != 1 {
			continue
		}
		return cloneManagedCredentialRecord(record).Credential, true
	}
	return Credential{}, false
}

func (s *ManagedCredentialStore) List() []ManagedCredentialRecord {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	records := make([]ManagedCredentialRecord, 0, len(s.records))
	for _, record := range s.records {
		records = append(records, cloneManagedCredentialRecord(record))
	}
	sort.Slice(records, func(i, j int) bool {
		left := strings.TrimSpace(records[i].Credential.ID)
		right := strings.TrimSpace(records[j].Credential.ID)
		if left == right {
			return records[i].CreatedAt.Before(records[j].CreatedAt)
		}
		return left < right
	})
	return records
}

func (s *ManagedCredentialStore) Get(id string) (ManagedCredentialRecord, bool) {
	if s == nil {
		return ManagedCredentialRecord{}, false
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return ManagedCredentialRecord{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[id]
	if !ok {
		return ManagedCredentialRecord{}, false
	}
	return cloneManagedCredentialRecord(record), true
}

func (s *ManagedCredentialStore) Create(spec ManagedCredentialSpec, now time.Time) (ManagedCredentialRecord, string, error) {
	if s == nil {
		return ManagedCredentialRecord{}, "", fmt.Errorf("managed credential store is nil")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	secret, err := newManagedCredentialSecret()
	if err != nil {
		return ManagedCredentialRecord{}, "", err
	}
	record := ManagedCredentialRecord{
		Credential: buildManagedCredential(spec, now),
		SecretHash: credentialSecretHash(secret),
		CreatedAt:  now.UTC(),
		ExpiresAt:  cloneTimePtr(spec.ExpiresAt),
		Metadata:   cloneStringMap(spec.Metadata),
	}
	record.SecretPrefix = secretPreview(secret)
	record = normalizeManagedCredentialRecord(record)

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[record.Credential.ID]; ok {
		return ManagedCredentialRecord{}, "", fmt.Errorf("managed credential %q already exists", record.Credential.ID)
	}
	s.records[record.Credential.ID] = record
	if err := s.persistLocked(); err != nil {
		delete(s.records, record.Credential.ID)
		return ManagedCredentialRecord{}, "", err
	}
	return cloneManagedCredentialRecord(record), secret, nil
}

func (s *ManagedCredentialStore) Rotate(id string, now time.Time) (ManagedCredentialRecord, string, error) {
	if s == nil {
		return ManagedCredentialRecord{}, "", fmt.Errorf("managed credential store is nil")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return ManagedCredentialRecord{}, "", fmt.Errorf("credential id is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	secret, err := newManagedCredentialSecret()
	if err != nil {
		return ManagedCredentialRecord{}, "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return ManagedCredentialRecord{}, "", fmt.Errorf("managed credential %q not found", id)
	}
	if record.RevokedAt != nil {
		return ManagedCredentialRecord{}, "", fmt.Errorf("managed credential %q is revoked", id)
	}
	previous := cloneManagedCredentialRecord(record)
	record.SecretHash = credentialSecretHash(secret)
	record.SecretPrefix = secretPreview(secret)
	record.Credential.Enabled = true
	rotatedAt := now.UTC()
	record.RotatedAt = &rotatedAt
	record = normalizeManagedCredentialRecord(record)
	s.records[id] = record
	if err := s.persistLocked(); err != nil {
		s.records[id] = previous
		return ManagedCredentialRecord{}, "", err
	}
	return cloneManagedCredentialRecord(record), secret, nil
}

func (s *ManagedCredentialStore) Revoke(id string, reason string, now time.Time) (ManagedCredentialRecord, error) {
	if s == nil {
		return ManagedCredentialRecord{}, fmt.Errorf("managed credential store is nil")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return ManagedCredentialRecord{}, fmt.Errorf("credential id is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return ManagedCredentialRecord{}, fmt.Errorf("managed credential %q not found", id)
	}
	if record.RevokedAt != nil {
		return cloneManagedCredentialRecord(record), nil
	}
	previous := cloneManagedCredentialRecord(record)
	revokedAt := now.UTC()
	record.RevokedAt = &revokedAt
	record.RevocationReason = strings.TrimSpace(reason)
	record.Credential.Enabled = false
	record = normalizeManagedCredentialRecord(record)
	s.records[id] = record
	if err := s.persistLocked(); err != nil {
		s.records[id] = previous
		return ManagedCredentialRecord{}, err
	}
	return cloneManagedCredentialRecord(record), nil
}

func (s *ManagedCredentialStore) persistLocked() error {
	if strings.TrimSpace(s.path) == "" {
		return nil
	}
	state := managedCredentialState{
		APIVersion:  "cerebro.api_credentials/v1alpha1",
		GeneratedAt: time.Now().UTC(),
		Credentials: make([]ManagedCredentialRecord, 0, len(s.records)),
	}
	for _, record := range s.records {
		state.Credentials = append(state.Credentials, cloneManagedCredentialRecord(record))
	}
	sort.Slice(state.Credentials, func(i, j int) bool {
		return strings.TrimSpace(state.Credentials[i].Credential.ID) < strings.TrimSpace(state.Credentials[j].Credential.ID)
	})
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal managed credential state: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create managed credential state dir: %w", err)
	}
	tempFile := s.path + ".tmp"
	if err := os.WriteFile(tempFile, append(payload, '\n'), 0o600); err != nil {
		return fmt.Errorf("write managed credential state temp file: %w", err)
	}
	if err := os.Rename(tempFile, s.path); err != nil {
		_ = os.Remove(tempFile)
		return fmt.Errorf("replace managed credential state: %w", err)
	}
	return nil
}

func buildManagedCredential(spec ManagedCredentialSpec, now time.Time) Credential {
	id := strings.TrimSpace(spec.ID)
	if id == "" {
		id = "cred-" + uuid.NewString()
	}
	name := strings.TrimSpace(spec.Name)
	if name == "" {
		name = id
	}
	userID := strings.TrimSpace(spec.UserID)
	if userID == "" {
		userID = "sdk-client-" + strings.TrimPrefix(id, "cred-")
	}
	kind := strings.TrimSpace(spec.Kind)
	if kind == "" {
		kind = "sdk_api_key"
	}
	surface := strings.TrimSpace(spec.Surface)
	if surface == "" {
		surface = "agent_sdk"
	}
	metadata := cloneStringMap(spec.Metadata)
	if metadata == nil {
		metadata = make(map[string]string)
	}
	metadata["managed"] = "true"
	metadata["created_at"] = now.UTC().Format(time.RFC3339)

	credential := Credential{
		ID:              id,
		Name:            name,
		UserID:          userID,
		Kind:            kind,
		Surface:         surface,
		ClientID:        strings.TrimSpace(spec.ClientID),
		Scopes:          normalizeScopes(spec.Scopes),
		RateLimitBucket: strings.TrimSpace(spec.RateLimitBucket),
		TenantID:        strings.TrimSpace(spec.TenantID),
		Enabled:         true,
		Metadata:        metadata,
	}
	if credential.ClientID == "" {
		credential.ClientID = "sdk-client-" + strings.TrimPrefix(id, "cred-")
	}
	if credential.RateLimitBucket == "" {
		credential.RateLimitBucket = credential.ID
	}
	return credential
}

func cloneManagedCredentialRecord(record ManagedCredentialRecord) ManagedCredentialRecord {
	record.Credential.Metadata = cloneStringMap(record.Credential.Metadata)
	record.Credential.Scopes = append([]string(nil), record.Credential.Scopes...)
	record.RotatedAt = cloneTimePtr(record.RotatedAt)
	record.RevokedAt = cloneTimePtr(record.RevokedAt)
	record.ExpiresAt = cloneTimePtr(record.ExpiresAt)
	record.Metadata = cloneStringMap(record.Metadata)
	return record
}

func normalizeManagedCredentialRecord(record ManagedCredentialRecord) ManagedCredentialRecord {
	record.Credential.Name = strings.TrimSpace(record.Credential.Name)
	record.Credential.Kind = strings.TrimSpace(record.Credential.Kind)
	record.Credential.Surface = strings.TrimSpace(record.Credential.Surface)
	record.Credential.ClientID = strings.TrimSpace(record.Credential.ClientID)
	record.Credential.RateLimitBucket = strings.TrimSpace(record.Credential.RateLimitBucket)
	record.Credential.TenantID = strings.TrimSpace(record.Credential.TenantID)
	record.Credential.UserID = strings.TrimSpace(record.Credential.UserID)
	record.Credential.Metadata = cloneStringMap(record.Credential.Metadata)
	record.Credential.Scopes = normalizeScopes(record.Credential.Scopes)
	record.SecretHash = strings.TrimSpace(record.SecretHash)
	record.SecretPrefix = strings.TrimSpace(record.SecretPrefix)
	record.RevocationReason = strings.TrimSpace(record.RevocationReason)
	record.Metadata = cloneStringMap(record.Metadata)
	record.CreatedAt = record.CreatedAt.UTC()
	if record.RotatedAt != nil {
		rotatedAt := record.RotatedAt.UTC()
		record.RotatedAt = &rotatedAt
	}
	if record.RevokedAt != nil {
		revokedAt := record.RevokedAt.UTC()
		record.RevokedAt = &revokedAt
	}
	if record.ExpiresAt != nil {
		expiresAt := record.ExpiresAt.UTC()
		record.ExpiresAt = &expiresAt
	}
	return record
}

func newManagedCredentialSecret() (string, error) {
	randomBytes := make([]byte, 24)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generate managed credential secret: %w", err)
	}
	return managedCredentialSecretPrefix + hex.EncodeToString(randomBytes), nil
}

func credentialSecretHash(secret string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(secret)))
	return hex.EncodeToString(sum[:])
}

func secretPreview(secret string) string {
	secret = strings.TrimSpace(secret)
	if len(secret) <= 10 {
		return secret
	}
	return secret[:10]
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := value.UTC()
	return &cloned
}
