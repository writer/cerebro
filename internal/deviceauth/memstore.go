package deviceauth

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"time"
)

// MemStore is an in-memory [Store] implementation used for unit tests and as
// a reference for the persistence contract. It is not suitable for
// production: the bootstrap binary is required to use a real driver per
// docs/engineering/non-goals.md.
type MemStore struct {
	mu                        sync.Mutex
	devices                   map[string]DeviceRecord
	bootstrapTokens           map[[32]byte]BootstrapToken
	refreshTokens             map[[32]byte]RefreshToken
	refreshByFamily           map[string]map[[32]byte]struct{}
	idempotency               map[string]idempotencyEntry
	now                       func() time.Time
	createBootstrapTokenFault error
}

type idempotencyEntry struct {
	requestHash [32]byte
	status      int
	body        []byte
	expiresAt   time.Time
}

// NewMemStore returns a freshly initialized in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{
		devices:         make(map[string]DeviceRecord),
		bootstrapTokens: make(map[[32]byte]BootstrapToken),
		refreshTokens:   make(map[[32]byte]RefreshToken),
		refreshByFamily: make(map[string]map[[32]byte]struct{}),
		idempotency:     make(map[string]idempotencyEntry),
		now:             time.Now,
	}
}

// SetClock overrides the in-memory store's wall clock for tests.
func (s *MemStore) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now == nil {
		now = time.Now
	}
	s.now = now
}

// EnrollDevice inserts or replaces the device row.
func (s *MemStore) EnrollDevice(_ context.Context, device DeviceRecord) (DeviceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[device.DeviceID] = device
	return device, nil
}

// LookupDevice returns the device by id or [ErrDeviceNotFound].
func (s *MemStore) LookupDevice(_ context.Context, deviceID string) (DeviceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	device, ok := s.devices[deviceID]
	if !ok {
		return DeviceRecord{}, ErrDeviceNotFound
	}
	return device, nil
}

// LookupDeviceByHardware returns the device by tenant and hardware UUID.
func (s *MemStore) LookupDeviceByHardware(_ context.Context, tenantID string, hardwareUUID string) (DeviceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tenantID = strings.TrimSpace(tenantID)
	hardwareUUID = strings.TrimSpace(hardwareUUID)
	for _, device := range s.devices {
		if strings.TrimSpace(device.TenantID) == tenantID && strings.TrimSpace(device.HardwareUUID) == hardwareUUID {
			return device, nil
		}
	}
	return DeviceRecord{}, ErrDeviceNotFound
}

// MarkSeen updates last_seen_at on the device row.
func (s *MemStore) MarkSeen(_ context.Context, deviceID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	device, ok := s.devices[deviceID]
	if !ok {
		return ErrDeviceNotFound
	}
	device.LastSeenAt = at.UTC()
	s.devices[deviceID] = device
	return nil
}

// RevokeDevice flips the device status and records the revoke time.
func (s *MemStore) RevokeDevice(_ context.Context, deviceID string, at time.Time, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	device, ok := s.devices[deviceID]
	if !ok {
		return ErrDeviceNotFound
	}
	device.Status = "revoked"
	device.RevokedAt = at.UTC()
	s.devices[deviceID] = device
	return nil
}

// SetCreateBootstrapTokenFault is a test seam: when set, the next
// (and every subsequent) call to CreateBootstrapToken returns the
// supplied error WITHOUT mutating the store. Used to assert callers
// emit audit events only AFTER the durable write succeeds.
func (s *MemStore) SetCreateBootstrapTokenFault(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.createBootstrapTokenFault = err
}

// CreateBootstrapToken inserts a new bootstrap token row.
func (s *MemStore) CreateBootstrapToken(_ context.Context, token BootstrapToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.createBootstrapTokenFault != nil {
		return s.createBootstrapTokenFault
	}
	s.bootstrapTokens[token.TokenHash] = token
	return nil
}

// ConsumeBootstrapToken atomically validates and consumes a bootstrap token.
func (s *MemStore) ConsumeBootstrapToken(_ context.Context, hash [32]byte, hardwareUUID string, at time.Time, by string) (BootstrapToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.bootstrapTokens[hash]
	if !ok {
		return BootstrapToken{}, ErrBootstrapTokenNotFound
	}
	if !token.ConsumedAt.IsZero() {
		return BootstrapToken{}, ErrBootstrapTokenConsumed
	}
	if !token.ExpiresAt.IsZero() && at.After(token.ExpiresAt) {
		return BootstrapToken{}, ErrBootstrapTokenExpired
	}
	if token.HardwareUUID != "" && token.HardwareUUID != hardwareUUID {
		return BootstrapToken{}, ErrBootstrapTokenMismatch
	}
	consumed := token
	consumed.ConsumedAt = at.UTC()
	consumed.ConsumedBy = by
	s.bootstrapTokens[hash] = consumed
	return token, nil
}

// IssueRefreshToken inserts a new refresh-token row.
func (s *MemStore) IssueRefreshToken(_ context.Context, token RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshTokens[token.TokenHash] = token
	if _, ok := s.refreshByFamily[token.FamilyID]; !ok {
		s.refreshByFamily[token.FamilyID] = make(map[[32]byte]struct{})
	}
	s.refreshByFamily[token.FamilyID][token.TokenHash] = struct{}{}
	return nil
}

// LookupRefreshToken returns refresh-token metadata without consuming it.
func (s *MemStore) LookupRefreshToken(_ context.Context, hash [32]byte, at time.Time) (RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.refreshTokens[hash]
	if !ok {
		return RefreshToken{}, ErrRefreshNotFound
	}
	if token.FamilyRevoked {
		return token, nil
	}
	if !token.ExpiresAt.IsZero() && at.After(token.ExpiresAt) {
		return RefreshToken{}, ErrRefreshExpired
	}
	return token, nil
}

// ConsumeRefreshToken atomically consumes (or replay-revokes) a refresh token.
func (s *MemStore) ConsumeRefreshToken(_ context.Context, hash [32]byte, at time.Time) (RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.refreshTokens[hash]
	if !ok {
		return RefreshToken{}, ErrRefreshNotFound
	}
	if token.FamilyRevoked {
		return RefreshToken{}, ErrRefreshReplay
	}
	if !token.ConsumedAt.IsZero() {
		s.revokeFamilyLocked(token.FamilyID)
		return RefreshToken{}, ErrRefreshReplay
	}
	if !token.ExpiresAt.IsZero() && at.After(token.ExpiresAt) {
		return RefreshToken{}, ErrRefreshExpired
	}
	device, ok := s.devices[token.DeviceID]
	if !ok {
		return RefreshToken{}, ErrDeviceNotFound
	}
	if device.Status != "" && device.Status != "active" {
		return RefreshToken{}, ErrDeviceInactive
	}
	consumed := token
	consumed.ConsumedAt = at.UTC()
	consumed.Superseded = true
	s.refreshTokens[hash] = consumed
	return token, nil
}

// RevokeRefreshFamily marks every refresh token in the family as revoked.
func (s *MemStore) RevokeRefreshFamily(_ context.Context, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokeFamilyLocked(familyID)
	return nil
}

func (s *MemStore) nowLocked() time.Time {
	if s.now == nil {
		return time.Now()
	}
	return s.now()
}

func (s *MemStore) revokeFamilyLocked(familyID string) {
	hashes, ok := s.refreshByFamily[familyID]
	if !ok {
		return
	}
	for hash := range hashes {
		token := s.refreshTokens[hash]
		token.FamilyRevoked = true
		s.refreshTokens[hash] = token
	}
}

// CheckIdempotency returns a cached response if one exists and the request
// hash matches. A hash mismatch returns [ErrIdempotencyConflict].
func (s *MemStore) CheckIdempotency(_ context.Context, key string, requestHash [32]byte) ([]byte, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.idempotency[key]
	if !ok {
		return nil, 0, nil
	}
	if !entry.expiresAt.IsZero() && s.nowLocked().After(entry.expiresAt) {
		delete(s.idempotency, key)
		return nil, 0, nil
	}
	if !bytes.Equal(entry.requestHash[:], requestHash[:]) {
		return nil, 0, ErrIdempotencyConflict
	}
	out := make([]byte, len(entry.body))
	copy(out, entry.body)
	return out, entry.status, nil
}

// PutIdempotency caches a response under the given idempotency key.
func (s *MemStore) PutIdempotency(_ context.Context, key string, requestHash [32]byte, status int, body []byte, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored := make([]byte, len(body))
	copy(stored, body)
	s.idempotency[key] = idempotencyEntry{
		requestHash: requestHash,
		status:      status,
		body:        stored,
		expiresAt:   expiresAt.UTC(),
	}
	return nil
}
