package deviceauth

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

// DeviceRecord represents an enrolled device in the system.
type DeviceRecord struct {
	DeviceID     string            `json:"device_id"`
	HardwareUUID string           `json:"hardware_uuid"`
	SerialNumber string            `json:"serial_number"`
	Hostname     string            `json:"hostname"`
	OrgID        string            `json:"org_id"`
	OSType       string            `json:"os_type"`
	AgentVersion string            `json:"agent_version"`
	Status       string            `json:"status"`
	EnrolledAt   time.Time         `json:"enrolled_at"`
	LastSeen     time.Time         `json:"last_seen"`
	RevokedAt    *time.Time        `json:"revoked_at,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// BootstrapToken represents a single-use, time-bound token provisioned via MDM.
type BootstrapToken struct {
	TokenID      string            `json:"token_id"`
	TokenHash    string            `json:"token_hash"`
	HardwareUUID string           `json:"hardware_uuid"`
	OrgID        string            `json:"org_id"`
	CreatedAt    time.Time         `json:"created_at"`
	ExpiresAt    time.Time         `json:"expires_at"`
	ConsumedAt   *time.Time        `json:"consumed_at,omitempty"`
	ConsumedBy   string            `json:"consumed_by,omitempty"`
	Scopes       []string          `json:"scopes,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// RefreshTokenRecord tracks a single-use refresh token with family-based
// replay detection.
type RefreshTokenRecord struct {
	TokenHash  string     `json:"token_hash"`
	DeviceID   string     `json:"device_id"`
	FamilyID   string     `json:"family_id"`
	Generation int        `json:"generation"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	Consumed   bool       `json:"consumed"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
	Superseded bool       `json:"superseded"`
}

// BootstrapTokenSpec is the input for creating a new bootstrap token.
type BootstrapTokenSpec struct {
	HardwareUUID string
	OrgID        string
	ExpiresAt    time.Time
	Scopes       []string
	Metadata     map[string]string
}

// DeviceSpec is the input for registering a new device.
type DeviceSpec struct {
	HardwareUUID string
	SerialNumber string
	Hostname     string
	OrgID        string
	OSType       string
	AgentVersion string
	Metadata     map[string]string
}

type storeState struct {
	APIVersion      string               `json:"api_version"`
	GeneratedAt     time.Time            `json:"generated_at"`
	Devices         []DeviceRecord       `json:"devices"`
	BootstrapTokens []BootstrapToken     `json:"bootstrap_tokens"`
	RefreshTokens   []RefreshTokenRecord `json:"refresh_tokens"`
}

// Store is a file-backed device authentication store with mutex-protected
// concurrent access. It mirrors the ManagedCredentialStore pattern found
// in internal/apiauth.
type Store struct {
	path          string
	mu            sync.RWMutex
	devices       map[string]DeviceRecord       // device_id -> record
	bootstraps    map[string]BootstrapToken      // token_id -> record
	refreshTokens map[string]RefreshTokenRecord  // token_hash -> record
}

// NewStore creates a new device auth store backed by the given file path.
func NewStore(path string) *Store {
	return &Store{
		path:          strings.TrimSpace(path),
		devices:       make(map[string]DeviceRecord),
		bootstraps:    make(map[string]BootstrapToken),
		refreshTokens: make(map[string]RefreshTokenRecord),
	}
}

// Path returns the backing file path.
func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Load reads persisted state from the backing file.
func (s *Store) Load() error {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return nil
	}
	payload, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read device auth state: %w", err)
	}
	var state storeState
	if err := json.Unmarshal(payload, &state); err != nil {
		return fmt.Errorf("decode device auth state: %w", err)
	}

	devices := make(map[string]DeviceRecord, len(state.Devices))
	for _, d := range state.Devices {
		if strings.TrimSpace(d.DeviceID) == "" {
			return fmt.Errorf("device auth state contains record without device id")
		}
		devices[d.DeviceID] = d
	}
	bootstraps := make(map[string]BootstrapToken, len(state.BootstrapTokens))
	for _, b := range state.BootstrapTokens {
		if strings.TrimSpace(b.TokenID) == "" {
			return fmt.Errorf("device auth state contains bootstrap token without id")
		}
		bootstraps[b.TokenID] = b
	}
	refreshTokens := make(map[string]RefreshTokenRecord, len(state.RefreshTokens))
	for _, r := range state.RefreshTokens {
		if strings.TrimSpace(r.TokenHash) == "" {
			continue
		}
		refreshTokens[r.TokenHash] = r
	}

	s.mu.Lock()
	s.devices = devices
	s.bootstraps = bootstraps
	s.refreshTokens = refreshTokens
	s.mu.Unlock()
	return nil
}

// CreateBootstrapToken generates a cryptographically random bootstrap token,
// stores only its SHA-256 hash, and returns both the record and the plaintext
// token. The plaintext must be delivered to the MDM system and is never stored.
func (s *Store) CreateBootstrapToken(spec BootstrapTokenSpec) (BootstrapToken, string, error) {
	if s == nil {
		return BootstrapToken{}, "", fmt.Errorf("device auth store is nil")
	}

	rawToken, err := generateSecureToken(32)
	if err != nil {
		return BootstrapToken{}, "", fmt.Errorf("generate bootstrap token: %w", err)
	}

	now := time.Now().UTC()
	expiresAt := spec.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = now.Add(72 * time.Hour)
	}

	record := BootstrapToken{
		TokenID:      "bt-" + uuid.NewString(),
		TokenHash:    tokenHash(rawToken),
		HardwareUUID: strings.TrimSpace(spec.HardwareUUID),
		OrgID:        strings.TrimSpace(spec.OrgID),
		CreatedAt:    now,
		ExpiresAt:    expiresAt.UTC(),
		Scopes:       cloneScopes(spec.Scopes),
		Metadata:     cloneStringMap(spec.Metadata),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.bootstraps[record.TokenID] = record
	if err := s.persistLocked(); err != nil {
		delete(s.bootstraps, record.TokenID)
		return BootstrapToken{}, "", err
	}
	return cloneBootstrapToken(record), rawToken, nil
}

// ConsumeBootstrapToken validates and consumes a bootstrap token. It verifies
// that the token exists, has not expired, has not already been consumed, and
// that the hardware UUID matches the expected value. The token hash is compared
// in constant time.
func (s *Store) ConsumeBootstrapToken(rawToken string, hardwareUUID string) (BootstrapToken, error) {
	if s == nil {
		return BootstrapToken{}, fmt.Errorf("device auth store is nil")
	}
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return BootstrapToken{}, fmt.Errorf("bootstrap token is required")
	}
	hardwareUUID = strings.TrimSpace(hardwareUUID)
	if hardwareUUID == "" {
		return BootstrapToken{}, fmt.Errorf("hardware uuid is required")
	}

	hash := tokenHash(rawToken)
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	var matched *BootstrapToken
	for id, bt := range s.bootstraps {
		if subtle.ConstantTimeCompare([]byte(bt.TokenHash), []byte(hash)) == 1 {
			copy := bt
			copy.TokenID = id
			matched = &copy
			break
		}
	}
	if matched == nil {
		return BootstrapToken{}, fmt.Errorf("invalid bootstrap token")
	}
	if matched.ConsumedAt != nil {
		return BootstrapToken{}, fmt.Errorf("bootstrap token already consumed")
	}
	if now.After(matched.ExpiresAt) {
		return BootstrapToken{}, fmt.Errorf("bootstrap token expired")
	}
	if subtle.ConstantTimeCompare([]byte(matched.HardwareUUID), []byte(hardwareUUID)) != 1 {
		return BootstrapToken{}, fmt.Errorf("hardware uuid mismatch")
	}

	consumed := now
	matched.ConsumedAt = &consumed
	s.bootstraps[matched.TokenID] = *matched
	if err := s.persistLocked(); err != nil {
		matched.ConsumedAt = nil
		s.bootstraps[matched.TokenID] = *matched
		return BootstrapToken{}, err
	}
	return cloneBootstrapToken(*matched), nil
}

// MarkBootstrapTokenConsumedBy sets the consumed_by field on a previously
// consumed bootstrap token. Call this after the device has been registered.
func (s *Store) MarkBootstrapTokenConsumedBy(tokenID, deviceID string) error {
	if s == nil {
		return fmt.Errorf("device auth store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	bt, ok := s.bootstraps[tokenID]
	if !ok {
		return fmt.Errorf("bootstrap token %q not found", tokenID)
	}
	bt.ConsumedBy = deviceID
	s.bootstraps[tokenID] = bt
	return s.persistLocked()
}

// RevokeBootstrapToken marks an unconsumed bootstrap token as consumed so
// it can no longer be used.
func (s *Store) RevokeBootstrapToken(tokenID string) error {
	if s == nil {
		return fmt.Errorf("device auth store is nil")
	}
	tokenID = strings.TrimSpace(tokenID)
	if tokenID == "" {
		return fmt.Errorf("token id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	bt, ok := s.bootstraps[tokenID]
	if !ok {
		return fmt.Errorf("bootstrap token %q not found", tokenID)
	}
	if bt.ConsumedAt != nil {
		return nil // already consumed/revoked
	}
	now := time.Now().UTC()
	bt.ConsumedAt = &now
	bt.ConsumedBy = "admin:revoked"
	s.bootstraps[tokenID] = bt
	return s.persistLocked()
}

// RegisterDevice creates a new device record in the store.
func (s *Store) RegisterDevice(spec DeviceSpec) (DeviceRecord, error) {
	if s == nil {
		return DeviceRecord{}, fmt.Errorf("device auth store is nil")
	}

	now := time.Now().UTC()
	record := DeviceRecord{
		DeviceID:     "dev-" + uuid.NewString(),
		HardwareUUID: strings.TrimSpace(spec.HardwareUUID),
		SerialNumber: strings.TrimSpace(spec.SerialNumber),
		Hostname:     strings.TrimSpace(spec.Hostname),
		OrgID:        strings.TrimSpace(spec.OrgID),
		OSType:       strings.TrimSpace(spec.OSType),
		AgentVersion: strings.TrimSpace(spec.AgentVersion),
		Status:       "active",
		EnrolledAt:   now,
		LastSeen:     now,
		Metadata:     cloneStringMap(spec.Metadata),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[record.DeviceID] = record
	if err := s.persistLocked(); err != nil {
		delete(s.devices, record.DeviceID)
		return DeviceRecord{}, err
	}
	return cloneDeviceRecord(record), nil
}

// GetDevice returns a device record by ID.
func (s *Store) GetDevice(deviceID string) (DeviceRecord, bool) {
	if s == nil {
		return DeviceRecord{}, false
	}
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return DeviceRecord{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.devices[deviceID]
	if !ok {
		return DeviceRecord{}, false
	}
	return cloneDeviceRecord(record), true
}

// GetDeviceByHardwareUUID returns the first active device matching the given
// hardware UUID.
func (s *Store) GetDeviceByHardwareUUID(hwUUID string) (DeviceRecord, bool) {
	if s == nil {
		return DeviceRecord{}, false
	}
	hwUUID = strings.TrimSpace(hwUUID)
	if hwUUID == "" {
		return DeviceRecord{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, record := range s.devices {
		if record.HardwareUUID == hwUUID {
			return cloneDeviceRecord(record), true
		}
	}
	return DeviceRecord{}, false
}

// ListDevices returns all device records sorted by device ID.
func (s *Store) ListDevices() []DeviceRecord {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	records := make([]DeviceRecord, 0, len(s.devices))
	for _, record := range s.devices {
		records = append(records, cloneDeviceRecord(record))
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].DeviceID < records[j].DeviceID
	})
	return records
}

// ListBootstrapTokens returns all bootstrap tokens sorted by token ID.
func (s *Store) ListBootstrapTokens() []BootstrapToken {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	tokens := make([]BootstrapToken, 0, len(s.bootstraps))
	for _, bt := range s.bootstraps {
		tokens = append(tokens, cloneBootstrapToken(bt))
	}
	sort.Slice(tokens, func(i, j int) bool {
		return tokens[i].TokenID < tokens[j].TokenID
	})
	return tokens
}

// RevokeDevice marks a device as revoked and revokes all of its refresh token
// families.
func (s *Store) RevokeDevice(deviceID, reason string) error {
	if s == nil {
		return fmt.Errorf("device auth store is nil")
	}
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return fmt.Errorf("device id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.devices[deviceID]
	if !ok {
		return fmt.Errorf("device %q not found", deviceID)
	}
	if record.Status == "revoked" {
		return nil
	}
	now := time.Now().UTC()
	record.Status = "revoked"
	record.RevokedAt = &now
	if meta := record.Metadata; meta != nil {
		meta["revocation_reason"] = strings.TrimSpace(reason)
	} else {
		record.Metadata = map[string]string{"revocation_reason": strings.TrimSpace(reason)}
	}
	s.devices[deviceID] = record

	// Revoke all refresh tokens belonging to this device.
	for hash, rt := range s.refreshTokens {
		if rt.DeviceID == deviceID && !rt.Consumed {
			rt.Consumed = true
			consumed := now
			rt.ConsumedAt = &consumed
			s.refreshTokens[hash] = rt
		}
	}
	return s.persistLocked()
}

// UpdateDeviceLastSeen updates the last_seen timestamp and agent version for
// a device.
func (s *Store) UpdateDeviceLastSeen(deviceID string, agentVersion string) error {
	if s == nil {
		return fmt.Errorf("device auth store is nil")
	}
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return fmt.Errorf("device id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.devices[deviceID]
	if !ok {
		return fmt.Errorf("device %q not found", deviceID)
	}
	record.LastSeen = time.Now().UTC()
	if v := strings.TrimSpace(agentVersion); v != "" {
		record.AgentVersion = v
	}
	s.devices[deviceID] = record
	return s.persistLocked()
}

// StoreRefreshToken persists a refresh token record (hash-only, no plaintext).
func (s *Store) StoreRefreshToken(record RefreshTokenRecord) error {
	if s == nil {
		return fmt.Errorf("device auth store is nil")
	}
	if strings.TrimSpace(record.TokenHash) == "" {
		return fmt.Errorf("refresh token hash is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshTokens[record.TokenHash] = record
	return s.persistLocked()
}

// ConsumeRefreshToken validates and consumes a refresh token. If a replay
// attack is detected (token already consumed), the entire token family is
// revoked and an error is returned.
func (s *Store) ConsumeRefreshToken(rawToken string) (RefreshTokenRecord, error) {
	if s == nil {
		return RefreshTokenRecord{}, fmt.Errorf("device auth store is nil")
	}
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return RefreshTokenRecord{}, fmt.Errorf("refresh token is required")
	}

	hash := tokenHash(rawToken)
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	var matched *RefreshTokenRecord
	var matchedHash string
	for h, rt := range s.refreshTokens {
		if subtle.ConstantTimeCompare([]byte(h), []byte(hash)) == 1 {
			copy := rt
			matchedHash = h
			matched = &copy
			break
		}
	}
	if matched == nil {
		return RefreshTokenRecord{}, fmt.Errorf("invalid refresh token")
	}

	// Replay detection: if the token was already consumed, revoke the
	// entire family to prevent further abuse.
	if matched.Consumed {
		s.revokeTokenFamilyLocked(matched.FamilyID)
		_ = s.persistLocked()
		return RefreshTokenRecord{}, fmt.Errorf("refresh token replay detected")
	}

	if now.After(matched.ExpiresAt) {
		return RefreshTokenRecord{}, fmt.Errorf("refresh token expired")
	}

	// Verify the device is still active.
	device, ok := s.devices[matched.DeviceID]
	if !ok {
		return RefreshTokenRecord{}, fmt.Errorf("device not found")
	}
	if device.Status != "active" {
		return RefreshTokenRecord{}, fmt.Errorf("device is %s", device.Status)
	}

	consumed := now
	matched.Consumed = true
	matched.ConsumedAt = &consumed
	s.refreshTokens[matchedHash] = *matched
	if err := s.persistLocked(); err != nil {
		matched.Consumed = false
		matched.ConsumedAt = nil
		s.refreshTokens[matchedHash] = *matched
		return RefreshTokenRecord{}, err
	}
	return cloneRefreshTokenRecord(*matched), nil
}

// RevokeTokenFamily marks all refresh tokens in a family as consumed.
func (s *Store) RevokeTokenFamily(familyID string) error {
	if s == nil {
		return fmt.Errorf("device auth store is nil")
	}
	familyID = strings.TrimSpace(familyID)
	if familyID == "" {
		return fmt.Errorf("family id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokeTokenFamilyLocked(familyID)
	return s.persistLocked()
}

func (s *Store) revokeTokenFamilyLocked(familyID string) {
	now := time.Now().UTC()
	for hash, rt := range s.refreshTokens {
		if rt.FamilyID == familyID && !rt.Consumed {
			rt.Consumed = true
			consumed := now
			rt.ConsumedAt = &consumed
			s.refreshTokens[hash] = rt
		}
	}
}

// CleanExpiredTokens removes expired bootstrap and refresh tokens from the
// store.
func (s *Store) CleanExpiredTokens() {
	if s == nil {
		return
	}
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	for id, bt := range s.bootstraps {
		if now.After(bt.ExpiresAt) && bt.ConsumedAt != nil {
			delete(s.bootstraps, id)
		}
	}
	for hash, rt := range s.refreshTokens {
		if now.After(rt.ExpiresAt) {
			delete(s.refreshTokens, hash)
		}
	}
	_ = s.persistLocked()
}

// persistLocked writes the current state to disk. The caller must hold s.mu.
func (s *Store) persistLocked() error {
	if strings.TrimSpace(s.path) == "" {
		return nil
	}
	state := storeState{
		APIVersion:      "cerebro.device_auth/v1alpha1",
		GeneratedAt:     time.Now().UTC(),
		Devices:         make([]DeviceRecord, 0, len(s.devices)),
		BootstrapTokens: make([]BootstrapToken, 0, len(s.bootstraps)),
		RefreshTokens:   make([]RefreshTokenRecord, 0, len(s.refreshTokens)),
	}
	for _, d := range s.devices {
		state.Devices = append(state.Devices, cloneDeviceRecord(d))
	}
	sort.Slice(state.Devices, func(i, j int) bool {
		return state.Devices[i].DeviceID < state.Devices[j].DeviceID
	})
	for _, b := range s.bootstraps {
		state.BootstrapTokens = append(state.BootstrapTokens, cloneBootstrapToken(b))
	}
	sort.Slice(state.BootstrapTokens, func(i, j int) bool {
		return state.BootstrapTokens[i].TokenID < state.BootstrapTokens[j].TokenID
	})
	for _, r := range s.refreshTokens {
		state.RefreshTokens = append(state.RefreshTokens, cloneRefreshTokenRecord(r))
	}
	sort.Slice(state.RefreshTokens, func(i, j int) bool {
		return state.RefreshTokens[i].TokenHash < state.RefreshTokens[j].TokenHash
	})

	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal device auth state: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create device auth state dir: %w", err)
	}
	tempFile := s.path + ".tmp"
	if err := os.WriteFile(tempFile, append(payload, '\n'), 0o600); err != nil {
		return fmt.Errorf("write device auth state temp file: %w", err)
	}
	if err := os.Rename(tempFile, s.path); err != nil {
		_ = os.Remove(tempFile)
		return fmt.Errorf("replace device auth state: %w", err)
	}
	return nil
}

// ---------- helpers ----------

func generateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate secure token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func tokenHash(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for k, v := range values {
		cloned[k] = v
	}
	return cloned
}

func cloneScopes(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := value.UTC()
	return &cloned
}

func cloneDeviceRecord(d DeviceRecord) DeviceRecord {
	d.Metadata = cloneStringMap(d.Metadata)
	d.RevokedAt = cloneTimePtr(d.RevokedAt)
	return d
}

func cloneBootstrapToken(b BootstrapToken) BootstrapToken {
	b.Scopes = cloneScopes(b.Scopes)
	b.Metadata = cloneStringMap(b.Metadata)
	b.ConsumedAt = cloneTimePtr(b.ConsumedAt)
	return b
}

func cloneRefreshTokenRecord(r RefreshTokenRecord) RefreshTokenRecord {
	r.ConsumedAt = cloneTimePtr(r.ConsumedAt)
	return r
}
