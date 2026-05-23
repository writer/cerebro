package deviceauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"time"
)

// DeviceRecord describes an enrolled SeCheck agent. The struct is the cross-
// driver representation; the Postgres driver maps it 1:1 to the
// device_records table.
type DeviceRecord struct {
	DeviceID     string
	HardwareUUID string
	SerialNumber string
	Hostname     string
	TenantID     string
	OSType       string
	OSVersion    string
	AgentVersion string
	Status       string
	EnrolledAt   time.Time
	LastSeenAt   time.Time
	RevokedAt    time.Time
	Metadata     map[string]string
}

// BootstrapToken represents a single-use, MDM-delivered enrollment credential.
// Only the SHA-256 hash is persisted in TokenHash; the plaintext token is
// known only to whoever generated it (and then to the agent).
type BootstrapToken struct {
	TokenID      string
	TokenHash    [32]byte
	HardwareUUID string
	TenantID     string
	Scopes       []string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	ConsumedAt   time.Time
	ConsumedBy   string
}

// RefreshToken tracks a single-use refresh-token row. Token plaintext lives
// only in memory long enough to return it to the agent. The persisted
// representation is the SHA-256 hash.
type RefreshToken struct {
	TokenHash     [32]byte
	DeviceID      string
	FamilyID      string
	Generation    int
	Scopes        []string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	ConsumedAt    time.Time
	FamilyRevoked bool
	Superseded    bool
}

// Store is the persistence boundary for device-auth state. Implementations
// must be transactional: ConsumeRefreshToken in particular MUST atomically
// match-by-hash, mark-consumed, and (on replay) revoke the family in a
// single serialized step.
type Store interface {
	// EnrollDevice inserts a new device row. If the (tenant_id, hardware_uuid)
	// already exists the implementation MAY replace the row and return the
	// existing device_id; the caller does not depend on a particular choice.
	EnrollDevice(ctx context.Context, device DeviceRecord) (DeviceRecord, error)
	// LookupDevice returns the device by id.
	LookupDevice(ctx context.Context, deviceID string) (DeviceRecord, error)
	// MarkSeen updates last_seen_at on the device row.
	MarkSeen(ctx context.Context, deviceID string, at time.Time) error
	// RevokeDevice flips status to revoked and records revoked_at.
	RevokeDevice(ctx context.Context, deviceID string, at time.Time, reason string) error

	// CreateBootstrapToken inserts a new bootstrap token row.
	CreateBootstrapToken(ctx context.Context, token BootstrapToken) error
	// ConsumeBootstrapToken atomically marks the token (matched by hash) as
	// consumed. It returns the token row as it was prior to the consume so
	// the caller can validate hardware_uuid, tenant_id, and scopes.
	ConsumeBootstrapToken(ctx context.Context, hash [32]byte, hardwareUUID string, at time.Time, by string) (BootstrapToken, error)

	// IssueRefreshToken inserts a new refresh-token row.
	IssueRefreshToken(ctx context.Context, token RefreshToken) error
	// ConsumeRefreshToken consumes a refresh token by hash, returning the
	// pre-consume row. If the token was already consumed, the implementation
	// MUST mark the entire family revoked and return [ErrRefreshReplay].
	ConsumeRefreshToken(ctx context.Context, hash [32]byte, at time.Time) (RefreshToken, error)
	// RevokeRefreshFamily marks every token in the given family as revoked.
	RevokeRefreshFamily(ctx context.Context, familyID string) error

	// CheckIdempotency returns the cached response for the given key if it
	// exists and the request hash matches. A hash mismatch returns
	// [ErrIdempotencyConflict]. A missing key returns ([]byte(nil), 0, nil).
	CheckIdempotency(ctx context.Context, key string, requestHash [32]byte) (responseBody []byte, responseStatus int, err error)
	// PutIdempotency caches a response for the given key with the given TTL.
	PutIdempotency(ctx context.Context, key string, requestHash [32]byte, status int, body []byte, expiresAt time.Time) error
}

// Typed store-level errors.
var (
	ErrDeviceNotFound         = errors.New("deviceauth: device not found")
	ErrDeviceInactive         = errors.New("deviceauth: device is not active")
	ErrBootstrapTokenNotFound = errors.New("deviceauth: bootstrap token not found")
	ErrBootstrapTokenConsumed = errors.New("deviceauth: bootstrap token already consumed")
	ErrBootstrapTokenExpired  = errors.New("deviceauth: bootstrap token expired")
	ErrBootstrapTokenMismatch = errors.New("deviceauth: bootstrap token hardware_uuid mismatch")
	ErrRefreshNotFound        = errors.New("deviceauth: refresh token not found")
	ErrRefreshReplay          = errors.New("deviceauth: refresh token replay detected")
	ErrRefreshExpired         = errors.New("deviceauth: refresh token expired")
	ErrIdempotencyConflict    = errors.New("deviceauth: idempotency-key request hash mismatch")
)

// HashToken returns the SHA-256 digest of the given plaintext token.
func HashToken(token string) [32]byte {
	return sha256.Sum256([]byte(strings.TrimSpace(token)))
}
