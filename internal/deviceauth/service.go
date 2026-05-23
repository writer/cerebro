package deviceauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Scope strings published by the device-auth surface. The bootstrap mux maps
// HTTP routes to these scopes through the normal authorizeHTTPRequestScope
// switch, so a device-issued JWT and a capability token both flow through
// the same authorization decision.
const (
	ScopeDevicesEnroll          = "platform.devices.enroll"
	ScopeDevicesToken           = "platform.devices.token"
	ScopeDevicesRead            = "platform.devices.read"
	ScopeDevicesRevoke          = "platform.devices.revoke"
	ScopeDevicesBootstrapWrite  = "platform.devices.bootstrap_tokens.write"
	ScopeTelemetryIngest        = "platform.telemetry.ingest"
	ScopeDeviceFindingsRead     = "security.devices.findings.read"
)

// DefaultDeviceScopes is the default scope set assigned to a freshly enrolled
// agent. Admin-side scopes (issuing bootstrap tokens, revoking devices) are
// intentionally excluded; those are operator scopes carried by capability
// tokens, not by device JWTs.
var DefaultDeviceScopes = []string{
	ScopeDevicesToken,
	ScopeTelemetryIngest,
	ScopeDeviceFindingsRead,
}

// EnrollRequest is the input to [Service.Enroll]. The agent supplies the
// bootstrap token plaintext and its hardware identity; the server validates,
// consumes the bootstrap token, persists the device, and returns the first
// access + refresh pair.
type EnrollRequest struct {
	BootstrapToken string
	HardwareUUID   string
	SerialNumber   string
	Hostname       string
	OSType         string
	OSVersion      string
	AgentVersion   string
}

// EnrollResponse is the output of [Service.Enroll].
type EnrollResponse struct {
	DeviceID      string
	AccessToken   string
	AccessExpires time.Time
	RefreshToken  string
	RefreshExpires time.Time
	Scopes        []string
	TokenType     string
}

// TokenRequest is the input to [Service.IssueToken]. The agent supplies the
// refresh token; the server rotates and returns the next pair. Replay of a
// previously consumed refresh token revokes the entire family.
type TokenRequest struct {
	GrantType    string
	RefreshToken string
}

// TokenResponse is the output of [Service.IssueToken].
type TokenResponse struct {
	AccessToken    string
	AccessExpires  time.Time
	RefreshToken   string
	RefreshExpires time.Time
	Scopes         []string
	TokenType      string
}

// IssueBootstrapTokenRequest is what an admin (capability-token-authenticated
// operator) sends to mint a single-use enrollment credential for one device.
type IssueBootstrapTokenRequest struct {
	HardwareUUID string
	TenantID     string
	Scopes       []string
	TTL          time.Duration
	IssuedBy     string
}

// IssueBootstrapTokenResponse is the output of
// [Service.IssueBootstrapToken]. The plaintext token is returned exactly
// once; the server only persists the SHA-256 hash.
type IssueBootstrapTokenResponse struct {
	TokenID    string
	Token      string
	ExpiresAt  time.Time
}

// ServiceConfig configures the [Service].
type ServiceConfig struct {
	Issuer            string
	Audience          string
	AccessTTL         time.Duration
	RefreshTTL        time.Duration
	BootstrapTokenTTL time.Duration
	IdempotencyTTL    time.Duration
	ClockSkew         time.Duration
	DefaultTenantID   string
	Now               func() time.Time
}

// Service is the device-auth orchestration layer. It owns the lifecycle of
// devices, bootstrap tokens, and refresh tokens, and is the only entry point
// the HTTP layer should call.
type Service struct {
	cfg      ServiceConfig
	store    Store
	issuer   *JWTIssuer
	verifier *JWTVerifier
	keyset   *KeySet
}

// NewService constructs a service.
func NewService(cfg ServiceConfig, store Store, issuer *JWTIssuer, verifier *JWTVerifier, keyset *KeySet) (*Service, error) {
	if store == nil {
		return nil, errors.New("deviceauth: store is required")
	}
	if issuer == nil {
		return nil, errors.New("deviceauth: issuer is required")
	}
	if verifier == nil {
		return nil, errors.New("deviceauth: verifier is required")
	}
	if keyset == nil || len(keyset.Keys) == 0 {
		return nil, errors.New("deviceauth: keyset is required")
	}
	if cfg.AccessTTL <= 0 {
		cfg.AccessTTL = DefaultAccessTTL
	}
	if cfg.RefreshTTL <= 0 {
		cfg.RefreshTTL = 30 * 24 * time.Hour
	}
	if cfg.BootstrapTokenTTL <= 0 {
		cfg.BootstrapTokenTTL = 24 * time.Hour
	}
	if cfg.IdempotencyTTL <= 0 {
		cfg.IdempotencyTTL = 24 * time.Hour
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = DefaultClockSkew
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	cfg.Issuer = strings.TrimSpace(cfg.Issuer)
	if cfg.Issuer == "" {
		cfg.Issuer = "cerebro"
	}
	cfg.Audience = strings.TrimSpace(cfg.Audience)
	if cfg.Audience == "" {
		cfg.Audience = "cerebro-device"
	}
	cfg.DefaultTenantID = strings.TrimSpace(cfg.DefaultTenantID)
	return &Service{cfg: cfg, store: store, issuer: issuer, verifier: verifier, keyset: keyset}, nil
}

// Verifier returns the underlying JWT verifier so the bootstrap auth pipeline
// can reuse it.
func (s *Service) Verifier() *JWTVerifier {
	return s.verifier
}

// KeySet returns the active verification keys for the JWKS endpoint.
func (s *Service) KeySet() *KeySet {
	return s.keyset
}

// Enroll consumes a bootstrap token and provisions a device.
func (s *Service) Enroll(ctx context.Context, request EnrollRequest) (EnrollResponse, error) {
	bootstrapToken, err := NormalizeOpaqueToken(request.BootstrapToken)
	if err != nil {
		return EnrollResponse{}, fmt.Errorf("%w: bootstrap_token", ErrInvalidRequest)
	}
	hardwareUUID := strings.TrimSpace(request.HardwareUUID)
	if hardwareUUID == "" {
		return EnrollResponse{}, fmt.Errorf("%w: hardware_uuid", ErrInvalidRequest)
	}
	now := s.cfg.Now().UTC()
	hash := HashToken(bootstrapToken)
	consumed, err := s.store.ConsumeBootstrapToken(ctx, hash, hardwareUUID, now, "agent")
	if err != nil {
		return EnrollResponse{}, err
	}
	tenantID := strings.TrimSpace(consumed.TenantID)
	if tenantID == "" {
		tenantID = s.cfg.DefaultTenantID
	}
	if tenantID == "" {
		return EnrollResponse{}, fmt.Errorf("%w: bootstrap token has no tenant_id", ErrInvalidRequest)
	}
	scopes := normalizedNonEmptyStrings(consumed.Scopes)
	if len(scopes) == 0 {
		scopes = append([]string(nil), DefaultDeviceScopes...)
	}
	deviceID, err := generateID("dev_")
	if err != nil {
		return EnrollResponse{}, fmt.Errorf("deviceauth: generate device id: %w", err)
	}
	device := DeviceRecord{
		DeviceID:     deviceID,
		HardwareUUID: hardwareUUID,
		SerialNumber: strings.TrimSpace(request.SerialNumber),
		Hostname:     strings.TrimSpace(request.Hostname),
		TenantID:     tenantID,
		OSType:       strings.TrimSpace(request.OSType),
		OSVersion:    strings.TrimSpace(request.OSVersion),
		AgentVersion: strings.TrimSpace(request.AgentVersion),
		Status:       "active",
		EnrolledAt:   now,
		LastSeenAt:   now,
	}
	device, err = s.store.EnrollDevice(ctx, device)
	if err != nil {
		return EnrollResponse{}, fmt.Errorf("deviceauth: enroll device: %w", err)
	}
	access, accessExpires, err := s.mintAccess(device, scopes)
	if err != nil {
		return EnrollResponse{}, err
	}
	refresh, refreshExpires, err := s.mintRefresh(ctx, device.DeviceID, scopes, "", 0, now)
	if err != nil {
		return EnrollResponse{}, err
	}
	return EnrollResponse{
		DeviceID:       device.DeviceID,
		AccessToken:    access,
		AccessExpires:  accessExpires,
		RefreshToken:   refresh,
		RefreshExpires: refreshExpires,
		Scopes:         scopes,
		TokenType:      "Bearer",
	}, nil
}

// IssueToken rotates a refresh token. The grant type must be
// "refresh_token"; any other value returns [ErrInvalidRequest].
func (s *Service) IssueToken(ctx context.Context, request TokenRequest) (TokenResponse, error) {
	if strings.TrimSpace(request.GrantType) != "refresh_token" {
		return TokenResponse{}, fmt.Errorf("%w: grant_type must be refresh_token", ErrInvalidRequest)
	}
	refreshToken, err := NormalizeOpaqueToken(request.RefreshToken)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("%w: refresh_token", ErrInvalidRequest)
	}
	now := s.cfg.Now().UTC()
	consumed, err := s.store.ConsumeRefreshToken(ctx, HashToken(refreshToken), now)
	if err != nil {
		return TokenResponse{}, err
	}
	device, err := s.store.LookupDevice(ctx, consumed.DeviceID)
	if err != nil {
		return TokenResponse{}, err
	}
	if device.Status != "" && device.Status != "active" {
		return TokenResponse{}, ErrDeviceInactive
	}
	if err := s.store.MarkSeen(ctx, device.DeviceID, now); err != nil {
		return TokenResponse{}, fmt.Errorf("deviceauth: mark seen: %w", err)
	}
	scopes := normalizedNonEmptyStrings(consumed.Scopes)
	if len(scopes) == 0 {
		scopes = append([]string(nil), DefaultDeviceScopes...)
	}
	access, accessExpires, err := s.mintAccess(device, scopes)
	if err != nil {
		return TokenResponse{}, err
	}
	refresh, refreshExpires, err := s.mintRefresh(ctx, device.DeviceID, scopes, consumed.FamilyID, consumed.Generation+1, now)
	if err != nil {
		return TokenResponse{}, err
	}
	return TokenResponse{
		AccessToken:    access,
		AccessExpires:  accessExpires,
		RefreshToken:   refresh,
		RefreshExpires: refreshExpires,
		Scopes:         scopes,
		TokenType:      "Bearer",
	}, nil
}

// Revoke marks a device revoked. Subsequent refresh attempts will fail and
// in-flight access tokens expire on their own; callers that need immediate
// revocation must wait for the access TTL or use a denylist mechanism that
// is not in scope here.
func (s *Service) Revoke(ctx context.Context, deviceID string, reason string) error {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return fmt.Errorf("%w: device_id", ErrInvalidRequest)
	}
	now := s.cfg.Now().UTC()
	if err := s.store.RevokeDevice(ctx, deviceID, now, reason); err != nil {
		return err
	}
	return nil
}

// IssueBootstrapToken mints a single-use enrollment credential.
func (s *Service) IssueBootstrapToken(ctx context.Context, request IssueBootstrapTokenRequest) (IssueBootstrapTokenResponse, error) {
	hardwareUUID := strings.TrimSpace(request.HardwareUUID)
	if hardwareUUID == "" {
		return IssueBootstrapTokenResponse{}, fmt.Errorf("%w: hardware_uuid", ErrInvalidRequest)
	}
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		tenantID = s.cfg.DefaultTenantID
	}
	if tenantID == "" {
		return IssueBootstrapTokenResponse{}, fmt.Errorf("%w: tenant_id", ErrInvalidRequest)
	}
	scopes := normalizedNonEmptyStrings(request.Scopes)
	if len(scopes) == 0 {
		scopes = append([]string(nil), DefaultDeviceScopes...)
	}
	ttl := request.TTL
	if ttl <= 0 {
		ttl = s.cfg.BootstrapTokenTTL
	}
	now := s.cfg.Now().UTC()
	plaintext, err := GenerateOpaqueToken()
	if err != nil {
		return IssueBootstrapTokenResponse{}, fmt.Errorf("deviceauth: generate bootstrap token: %w", err)
	}
	tokenID, err := generateID("btk_")
	if err != nil {
		return IssueBootstrapTokenResponse{}, fmt.Errorf("deviceauth: generate bootstrap id: %w", err)
	}
	token := BootstrapToken{
		TokenID:      tokenID,
		TokenHash:    HashToken(plaintext),
		HardwareUUID: hardwareUUID,
		TenantID:     tenantID,
		Scopes:       scopes,
		CreatedAt:    now,
		ExpiresAt:    now.Add(ttl),
	}
	if err := s.store.CreateBootstrapToken(ctx, token); err != nil {
		return IssueBootstrapTokenResponse{}, fmt.Errorf("deviceauth: create bootstrap token: %w", err)
	}
	return IssueBootstrapTokenResponse{
		TokenID:   tokenID,
		Token:     plaintext,
		ExpiresAt: token.ExpiresAt,
	}, nil
}

// IngestPayload represents a single telemetry submission. Body is the raw
// JSON received from the agent; the service does not parse the contents -- a
// downstream pipeline normalizes telemetry into Source CDK events.
type IngestPayload struct {
	DeviceID       string
	IdempotencyKey string
	Body           []byte
}

// IngestResult is the outcome of [Service.IngestTelemetry].
type IngestResult struct {
	Status     int
	Body       []byte
	Cached     bool
	ReceivedAt time.Time
}

// IngestTelemetry validates the device, enforces the Idempotency-Key
// contract, and accepts the payload. The service stores the canonical
// response in the idempotency cache so a retried submission returns the
// same response with no side effects.
func (s *Service) IngestTelemetry(ctx context.Context, payload IngestPayload) (IngestResult, error) {
	deviceID := strings.TrimSpace(payload.DeviceID)
	if deviceID == "" {
		return IngestResult{}, fmt.Errorf("%w: device_id", ErrInvalidRequest)
	}
	idempotencyKey := strings.TrimSpace(payload.IdempotencyKey)
	if idempotencyKey == "" {
		return IngestResult{}, fmt.Errorf("%w: Idempotency-Key header is required", ErrInvalidRequest)
	}
	if len(idempotencyKey) > 255 {
		return IngestResult{}, fmt.Errorf("%w: Idempotency-Key exceeds 255 bytes", ErrInvalidRequest)
	}
	if len(payload.Body) > MaxIngestBodyBytes {
		return IngestResult{}, fmt.Errorf("%w: body exceeds %d bytes", ErrInvalidRequest, MaxIngestBodyBytes)
	}
	device, err := s.store.LookupDevice(ctx, deviceID)
	if err != nil {
		return IngestResult{}, err
	}
	if device.Status != "" && device.Status != "active" {
		return IngestResult{}, ErrDeviceInactive
	}
	now := s.cfg.Now().UTC()
	cacheKey := "device:" + deviceID + ":" + idempotencyKey
	requestHash := HashToken(string(payload.Body))
	cached, status, err := s.store.CheckIdempotency(ctx, cacheKey, requestHash)
	if err != nil {
		return IngestResult{}, err
	}
	if cached != nil {
		return IngestResult{Status: status, Body: cached, Cached: true, ReceivedAt: now}, nil
	}
	if err := s.store.MarkSeen(ctx, deviceID, now); err != nil {
		return IngestResult{}, fmt.Errorf("deviceauth: mark seen: %w", err)
	}
	receipt := fmt.Sprintf(`{"status":"accepted","device_id":%q,"received_at":%q,"bytes":%d}`, deviceID, now.Format(time.RFC3339Nano), len(payload.Body))
	body := []byte(receipt)
	if err := s.store.PutIdempotency(ctx, cacheKey, requestHash, 202, body, now.Add(s.cfg.IdempotencyTTL)); err != nil {
		return IngestResult{}, fmt.Errorf("deviceauth: store idempotency: %w", err)
	}
	return IngestResult{Status: 202, Body: body, Cached: false, ReceivedAt: now}, nil
}

// MaxIngestBodyBytes caps a single telemetry submission. Aligns with the
// existing maxProtoJSONBodyBytes in internal/bootstrap/app.go.
const MaxIngestBodyBytes = 1 << 20

// ErrInvalidRequest is returned for caller-side argument or contract errors.
// It is wrapped with %w so callers can errors.Is it through the HTTP layer.
var ErrInvalidRequest = errors.New("deviceauth: invalid request")

func (s *Service) mintAccess(device DeviceRecord, scopes []string) (string, time.Time, error) {
	expires := s.cfg.Now().UTC().Add(s.cfg.AccessTTL)
	token, err := s.issuer.IssueAccess(device, scopes)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("deviceauth: issue access: %w", err)
	}
	return token, expires, nil
}

func (s *Service) mintRefresh(ctx context.Context, deviceID string, scopes []string, familyID string, generation int, now time.Time) (string, time.Time, error) {
	plaintext, err := GenerateOpaqueToken()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("deviceauth: generate refresh: %w", err)
	}
	if familyID == "" {
		familyID, err = NewFamilyID()
		if err != nil {
			return "", time.Time{}, fmt.Errorf("deviceauth: generate family: %w", err)
		}
		generation = 1
	}
	expires := now.Add(s.cfg.RefreshTTL)
	row := RefreshToken{
		TokenHash:  HashToken(plaintext),
		DeviceID:   deviceID,
		FamilyID:   familyID,
		Generation: generation,
		Scopes:     scopes,
		CreatedAt:  now,
		ExpiresAt:  expires,
	}
	if err := s.store.IssueRefreshToken(ctx, row); err != nil {
		return "", time.Time{}, fmt.Errorf("deviceauth: issue refresh: %w", err)
	}
	return plaintext, expires, nil
}

func generateID(prefix string) (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

func normalizedNonEmptyStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}
