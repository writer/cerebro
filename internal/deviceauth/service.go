package deviceauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/deviceauth/attestation"
	"github.com/writer/cerebro/internal/deviceauth/risk"
)

// Scope strings published by the device-auth surface. The bootstrap mux maps
// HTTP routes to these scopes through the normal authorizeHTTPRequestScope
// switch, so a device-issued JWT and a capability token both flow through
// the same authorization decision.
const (
	ScopeDevicesEnroll         = "platform.devices.enroll"
	ScopeDevicesToken          = "platform.devices.token"
	ScopeDevicesRead           = "platform.devices.read"
	ScopeDevicesRevoke         = "platform.devices.revoke"
	ScopeDevicesBootstrapWrite = "platform.devices.bootstrap_tokens.write"
	ScopeTelemetryIngest       = "platform.telemetry.ingest"
	ScopeDeviceFindingsRead    = "security.devices.findings.read"
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

var allowedBootstrapDeviceScopes = map[string]struct{}{
	ScopeDevicesToken:       {},
	ScopeTelemetryIngest:    {},
	ScopeDeviceFindingsRead: {},
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
	// Attestation, when non-empty, is the base64-encoded device-bound proof
	// (App Attest CBOR object on macOS, TPM 2.0 quote bundle on Windows).
	// The Service runs it through the configured [attestation.Registry];
	// when the registry is configured as required, an empty value rejects
	// the enrollment.
	Attestation string
	// DeviceJWK, when non-empty, is the agent-supplied public JWK that the
	// agent will use to sign DPoP proofs (RFC 9449). Accepting an
	// agent-supplied key is what lets a software-assurance enrollment
	// produce a sender-constrained access token: cnf.jkt is populated
	// from this key's RFC 7638 thumbprint and every subsequent refresh
	// (and any DPoP-protected resource call) must carry a proof signed
	// by the matching private key. Only EC P-256 / EC P-384 / Ed25519
	// are accepted; RSA is rejected to keep the signing surface narrow.
	// When attestation also supplies a public key, the two thumbprints
	// MUST match -- a hardware-attested key is authoritative and a
	// mismatched JWK rejects the enrollment.
	DeviceJWK json.RawMessage
	// RemoteIP is the agent's source address as observed by the front
	// door. Used for risk scoring and audit logging.
	RemoteIP net.IP
}

// EnrollResponse is the output of [Service.Enroll].
type EnrollResponse struct {
	DeviceID       string
	AccessToken    string
	AccessExpires  time.Time
	RefreshToken   string
	RefreshExpires time.Time
	Scopes         []string
	TokenType      string
	// AssuranceLevel reflects whether attestation produced a hardware-
	// bound result ("hardware") or a software fallback ("software").
	AssuranceLevel string
	// AttestationVendor names the verifier that produced the assurance
	// (e.g. "apple-appattest", "tpm-2.0", or "none").
	AttestationVendor string
}

// TokenRequest is the input to [Service.IssueToken]. The agent supplies the
// refresh token; the server rotates and returns the next pair. Replay of a
// previously consumed refresh token revokes the entire family.
type TokenRequest struct {
	GrantType    string
	RefreshToken string
	// DPoPProof, when the device was enrolled with a device-bound key, is
	// the RFC 9449 proof JWT that the server requires to confirm the
	// agent still controls the key. The verifier is configured at the
	// service level; an empty value here rejects the rotation when DPoP
	// binding is mandatory for the device.
	DPoPProof string
	// HTTPMethod and HTTPURL are passed through to the DPoP verifier when
	// proof verification is required. Both default to POST and the token
	// endpoint URL configured on the service.
	HTTPMethod string
	HTTPURL    string
	// RemoteIP is the agent's source address (for risk scoring).
	RemoteIP net.IP
}

// TokenResponse is the output of [Service.IssueToken].
type TokenResponse struct {
	AccessToken    string
	AccessExpires  time.Time
	RefreshToken   string
	RefreshExpires time.Time
	Scopes         []string
	TokenType      string
	// RiskScore is the 0..100 score the risk pipeline computed for this
	// rotation, surfaced for the audit log.
	RiskScore int
	// RiskLevel is "low" / "elevated" / "high".
	RiskLevel string
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
	TokenID   string
	Token     string
	ExpiresAt time.Time
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
	// Attestations, if set, is consulted on every Enroll to verify the
	// agent's device-bound key. When the registry is required, missing
	// or invalid attestations reject the enrollment.
	Attestations *attestation.Registry
	// DPoP, if set, verifies RFC 9449 proof JWTs on refresh-token
	// rotation. When the device was enrolled with a device-bound key,
	// the proof is mandatory and the proof's JKT must equal the device's
	// stored key thumbprint.
	DPoP *DPoPVerifier
	// Risk, if set, runs every successful refresh through the risk
	// scorer. The scorer's decision is recorded on the device's last
	// observation; the auth pipeline uses [risk.Decision.FilterScopes]
	// to drop sensitive scopes when the score is high.
	Risk *risk.Scorer
	// Observations, if set, is the per-device geo/ASN observation store
	// the risk pipeline reads from and writes to.
	Observations risk.ObservationStore
	// Audit, if set, is invoked once per business-level lifecycle event
	// on the device-auth surface (currently: bootstrap-token issuance).
	// Production wiring should publish the event to the AppendLog so
	// SOC tooling can correlate mints to subsequent enrollments. The
	// callback is invoked synchronously after the database write
	// succeeds; implementations MUST be non-blocking and MUST NOT
	// return errors that should fail the request -- a logged-but-not-
	// emitted audit event is preferable to a denied legitimate mint.
	Audit AuditEmitter
}

// AuditEvent describes a single device-auth business-level event.
//
// HardwareUUIDHash holds the SHA-256 (lower-hex) digest of the raw
// hardware UUID rather than the UUID itself, so the audit pipeline
// can correlate without storing the raw identifier in plain text in
// long-term log retention.
type AuditEvent struct {
	Kind             string
	OccurredAt       time.Time
	TenantID         string
	IssuedBy         string
	TokenID          string
	HardwareUUIDHash string
	Scopes           []string
	TTL              time.Duration
	ExpiresAt        time.Time
}

// AuditEmitter is the optional callback invoked once per device-auth
// lifecycle event. See [ServiceConfig.Audit] for invariants.
type AuditEmitter func(ctx context.Context, event AuditEvent)

// Audit kinds. These are the canonical strings the audit pipeline
// matches on; do not rename without coordinating with downstream
// consumers.
const (
	AuditKindBootstrapTokenIssued = "deviceauth.bootstrap_token.issued" // #nosec G101 -- audit event kind, not a secret token.
)

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
		// 7 days is the pilot default. Shorter than the 30-day RFC-6749
		// upper bound recommended for refresh tokens because in software
		// assurance the refresh token IS the long-lived bearer secret;
		// once hardware-bound DPoP is universally enforced this can be
		// raised. Operators can override via
		// CEREBRO_DEVICE_AUTH_REFRESH_TTL=720h to restore the prior 30d
		// behavior.
		cfg.RefreshTTL = 7 * 24 * time.Hour
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
//
// Order of operations (security-critical):
//  1. Parse and validate every caller-supplied input (bootstrap token,
//     hardware UUID, agent-supplied JWK if any).
//  2. Run device-bound attestation. The attestation envelope is signed over
//     SHA-256("bootstrap_token" || "hardware_uuid"), both of which come
//     from the request body, so attestation does not require the bootstrap
//     row to be looked up first.
//  3. Atomically consume the bootstrap token (SELECT ... FOR UPDATE).
//  4. Persist the device record and mint the first access + refresh pair.
//
// Steps 1 and 2 run before step 3 so a malformed JWK or a busted attestation
// envelope from a buggy or compromised agent does NOT burn the legitimate
// agent's single-use bootstrap token.
func (s *Service) Enroll(ctx context.Context, request EnrollRequest) (EnrollResponse, error) {
	bootstrapToken, err := NormalizeOpaqueToken(request.BootstrapToken)
	if err != nil {
		return EnrollResponse{}, fmt.Errorf("%w: bootstrap_token", ErrInvalidRequest)
	}
	hardwareUUID := strings.TrimSpace(request.HardwareUUID)
	if hardwareUUID == "" {
		return EnrollResponse{}, fmt.Errorf("%w: hardware_uuid", ErrInvalidRequest)
	}
	agentJKT, err := parseEnrollDeviceJWK(request.DeviceJWK)
	if err != nil {
		return EnrollResponse{}, fmt.Errorf("%w: device_key: %w", ErrInvalidRequest, err)
	}
	now := s.cfg.Now().UTC()
	clientHash := attestationClientDataHash(bootstrapToken, hardwareUUID)
	attResult, err := s.runAttestation(ctx, clientHash, request)
	if err != nil {
		return EnrollResponse{}, err
	}
	attestationJKT, err := computeJKTFromPublicKeyDER(attResult.PublicKey)
	if err != nil {
		return EnrollResponse{}, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	// When both attestation AND the agent supply a key, they must agree.
	// A mismatch means the agent is trying to bind a different key than
	// the one its hardware just attested -- treat as an attack.
	if agentJKT != "" && attestationJKT != "" && !constantTimeStringEqual(agentJKT, attestationJKT) {
		return EnrollResponse{}, fmt.Errorf("%w: device_key thumbprint does not match attested key", ErrInvalidRequest)
	}
	if agentJKT == "" && attestationJKT == "" {
		return EnrollResponse{}, fmt.Errorf("%w: device_key or attestation is required to bind refresh tokens", ErrInvalidRequest)
	}
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
	existing, err := s.store.LookupDeviceByHardware(ctx, tenantID, hardwareUUID)
	if err == nil && existing.Status != "" && existing.Status != "active" {
		return EnrollResponse{}, ErrDeviceInactive
	}
	if err != nil && !errors.Is(err, ErrDeviceNotFound) {
		return EnrollResponse{}, err
	}
	scopes := normalizedNonEmptyStrings(consumed.Scopes)
	scopes = filterAllowedBootstrapDeviceScopes(scopes)
	if len(scopes) == 0 {
		scopes = append([]string(nil), DefaultDeviceScopes...)
	}
	deviceID := strings.TrimSpace(existing.DeviceID)
	if deviceID == "" {
		deviceID, err = generateID("dev_")
		if err != nil {
			return EnrollResponse{}, fmt.Errorf("deviceauth: generate device id: %w", err)
		}
	}
	priorJKT := ""
	priorAttestationVendor := ""
	existingHardwareBound := false
	if existing.Metadata != nil {
		priorJKT = strings.TrimSpace(existing.Metadata["dpop_jkt"])
		priorAttestationVendor = strings.TrimSpace(existing.Metadata["attestation_vendor"])
		existingHardwareBound = priorJKT != "" && strings.TrimSpace(existing.Metadata["assurance_level"]) == "hardware"
	}
	if attestationJKT == "" && existingHardwareBound && agentJKT != "" && !constantTimeStringEqual(agentJKT, priorJKT) {
		return EnrollResponse{}, fmt.Errorf("%w: device_key cannot replace existing hardware-bound key without attestation", ErrInvalidRequest)
	}
	metadata := map[string]string{
		"assurance_level":    attResult.AssuranceLevel,
		"attestation_vendor": attResult.Vendor,
	}
	// Pin dpop_jkt in priority order: attestation-bound key (hardware
	// proven), then an existing hardware-bound key, then agent-supplied
	// key (software assurance), then prior non-hardware enrollment key.
	// Enrollment must produce a binding before any refresh token is minted.
	switch {
	case attestationJKT != "":
		metadata["dpop_jkt"] = attestationJKT
	case existingHardwareBound:
		metadata["dpop_jkt"] = priorJKT
		metadata["assurance_level"] = "hardware"
		if priorAttestationVendor != "" {
			metadata["attestation_vendor"] = priorAttestationVendor
		}
	case agentJKT != "":
		metadata["dpop_jkt"] = agentJKT
	case priorJKT != "":
		metadata["dpop_jkt"] = priorJKT
	}
	if strings.TrimSpace(metadata["dpop_jkt"]) == "" {
		return EnrollResponse{}, fmt.Errorf("%w: device_key or attestation is required to bind refresh tokens", ErrInvalidRequest)
	}
	if attResult.KeyID != "" {
		metadata["attestation_keyid"] = attResult.KeyID
	}
	for k, v := range attResult.Diagnostics {
		metadata["attestation_"+k] = v
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
		Metadata:     metadata,
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
		DeviceID:          device.DeviceID,
		AccessToken:       access,
		AccessExpires:     accessExpires,
		RefreshToken:      refresh,
		RefreshExpires:    refreshExpires,
		Scopes:            scopes,
		TokenType:         "Bearer",
		AssuranceLevel:    strings.TrimSpace(device.Metadata["assurance_level"]),
		AttestationVendor: strings.TrimSpace(device.Metadata["attestation_vendor"]),
	}, nil
}

func attestationClientDataHash(bootstrapToken string, hardwareUUID string) [32]byte {
	h := sha256.New()
	writeHashField(h, "bootstrap_token", strings.TrimSpace(bootstrapToken))
	writeHashField(h, "hardware_uuid", strings.TrimSpace(hardwareUUID))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func writeHashField(h interface{ Write([]byte) (int, error) }, name string, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(name)))
	_, _ = h.Write(length[:])
	_, _ = h.Write([]byte(name))
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = h.Write(length[:])
	_, _ = h.Write([]byte(value))
}

func (s *Service) runAttestation(ctx context.Context, clientHash [32]byte, request EnrollRequest) (*attestation.Result, error) {
	if s.cfg.Attestations == nil {
		return &attestation.Result{AssuranceLevel: "software", Vendor: "none"}, nil
	}
	res, err := s.cfg.Attestations.Verify(ctx, attestation.Input{
		HardwareUUID:   strings.TrimSpace(request.HardwareUUID),
		ClientDataHash: clientHash,
		Format:         strings.ToLower(strings.TrimSpace(request.OSType)),
		Statement:      strings.TrimSpace(request.Attestation),
	})
	if err != nil {
		return nil, err
	}
	if res == nil {
		return &attestation.Result{AssuranceLevel: "software", Vendor: "none"}, nil
	}
	return res, nil
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
	refreshHash := HashToken(refreshToken)
	peek, err := s.store.LookupRefreshToken(ctx, refreshHash, now)
	if err != nil {
		return TokenResponse{}, err
	}
	device, err := s.store.LookupDevice(ctx, peek.DeviceID)
	if err != nil {
		return TokenResponse{}, err
	}
	if device.Status != "" && device.Status != "active" {
		return TokenResponse{}, ErrDeviceInactive
	}
	if err := s.verifyDPoPForRefresh(device, request); err != nil {
		return TokenResponse{}, err
	}
	consumed, err := s.store.ConsumeRefreshToken(ctx, refreshHash, now)
	if err != nil {
		return TokenResponse{}, err
	}
	if err := s.store.MarkSeen(ctx, device.DeviceID, now); err != nil {
		return TokenResponse{}, fmt.Errorf("deviceauth: mark seen: %w", err)
	}
	refreshScopes := normalizedNonEmptyStrings(consumed.Scopes)
	if len(refreshScopes) == 0 {
		refreshScopes = append([]string(nil), DefaultDeviceScopes...)
	}
	accessScopes, riskDecision := s.applyRisk(ctx, device, request.RemoteIP, now, refreshScopes)
	access, accessExpires, err := s.mintAccess(device, accessScopes)
	if err != nil {
		return TokenResponse{}, err
	}
	refresh, refreshExpires, err := s.mintRefresh(ctx, device.DeviceID, refreshScopes, consumed.FamilyID, consumed.Generation+1, now)
	if err != nil {
		return TokenResponse{}, err
	}
	resp := TokenResponse{
		AccessToken:    access,
		AccessExpires:  accessExpires,
		RefreshToken:   refresh,
		RefreshExpires: refreshExpires,
		Scopes:         accessScopes,
		TokenType:      "Bearer",
	}
	if riskDecision != nil {
		resp.RiskScore = riskDecision.Score
		resp.RiskLevel = riskDecision.Level
	}
	return resp, nil
}

// RefreshTokenRateLimitKey returns a stable, non-secret rate-limit bucket for
// a refresh token without consuming it. Unknown or malformed tokens return an
// error so callers can fall back to a remote-address bucket.
func (s *Service) RefreshTokenRateLimitKey(ctx context.Context, refreshToken string) (string, error) {
	token, err := NormalizeOpaqueToken(refreshToken)
	if err != nil {
		return "", err
	}
	row, err := s.store.LookupRefreshToken(ctx, HashToken(token), s.cfg.Now().UTC())
	if err != nil {
		return "", err
	}
	if row.FamilyRevoked || !row.ConsumedAt.IsZero() {
		return "", ErrRefreshReplay
	}
	deviceID := strings.TrimSpace(row.DeviceID)
	if deviceID == "" {
		return "", ErrRefreshNotFound
	}
	return "device:" + deviceID, nil
}

func (s *Service) verifyDPoPForRefresh(device DeviceRecord, request TokenRequest) error {
	jkt := strings.TrimSpace(device.Metadata["dpop_jkt"])
	if jkt == "" {
		return fmt.Errorf("%w: device has no DPoP binding", ErrInvalidRequest)
	}
	if s.cfg.DPoP == nil {
		return ErrDPoPVerifierUnavailable
	}
	proof := strings.TrimSpace(request.DPoPProof)
	if proof == "" {
		return ErrDPoPMissing
	}
	method := strings.ToUpper(strings.TrimSpace(request.HTTPMethod))
	if method == "" {
		method = "POST"
	}
	url := strings.TrimSpace(request.HTTPURL)
	res, err := s.cfg.DPoP.Verify(proof, method, url)
	if err != nil {
		return err
	}
	if res.JKT != jkt {
		return ErrDPoPJKTMismatch
	}
	return nil
}

func (s *Service) applyRisk(ctx context.Context, device DeviceRecord, remoteIP net.IP, now time.Time, scopes []string) ([]string, *risk.Decision) {
	if s.cfg.Risk == nil {
		return scopes, nil
	}
	var prior *risk.Observation
	if s.cfg.Observations != nil {
		if obs, ok := s.cfg.Observations.Get(ctx, device.DeviceID); ok {
			prior = obs
		}
	}
	dec := s.cfg.Risk.Score(ctx, risk.Signal{
		DeviceID:         device.DeviceID,
		TenantID:         device.TenantID,
		RemoteIP:         remoteIP,
		Now:              now,
		PriorObservation: prior,
	})
	if s.cfg.Observations != nil && dec.Geo != nil {
		_ = s.cfg.Observations.Put(ctx, device.DeviceID, risk.Observation{
			IP:        ipString(remoteIP),
			Country:   dec.Geo.Country,
			ASN:       dec.Geo.ASN,
			Latitude:  dec.Geo.Latitude,
			Longitude: dec.Geo.Longitude,
			At:        now,
		})
	}
	return dec.FilterScopes(scopes), &dec
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
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

// LookupDevice returns the persisted device record by id.
func (s *Service) LookupDevice(ctx context.Context, deviceID string) (DeviceRecord, error) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return DeviceRecord{}, fmt.Errorf("%w: device_id", ErrInvalidRequest)
	}
	return s.store.LookupDevice(ctx, deviceID)
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
	} else if err := validateBootstrapDeviceScopes(scopes); err != nil {
		return IssueBootstrapTokenResponse{}, err
	}
	ttl := request.TTL
	if ttl < 0 {
		return IssueBootstrapTokenResponse{}, fmt.Errorf("%w: ttl", ErrInvalidRequest)
	}
	if ttl == 0 {
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
	// Emit the business-level audit event AFTER the durable write
	// succeeds. Order matters: emitting before the write would create
	// a forensic trail entry for a token that does not exist in the
	// database, leaving SOC investigators chasing ghosts. The Audit
	// callback is documented as non-failing; we deliberately ignore
	// any side-channel errors it might surface so a log-pipeline
	// outage cannot deny legitimate mints.
	if s.cfg.Audit != nil {
		hardwareHash := sha256.Sum256([]byte(hardwareUUID))
		s.cfg.Audit(ctx, AuditEvent{
			Kind:             AuditKindBootstrapTokenIssued,
			OccurredAt:       now,
			TenantID:         tenantID,
			IssuedBy:         strings.TrimSpace(request.IssuedBy),
			TokenID:          tokenID,
			HardwareUUIDHash: hex.EncodeToString(hardwareHash[:]),
			Scopes:           append([]string(nil), scopes...),
			TTL:              ttl,
			ExpiresAt:        token.ExpiresAt,
		})
	}
	return IssueBootstrapTokenResponse{
		TokenID:   tokenID,
		Token:     plaintext,
		ExpiresAt: token.ExpiresAt,
	}, nil
}

func validateBootstrapDeviceScopes(scopes []string) error {
	hasNonSensitiveScope := false
	for _, scope := range scopes {
		if _, ok := allowedBootstrapDeviceScopes[scope]; !ok {
			return fmt.Errorf("%w: unsupported device bootstrap scope %q", ErrInvalidRequest, scope)
		}
		if _, sensitive := risk.SensitiveScopes[scope]; !sensitive {
			hasNonSensitiveScope = true
		}
	}
	if !hasNonSensitiveScope {
		return fmt.Errorf("%w: device bootstrap scopes must include a non-sensitive scope", ErrInvalidRequest)
	}
	return nil
}

func filterAllowedBootstrapDeviceScopes(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if _, ok := allowedBootstrapDeviceScopes[scope]; ok {
			out = append(out, scope)
		}
	}
	return out
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
	requestHash := sha256.Sum256(payload.Body)
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
	opts := AccessOptions{
		DPoPJKT:        strings.TrimSpace(device.Metadata["dpop_jkt"]),
		AssuranceLevel: strings.TrimSpace(device.Metadata["assurance_level"]),
	}
	token, err := s.issuer.IssueAccessWithOptions(device, scopes, opts)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("deviceauth: issue access: %w", err)
	}
	return token, expires, nil
}

// parseEnrollDeviceJWK accepts the agent-supplied JWK from an EnrollRequest
// and returns its RFC 7638 SHA-256 thumbprint. The function reuses the
// package-internal parseJWK helper, so the same kty / curve allowlist that
// applies to DPoP proofs (EC P-256, EC P-384, OKP Ed25519; **no RSA**)
// applies here too. An empty input returns ("", nil); Enroll rejects that
// unless attestation or an existing device record supplies a DPoP binding.
func parseEnrollDeviceJWK(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	if len(raw) > maxEnrollDeviceJWKBytes {
		return "", fmt.Errorf("device_key exceeds %d bytes", maxEnrollDeviceJWKBytes)
	}
	if !json.Valid(raw) {
		return "", errors.New("device_key is not valid JSON")
	}
	if !looksLikeJSONObject(raw) {
		return "", errors.New("device_key must be a JSON object")
	}
	_, jkt, err := parseJWK(raw)
	if err != nil {
		return "", err
	}
	if jkt == "" {
		return "", errors.New("device_key produced an empty thumbprint")
	}
	return jkt, nil
}

// looksLikeJSONObject returns true iff raw, after leading whitespace, begins
// with '{'. This guards parseJWK from being passed a JSON literal like
// "null", "[]", "true", or a quoted string -- json.Valid would accept those
// but parseJWK would crash trying to address its fields.
func looksLikeJSONObject(raw json.RawMessage) bool {
	for _, b := range raw {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case '{':
			return true
		default:
			return false
		}
	}
	return false
}

// maxEnrollDeviceJWKBytes caps a single agent-supplied JWK body. An Ed25519
// public-key JWK is ~120 bytes; an EC P-384 JWK is ~250 bytes. 4 KiB leaves
// headroom for canonicalization-safe representations without inviting
// payload-amplification weirdness.
const maxEnrollDeviceJWKBytes = 4 * 1024

// constantTimeStringEqual reports whether a and b are byte-for-byte equal,
// in constant time relative to the shorter input. Used for thumbprint
// comparison so an attacker cannot use a timing side channel to learn how
// many leading characters of an attested thumbprint match a guessed key.
func constantTimeStringEqual(a, b string) bool {
	return subtleByteEqual([]byte(a), []byte(b))
}

func subtleByteEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// computeJKTFromPublicKeyDER returns the RFC 7638 JWK SHA-256 thumbprint of
// the supplied SubjectPublicKeyInfo. Only EC (P-256, P-384) and Ed25519
// keys are supported; other types fall through with an empty result so the
// caller can bind an agent-supplied key or reject enrollment before issuing
// refresh tokens.
func computeJKTFromPublicKeyDER(pubDER []byte) (string, error) {
	if len(pubDER) == 0 {
		return "", nil
	}
	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return "", fmt.Errorf("parse pubkey: %w", err)
	}
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		var crv string
		var coordLen int
		switch p.Curve {
		case elliptic.P256():
			crv, coordLen = "P-256", 32
		case elliptic.P384():
			crv, coordLen = "P-384", 48
		default:
			return "", nil
		}
		x, y, err := ecdsaPublicKeyXY(p, coordLen)
		if err != nil {
			return "", err
		}
		canonical := fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`,
			crv,
			base64.RawURLEncoding.EncodeToString(x),
			base64.RawURLEncoding.EncodeToString(y),
		)
		sum := sha256.Sum256([]byte(canonical))
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil
	case ed25519.PublicKey:
		canonical := fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":"%s"}`, base64.RawURLEncoding.EncodeToString(p))
		sum := sha256.Sum256([]byte(canonical))
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil
	default:
		return "", nil
	}
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

// ecdsaPublicKeyXY returns the big-endian X and Y coordinates of pub
// padded to coordLen, derived via the SEC1 uncompressed encoding emitted
// by crypto/ecdh. This avoids touching the deprecated raw .X / .Y fields
// on ecdsa.PublicKey while preserving the existing JWK thumbprint format
// (RFC 7638). Only NIST P-256 / P-384 are supported here; callers must
// gate on curve before calling.
func ecdsaPublicKeyXY(pub *ecdsa.PublicKey, coordLen int) ([]byte, []byte, error) {
	ecdhPub, err := pub.ECDH()
	if err != nil {
		return nil, nil, fmt.Errorf("deviceauth: ecdsa->ecdh: %w", err)
	}
	raw := ecdhPub.Bytes()
	want := 1 + 2*coordLen
	if len(raw) != want || raw[0] != 0x04 {
		return nil, nil, fmt.Errorf("deviceauth: unexpected SEC1 length %d (want %d)", len(raw), want)
	}
	return raw[1 : 1+coordLen], raw[1+coordLen:], nil
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
