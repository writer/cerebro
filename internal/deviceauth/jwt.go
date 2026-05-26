package deviceauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// AccessTokenKind is the value placed in the kind claim of a SeCheck access
// token. Refresh tokens are opaque strings, not JWTs, and are tracked through
// [Store].
const AccessTokenKind = "device_access"

// DefaultAccessTTL bounds the lifetime of a device access token. Short enough
// that a stolen token's blast radius is small; long enough that the agent does
// not refresh on every poll.
const DefaultAccessTTL = 10 * time.Minute

// DefaultClockSkew is the maximum allowed difference between the verifier's
// clock and the iat/nbf/exp claims on an incoming token.
const DefaultClockSkew = 1 * time.Minute

// SigningKey describes a single Ed25519 key, addressable by its kid.
type SigningKey struct {
	KID    string
	Public ed25519.PublicKey
	// Private is optional. Verifiers do not need it. The KMS-backed signer
	// keeps Private nil and instead delegates Sign through KMS.
	Private ed25519.PrivateKey
}

// Signer is the abstraction the issuer uses to produce a signature. The
// in-process implementation is [LocalSigner]; production wires a KMS-backed
// implementation that sign-delegates to AWS KMS without ever exposing the
// private key.
type Signer interface {
	// CurrentKID returns the kid that should be embedded in the JWT header
	// for new tokens. Verifiers must accept all KIDs in [KeySet.Keys].
	CurrentKID() string
	// Sign signs the JWT signing input (header.payload bytes) with the key
	// identified by kid. The returned signature is the raw 64-byte Ed25519
	// output (not base64-encoded).
	Sign(kid string, signingInput []byte) ([]byte, error)
}

// KeySet is the verifier's view of the active and retiring signing keys.
// Direct JSON serialization is intentionally routed through the public JWKS
// shape so private signing material is never emitted.
type KeySet struct {
	Keys []SigningKey
}

// Find returns the key with the given kid. The bool is false if no such key
// is in the set.
func (ks *KeySet) Find(kid string) (SigningKey, bool) {
	if ks == nil {
		return SigningKey{}, false
	}
	for _, key := range ks.Keys {
		if key.KID == kid {
			return key, true
		}
	}
	return SigningKey{}, false
}

// LocalSigner signs with an in-process Ed25519 private key. Use only for tests
// and for the dev-mode signing path; production should wire a KMS signer.
type LocalSigner struct {
	currentKID string
	keys       map[string]ed25519.PrivateKey
}

// ErrSigningKeyMismatch indicates that configured public verification key
// material does not correspond to the configured private signing key.
var ErrSigningKeyMismatch = errors.New("deviceauth: signing key public/private mismatch")

// NewLocalSigner constructs a signer. The first kid in keys is treated as the
// current kid.
func NewLocalSigner(keys []SigningKey) (*LocalSigner, error) {
	if len(keys) == 0 {
		return nil, errors.New("deviceauth: at least one signing key is required")
	}
	signer := &LocalSigner{
		currentKID: keys[0].KID,
		keys:       make(map[string]ed25519.PrivateKey, len(keys)),
	}
	for _, key := range keys {
		if strings.TrimSpace(key.KID) == "" {
			return nil, errors.New("deviceauth: signing key requires a non-empty kid")
		}
		if len(key.Private) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("deviceauth: signing key %q has invalid private size", key.KID)
		}
		if len(key.Public) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("deviceauth: signing key %q has invalid public size", key.KID)
		}
		if derived, ok := key.Private.Public().(ed25519.PublicKey); !ok || !bytes.Equal(derived, key.Public) {
			return nil, fmt.Errorf("%w: kid %q", ErrSigningKeyMismatch, key.KID)
		}
		if _, exists := signer.keys[key.KID]; exists {
			return nil, fmt.Errorf("deviceauth: duplicate kid %q", key.KID)
		}
		signer.keys[key.KID] = key.Private
	}
	return signer, nil
}

// CurrentKID returns the kid that should be used to sign new tokens.
func (s *LocalSigner) CurrentKID() string { return s.currentKID }

// Sign produces an Ed25519 signature over signingInput using the private key
// identified by kid.
func (s *LocalSigner) Sign(kid string, signingInput []byte) ([]byte, error) {
	priv, ok := s.keys[kid]
	if !ok {
		return nil, fmt.Errorf("deviceauth: unknown kid %q", kid)
	}
	return ed25519.Sign(priv, signingInput), nil
}

// IssuerConfig configures a [JWTIssuer].
type IssuerConfig struct {
	Issuer    string
	Audience  string
	AccessTTL time.Duration
	Now       func() time.Time
}

// JWTIssuer mints SeCheck device access tokens.
type JWTIssuer struct {
	cfg    IssuerConfig
	signer Signer
}

// NewJWTIssuer constructs an issuer.
func NewJWTIssuer(cfg IssuerConfig, signer Signer) (*JWTIssuer, error) {
	if signer == nil {
		return nil, errors.New("deviceauth: signer is required")
	}
	cfg.Issuer = strings.TrimSpace(cfg.Issuer)
	if cfg.Issuer == "" {
		cfg.Issuer = "cerebro"
	}
	cfg.Audience = strings.TrimSpace(cfg.Audience)
	if cfg.Audience == "" {
		cfg.Audience = "cerebro-device"
	}
	if cfg.AccessTTL <= 0 {
		cfg.AccessTTL = DefaultAccessTTL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &JWTIssuer{cfg: cfg, signer: signer}, nil
}

// AccessClaims are the SeCheck-specific claims placed in a device access token.
type AccessClaims struct {
	DeviceID     string   `json:"device_id"`
	HardwareUUID string   `json:"hardware_uuid,omitempty"`
	TenantID     string   `json:"tenant_id"`
	Scopes       []string `json:"scopes,omitempty"`
}

// AccessOptions are the per-token additions a caller can place on top of the
// scope list when issuing an access token.
type AccessOptions struct {
	// DPoPJKT, when non-empty, is the SHA-256 JWK thumbprint (RFC 7638) of
	// the device's holder-of-key DPoP key. The verifier requires that every
	// authenticated request carry a DPoP proof signed by this key, per
	// RFC 9449 §6.
	DPoPJKT string
	// AssuranceLevel is propagated as the acr claim and is also used by the
	// risk pipeline to decide whether sensitive scopes should be granted on
	// this token. "hardware" indicates a device-bound key was attested at
	// enroll; "software" indicates a software key only.
	AssuranceLevel string
}

// IssueAccess produces a signed JWT for the given device with the given scopes.
// The returned string is the compact-serialized token (header.payload.sig).
func (j *JWTIssuer) IssueAccess(device DeviceRecord, scopes []string) (string, error) {
	return j.IssueAccessWithOptions(device, scopes, AccessOptions{})
}

// IssueAccessWithOptions is the full form of [JWTIssuer.IssueAccess] that
// supports DPoP binding (cnf.jkt) and an assurance level (acr). Both are
// optional; the zero value behaves identically to IssueAccess.
func (j *JWTIssuer) IssueAccessWithOptions(device DeviceRecord, scopes []string, opts AccessOptions) (string, error) {
	if strings.TrimSpace(device.DeviceID) == "" {
		return "", errors.New("deviceauth: device_id is required")
	}
	if strings.TrimSpace(device.TenantID) == "" {
		return "", errors.New("deviceauth: tenant_id is required")
	}
	if len(scopes) == 0 {
		return "", errors.New("deviceauth: at least one scope is required")
	}
	now := j.cfg.Now().UTC()
	jti, err := newJTI()
	if err != nil {
		return "", fmt.Errorf("deviceauth: generate jti: %w", err)
	}
	header := jwtHeader{
		Alg: "EdDSA",
		Typ: "JWT",
		Kid: j.signer.CurrentKID(),
	}
	payload := jwtPayload{
		Iss:          j.cfg.Issuer,
		Aud:          j.cfg.Audience,
		Sub:          "device:" + device.DeviceID,
		Exp:          now.Add(j.cfg.AccessTTL).Unix(),
		Nbf:          now.Unix(),
		Iat:          now.Unix(),
		JTI:          jti,
		Kind:         AccessTokenKind,
		DeviceID:     device.DeviceID,
		HardwareUUID: device.HardwareUUID,
		TenantID:     device.TenantID,
		Scopes:       cloneStrings(scopes),
		ACR:          strings.TrimSpace(opts.AssuranceLevel),
	}
	if jkt := strings.TrimSpace(opts.DPoPJKT); jkt != "" {
		payload.CNF = &jwtConfirmation{JKT: jkt}
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("deviceauth: marshal header: %w", err)
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("deviceauth: marshal payload: %w", err)
	}
	headerSegment := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadSegment := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := headerSegment + "." + payloadSegment
	sig, err := j.signer.Sign(header.Kid, []byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("deviceauth: sign: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifierConfig configures a [JWTVerifier].
type VerifierConfig struct {
	Issuer    string
	Audience  string
	ClockSkew time.Duration
	Now       func() time.Time
}

// JWTVerifier validates tokens issued by [JWTIssuer].
type JWTVerifier struct {
	cfg  VerifierConfig
	keys *KeySet
}

// NewJWTVerifier constructs a verifier. It does not copy keys; callers must not
// mutate the [KeySet] after passing it in.
func NewJWTVerifier(cfg VerifierConfig, keys *KeySet) (*JWTVerifier, error) {
	if keys == nil || len(keys.Keys) == 0 {
		return nil, errors.New("deviceauth: at least one verification key is required")
	}
	cfg.Issuer = strings.TrimSpace(cfg.Issuer)
	if cfg.Issuer == "" {
		cfg.Issuer = "cerebro"
	}
	cfg.Audience = strings.TrimSpace(cfg.Audience)
	if cfg.Audience == "" {
		cfg.Audience = "cerebro-device"
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = DefaultClockSkew
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &JWTVerifier{cfg: cfg, keys: keys}, nil
}

// VerifiedToken is the result of a successful [JWTVerifier.Verify] call.
type VerifiedToken struct {
	DeviceID       string
	HardwareUUID   string
	TenantID       string
	Scopes         []string
	JTI            string
	IssuedAt       time.Time
	ExpiresAt      time.Time
	DPoPJKT        string // confirmation jkt if the token was minted DPoP-bound
	AssuranceLevel string // acr claim ("hardware" or "software")
}

// Verify parses and validates a compact-serialized device JWT. On success it
// returns the verified claims; on failure it returns a typed error.
func (v *JWTVerifier) Verify(token string) (VerifiedToken, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return VerifiedToken{}, ErrMalformedToken
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return VerifiedToken{}, ErrMalformedToken
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return VerifiedToken{}, ErrMalformedToken
	}
	if header.Alg != "EdDSA" || header.Typ != "JWT" {
		return VerifiedToken{}, ErrUnsupportedAlgorithm
	}
	if strings.TrimSpace(header.Kid) == "" {
		return VerifiedToken{}, ErrUnknownKID
	}
	key, ok := v.keys.Find(header.Kid)
	if !ok {
		return VerifiedToken{}, ErrUnknownKID
	}
	if len(key.Public) != ed25519.PublicKeySize {
		return VerifiedToken{}, ErrUnknownKID
	}
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return VerifiedToken{}, ErrMalformedToken
	}
	if !ed25519.Verify(key.Public, []byte(signingInput), sig) {
		return VerifiedToken{}, ErrInvalidSignature
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return VerifiedToken{}, ErrMalformedToken
	}
	var payload jwtPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return VerifiedToken{}, ErrMalformedToken
	}
	if payload.Kind != AccessTokenKind {
		return VerifiedToken{}, ErrWrongKind
	}
	if payload.Iss != v.cfg.Issuer {
		return VerifiedToken{}, ErrIssuerMismatch
	}
	if payload.Aud != v.cfg.Audience {
		return VerifiedToken{}, ErrAudienceMismatch
	}
	now := v.cfg.Now().UTC()
	if payload.Exp == 0 || now.After(time.Unix(payload.Exp, 0).Add(v.cfg.ClockSkew)) {
		return VerifiedToken{}, ErrExpired
	}
	if payload.Nbf > 0 && now.Add(v.cfg.ClockSkew).Before(time.Unix(payload.Nbf, 0)) {
		return VerifiedToken{}, ErrNotYetValid
	}
	if strings.TrimSpace(payload.DeviceID) == "" {
		return VerifiedToken{}, ErrMissingDeviceID
	}
	if strings.TrimSpace(payload.TenantID) == "" {
		return VerifiedToken{}, ErrMissingTenantID
	}
	if len(payload.Scopes) == 0 {
		return VerifiedToken{}, ErrMissingScopes
	}
	verified := VerifiedToken{
		DeviceID:       payload.DeviceID,
		HardwareUUID:   payload.HardwareUUID,
		TenantID:       payload.TenantID,
		Scopes:         cloneStrings(payload.Scopes),
		JTI:            payload.JTI,
		IssuedAt:       time.Unix(payload.Iat, 0).UTC(),
		ExpiresAt:      time.Unix(payload.Exp, 0).UTC(),
		AssuranceLevel: strings.TrimSpace(payload.ACR),
	}
	if payload.CNF != nil {
		verified.DPoPJKT = strings.TrimSpace(payload.CNF.JKT)
	}
	return verified, nil
}

// Typed verification errors. Callers should translate these into HTTP 401
// responses with stable error codes.
var (
	ErrMalformedToken       = errors.New("deviceauth: malformed token")
	ErrUnsupportedAlgorithm = errors.New("deviceauth: unsupported algorithm")
	ErrUnknownKID           = errors.New("deviceauth: unknown kid")
	ErrInvalidSignature     = errors.New("deviceauth: invalid signature")
	ErrWrongKind            = errors.New("deviceauth: wrong token kind")
	ErrIssuerMismatch       = errors.New("deviceauth: issuer mismatch")
	ErrAudienceMismatch     = errors.New("deviceauth: audience mismatch")
	ErrExpired              = errors.New("deviceauth: token expired")
	ErrNotYetValid          = errors.New("deviceauth: token not yet valid")
	ErrMissingDeviceID      = errors.New("deviceauth: missing device_id claim")
	ErrMissingTenantID      = errors.New("deviceauth: missing tenant_id claim")
	ErrMissingScopes        = errors.New("deviceauth: missing scopes claim")
)

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type jwtPayload struct {
	Iss          string           `json:"iss"`
	Aud          string           `json:"aud"`
	Sub          string           `json:"sub"`
	Exp          int64            `json:"exp"`
	Nbf          int64            `json:"nbf"`
	Iat          int64            `json:"iat"`
	JTI          string           `json:"jti"`
	Kind         string           `json:"kind"`
	DeviceID     string           `json:"device_id"`
	HardwareUUID string           `json:"hardware_uuid,omitempty"`
	TenantID     string           `json:"tenant_id"`
	Scopes       []string         `json:"scopes"`
	ACR          string           `json:"acr,omitempty"`
	CNF          *jwtConfirmation `json:"cnf,omitempty"`
}

// jwtConfirmation is the RFC 7800 cnf claim. We use the jkt subset for DPoP
// holder-of-key binding (RFC 9449 §6).
type jwtConfirmation struct {
	JKT string `json:"jkt,omitempty"`
}

func newJTI() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func cloneStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
