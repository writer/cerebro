package deviceauth

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DPoPProof is the parsed payload of a DPoP proof JWT (RFC 9449 §4).
type DPoPProof struct {
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	IAT int64  `json:"iat"`
	JTI string `json:"jti"`
	Ath string `json:"ath,omitempty"`
}

// DPoPResult is what the verifier hands back on success: the proof, plus the
// JWK SHA-256 thumbprint (RFC 7638) used to bind the access token to the
// holder's key. The cnf.jkt claim minted into the access token must equal
// this value or the request is rejected.
type DPoPResult struct {
	Proof DPoPProof
	JKT   string
}

// DPoPVerifier validates RFC 9449 DPoP proof JWTs and dedupes seen jti values
// for proofTTL+clockSkew. The dedupe table is per-process; deployments with
// more than one Cerebro replica should use shared replay state before enabling
// multi-replica device-auth traffic.
type DPoPVerifier struct {
	clockSkew time.Duration
	proofTTL  time.Duration
	now       func() time.Time

	mu   sync.Mutex
	seen map[string]time.Time
}

// NewDPoPVerifier returns a verifier with the given clock skew and proof TTL.
// If either is non-positive, sensible defaults are used (30s skew, 60s TTL).
func NewDPoPVerifier(clockSkew, proofTTL time.Duration) *DPoPVerifier {
	if clockSkew <= 0 {
		clockSkew = 30 * time.Second
	}
	if proofTTL <= 0 {
		proofTTL = 60 * time.Second
	}
	return &DPoPVerifier{
		clockSkew: clockSkew,
		proofTTL:  proofTTL,
		now:       time.Now,
		seen:      make(map[string]time.Time),
	}
}

// ReplayStateShared reports whether replayed jti state is shared across
// process boundaries. The built-in verifier is intentionally process-local;
// bootstrap must reject multi-replica configurations until a shared DPoP
// replay store is wired.
func (v *DPoPVerifier) ReplayStateShared() bool {
	return false
}

// SetClock overrides the wall clock used to validate iat. Tests only.
func (v *DPoPVerifier) SetClock(now func() time.Time) {
	if now == nil {
		now = time.Now
	}
	v.mu.Lock()
	v.now = now
	v.mu.Unlock()
}

// Verify parses proofToken, verifies the embedded JWS over the supplied JWK,
// validates htm/htu/iat per RFC 9449 §4.3, optionally binds the proof ath
// claim to the presented access token, and rejects any jti seen within the
// replay window.
func (v *DPoPVerifier) Verify(proofToken, method, requestURL string, accessToken ...string) (*DPoPResult, error) {
	parts := strings.Split(proofToken, ".")
	if len(parts) != 3 {
		return nil, ErrDPoPMalformed
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrDPoPMalformed
	}
	var hdr struct {
		Typ string          `json:"typ"`
		Alg string          `json:"alg"`
		JWK json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return nil, ErrDPoPMalformed
	}
	if hdr.Typ != "dpop+jwt" {
		return nil, fmt.Errorf("%w: typ=%q", ErrDPoPInvalidHeader, hdr.Typ)
	}
	pub, jkt, err := parseJWK(hdr.JWK)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDPoPInvalidJWK, err)
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrDPoPMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrDPoPMalformed
	}
	var p DPoPProof
	if err := json.Unmarshal(payloadJSON, &p); err != nil {
		return nil, ErrDPoPMalformed
	}
	signed := []byte(parts[0] + "." + parts[1])
	if err := verifyDPoPSignature(hdr.Alg, pub, signed, sig); err != nil {
		return nil, err
	}
	if !strings.EqualFold(p.HTM, method) {
		return nil, fmt.Errorf("%w: htm=%q want=%q", ErrDPoPMismatch, p.HTM, method)
	}
	if !urlsEqual(p.HTU, requestURL) {
		return nil, fmt.Errorf("%w: htu=%q want=%q", ErrDPoPMismatch, p.HTU, requestURL)
	}
	if len(accessToken) > 0 && strings.TrimSpace(accessToken[0]) != "" {
		expectedAth := dpopAccessTokenHash(accessToken[0])
		if strings.TrimSpace(p.Ath) == "" || p.Ath != expectedAth {
			return nil, fmt.Errorf("%w: ath mismatch", ErrDPoPMismatch)
		}
	}
	now := v.now().UTC()
	iat := time.Unix(p.IAT, 0)
	if now.Sub(iat) > v.proofTTL+v.clockSkew {
		return nil, ErrDPoPExpired
	}
	if iat.Sub(now) > v.clockSkew {
		return nil, ErrDPoPFromFuture
	}
	if strings.TrimSpace(p.JTI) == "" {
		return nil, ErrDPoPMissingJTI
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.gcLocked(now)
	if _, ok := v.seen[p.JTI]; ok {
		return nil, ErrDPoPReplay
	}
	v.seen[p.JTI] = iat.Add(v.proofTTL + v.clockSkew)
	_ = pub
	return &DPoPResult{Proof: p, JKT: jkt}, nil
}

func dpopAccessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(accessToken)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (v *DPoPVerifier) gcLocked(now time.Time) {
	for jti, exp := range v.seen {
		if now.After(exp) {
			delete(v.seen, jti)
		}
	}
}

func urlsEqual(a, b string) bool {
	au, err := url.Parse(a)
	if err != nil {
		return false
	}
	bu, err := url.Parse(b)
	if err != nil {
		return false
	}
	canon := func(u *url.URL) string {
		host := strings.ToLower(u.Host)
		path := strings.TrimRight(u.Path, "/")
		if path == "" {
			path = "/"
		}
		return strings.ToLower(u.Scheme) + "://" + host + path
	}
	return canon(au) == canon(bu)
}

// parseJWK accepts the JWK from a DPoP header and returns the parsed public
// key plus its RFC 7638 SHA-256 thumbprint encoded as base64url. Only EC
// (P-256, P-384) and OKP (Ed25519) are supported; RSA is intentionally
// excluded so the signing surface stays narrow.
func parseJWK(raw json.RawMessage) (interface{}, string, error) {
	var jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, "", err
	}
	switch jwk.Kty {
	case "EC":
		var curve elliptic.Curve
		var ecdhCurve ecdh.Curve
		var coordLen int
		switch jwk.Crv {
		case "P-256":
			curve, ecdhCurve, coordLen = elliptic.P256(), ecdh.P256(), 32
		case "P-384":
			curve, ecdhCurve, coordLen = elliptic.P384(), ecdh.P384(), 48
		default:
			return nil, "", fmt.Errorf("unsupported EC curve %q", jwk.Crv)
		}
		x, errX := base64.RawURLEncoding.DecodeString(jwk.X)
		y, errY := base64.RawURLEncoding.DecodeString(jwk.Y)
		if errX != nil || errY != nil || len(x) > coordLen || len(y) > coordLen {
			return nil, "", errors.New("malformed jwk x/y")
		}
		uncompressed := make([]byte, 1+2*coordLen)
		uncompressed[0] = 0x04
		copy(uncompressed[1+coordLen-len(x):1+coordLen], x)
		copy(uncompressed[1+2*coordLen-len(y):], y)
		ecdhPub, err := ecdhCurve.NewPublicKey(uncompressed)
		if err != nil {
			return nil, "", fmt.Errorf("jwk point not on curve: %w", err)
		}
		_ = ecdhPub
		canonical := fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`, jwk.Crv, jwk.X, jwk.Y)
		sum := sha256.Sum256([]byte(canonical))
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}, base64.RawURLEncoding.EncodeToString(sum[:]), nil
	case "OKP":
		if jwk.Crv != "Ed25519" {
			return nil, "", fmt.Errorf("unsupported OKP curve %q", jwk.Crv)
		}
		x, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, "", errors.New("malformed Ed25519 jwk")
		}
		canonical := fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":"%s"}`, jwk.X)
		sum := sha256.Sum256([]byte(canonical))
		return ed25519.PublicKey(x), base64.RawURLEncoding.EncodeToString(sum[:]), nil
	default:
		return nil, "", fmt.Errorf("unsupported kty %q", jwk.Kty)
	}
}

func verifyDPoPSignature(alg string, pub interface{}, signed, sig []byte) error {
	switch alg {
	case "ES256":
		ecpub, ok := pub.(*ecdsa.PublicKey)
		if !ok || ecpub.Curve != elliptic.P256() {
			return ErrDPoPInvalidSignature
		}
		if len(sig) != 64 {
			return ErrDPoPInvalidSignature
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		sum := sha256.Sum256(signed)
		if !ecdsa.Verify(ecpub, sum[:], r, s) {
			return ErrDPoPInvalidSignature
		}
		return nil
	case "ES384":
		ecpub, ok := pub.(*ecdsa.PublicKey)
		if !ok || ecpub.Curve != elliptic.P384() {
			return ErrDPoPInvalidSignature
		}
		if len(sig) != 96 {
			return ErrDPoPInvalidSignature
		}
		r := new(big.Int).SetBytes(sig[:48])
		s := new(big.Int).SetBytes(sig[48:])
		sum := sha384Sum(signed)
		if !ecdsa.Verify(ecpub, sum, r, s) {
			return ErrDPoPInvalidSignature
		}
		return nil
	case "EdDSA":
		edpub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return ErrDPoPInvalidSignature
		}
		if !ed25519.Verify(edpub, signed, sig) {
			return ErrDPoPInvalidSignature
		}
		return nil
	default:
		return fmt.Errorf("%w: alg=%q", ErrDPoPInvalidHeader, alg)
	}
}

// ErrDPoP* are typed errors so handlers can map to stable JSON error codes.
var (
	ErrDPoPMalformed           = errors.New("deviceauth: dpop proof malformed")
	ErrDPoPInvalidHeader       = errors.New("deviceauth: dpop header invalid")
	ErrDPoPInvalidJWK          = errors.New("deviceauth: dpop jwk invalid")
	ErrDPoPInvalidSignature    = errors.New("deviceauth: dpop signature invalid")
	ErrDPoPMismatch            = errors.New("deviceauth: dpop htm/htu mismatch")
	ErrDPoPExpired             = errors.New("deviceauth: dpop proof expired")
	ErrDPoPFromFuture          = errors.New("deviceauth: dpop proof iat from the future")
	ErrDPoPMissingJTI          = errors.New("deviceauth: dpop missing jti")
	ErrDPoPReplay              = errors.New("deviceauth: dpop jti replayed")
	ErrDPoPMissing             = errors.New("deviceauth: dpop proof header missing")
	ErrDPoPBindingMissing      = errors.New("deviceauth: dpop binding missing")
	ErrDPoPJKTMismatch         = errors.New("deviceauth: dpop key thumbprint does not match cnf.jkt")
	ErrDPoPVerifierUnavailable = errors.New("deviceauth: dpop verifier unavailable")
)
