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
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/deviceauth/attestation"
	"github.com/writer/cerebro/internal/deviceauth/risk"
)

type stubVerifier struct {
	pubDER []byte
	keyID  string
}

func (s *stubVerifier) Format() string { return attestation.FormatAppleAppAttest }

func (s *stubVerifier) Verify(_ context.Context, _ attestation.Input) (*attestation.Result, error) {
	return &attestation.Result{
		AssuranceLevel: "hardware",
		PublicKey:      s.pubDER,
		KeyID:          s.keyID,
		Vendor:         "stub-appattest",
	}, nil
}

func ecPublicKeyDER(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	return der
}

func newDPoPProofES256(t *testing.T, key *ecdsa.PrivateKey, htm, htu string, iat time.Time, jti string) string {
	t.Helper()
	x, y := p256XY(t, &key.PublicKey)
	jwk := map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(x),
		"y":   base64.RawURLEncoding.EncodeToString(y),
	}
	header := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
	hb, _ := json.Marshal(header)
	payload := map[string]any{"htm": htm, "htu": htu, "iat": iat.Unix(), "jti": jti}
	pb, _ := json.Marshal(payload)
	signing := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	out := make([]byte, 64)
	copy(out[32-len(r.Bytes()):32], r.Bytes())
	copy(out[64-len(s.Bytes()):64], s.Bytes())
	return signing + "." + base64.RawURLEncoding.EncodeToString(out)
}

// TestServiceEnrollDPoPRiskEndToEnd exercises the full Phase-1+2+3 path:
//
//   - bootstrap-token issuance + enroll with attestation,
//   - storage of dpop_jkt on the device,
//   - DPoP-bound refresh succeeds with the correct key,
//   - missing DPoP fails with ErrDPoPMissing,
//   - high-velocity geo drift downgrades sensitive scopes.
func TestServiceEnrollDPoPRiskEndToEnd(t *testing.T) {
	ctx := context.Background()

	store := NewMemStore()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen ed: %v", err)
	}
	signer, _ := NewLocalSigner([]SigningKey{{KID: "k1", Public: pub, Private: priv}})
	keyset := &KeySet{Keys: []SigningKey{{KID: "k1", Public: pub}}}
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	store.SetClock(clock)
	issuer, _ := NewJWTIssuer(IssuerConfig{Now: clock}, signer)
	verifier, _ := NewJWTVerifier(VerifierConfig{Now: clock}, keyset)

	devKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ec: %v", err)
	}
	registry := attestation.NewRegistry(true, &stubVerifier{
		pubDER: ecPublicKeyDER(t, &devKey.PublicKey),
		keyID:  "stub-key",
	})
	dpop := NewDPoPVerifier(time.Minute, time.Minute)
	dpop.SetClock(clock)

	geo := risk.NewInMemoryLookup()
	geo.Set("203.0.113.10", risk.GeoFact{Country: "US", ASN: "AS1", Latitude: 40.7128, Longitude: -74.0060})
	geo.Set("203.0.113.20", risk.GeoFact{Country: "AU", ASN: "AS2", Latitude: -33.8688, Longitude: 151.2093})

	obsStore := risk.NewInMemoryObservationStore()
	scorer := risk.NewScorer(
		risk.Thresholds{Elevated: 30, High: 60},
		geo,
		risk.NoOpEmitter{},
		risk.NewVelocityDetector(),
		risk.NewCountryDriftDetector(),
		risk.NewASNDriftDetector(),
	)

	service, err := NewService(ServiceConfig{
		AccessTTL:         5 * time.Minute,
		RefreshTTL:        24 * time.Hour,
		BootstrapTokenTTL: time.Hour,
		IdempotencyTTL:    time.Hour,
		Now:               clock,
		Attestations:      registry,
		DPoP:              dpop,
		Risk:              scorer,
		Observations:      obsStore,
	}, store, issuer, verifier, keyset)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	bootstrap, err := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{
		HardwareUUID: "hw-1", TenantID: "writer", TTL: time.Hour, IssuedBy: "operator",
		Scopes: []string{ScopeDevicesToken, ScopeTelemetryIngest, ScopeDeviceFindingsRead},
	})
	if err != nil {
		t.Fatalf("IssueBootstrapToken: %v", err)
	}

	enroll, err := service.Enroll(ctx, EnrollRequest{
		BootstrapToken: bootstrap.Token,
		HardwareUUID:   "hw-1",
		OSType:         "darwin",
		Attestation:    "stub-statement",
		RemoteIP:       net.ParseIP("203.0.113.10"),
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if enroll.AssuranceLevel != "hardware" {
		t.Fatalf("AssuranceLevel = %q, want hardware", enroll.AssuranceLevel)
	}

	device, err := store.LookupDevice(ctx, enroll.DeviceID)
	if err != nil {
		t.Fatalf("LookupDevice: %v", err)
	}
	if device.Metadata["dpop_jkt"] == "" {
		t.Fatal("expected dpop_jkt to be persisted on device metadata")
	}

	// Refresh with a valid DPoP proof signed by the bound key succeeds.
	proof := newDPoPProofES256(t, devKey, "POST", "https://cerebro.test/platform/devices/token", now, "jti-1")
	rotated, err := service.IssueToken(ctx, TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: enroll.RefreshToken,
		DPoPProof:    proof,
		HTTPMethod:   "POST",
		HTTPURL:      "https://cerebro.test/platform/devices/token",
		RemoteIP:     net.ParseIP("203.0.113.10"),
	})
	if err != nil {
		t.Fatalf("IssueToken with DPoP: %v", err)
	}
	if rotated.RiskLevel != "low" {
		t.Errorf("first rotation RiskLevel = %q, want low", rotated.RiskLevel)
	}
	if !containsScope(rotated.Scopes, ScopeTelemetryIngest) {
		t.Errorf("first rotation missing telemetry ingest scope: %v", rotated.Scopes)
	}

	// Now the device shows up in Sydney three minutes later: impossible
	// travel + country drift + ASN drift => high score, sensitive scopes
	// should be downgraded.
	now = now.Add(3 * time.Minute)
	store.SetClock(clock)
	dpop.SetClock(clock)
	proof2 := newDPoPProofES256(t, devKey, "POST", "https://cerebro.test/platform/devices/token", now, "jti-2")
	highRisk, err := service.IssueToken(ctx, TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: rotated.RefreshToken,
		DPoPProof:    proof2,
		HTTPMethod:   "POST",
		HTTPURL:      "https://cerebro.test/platform/devices/token",
		RemoteIP:     net.ParseIP("203.0.113.20"),
	})
	if err != nil {
		t.Fatalf("IssueToken (relocated): %v", err)
	}
	if highRisk.RiskLevel != "high" {
		t.Fatalf("relocated RiskLevel = %q, want high (score=%d)", highRisk.RiskLevel, highRisk.RiskScore)
	}
	if containsScope(highRisk.Scopes, ScopeTelemetryIngest) {
		t.Errorf("high-risk rotation should drop telemetry ingest scope: %v", highRisk.Scopes)
	}
}

// TestServiceRefreshRejectsMissingDPoPOnBoundDevice covers the path where
// the device was enrolled with a hardware-bound key (so dpop_jkt is set on
// metadata), and a subsequent refresh attempt arrives without a DPoP proof.
func TestServiceRefreshRejectsMissingDPoPOnBoundDevice(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := NewLocalSigner([]SigningKey{{KID: "k1", Public: pub, Private: priv}})
	keyset := &KeySet{Keys: []SigningKey{{KID: "k1", Public: pub}}}
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	store.SetClock(clock)
	issuer, _ := NewJWTIssuer(IssuerConfig{Now: clock}, signer)
	verifier, _ := NewJWTVerifier(VerifierConfig{Now: clock}, keyset)

	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry := attestation.NewRegistry(true, &stubVerifier{
		pubDER: ecPublicKeyDER(t, &devKey.PublicKey), keyID: "stub-key",
	})
	dpop := NewDPoPVerifier(time.Minute, time.Minute)
	dpop.SetClock(clock)

	service, err := NewService(ServiceConfig{
		AccessTTL: 5 * time.Minute, RefreshTTL: 24 * time.Hour,
		BootstrapTokenTTL: time.Hour, IdempotencyTTL: time.Hour,
		Now: clock, Attestations: registry, DPoP: dpop,
	}, store, issuer, verifier, keyset)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	bootstrap, _ := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{
		HardwareUUID: "hw-2", TenantID: "writer", TTL: time.Hour, IssuedBy: "operator",
	})
	enroll, err := service.Enroll(ctx, EnrollRequest{
		BootstrapToken: bootstrap.Token,
		HardwareUUID:   "hw-2",
		OSType:         "darwin",
		Attestation:    "stub-statement",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if _, err := service.IssueToken(ctx, TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: enroll.RefreshToken,
		HTTPMethod:   "POST",
		HTTPURL:      "https://cerebro.test/platform/devices/token",
	}); !errors.Is(err, ErrDPoPMissing) {
		t.Fatalf("missing-DPoP err = %v, want ErrDPoPMissing", err)
	}
}

func containsScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

// p256XY returns the 32-byte big-endian X and Y coordinates of pub via the
// crypto/ecdh SEC1 encoding, avoiding the deprecated raw .X / .Y fields.
func p256XY(t *testing.T, pub *ecdsa.PublicKey) ([]byte, []byte) {
	t.Helper()
	ecdhPub, err := pub.ECDH()
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}
	raw := ecdhPub.Bytes()
	if len(raw) != 65 || raw[0] != 0x04 {
		t.Fatalf("unexpected SEC1 length %d", len(raw))
	}
	return raw[1:33], raw[33:]
}
