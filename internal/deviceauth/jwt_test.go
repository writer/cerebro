package deviceauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

func newSignerForTest(t *testing.T, kids ...string) (*LocalSigner, *KeySet) {
	t.Helper()
	if len(kids) == 0 {
		kids = []string{"test-kid-1"}
	}
	keys := make([]SigningKey, 0, len(kids))
	verifyKeys := make([]SigningKey, 0, len(kids))
	for _, kid := range kids {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		keys = append(keys, SigningKey{KID: kid, Public: pub, Private: priv})
		verifyKeys = append(verifyKeys, SigningKey{KID: kid, Public: pub})
	}
	signer, err := NewLocalSigner(keys)
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	return signer, &KeySet{Keys: verifyKeys}
}

func TestJWTIssuerVerifierRoundTrip(t *testing.T) {
	signer, keyset := newSignerForTest(t)
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	issuer, err := NewJWTIssuer(IssuerConfig{Issuer: "cerebro", Audience: "cerebro-device", Now: clock}, signer)
	if err != nil {
		t.Fatalf("NewJWTIssuer: %v", err)
	}
	verifier, err := NewJWTVerifier(VerifierConfig{Issuer: "cerebro", Audience: "cerebro-device", Now: clock}, keyset)
	if err != nil {
		t.Fatalf("NewJWTVerifier: %v", err)
	}

	device := DeviceRecord{DeviceID: "dev-1", TenantID: "writer", HardwareUUID: "hw-1"}
	scopes := []string{"platform.devices.read", "platform.telemetry.ingest"}

	token, err := issuer.IssueAccess(device, scopes)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	if strings.Count(token, ".") != 2 {
		t.Fatalf("expected three-segment compact JWT, got %q", token)
	}

	verified, err := verifier.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.DeviceID != "dev-1" {
		t.Errorf("device_id = %q, want dev-1", verified.DeviceID)
	}
	if verified.TenantID != "writer" {
		t.Errorf("tenant_id = %q, want writer", verified.TenantID)
	}
	if verified.HardwareUUID != "hw-1" {
		t.Errorf("hardware_uuid = %q, want hw-1", verified.HardwareUUID)
	}
	if len(verified.Scopes) != 2 {
		t.Errorf("scopes = %v, want 2 entries", verified.Scopes)
	}
}

func TestJWTVerifierRejectsExpired(t *testing.T) {
	signer, keyset := newSignerForTest(t)
	issueAt := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	verifyAt := issueAt.Add(2 * DefaultAccessTTL)

	issuer, _ := NewJWTIssuer(IssuerConfig{Now: func() time.Time { return issueAt }}, signer)
	verifier, _ := NewJWTVerifier(VerifierConfig{Now: func() time.Time { return verifyAt }}, keyset)

	token, err := issuer.IssueAccess(DeviceRecord{DeviceID: "dev-1", TenantID: "writer"}, []string{"a"})
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	if _, err := verifier.Verify(token); !errors.Is(err, ErrExpired) {
		t.Fatalf("Verify err = %v, want ErrExpired", err)
	}
}

func TestJWTVerifierRejectsUnknownKID(t *testing.T) {
	signer, _ := newSignerForTest(t, "issuer-kid")
	_, otherKeyset := newSignerForTest(t, "other-kid")
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	issuer, _ := NewJWTIssuer(IssuerConfig{Now: clock}, signer)
	verifier, _ := NewJWTVerifier(VerifierConfig{Now: clock}, otherKeyset)

	token, err := issuer.IssueAccess(DeviceRecord{DeviceID: "dev-1", TenantID: "writer"}, []string{"a"})
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	if _, err := verifier.Verify(token); !errors.Is(err, ErrUnknownKID) {
		t.Fatalf("Verify err = %v, want ErrUnknownKID", err)
	}
}

func TestJWTVerifierRejectsAudienceMismatch(t *testing.T) {
	signer, keyset := newSignerForTest(t)
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	issuer, _ := NewJWTIssuer(IssuerConfig{Issuer: "cerebro", Audience: "cerebro-device", Now: clock}, signer)
	verifier, _ := NewJWTVerifier(VerifierConfig{Issuer: "cerebro", Audience: "different-aud", Now: clock}, keyset)

	token, _ := issuer.IssueAccess(DeviceRecord{DeviceID: "dev-1", TenantID: "writer"}, []string{"a"})
	if _, err := verifier.Verify(token); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("Verify err = %v, want ErrAudienceMismatch", err)
	}
}

func TestJWTVerifierRejectsTamperedSignature(t *testing.T) {
	signer, keyset := newSignerForTest(t)
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	issuer, _ := NewJWTIssuer(IssuerConfig{Now: clock}, signer)
	verifier, _ := NewJWTVerifier(VerifierConfig{Now: clock}, keyset)

	token, _ := issuer.IssueAccess(DeviceRecord{DeviceID: "dev-1", TenantID: "writer"}, []string{"a"})
	parts := strings.Split(token, ".")
	tampered := parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-1] + "A"
	if _, err := verifier.Verify(tampered); !errors.Is(err, ErrInvalidSignature) && !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("Verify err = %v, want ErrInvalidSignature or ErrMalformedToken", err)
	}
}

func TestJWTIssuerRequiresScopes(t *testing.T) {
	signer, _ := newSignerForTest(t)
	issuer, _ := NewJWTIssuer(IssuerConfig{}, signer)
	if _, err := issuer.IssueAccess(DeviceRecord{DeviceID: "dev-1", TenantID: "writer"}, nil); err == nil {
		t.Fatalf("IssueAccess with no scopes succeeded; want error")
	}
}

func TestKeySetSupportsRotation(t *testing.T) {
	// Two keys: old (retiring) and new (current). New tokens use "new"; old
	// tokens issued before rotation must still verify.
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)

	oldSigner, _ := NewLocalSigner([]SigningKey{{KID: "old", Public: pub1, Private: priv1}})
	newSigner, _ := NewLocalSigner([]SigningKey{{KID: "new", Public: pub2, Private: priv2}})

	combinedKeyset := &KeySet{Keys: []SigningKey{
		{KID: "new", Public: pub2},
		{KID: "old", Public: pub1},
	}}

	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	oldIssuer, _ := NewJWTIssuer(IssuerConfig{Now: clock}, oldSigner)
	newIssuer, _ := NewJWTIssuer(IssuerConfig{Now: clock}, newSigner)
	verifier, _ := NewJWTVerifier(VerifierConfig{Now: clock}, combinedKeyset)

	oldToken, _ := oldIssuer.IssueAccess(DeviceRecord{DeviceID: "dev-1", TenantID: "writer"}, []string{"a"})
	newToken, _ := newIssuer.IssueAccess(DeviceRecord{DeviceID: "dev-2", TenantID: "writer"}, []string{"a"})

	if _, err := verifier.Verify(oldToken); err != nil {
		t.Fatalf("verify old token after rotation: %v", err)
	}
	if _, err := verifier.Verify(newToken); err != nil {
		t.Fatalf("verify new token after rotation: %v", err)
	}
}
