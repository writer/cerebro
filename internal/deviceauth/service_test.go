package deviceauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/deviceauth/attestation"
)

func newServiceForTest(t *testing.T) (*Service, *MemStore, time.Time) {
	t.Helper()
	store := NewMemStore()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := NewLocalSigner([]SigningKey{{KID: "test", Public: pub, Private: priv}})
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	keyset := &KeySet{Keys: []SigningKey{{KID: "test", Public: pub}}}
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	store.SetClock(clock)
	issuer, _ := NewJWTIssuer(IssuerConfig{Now: clock}, signer)
	verifier, _ := NewJWTVerifier(VerifierConfig{Now: clock}, keyset)
	service, err := NewService(ServiceConfig{
		AccessTTL:         5 * time.Minute,
		RefreshTTL:        24 * time.Hour,
		BootstrapTokenTTL: time.Hour,
		IdempotencyTTL:    time.Hour,
		Now:               clock,
	}, store, issuer, verifier, keyset)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return service, store, now
}

func TestServiceEnrollAndIssueToken(t *testing.T) {
	ctx := context.Background()
	service, _, now := newServiceForTest(t)
	service.cfg.DPoP = NewDPoPVerifier(time.Minute, time.Minute)
	service.cfg.DPoP.SetClock(service.cfg.Now)
	signer := newDPoPSignerEd25519(t)
	deviceJWK, err := json.Marshal(signer.jwk())
	if err != nil {
		t.Fatalf("marshal device JWK: %v", err)
	}

	bootstrapResp, err := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{
		HardwareUUID: "hw-1",
		TenantID:     "writer",
		TTL:          time.Hour,
		IssuedBy:     "operator",
	})
	if err != nil {
		t.Fatalf("IssueBootstrapToken: %v", err)
	}
	if bootstrapResp.Token == "" {
		t.Fatal("IssueBootstrapToken returned empty token")
	}

	enroll, err := service.Enroll(ctx, EnrollRequest{
		BootstrapToken: bootstrapResp.Token,
		HardwareUUID:   "hw-1",
		Hostname:       "laptop-1",
		OSType:         "darwin",
		AgentVersion:   "1.0.0",
		DeviceJWK:      deviceJWK,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if enroll.AccessToken == "" || enroll.RefreshToken == "" {
		t.Fatal("Enroll returned empty tokens")
	}
	if enroll.DeviceID == "" {
		t.Fatal("Enroll returned empty device_id")
	}

	verified, err := service.Verifier().Verify(enroll.AccessToken)
	if err != nil {
		t.Fatalf("Verify access token: %v", err)
	}
	if verified.DeviceID != enroll.DeviceID {
		t.Errorf("verified device_id = %q, want %q", verified.DeviceID, enroll.DeviceID)
	}

	rotated, err := service.IssueToken(ctx, TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: enroll.RefreshToken,
		DPoPProof:    makeDPoPProof(t, signer, "POST", "https://cerebro.test/platform/devices/token", now, "jti-refresh-1"),
		HTTPMethod:   "POST",
		HTTPURL:      "https://cerebro.test/platform/devices/token",
	})
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if rotated.RefreshToken == enroll.RefreshToken {
		t.Fatal("IssueToken did not rotate the refresh token")
	}

	if _, err := service.IssueToken(ctx, TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: enroll.RefreshToken,
		DPoPProof:    makeDPoPProof(t, signer, "POST", "https://cerebro.test/platform/devices/token", now, "jti-refresh-2"),
		HTTPMethod:   "POST",
		HTTPURL:      "https://cerebro.test/platform/devices/token",
	}); !errors.Is(err, ErrRefreshReplay) {
		t.Fatalf("replay err = %v, want ErrRefreshReplay", err)
	}
	if _, err := service.IssueToken(ctx, TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: rotated.RefreshToken,
		DPoPProof:    makeDPoPProof(t, signer, "POST", "https://cerebro.test/platform/devices/token", now, "jti-refresh-3"),
		HTTPMethod:   "POST",
		HTTPURL:      "https://cerebro.test/platform/devices/token",
	}); !errors.Is(err, ErrRefreshReplay) {
		t.Fatalf("post-replay rotated err = %v, want ErrRefreshReplay", err)
	}
	_ = now
}

func TestServiceEnrollRejectsUnboundRefreshTokenMinting(t *testing.T) {
	ctx := context.Background()
	service, store, _ := newServiceForTest(t)

	bootstrap, err := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{
		HardwareUUID: "hw-unbound",
		TenantID:     "writer",
		TTL:          time.Hour,
		IssuedBy:     "operator",
	})
	if err != nil {
		t.Fatalf("IssueBootstrapToken: %v", err)
	}

	if _, err := service.Enroll(ctx, EnrollRequest{
		BootstrapToken: bootstrap.Token,
		HardwareUUID:   "hw-unbound",
		OSType:         "darwin",
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Enroll without DPoP binding err = %v, want ErrInvalidRequest", err)
	}
	if _, err := store.LookupDeviceByHardware(ctx, "writer", "hw-unbound"); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("LookupDeviceByHardware after rejected unbound enroll err = %v, want ErrDeviceNotFound", err)
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	deviceJWK, _ := makeEd25519JWK(t, pub)
	enroll, err := service.Enroll(ctx, EnrollRequest{
		BootstrapToken: bootstrap.Token,
		HardwareUUID:   "hw-unbound",
		OSType:         "darwin",
		DeviceJWK:      deviceJWK,
	})
	if err != nil {
		t.Fatalf("Enroll after rejected unbound attempt: %v", err)
	}
	if enroll.AccessToken == "" || enroll.RefreshToken == "" {
		t.Fatal("bound enrollment returned empty tokens")
	}
}

func TestServiceReenrollRequiresPresentedBindingForSoftwareDevice(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newServiceForTest(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	deviceJWK, _ := makeEd25519JWK(t, pub)
	firstBootstrap, _ := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-software", TenantID: "writer"})
	first, err := service.Enroll(ctx, EnrollRequest{
		BootstrapToken: firstBootstrap.Token,
		HardwareUUID:   "hw-software",
		OSType:         "darwin",
		DeviceJWK:      deviceJWK,
	})
	if err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	device, err := service.LookupDevice(ctx, first.DeviceID)
	if err != nil {
		t.Fatalf("LookupDevice: %v", err)
	}
	priorJKT := strings.TrimSpace(device.Metadata["dpop_jkt"])
	if priorJKT == "" {
		t.Fatal("first enrollment did not bind DPoP JKT")
	}

	secondBootstrap, _ := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-software", TenantID: "writer"})
	if _, err := service.Enroll(ctx, EnrollRequest{
		BootstrapToken: secondBootstrap.Token,
		HardwareUUID:   "hw-software",
		OSType:         "darwin",
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("second Enroll without presented binding err = %v, want ErrInvalidRequest", err)
	}
	device, err = service.LookupDevice(ctx, first.DeviceID)
	if err != nil {
		t.Fatalf("LookupDevice after rejected reenroll: %v", err)
	}
	if got := strings.TrimSpace(device.Metadata["dpop_jkt"]); got != priorJKT {
		t.Fatalf("dpop_jkt after rejected reenroll = %q, want preserved %q", got, priorJKT)
	}
}

func TestServiceIssueTokenRejectsLegacyUnboundDeviceRefresh(t *testing.T) {
	ctx := context.Background()
	service, store, now := newServiceForTest(t)
	device := DeviceRecord{
		DeviceID:     "dev-legacy",
		HardwareUUID: "hw-legacy",
		TenantID:     "writer",
		Status:       "active",
		EnrolledAt:   now,
		LastSeenAt:   now,
		Metadata: map[string]string{
			"assurance_level": "software",
		},
	}
	if _, err := store.EnrollDevice(ctx, device); err != nil {
		t.Fatalf("EnrollDevice legacy row: %v", err)
	}
	refresh, _, err := service.mintRefresh(ctx, device.DeviceID, DefaultDeviceScopes, "", 0, now)
	if err != nil {
		t.Fatalf("mintRefresh legacy row: %v", err)
	}
	if _, err := service.IssueToken(ctx, TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: refresh,
		HTTPMethod:   "POST",
		HTTPURL:      "https://cerebro.test/platform/devices/token",
	}); !errors.Is(err, ErrDPoPBindingMissing) {
		t.Fatalf("IssueToken legacy unbound err = %v, want ErrDPoPBindingMissing", err)
	}
	row, err := store.LookupRefreshToken(ctx, HashToken(refresh), now)
	if err != nil {
		t.Fatalf("LookupRefreshToken after rejected legacy refresh: %v", err)
	}
	if !row.ConsumedAt.IsZero() {
		t.Fatal("legacy unbound refresh was consumed before DPoP rejection")
	}
}

func TestServiceEnrollRequiresMatchingHardware(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newServiceForTest(t)
	bootstrap, _ := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-1", TenantID: "writer"})
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	deviceJWK, _ := makeEd25519JWK(t, pub)
	if _, err := service.Enroll(ctx, EnrollRequest{BootstrapToken: bootstrap.Token, HardwareUUID: "hw-DIFFERENT", DeviceJWK: deviceJWK}); !errors.Is(err, ErrBootstrapTokenMismatch) {
		t.Fatalf("Enroll with wrong hw err = %v, want ErrBootstrapTokenMismatch", err)
	}
}

func TestServiceIssueBootstrapTokenRejectsNegativeTTL(t *testing.T) {
	ctx := context.Background()
	service, _, now := newServiceForTest(t)
	if _, err := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{
		HardwareUUID: "hw-neg",
		TenantID:     "writer",
		TTL:          -time.Second,
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("IssueBootstrapToken negative TTL err = %v, want ErrInvalidRequest", err)
	}

	issued, err := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{
		HardwareUUID: "hw-default",
		TenantID:     "writer",
		TTL:          0,
	})
	if err != nil {
		t.Fatalf("IssueBootstrapToken zero TTL: %v", err)
	}
	if got := issued.ExpiresAt.Sub(now); got != time.Hour {
		t.Fatalf("zero TTL expiry delta = %v, want %v", got, time.Hour)
	}
}

type checkingAttestationVerifier struct {
	wantHash         [32]byte
	wantHardwareUUID string
	publicKey        []byte
	called           bool
}

func (v *checkingAttestationVerifier) Format() string { return attestation.FormatAppleAppAttest }

func (v *checkingAttestationVerifier) Verify(_ context.Context, in attestation.Input) (*attestation.Result, error) {
	v.called = true
	if in.HardwareUUID != v.wantHardwareUUID {
		return nil, attestation.ErrInvalidStatement
	}
	if in.ClientDataHash != v.wantHash {
		return nil, attestation.ErrNonceMismatch
	}
	return &attestation.Result{AssuranceLevel: "hardware", PublicKey: v.publicKey, Vendor: "stub-appattest"}, nil
}

func TestServiceEnrollAttestationClientHashBindsHardwareUUID(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newServiceForTest(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	verifier := &checkingAttestationVerifier{wantHardwareUUID: "hw-1", publicKey: pubDER}
	service.cfg.Attestations = attestation.NewRegistry(true, verifier)

	bootstrap, err := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-1", TenantID: "writer"})
	if err != nil {
		t.Fatalf("IssueBootstrapToken: %v", err)
	}
	verifier.wantHash = attestationClientDataHash(bootstrap.Token, "hw-1")

	if _, err := service.Enroll(ctx, EnrollRequest{
		BootstrapToken: bootstrap.Token,
		HardwareUUID:   "hw-1",
		OSType:         "darwin",
		Attestation:    "stub-attestation",
	}); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if !verifier.called {
		t.Fatal("attestation verifier was not called")
	}
}

func TestServiceIssueTokenRejectsWrongGrant(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newServiceForTest(t)
	if _, err := service.IssueToken(ctx, TokenRequest{GrantType: "client_credentials"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("IssueToken with wrong grant err = %v, want ErrInvalidRequest", err)
	}
}

func TestServiceIssueTokenRejectsBoundDeviceWhenDPoPVerifierUnavailable(t *testing.T) {
	ctx := context.Background()
	service, store, now := newServiceForTest(t)
	_, err := store.EnrollDevice(ctx, DeviceRecord{
		DeviceID:     "dev-bound",
		HardwareUUID: "hw-bound",
		TenantID:     "writer",
		Status:       "active",
		EnrolledAt:   now,
		LastSeenAt:   now,
		Metadata:     map[string]string{"dpop_jkt": "expected-jkt"},
	})
	if err != nil {
		t.Fatalf("EnrollDevice: %v", err)
	}
	refreshToken, err := GenerateOpaqueToken()
	if err != nil {
		t.Fatalf("GenerateOpaqueToken: %v", err)
	}
	familyID, err := NewFamilyID()
	if err != nil {
		t.Fatalf("NewFamilyID: %v", err)
	}
	if err := store.IssueRefreshToken(ctx, RefreshToken{
		TokenHash:  HashToken(refreshToken),
		DeviceID:   "dev-bound",
		FamilyID:   familyID,
		Generation: 1,
		Scopes:     DefaultDeviceScopes,
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}

	_, err = service.IssueToken(ctx, TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: refreshToken,
		DPoPProof:    "proof-present-but-unverifiable",
	})
	if !errors.Is(err, ErrDPoPVerifierUnavailable) {
		t.Fatalf("IssueToken err = %v, want ErrDPoPVerifierUnavailable", err)
	}
	row, err := store.LookupRefreshToken(ctx, HashToken(refreshToken), now)
	if err != nil {
		t.Fatalf("LookupRefreshToken: %v", err)
	}
	if !row.ConsumedAt.IsZero() {
		t.Fatalf("refresh token was consumed despite unavailable DPoP verifier")
	}
}

func TestServiceRevokeBlocksRefresh(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newServiceForTest(t)
	deviceJWK := newEnrollDeviceJWK(t)
	bootstrap, _ := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-1", TenantID: "writer"})
	enroll, _ := service.Enroll(ctx, EnrollRequest{BootstrapToken: bootstrap.Token, HardwareUUID: "hw-1", DeviceJWK: deviceJWK})
	if err := service.Revoke(ctx, enroll.DeviceID, "test"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := service.IssueToken(ctx, TokenRequest{GrantType: "refresh_token", RefreshToken: enroll.RefreshToken}); !errors.Is(err, ErrDeviceInactive) {
		t.Fatalf("IssueToken after revoke err = %v, want ErrDeviceInactive", err)
	}
}

func TestServiceEnrollRejectsRevokedHardware(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newServiceForTest(t)
	deviceJWK := newEnrollDeviceJWK(t)
	firstBootstrap, _ := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-1", TenantID: "writer"})
	secondBootstrap, _ := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-1", TenantID: "writer"})
	enroll, err := service.Enroll(ctx, EnrollRequest{BootstrapToken: firstBootstrap.Token, HardwareUUID: "hw-1", DeviceJWK: deviceJWK})
	if err != nil {
		t.Fatalf("Enroll(first): %v", err)
	}
	if err := service.Revoke(ctx, enroll.DeviceID, "lost"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := service.Enroll(ctx, EnrollRequest{BootstrapToken: secondBootstrap.Token, HardwareUUID: "hw-1", DeviceJWK: deviceJWK}); !errors.Is(err, ErrDeviceInactive) {
		t.Fatalf("Enroll(second) err = %v, want ErrDeviceInactive", err)
	}
}

func TestServiceReenrollActiveHardwarePreservesRefreshLineage(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newServiceForTest(t)
	service.cfg.DPoP = NewDPoPVerifier(time.Minute, time.Minute)
	service.cfg.DPoP.SetClock(service.cfg.Now)
	signer := newDPoPSignerEd25519(t)
	deviceJWK, err := json.Marshal(signer.jwk())
	if err != nil {
		t.Fatalf("marshal device JWK: %v", err)
	}
	now := service.cfg.Now()
	firstBootstrap, _ := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-1", TenantID: "writer"})
	secondBootstrap, _ := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-1", TenantID: "writer"})
	first, err := service.Enroll(ctx, EnrollRequest{BootstrapToken: firstBootstrap.Token, HardwareUUID: "hw-1", DeviceJWK: deviceJWK})
	if err != nil {
		t.Fatalf("Enroll(first): %v", err)
	}
	second, err := service.Enroll(ctx, EnrollRequest{BootstrapToken: secondBootstrap.Token, HardwareUUID: "hw-1", DeviceJWK: deviceJWK})
	if err != nil {
		t.Fatalf("Enroll(second): %v", err)
	}
	if second.DeviceID != first.DeviceID {
		t.Fatalf("second device_id = %q, want existing %q", second.DeviceID, first.DeviceID)
	}
	if _, err := service.IssueToken(ctx, TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: first.RefreshToken,
		DPoPProof:    makeDPoPProof(t, signer, "POST", "https://cerebro.test/platform/devices/token", now, "jti-lineage"),
		HTTPMethod:   "POST",
		HTTPURL:      "https://cerebro.test/platform/devices/token",
	}); err != nil {
		t.Fatalf("IssueToken with first refresh after re-enroll: %v", err)
	}
}

func TestServiceReenrollActiveHardwarePreservesDPoPBinding(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newServiceForTest(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	verifier := &checkingAttestationVerifier{
		wantHardwareUUID: "hw-1",
		publicKey:        pubDER,
	}
	service.cfg.Attestations = attestation.NewRegistry(true, verifier)
	firstBootstrap, _ := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-1", TenantID: "writer"})
	verifier.wantHash = attestationClientDataHash(firstBootstrap.Token, "hw-1")
	first, err := service.Enroll(ctx, EnrollRequest{
		BootstrapToken: firstBootstrap.Token,
		HardwareUUID:   "hw-1",
		OSType:         "darwin",
		Attestation:    "stub-attestation",
	})
	if err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	device, err := service.LookupDevice(ctx, first.DeviceID)
	if err != nil {
		t.Fatalf("LookupDevice: %v", err)
	}
	priorJKT := strings.TrimSpace(device.Metadata["dpop_jkt"])
	if priorJKT == "" {
		t.Fatal("first enrollment did not bind DPoP JKT")
	}

	service.cfg.Attestations = attestation.NewRegistry(false)
	secondBootstrap, _ := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-1", TenantID: "writer"})
	matchingJWK, _ := makeEd25519JWK(t, pub)
	second, err := service.Enroll(ctx, EnrollRequest{
		BootstrapToken: secondBootstrap.Token,
		HardwareUUID:   "hw-1",
		DeviceJWK:      json.RawMessage(matchingJWK),
	})
	if err != nil {
		t.Fatalf("second Enroll: %v", err)
	}
	if second.DeviceID != first.DeviceID {
		t.Fatalf("second device_id = %q, want %q", second.DeviceID, first.DeviceID)
	}
	device, err = service.LookupDevice(ctx, first.DeviceID)
	if err != nil {
		t.Fatalf("LookupDevice after reenroll: %v", err)
	}
	if got := strings.TrimSpace(device.Metadata["dpop_jkt"]); got != priorJKT {
		t.Fatalf("dpop_jkt after reenroll = %q, want preserved %q", got, priorJKT)
	}
}

func TestServiceReenrollRejectsSoftwareKeyDowngradeFromHardwareBinding(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newServiceForTest(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	verifier := &checkingAttestationVerifier{
		wantHardwareUUID: "hw-downgrade",
		publicKey:        pubDER,
	}
	service.cfg.Attestations = attestation.NewRegistry(true, verifier)
	firstBootstrap, _ := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-downgrade", TenantID: "writer"})
	verifier.wantHash = attestationClientDataHash(firstBootstrap.Token, "hw-downgrade")
	first, err := service.Enroll(ctx, EnrollRequest{
		BootstrapToken: firstBootstrap.Token,
		HardwareUUID:   "hw-downgrade",
		OSType:         "darwin",
		Attestation:    "stub-attestation",
	})
	if err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	device, err := service.LookupDevice(ctx, first.DeviceID)
	if err != nil {
		t.Fatalf("LookupDevice: %v", err)
	}
	priorJKT := strings.TrimSpace(device.Metadata["dpop_jkt"])
	if priorJKT == "" {
		t.Fatal("first enrollment did not bind DPoP JKT")
	}

	service.cfg.Attestations = attestation.NewRegistry(false)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	otherJWK, _ := makeEd25519JWK(t, otherPub)
	secondBootstrap, _ := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-downgrade", TenantID: "writer"})
	if _, err := service.Enroll(ctx, EnrollRequest{
		BootstrapToken: secondBootstrap.Token,
		HardwareUUID:   "hw-downgrade",
		DeviceJWK:      json.RawMessage(otherJWK),
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("software downgrade Enroll err = %v, want ErrInvalidRequest", err)
	}
	device, err = service.LookupDevice(ctx, first.DeviceID)
	if err != nil {
		t.Fatalf("LookupDevice after failed downgrade: %v", err)
	}
	if got := strings.TrimSpace(device.Metadata["dpop_jkt"]); got != priorJKT {
		t.Fatalf("dpop_jkt after failed downgrade = %q, want preserved %q", got, priorJKT)
	}
}

func TestServiceReenrollPreservesHardwareAssuranceToBlockTwoStepDowngrade(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newServiceForTest(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	verifier := &checkingAttestationVerifier{
		wantHardwareUUID: "hw-two-step",
		publicKey:        pubDER,
	}
	service.cfg.Attestations = attestation.NewRegistry(true, verifier)
	firstBootstrap, _ := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-two-step", TenantID: "writer"})
	verifier.wantHash = attestationClientDataHash(firstBootstrap.Token, "hw-two-step")
	first, err := service.Enroll(ctx, EnrollRequest{
		BootstrapToken: firstBootstrap.Token,
		HardwareUUID:   "hw-two-step",
		OSType:         "darwin",
		Attestation:    "stub-attestation",
	})
	if err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	device, err := service.LookupDevice(ctx, first.DeviceID)
	if err != nil {
		t.Fatalf("LookupDevice: %v", err)
	}
	priorJKT := strings.TrimSpace(device.Metadata["dpop_jkt"])
	if priorJKT == "" {
		t.Fatal("first enrollment did not bind DPoP JKT")
	}

	service.cfg.Attestations = attestation.NewRegistry(false)
	secondBootstrap, _ := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-two-step", TenantID: "writer"})
	matchingJWK, _ := makeEd25519JWK(t, pub)
	second, err := service.Enroll(ctx, EnrollRequest{
		BootstrapToken: secondBootstrap.Token,
		HardwareUUID:   "hw-two-step",
		DeviceJWK:      json.RawMessage(matchingJWK),
	})
	if err != nil {
		t.Fatalf("second Enroll: %v", err)
	}
	if second.DeviceID != first.DeviceID {
		t.Fatalf("second device_id = %q, want %q", second.DeviceID, first.DeviceID)
	}
	if second.AssuranceLevel != "hardware" {
		t.Fatalf("second assurance_level = %q, want hardware", second.AssuranceLevel)
	}
	if second.AttestationVendor != "stub-appattest" {
		t.Fatalf("second attestation_vendor = %q, want stub-appattest", second.AttestationVendor)
	}
	device, err = service.LookupDevice(ctx, first.DeviceID)
	if err != nil {
		t.Fatalf("LookupDevice after second enroll: %v", err)
	}
	if got := strings.TrimSpace(device.Metadata["dpop_jkt"]); got != priorJKT {
		t.Fatalf("dpop_jkt after second enroll = %q, want preserved %q", got, priorJKT)
	}
	if got := strings.TrimSpace(device.Metadata["assurance_level"]); got != "hardware" {
		t.Fatalf("assurance_level after second enroll = %q, want hardware", got)
	}
	if got := strings.TrimSpace(device.Metadata["attestation_vendor"]); got != "stub-appattest" {
		t.Fatalf("attestation_vendor after second enroll = %q, want stub-appattest", got)
	}

	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	otherJWK, _ := makeEd25519JWK(t, otherPub)
	thirdBootstrap, _ := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-two-step", TenantID: "writer"})
	if _, err := service.Enroll(ctx, EnrollRequest{
		BootstrapToken: thirdBootstrap.Token,
		HardwareUUID:   "hw-two-step",
		DeviceJWK:      json.RawMessage(otherJWK),
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("third Enroll err = %v, want ErrInvalidRequest", err)
	}
}

func TestRefreshTokenRateLimitKeyRejectsConsumedTokens(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newServiceForTest(t)
	service.cfg.DPoP = NewDPoPVerifier(time.Minute, time.Minute)
	service.cfg.DPoP.SetClock(service.cfg.Now)
	signer := newDPoPSignerEd25519(t)
	deviceJWK, err := json.Marshal(signer.jwk())
	if err != nil {
		t.Fatalf("marshal device JWK: %v", err)
	}
	now := service.cfg.Now()
	bootstrap, _ := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-1", TenantID: "writer"})
	enroll, err := service.Enroll(ctx, EnrollRequest{BootstrapToken: bootstrap.Token, HardwareUUID: "hw-1", DeviceJWK: deviceJWK})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	rotated, err := service.IssueToken(ctx, TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: enroll.RefreshToken,
		DPoPProof:    makeDPoPProof(t, signer, "POST", "https://cerebro.test/platform/devices/token", now, "jti-rate-limit"),
		HTTPMethod:   "POST",
		HTTPURL:      "https://cerebro.test/platform/devices/token",
	})
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if _, err := service.RefreshTokenRateLimitKey(ctx, enroll.RefreshToken); !errors.Is(err, ErrRefreshReplay) {
		t.Fatalf("RefreshTokenRateLimitKey(consumed) err = %v, want ErrRefreshReplay", err)
	}
	if got, err := service.RefreshTokenRateLimitKey(ctx, rotated.RefreshToken); err != nil || got != "device:"+enroll.DeviceID {
		t.Fatalf("RefreshTokenRateLimitKey(live) = %q, %v; want device:%s", got, err, enroll.DeviceID)
	}
}

func TestServiceIngestTelemetryRequiresIdempotencyKey(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newServiceForTest(t)
	deviceJWK := newEnrollDeviceJWK(t)
	bootstrap, _ := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-1", TenantID: "writer"})
	enroll, _ := service.Enroll(ctx, EnrollRequest{BootstrapToken: bootstrap.Token, HardwareUUID: "hw-1", DeviceJWK: deviceJWK})
	if _, err := service.IngestTelemetry(ctx, IngestPayload{DeviceID: enroll.DeviceID, Body: []byte(`{"events":[]}`)}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("IngestTelemetry without key err = %v, want ErrInvalidRequest", err)
	}
}

func TestServiceIngestTelemetryIdempotent(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newServiceForTest(t)
	deviceJWK := newEnrollDeviceJWK(t)
	bootstrap, _ := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-1", TenantID: "writer"})
	enroll, _ := service.Enroll(ctx, EnrollRequest{BootstrapToken: bootstrap.Token, HardwareUUID: "hw-1", DeviceJWK: deviceJWK})

	body := []byte(`{"events":[{"type":"login"}]}`)
	first, err := service.IngestTelemetry(ctx, IngestPayload{DeviceID: enroll.DeviceID, IdempotencyKey: "abc-123", Body: body})
	if err != nil {
		t.Fatalf("first IngestTelemetry: %v", err)
	}
	if first.Status != 202 {
		t.Errorf("first status = %d, want 202", first.Status)
	}

	second, err := service.IngestTelemetry(ctx, IngestPayload{DeviceID: enroll.DeviceID, IdempotencyKey: "abc-123", Body: body})
	if err != nil {
		t.Fatalf("second IngestTelemetry: %v", err)
	}
	if !second.Cached {
		t.Errorf("second not cached")
	}
	if string(first.Body) != string(second.Body) {
		t.Errorf("idempotent body mismatch: %q vs %q", first.Body, second.Body)
	}

	if _, err := service.IngestTelemetry(ctx, IngestPayload{DeviceID: enroll.DeviceID, IdempotencyKey: "abc-123", Body: []byte(`{"events":[{"type":"different"}]}`)}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting body err = %v, want ErrIdempotencyConflict", err)
	}
}

func TestServiceIngestTelemetryIdempotencyPreservesBodyWhitespace(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newServiceForTest(t)
	deviceJWK := newEnrollDeviceJWK(t)
	bootstrap, _ := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-1", TenantID: "writer"})
	enroll, _ := service.Enroll(ctx, EnrollRequest{BootstrapToken: bootstrap.Token, HardwareUUID: "hw-1", DeviceJWK: deviceJWK})

	if _, err := service.IngestTelemetry(ctx, IngestPayload{DeviceID: enroll.DeviceID, IdempotencyKey: "raw-body", Body: []byte(`{}`)}); err != nil {
		t.Fatalf("first IngestTelemetry: %v", err)
	}
	if _, err := service.IngestTelemetry(ctx, IngestPayload{DeviceID: enroll.DeviceID, IdempotencyKey: "raw-body", Body: []byte("{}\n")}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("whitespace-only body change err = %v, want ErrIdempotencyConflict", err)
	}
}

func TestServiceJWKSExposesKID(t *testing.T) {
	service, _, _ := newServiceForTest(t)
	doc := EncodeJWKS(service.KeySet())
	if len(doc.Keys) != 1 {
		t.Fatalf("expected 1 JWK, got %d", len(doc.Keys))
	}
	if doc.Keys[0].KTY != "OKP" || doc.Keys[0].CRV != "Ed25519" || doc.Keys[0].Alg != "EdDSA" {
		t.Fatalf("unexpected JWK fields: %+v", doc.Keys[0])
	}
	if doc.Keys[0].KID != "test" {
		t.Errorf("kid = %q, want test", doc.Keys[0].KID)
	}
	if strings.TrimSpace(doc.Keys[0].X) == "" {
		t.Errorf("public key x is empty")
	}
}

func TestKeySetMarshalJSONDoesNotExposePrivateKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := json.Marshal(&KeySet{Keys: []SigningKey{{KID: "test", Public: pub, Private: priv}}})
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if strings.Contains(string(doc), "Private") || strings.Contains(string(doc), "Public") {
		t.Fatalf("KeySet JSON exposed internal key fields: %s", doc)
	}
	if !strings.Contains(string(doc), `"kty":"OKP"`) || !strings.Contains(string(doc), `"kid":"test"`) {
		t.Fatalf("KeySet JSON is not JWKS-shaped: %s", doc)
	}
}

func TestIssueBootstrapTokenRejectsAdminScopes(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newServiceForTest(t)
	_, err := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{
		HardwareUUID: "hw-1",
		TenantID:     "writer",
		Scopes:       []string{ScopeDevicesBootstrapWrite},
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("IssueBootstrapToken err = %v, want ErrInvalidRequest", err)
	}
}

func TestIssueBootstrapTokenRejectsTelemetryOnlyScope(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newServiceForTest(t)
	_, err := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{
		HardwareUUID: "hw-1",
		TenantID:     "writer",
		Scopes:       []string{ScopeTelemetryIngest},
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("IssueBootstrapToken err = %v, want ErrInvalidRequest", err)
	}
}

func TestEnrollFiltersLegacyBootstrapAdminScopes(t *testing.T) {
	ctx := context.Background()
	service, store, now := newServiceForTest(t)
	plaintext, err := GenerateOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateBootstrapToken(ctx, BootstrapToken{
		TokenID:      "btk-legacy",
		TokenHash:    HashToken(plaintext),
		HardwareUUID: "hw-1",
		TenantID:     "writer",
		Scopes:       []string{ScopeDevicesBootstrapWrite, ScopeTelemetryIngest},
		CreatedAt:    now,
		ExpiresAt:    now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateBootstrapToken: %v", err)
	}
	enroll, err := service.Enroll(ctx, EnrollRequest{BootstrapToken: plaintext, HardwareUUID: "hw-1", DeviceJWK: newEnrollDeviceJWK(t)})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if containsScope(enroll.Scopes, ScopeDevicesBootstrapWrite) {
		t.Fatalf("enroll propagated admin scope: %v", enroll.Scopes)
	}
	if !containsScope(enroll.Scopes, ScopeTelemetryIngest) {
		t.Fatalf("enroll dropped allowed scope: %v", enroll.Scopes)
	}
}

func TestTokenBucketAllow(t *testing.T) {
	bucket := NewTokenBucket(1, 2)
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	bucket.now = func() time.Time { return now }
	if !bucket.Allow("ip-1") {
		t.Fatal("first allow false")
	}
	if !bucket.Allow("ip-1") {
		t.Fatal("second allow false (within burst)")
	}
	if bucket.Allow("ip-1") {
		t.Fatal("third allow true (over burst)")
	}
	now = now.Add(2 * time.Second)
	if !bucket.Allow("ip-1") {
		t.Fatal("after refill allow false")
	}
}

func TestKeyDecodeRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubPEM := mustEncodePEMPublic(t, pub)
	privPEM := mustEncodePEMPrivate(t, priv)
	gotPub, err := DecodePEMPublicKey(pubPEM)
	if err != nil {
		t.Fatalf("DecodePEMPublicKey: %v", err)
	}
	if string(gotPub) != string(pub) {
		t.Errorf("public key round-trip mismatch")
	}
	gotPriv, err := DecodePEMPrivateKey(privPEM)
	if err != nil {
		t.Fatalf("DecodePEMPrivateKey: %v", err)
	}
	if string(gotPriv) != string(priv) {
		t.Errorf("private key round-trip mismatch")
	}
}

// makeEd25519JWK returns a JSON-encoded RFC 7517 Ed25519 public JWK and the
// matching RFC 7638 thumbprint, derived from the supplied public key.
func makeEd25519JWK(t *testing.T, pub ed25519.PublicKey) ([]byte, string) {
	t.Helper()
	x := base64.RawURLEncoding.EncodeToString(pub)
	jwk := []byte(`{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`)
	sum := sha256.Sum256(jwk)
	return jwk, base64.RawURLEncoding.EncodeToString(sum[:])
}

func newEnrollDeviceJWK(t *testing.T) json.RawMessage {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwk, _ := makeEd25519JWK(t, pub)
	return json.RawMessage(jwk)
}

func TestServiceEnrollAcceptsAgentSuppliedJWKAndPinsCnfJKT(t *testing.T) {
	ctx := context.Background()
	service, store, _ := newServiceForTest(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwk, wantJKT := makeEd25519JWK(t, pub)

	bootstrap, err := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-jwk", TenantID: "writer"})
	if err != nil {
		t.Fatalf("IssueBootstrapToken: %v", err)
	}
	enroll, err := service.Enroll(ctx, EnrollRequest{
		BootstrapToken: bootstrap.Token,
		HardwareUUID:   "hw-jwk",
		DeviceJWK:      json.RawMessage(jwk),
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	device, err := store.LookupDevice(ctx, enroll.DeviceID)
	if err != nil {
		t.Fatalf("LookupDevice: %v", err)
	}
	if got := device.Metadata["dpop_jkt"]; got != wantJKT {
		t.Fatalf("dpop_jkt = %q, want %q", got, wantJKT)
	}
	verified, err := service.Verifier().Verify(enroll.AccessToken)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.DPoPJKT != wantJKT {
		t.Fatalf("access token cnf.jkt = %q, want %q", verified.DPoPJKT, wantJKT)
	}
}

func TestServiceEnrollPreservesBootstrapTokenOnInvalidJWK(t *testing.T) {
	// Soft-DoS regression: a malformed device_key MUST NOT consume the
	// bootstrap token. The legitimate agent must be able to retry with a
	// fixed JWK without operator intervention.
	ctx := context.Background()
	service, _, _ := newServiceForTest(t)
	bootstrap, err := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-soft-dos", TenantID: "writer"})
	if err != nil {
		t.Fatalf("IssueBootstrapToken: %v", err)
	}
	if _, err := service.Enroll(ctx, EnrollRequest{
		BootstrapToken: bootstrap.Token,
		HardwareUUID:   "hw-soft-dos",
		DeviceJWK:      json.RawMessage(`{"kty":"RSA","n":"abc","e":"AQAB"}`),
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Enroll with RSA jwk err = %v, want ErrInvalidRequest", err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	jwk, wantJKT := makeEd25519JWK(t, pub)
	enroll, err := service.Enroll(ctx, EnrollRequest{
		BootstrapToken: bootstrap.Token,
		HardwareUUID:   "hw-soft-dos",
		DeviceJWK:      json.RawMessage(jwk),
	})
	if err != nil {
		t.Fatalf("retry Enroll after RSA reject: %v", err)
	}
	verified, err := service.Verifier().Verify(enroll.AccessToken)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.DPoPJKT != wantJKT {
		t.Fatalf("retry cnf.jkt = %q, want %q", verified.DPoPJKT, wantJKT)
	}
}

func TestServiceEnrollRejectsMalformedDeviceJWK(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newServiceForTest(t)
	cases := map[string]string{
		"not-json":    `not-json`,
		"json-array":  `["x"]`,
		"json-string": `"hello"`,
		"json-null":   `null`,
		"unknown-kty": `{"kty":"RSA","n":"abc","e":"AQAB"}`,
		"bad-curve":   `{"kty":"EC","crv":"P-521","x":"AAAA","y":"AAAA"}`,
		"bad-okp":     `{"kty":"OKP","crv":"X25519","x":"AAAA"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			bootstrap, err := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-" + name, TenantID: "writer"})
			if err != nil {
				t.Fatalf("IssueBootstrapToken: %v", err)
			}
			_, err = service.Enroll(ctx, EnrollRequest{
				BootstrapToken: bootstrap.Token,
				HardwareUUID:   "hw-" + name,
				DeviceJWK:      json.RawMessage(body),
			})
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Enroll(%s) err = %v, want ErrInvalidRequest", name, err)
			}
		})
	}
}

func TestServiceEnrollRejectsAgentJWKMismatchWithAttestation(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newServiceForTest(t)
	// Attestation reports one Ed25519 public key.
	attestedPub, _, _ := ed25519.GenerateKey(rand.Reader)
	attestedDER, err := x509.MarshalPKIXPublicKey(attestedPub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	verifier := &checkingAttestationVerifier{wantHardwareUUID: "hw-mismatch", publicKey: attestedDER}
	registry := attestation.NewRegistry(true, verifier)
	service.cfg.Attestations = registry
	bootstrap, _ := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{HardwareUUID: "hw-mismatch", TenantID: "writer"})
	verifier.wantHash = attestationClientDataHash(bootstrap.Token, "hw-mismatch")

	// Agent submits a DIFFERENT public key in device_key. Treat as attack.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	otherJWK, _ := makeEd25519JWK(t, otherPub)
	if _, err := service.Enroll(ctx, EnrollRequest{
		BootstrapToken: bootstrap.Token,
		HardwareUUID:   "hw-mismatch",
		Attestation:    "stub",
		OSType:         "darwin",
		DeviceJWK:      json.RawMessage(otherJWK),
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("mismatch Enroll err = %v, want ErrInvalidRequest", err)
	}

	// Submitting the matching key succeeds.
	matchingJWK, _ := makeEd25519JWK(t, attestedPub)
	if _, err := service.Enroll(ctx, EnrollRequest{
		BootstrapToken: bootstrap.Token,
		HardwareUUID:   "hw-mismatch",
		Attestation:    "stub",
		OSType:         "darwin",
		DeviceJWK:      json.RawMessage(matchingJWK),
	}); err != nil {
		t.Fatalf("matched Enroll err = %v, want nil", err)
	}
}

func TestNewServiceDefaultRefreshTTLIs7Days(t *testing.T) {
	store := NewMemStore()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := NewLocalSigner([]SigningKey{{KID: "test", Public: pub, Private: priv}})
	keyset := &KeySet{Keys: []SigningKey{{KID: "test", Public: pub}}}
	issuer, _ := NewJWTIssuer(IssuerConfig{}, signer)
	verifier, _ := NewJWTVerifier(VerifierConfig{}, keyset)
	service, err := NewService(ServiceConfig{}, store, issuer, verifier, keyset)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if got, want := service.cfg.RefreshTTL, 7*24*time.Hour; got != want {
		t.Fatalf("default RefreshTTL = %v, want %v", got, want)
	}
}

// newServiceWithAuditForTest mirrors newServiceForTest but installs a
// caller-supplied AuditEmitter so tests can assert on the emitted
// payload shape.
func newServiceWithAuditForTest(t *testing.T, audit AuditEmitter) (*Service, *MemStore, time.Time) {
	t.Helper()
	store := NewMemStore()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := NewLocalSigner([]SigningKey{{KID: "test", Public: pub, Private: priv}})
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	keyset := &KeySet{Keys: []SigningKey{{KID: "test", Public: pub}}}
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	store.SetClock(clock)
	issuer, _ := NewJWTIssuer(IssuerConfig{Now: clock}, signer)
	verifier, _ := NewJWTVerifier(VerifierConfig{Now: clock}, keyset)
	service, err := NewService(ServiceConfig{
		AccessTTL:         5 * time.Minute,
		RefreshTTL:        24 * time.Hour,
		BootstrapTokenTTL: time.Hour,
		IdempotencyTTL:    time.Hour,
		Now:               clock,
		Audit:             audit,
	}, store, issuer, verifier, keyset)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return service, store, now
}

// TestIssueBootstrapTokenEmitsAuditEvent pins the forensic-trail
// invariant: every successful mint MUST surface a structured audit
// event downstream so SOC tooling can correlate "token id X was
// minted by operator Y at time Z" with subsequent enrollments using
// the same token id. Hardware UUID is hashed (SHA-256, lower-hex)
// rather than logged in plaintext so long-term retention does not
// hold a raw device-correlatable identifier.
func TestIssueBootstrapTokenEmitsAuditEvent(t *testing.T) {
	ctx := context.Background()
	var captured []AuditEvent
	emit := func(_ context.Context, event AuditEvent) {
		captured = append(captured, event)
	}
	service, _, now := newServiceWithAuditForTest(t, emit)
	resp, err := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{
		HardwareUUID: "hw-audit-1",
		TenantID:     "writer",
		Scopes:       []string{ScopeDevicesToken, ScopeTelemetryIngest},
		TTL:          15 * time.Minute,
		IssuedBy:     "operator:ben",
	})
	if err != nil {
		t.Fatalf("IssueBootstrapToken: %v", err)
	}
	if len(captured) != 1 {
		t.Fatalf("audit emit count = %d, want 1", len(captured))
	}
	event := captured[0]
	if event.Kind != AuditKindBootstrapTokenIssued {
		t.Errorf("event.Kind = %q, want %q", event.Kind, AuditKindBootstrapTokenIssued)
	}
	if event.TokenID != resp.TokenID {
		t.Errorf("event.TokenID = %q, want %q", event.TokenID, resp.TokenID)
	}
	if event.IssuedBy != "operator:ben" {
		t.Errorf("event.IssuedBy = %q, want %q", event.IssuedBy, "operator:ben")
	}
	if event.TenantID != "writer" {
		t.Errorf("event.TenantID = %q, want %q", event.TenantID, "writer")
	}
	wantHash := sha256Hex("hw-audit-1")
	if event.HardwareUUIDHash != wantHash {
		t.Errorf("event.HardwareUUIDHash = %q, want %q (SHA-256(hw-audit-1))", event.HardwareUUIDHash, wantHash)
	}
	if !event.OccurredAt.Equal(now) {
		t.Errorf("event.OccurredAt = %v, want %v", event.OccurredAt, now)
	}
	if event.TTL != 15*time.Minute {
		t.Errorf("event.TTL = %v, want %v", event.TTL, 15*time.Minute)
	}
	if !event.ExpiresAt.Equal(now.Add(15 * time.Minute)) {
		t.Errorf("event.ExpiresAt = %v, want %v", event.ExpiresAt, now.Add(15*time.Minute))
	}
	if len(event.Scopes) != 2 || event.Scopes[0] != ScopeDevicesToken || event.Scopes[1] != ScopeTelemetryIngest {
		t.Errorf("event.Scopes = %v, want [%s %s]", event.Scopes, ScopeDevicesToken, ScopeTelemetryIngest)
	}
}

// TestIssueBootstrapTokenAuditEventNotEmittedOnStoreFailure pins the
// ordering invariant: the audit event MUST be emitted AFTER the
// durable store write succeeds. Otherwise SOC investigators would
// chase token ids that never actually existed.
func TestIssueBootstrapTokenAuditEventNotEmittedOnStoreFailure(t *testing.T) {
	ctx := context.Background()
	emitted := 0
	emit := func(context.Context, AuditEvent) { emitted++ }
	service, store, _ := newServiceWithAuditForTest(t, emit)
	store.SetCreateBootstrapTokenFault(errors.New("forced failure"))
	_, err := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{
		HardwareUUID: "hw-fail",
		TenantID:     "writer",
		Scopes:       []string{ScopeDevicesToken},
	})
	if err == nil {
		t.Fatal("IssueBootstrapToken returned nil error despite store fault")
	}
	if emitted != 0 {
		t.Errorf("audit emit count = %d on failed mint, want 0", emitted)
	}
}

// TestIssueBootstrapTokenAuditEmitterOptional confirms backward
// compatibility: services constructed without an Audit emitter
// continue to work unchanged.
func TestIssueBootstrapTokenAuditEmitterOptional(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newServiceForTest(t)
	if _, err := service.IssueBootstrapToken(ctx, IssueBootstrapTokenRequest{
		HardwareUUID: "hw-no-audit",
		TenantID:     "writer",
		Scopes:       []string{ScopeDevicesToken},
	}); err != nil {
		t.Fatalf("IssueBootstrapToken without audit emitter: %v", err)
	}
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
