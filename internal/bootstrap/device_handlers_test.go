package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/deviceauth"
	"github.com/writer/cerebro/internal/deviceauth/attestation"
	"github.com/writer/cerebro/internal/ports"
)

func newAppForDeviceTest(t *testing.T) *App {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubPEM := encodePEMPublic(t, pub)
	privPEM := encodePEMPrivate(t, priv)

	cfg := config.Config{
		HTTPAddr: ":0",
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:       "operator-key",
				Principal: "ops",
				TenantID:  "writer",
			}},
			DeviceAuth: config.DeviceAuthConfig{
				Enabled:                     true,
				Issuer:                      "cerebro",
				Audience:                    "cerebro-device",
				CurrentKID:                  "test",
				EnrollPerIPRatePerSecond:    100,
				EnrollPerIPBurst:            100,
				TokenPerDeviceRatePerSecond: 100,
				TokenPerDeviceBurst:         100,
				SigningKeys: []config.DeviceAuthSigningKey{{
					KID:        "test",
					PublicPEM:  pubPEM,
					PrivatePEM: privPEM,
				}},
			},
		},
	}
	store := newDeviceAuthMemStore()
	app := New(cfg, Dependencies{StateStore: store}, nil)
	if app.deviceService == nil {
		t.Fatal("device service was not wired")
	}
	return app
}

// deviceAuthMemStore wraps deviceauth.MemStore and implements ports.StateStore
// (Ping) so it can be passed via Dependencies.
type deviceAuthMemStore struct {
	*deviceauth.MemStore
}

func newDeviceAuthMemStore() *deviceAuthMemStore {
	return &deviceAuthMemStore{MemStore: deviceauth.NewMemStore()}
}

// Ping satisfies ports.StateStore.
func (s *deviceAuthMemStore) Ping(_ context.Context) error { return nil }

var (
	_ ports.StateStore = (*deviceAuthMemStore)(nil)
	_ deviceauth.Store = (*deviceAuthMemStore)(nil)
)

func encodePEMPublic(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func encodePEMPrivate(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal priv: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestDeviceAuthEndToEnd(t *testing.T) {
	app := newAppForDeviceTest(t)
	handler := app.Handler()
	deviceKey := newTestDeviceDPoPKey(t)

	// Issue bootstrap token as an operator using the API key.
	bootstrapBody := bytes.NewBufferString(`{"hardware_uuid":"hw-1","tenant_id":"writer","ttl_seconds":3600}`)
	req := httptest.NewRequest(http.MethodPost, "/platform/devices/bootstrap-tokens", bootstrapBody)
	req.Header.Set("Authorization", "Bearer operator-key")
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusCreated {
		t.Fatalf("issue bootstrap token status = %d, body=%s", resp.Code, resp.Body.String())
	}
	var bootstrap struct {
		TokenID string `json:"token_id"`
		Token   string `json:"token"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &bootstrap); err != nil {
		t.Fatalf("decode bootstrap response: %v", err)
	}
	if bootstrap.Token == "" {
		t.Fatal("bootstrap token empty")
	}

	// Enroll the device (no auth header; route is public).
	enrollBody := []byte(`{"bootstrap_token":"` + bootstrap.Token + `","hardware_uuid":"hw-1","hostname":"laptop-1","os_type":"darwin","device_key":` + deviceKey.jwkJSON + `}`)
	req = httptest.NewRequest(http.MethodPost, "/platform/devices/enroll", bytes.NewReader(enrollBody))
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("enroll status = %d, body=%s", resp.Code, resp.Body.String())
	}
	var enroll struct {
		AccessToken  string   `json:"access_token"`
		RefreshToken string   `json:"refresh_token"`
		DeviceID     string   `json:"device_id"`
		Scopes       []string `json:"scopes"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &enroll); err != nil {
		t.Fatalf("decode enroll: %v", err)
	}
	if enroll.AccessToken == "" || enroll.RefreshToken == "" || enroll.DeviceID == "" {
		t.Fatalf("enroll missing fields: %+v", enroll)
	}
	if !containsString(enroll.Scopes, deviceauth.ScopeTelemetryIngest) {
		t.Errorf("scopes do not include telemetry ingest: %v", enroll.Scopes)
	}

	// Use the access token to ingest telemetry (idempotent).
	telemetry := []byte(`{"events":[{"type":"login","ts":"2026-05-22T12:00:00Z"}]}`)
	req = httptest.NewRequest(http.MethodPost, "/platform/telemetry/ingest", bytes.NewReader(telemetry))
	req.Header.Set("Authorization", "Bearer "+enroll.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "abc-123")
	setDPoPHeader(t, req, deviceKey, "ingest-1", enroll.AccessToken)
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusAccepted {
		t.Fatalf("ingest status = %d, body=%s", resp.Code, resp.Body.String())
	}
	firstBody := resp.Body.String()

	resp = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/platform/telemetry/ingest", bytes.NewReader(telemetry))
	req.Header.Set("Authorization", "Bearer "+enroll.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "abc-123")
	setDPoPHeader(t, req, deviceKey, "ingest-2", enroll.AccessToken)
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusAccepted {
		t.Fatalf("idempotent ingest status = %d", resp.Code)
	}
	if resp.Header().Get("Idempotent-Replayed") != "true" {
		t.Errorf("Idempotent-Replayed header missing on replay")
	}
	if resp.Body.String() != firstBody {
		t.Errorf("idempotent body mismatch")
	}

	// Conflicting body with the same idempotency key returns 409.
	conflictBody := []byte(`{"events":[{"type":"different"}]}`)
	resp = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/platform/telemetry/ingest", bytes.NewReader(conflictBody))
	req.Header.Set("Authorization", "Bearer "+enroll.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "abc-123")
	setDPoPHeader(t, req, deviceKey, "ingest-3", enroll.AccessToken)
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusConflict {
		t.Fatalf("conflicting ingest status = %d, body=%s", resp.Code, resp.Body.String())
	}

	// Rotate the refresh token.
	rotateBody := []byte(`{"grant_type":"refresh_token","refresh_token":"` + enroll.RefreshToken + `"}`)
	req = httptest.NewRequest(http.MethodPost, "/platform/devices/token", bytes.NewReader(rotateBody))
	req.Header.Set("Content-Type", "application/json")
	setDPoPHeader(t, req, deviceKey, "token-1", "")
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("token rotate status = %d, body=%s", resp.Code, resp.Body.String())
	}

	// Replay the original refresh token, expect 401.
	resp = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/platform/devices/token", bytes.NewReader(rotateBody))
	req.Header.Set("Content-Type", "application/json")
	setDPoPHeader(t, req, deviceKey, "token-2", "")
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), "refresh_token_replayed") {
		t.Errorf("replay body missing replay code: %s", resp.Body.String())
	}
}

func TestDeviceAuthRevokeNormalizesForeignDeviceLookup(t *testing.T) {
	app := newAppForDeviceTest(t)
	handler := app.Handler()
	ctx := context.Background()
	deviceKey := newTestDeviceDPoPKey(t)

	bootstrap, err := app.deviceService.IssueBootstrapToken(ctx, deviceauth.IssueBootstrapTokenRequest{
		HardwareUUID: "hw-security",
		TenantID:     "security",
	})
	if err != nil {
		t.Fatalf("IssueBootstrapToken: %v", err)
	}
	enroll, err := app.deviceService.Enroll(ctx, deviceauth.EnrollRequest{
		BootstrapToken: bootstrap.Token,
		HardwareUUID:   "hw-security",
		DeviceJWK:      json.RawMessage(deviceKey.jwkJSON),
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/platform/devices/"+enroll.DeviceID+"/revoke", bytes.NewBufferString(`{"reason":"test"}`))
	req.Header.Set("Authorization", "Bearer operator-key")
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("revoke status = %d, body=%s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "device_not_found") {
		t.Fatalf("revoke body = %s, want device_not_found", resp.Body.String())
	}
	device, err := app.deviceService.LookupDevice(ctx, enroll.DeviceID)
	if err != nil {
		t.Fatalf("LookupDevice: %v", err)
	}
	if device.Status == "revoked" {
		t.Fatal("cross-tenant revoke changed target device status")
	}
}

func TestDeviceAuthIssueBootstrapTokenRejectsNegativeTTLSeconds(t *testing.T) {
	app := newAppForDeviceTest(t)
	handler := app.Handler()

	req := httptest.NewRequest(http.MethodPost, "/platform/devices/bootstrap-tokens", bytes.NewBufferString(`{"hardware_uuid":"hw-neg","tenant_id":"writer","ttl_seconds":-1}`))
	req.Header.Set("Authorization", "Bearer operator-key")
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("bootstrap token status = %d, body=%s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "invalid_request") {
		t.Fatalf("bootstrap token body = %s, want invalid_request", resp.Body.String())
	}
}

func TestNewWithErrorFailsDeviceAuthWhenAPIAuthDisabled(t *testing.T) {
	_, err := NewWithError(config.Config{
		Auth: config.AuthConfig{
			Enabled: false,
			DeviceAuth: config.DeviceAuthConfig{
				Enabled: true,
			},
		},
	}, Dependencies{StateStore: newDeviceAuthMemStore()}, nil)
	if !errors.Is(err, errDeviceAuthRequiresAPIAuth) {
		t.Fatalf("NewWithError err = %v, want API auth requirement", err)
	}
}

func TestNewWithErrorFailsDeviceAuthWithoutStore(t *testing.T) {
	_, err := NewWithError(config.Config{
		Auth: config.AuthConfig{
			Enabled: true,
			DeviceAuth: config.DeviceAuthConfig{
				Enabled: true,
			},
		},
	}, Dependencies{}, nil)
	if !errors.Is(err, errDeviceAuthRequiresStore) {
		t.Fatalf("NewWithError err = %v, want device-auth store requirement", err)
	}
}

func TestNewWithErrorRejectsDeviceAuthMultipleReplicasWithInProcessDPoP(t *testing.T) {
	_, err := NewWithError(config.Config{
		Auth: config.AuthConfig{
			Enabled: true,
			DeviceAuth: config.DeviceAuthConfig{
				Enabled:      true,
				ReplicaCount: 2,
			},
		},
	}, Dependencies{StateStore: newDeviceAuthMemStore()}, nil)
	if !errors.Is(err, errDeviceAuthRequiresSharedDPoPReplay) {
		t.Fatalf("NewWithError err = %v, want shared DPoP replay requirement", err)
	}
}

func TestBuildAttestationRegistryRejectsRequiredWithoutVerifier(t *testing.T) {
	_, err := buildAttestationRegistry(config.DeviceAuthConfig{
		Attestation: config.DeviceAuthAttestationConfig{Required: true},
	})
	if err == nil {
		t.Fatal("buildAttestationRegistry error = nil, want non-nil")
	}
}

func TestNewWithErrorRejectsMismatchedDeviceAuthSigningKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate public key: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	_, err = NewWithError(config.Config{
		Auth: config.AuthConfig{
			Enabled: true,
			DeviceAuth: config.DeviceAuthConfig{
				Enabled:    true,
				CurrentKID: "test",
				SigningKeys: []config.DeviceAuthSigningKey{{
					KID:        "test",
					PublicPEM:  encodePEMPublic(t, pub),
					PrivatePEM: encodePEMPrivate(t, priv),
				}},
			},
		},
	}, Dependencies{StateStore: newDeviceAuthMemStore()}, nil)
	if !errors.Is(err, deviceauth.ErrSigningKeyMismatch) {
		t.Fatalf("NewWithError err = %v, want public/private mismatch", err)
	}
}

func TestWriteDeviceAuthServiceErrorMapsAttestationFailures(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "required", err: attestation.ErrAttestationRequired, status: http.StatusBadRequest, code: "attestation_required"},
		{name: "unsupported", err: attestation.ErrUnsupportedFormat, status: http.StatusBadRequest, code: "unsupported_attestation"},
		{name: "invalid statement", err: attestation.ErrInvalidStatement, status: http.StatusBadRequest, code: "invalid_attestation"},
		{name: "invalid chain", err: attestation.ErrChainInvalid, status: http.StatusBadRequest, code: "invalid_attestation"},
		{name: "nonce mismatch", err: attestation.ErrNonceMismatch, status: http.StatusBadRequest, code: "invalid_attestation"},
		{name: "dpop verifier unavailable", err: deviceauth.ErrDPoPVerifierUnavailable, status: http.StatusServiceUnavailable, code: "dpop_unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := httptest.NewRecorder()
			writeDeviceAuthServiceError(resp, tt.err)
			if resp.Code != tt.status {
				t.Fatalf("status = %d, want %d; body=%s", resp.Code, tt.status, resp.Body.String())
			}
			var body map[string]string
			if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if body["error"] != tt.code {
				t.Fatalf("error code = %q, want %q; body=%s", body["error"], tt.code, resp.Body.String())
			}
		})
	}
}

func TestAuthMiddlewareRejectsBoundDeviceTokenWhenDPoPVerifierUnavailable(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := deviceauth.NewLocalSigner([]deviceauth.SigningKey{{KID: "k1", Public: pub, Private: priv}})
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	keyset := &deviceauth.KeySet{Keys: []deviceauth.SigningKey{{KID: "k1", Public: pub}}}
	clock := func() time.Time { return time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC) }
	issuer, err := deviceauth.NewJWTIssuer(deviceauth.IssuerConfig{Now: clock}, signer)
	if err != nil {
		t.Fatalf("NewJWTIssuer: %v", err)
	}
	verifier, err := deviceauth.NewJWTVerifier(deviceauth.VerifierConfig{Now: clock}, keyset)
	if err != nil {
		t.Fatalf("NewJWTVerifier: %v", err)
	}
	token, err := issuer.IssueAccessWithOptions(
		deviceauth.DeviceRecord{DeviceID: "dev-1", TenantID: "writer", HardwareUUID: "hw-1"},
		[]string{deviceauth.ScopeTelemetryIngest},
		deviceauth.AccessOptions{DPoPJKT: "expected-jkt"},
	)
	if err != nil {
		t.Fatalf("IssueAccessWithOptions: %v", err)
	}
	handler := authMiddleware(config.AuthConfig{Enabled: true}, AuthDependencies{
		DeviceVerifier: verifier,
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called without a DPoP verifier")
	}))

	req := httptest.NewRequest(http.MethodPost, "/platform/telemetry/ingest", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", resp.Code, resp.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["error"] != "dpop_unavailable" {
		t.Fatalf("error = %q, want dpop_unavailable; body=%s", body["error"], resp.Body.String())
	}
}

func TestAuthMiddlewarePreservesDPoPErrorCodes(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := deviceauth.NewLocalSigner([]deviceauth.SigningKey{{KID: "k1", Public: pub, Private: priv}})
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	keyset := &deviceauth.KeySet{Keys: []deviceauth.SigningKey{{KID: "k1", Public: pub}}}
	clock := func() time.Time { return time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC) }
	issuer, err := deviceauth.NewJWTIssuer(deviceauth.IssuerConfig{Now: clock}, signer)
	if err != nil {
		t.Fatalf("NewJWTIssuer: %v", err)
	}
	verifier, err := deviceauth.NewJWTVerifier(deviceauth.VerifierConfig{Now: clock}, keyset)
	if err != nil {
		t.Fatalf("NewJWTVerifier: %v", err)
	}
	token, err := issuer.IssueAccessWithOptions(
		deviceauth.DeviceRecord{DeviceID: "dev-1", TenantID: "writer", HardwareUUID: "hw-1"},
		[]string{deviceauth.ScopeTelemetryIngest},
		deviceauth.AccessOptions{DPoPJKT: "expected-jkt"},
	)
	if err != nil {
		t.Fatalf("IssueAccessWithOptions: %v", err)
	}
	dpop := deviceauth.NewDPoPVerifier(time.Minute, time.Minute)
	dpop.SetClock(clock)
	handler := authMiddleware(config.AuthConfig{Enabled: true}, AuthDependencies{
		DeviceVerifier: verifier,
		DPoPVerifier:   dpop,
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called without DPoP proof")
	}))

	req := httptest.NewRequest(http.MethodPost, "/platform/telemetry/ingest", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", resp.Code, resp.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["error"] != "dpop_required" {
		t.Fatalf("error = %q, want dpop_required; body=%s", body["error"], resp.Body.String())
	}
}

func TestTelemetryIngestRejectsMalformedBodies(t *testing.T) {
	app := newAppForDeviceTest(t)
	handler := app.Handler()
	deviceKey := newTestDeviceDPoPKey(t)
	bootstrap, err := app.deviceService.IssueBootstrapToken(context.Background(), deviceauth.IssueBootstrapTokenRequest{
		HardwareUUID: "hw-json",
		TenantID:     "writer",
	})
	if err != nil {
		t.Fatalf("IssueBootstrapToken: %v", err)
	}
	enroll, err := app.deviceService.Enroll(context.Background(), deviceauth.EnrollRequest{
		BootstrapToken: bootstrap.Token,
		HardwareUUID:   "hw-json",
		DeviceJWK:      json.RawMessage(deviceKey.jwkJSON),
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	for i, body := range []string{"", "not-json", "[]", "null"} {
		req := httptest.NewRequest(http.MethodPost, "/platform/telemetry/ingest", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+enroll.AccessToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "telemetry-json-"+body)
		setDPoPHeader(t, req, deviceKey, fmt.Sprintf("telemetry-json-%d", i), enroll.AccessToken)
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		if resp.Code != http.StatusBadRequest {
			t.Fatalf("body %q status = %d, want 400; response=%s", body, resp.Code, resp.Body.String())
		}
	}
}

func TestRemoteIPForRateLimitIgnoresClientForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/platform/devices/enroll", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.200")
	if got := remoteIPForRateLimit(req); got != "198.51.100.10" {
		t.Fatalf("remoteIPForRateLimit = %q, want RemoteAddr host", got)
	}
}

func TestRemoteIPForRateLimitIgnoresForwardedForFromPrivateRemote(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/platform/devices/enroll", nil)
	req.RemoteAddr = "10.0.1.20:443"
	req.Header.Set("X-Forwarded-For", "203.0.113.200, 10.0.1.20")
	if got := remoteIPForRateLimit(req); got != "10.0.1.20" {
		t.Fatalf("remoteIPForRateLimit = %q, want RemoteAddr host", got)
	}
}

func TestRemoteIPForRateLimitIgnoresSpoofedLeftmostForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/platform/devices/enroll", nil)
	req.RemoteAddr = "10.0.1.20:443"
	req.Header.Set("X-Forwarded-For", "198.51.100.99, 203.0.113.200, 10.0.1.20")
	if got := remoteIPForRateLimit(req); got != "10.0.1.20" {
		t.Fatalf("remoteIPForRateLimit = %q, want RemoteAddr host", got)
	}
}

func TestDeviceAuthTokenLimiterUsesStableDeviceKey(t *testing.T) {
	app := newAppForDeviceTest(t)
	handler := app.Handler()
	deviceKey := newTestDeviceDPoPKey(t)

	req := httptest.NewRequest(http.MethodPost, "/platform/devices/bootstrap-tokens", bytes.NewBufferString(`{"hardware_uuid":"hw-1","tenant_id":"writer","ttl_seconds":3600}`))
	req.Header.Set("Authorization", "Bearer operator-key")
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusCreated {
		t.Fatalf("issue bootstrap token status = %d, body=%s", resp.Code, resp.Body.String())
	}
	var bootstrap struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &bootstrap); err != nil {
		t.Fatalf("decode bootstrap response: %v", err)
	}

	req = httptest.NewRequest(http.MethodPost, "/platform/devices/enroll", bytes.NewBufferString(`{"bootstrap_token":"`+bootstrap.Token+`","hardware_uuid":"hw-1","device_key":`+deviceKey.jwkJSON+`}`))
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("enroll status = %d, body=%s", resp.Code, resp.Body.String())
	}
	var enroll struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &enroll); err != nil {
		t.Fatalf("decode enroll: %v", err)
	}

	limiter := deviceauth.NewTokenBucket(100, 1)
	now := time.Now()
	limiter.SetClockForTest(func() time.Time { return now })
	app.deviceHandler.tokenLimit = limiter

	rotateBody := []byte(`{"grant_type":"refresh_token","refresh_token":"` + enroll.RefreshToken + `"}`)
	req = httptest.NewRequest(http.MethodPost, "/platform/devices/token", bytes.NewReader(rotateBody))
	req.Header.Set("Content-Type", "application/json")
	setDPoPHeader(t, req, deviceKey, "limit-token-1", "")
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("first token rotate status = %d, body=%s", resp.Code, resp.Body.String())
	}
	var rotated struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &rotated); err != nil {
		t.Fatalf("decode rotate: %v", err)
	}
	rotateBody = []byte(`{"grant_type":"refresh_token","refresh_token":"` + rotated.RefreshToken + `"}`)
	req = httptest.NewRequest(http.MethodPost, "/platform/devices/token", bytes.NewReader(rotateBody))
	req.Header.Set("Content-Type", "application/json")
	setDPoPHeader(t, req, deviceKey, "limit-token-2", "")
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusTooManyRequests {
		t.Fatalf("second token rotate status = %d, want 429; body=%s", resp.Code, resp.Body.String())
	}
}

func TestDeviceAuthEnrollRejectsWrongHardware(t *testing.T) {
	app := newAppForDeviceTest(t)
	handler := app.Handler()

	req := httptest.NewRequest(http.MethodPost, "/platform/devices/bootstrap-tokens", bytes.NewBufferString(`{"hardware_uuid":"hw-1","tenant_id":"writer"}`))
	req.Header.Set("Authorization", "Bearer operator-key")
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusCreated {
		t.Fatalf("bootstrap status = %d", resp.Code)
	}
	var bootstrap struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(resp.Body.Bytes(), &bootstrap)

	req = httptest.NewRequest(http.MethodPost, "/platform/devices/enroll", bytes.NewBufferString(`{"bootstrap_token":"`+bootstrap.Token+`","hardware_uuid":"hw-DIFFERENT"}`))
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("enroll wrong hw status = %d, want 401", resp.Code)
	}
}

func TestDeviceAuthJWKSReturnsCurrentKey(t *testing.T) {
	app := newAppForDeviceTest(t)
	handler := app.Handler()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/device-jwks.json", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("jwks status = %d, body=%s", resp.Code, resp.Body.String())
	}
	var doc struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(doc.Keys) == 0 || doc.Keys[0]["kid"] != "test" {
		t.Fatalf("unexpected jwks: %+v", doc)
	}
}

func TestDeviceAuthIngestRequiresDeviceJWT(t *testing.T) {
	app := newAppForDeviceTest(t)
	handler := app.Handler()

	req := httptest.NewRequest(http.MethodPost, "/platform/telemetry/ingest", bytes.NewBufferString(`{}`))
	req.Header.Set("Authorization", "Bearer operator-key")
	req.Header.Set("Idempotency-Key", "abc")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("ingest with non-device principal status = %d, want 403", resp.Code)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// TestDeviceAuthEnrollAndTokenSetNoStoreHeaders verifies that enroll, token,
// and bootstrap-token mint set the Cache-Control / Pragma no-store headers
// required by RFC 6749 §5.1 to prevent intermediate caches from holding
// access / refresh / bootstrap secret material.
func TestDeviceAuthEnrollAndTokenSetNoStoreHeaders(t *testing.T) {
	app := newAppForDeviceTest(t)
	handler := app.Handler()
	deviceKey := newTestDeviceDPoPKey(t)

	bootstrapBody := bytes.NewBufferString(`{"hardware_uuid":"hw-no-store","tenant_id":"writer","ttl_seconds":3600}`)
	req := httptest.NewRequest(http.MethodPost, "/platform/devices/bootstrap-tokens", bootstrapBody)
	req.Header.Set("Authorization", "Bearer operator-key")
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusCreated {
		t.Fatalf("bootstrap-token mint status = %d, body=%s", resp.Code, resp.Body.String())
	}
	assertNoStoreHeaders(t, "POST /platform/devices/bootstrap-tokens", resp.Header())
	var bootstrap struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &bootstrap); err != nil {
		t.Fatalf("decode bootstrap response: %v", err)
	}

	enrollBody := []byte(`{"bootstrap_token":"` + bootstrap.Token + `","hardware_uuid":"hw-no-store","os_type":"darwin","device_key":` + deviceKey.jwkJSON + `}`)
	req = httptest.NewRequest(http.MethodPost, "/platform/devices/enroll", bytes.NewReader(enrollBody))
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("enroll status = %d, body=%s", resp.Code, resp.Body.String())
	}
	assertNoStoreHeaders(t, "POST /platform/devices/enroll", resp.Header())
	var enroll struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &enroll); err != nil {
		t.Fatalf("decode enroll: %v", err)
	}

	rotateBody := []byte(`{"grant_type":"refresh_token","refresh_token":"` + enroll.RefreshToken + `"}`)
	req = httptest.NewRequest(http.MethodPost, "/platform/devices/token", bytes.NewReader(rotateBody))
	req.Header.Set("Content-Type", "application/json")
	setDPoPHeader(t, req, deviceKey, "no-store-token", "")
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("token rotate status = %d, body=%s", resp.Code, resp.Body.String())
	}
	assertNoStoreHeaders(t, "POST /platform/devices/token", resp.Header())
}

func assertNoStoreHeaders(t *testing.T, where string, h http.Header) {
	t.Helper()
	if got := h.Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Errorf("%s Cache-Control = %q, want to contain no-store", where, got)
	}
	if got := h.Get("Pragma"); got != "no-cache" {
		t.Errorf("%s Pragma = %q, want no-cache", where, got)
	}
}

// TestDeviceAuthEnrollAcceptsAgentDeviceKey verifies that an agent that
// supplies a device_key in the enrollment body gets a sender-constrained
// access token whose cnf.jkt matches the supplied key, while malformed
// device_key input is rejected without consuming the bootstrap token.
func TestDeviceAuthEnrollAcceptsAgentDeviceKey(t *testing.T) {
	app := newAppForDeviceTest(t)
	handler := app.Handler()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwkBody := `{"crv":"Ed25519","kty":"OKP","x":"` + base64Raw(pub) + `"}`

	bootstrapBody := bytes.NewBufferString(`{"hardware_uuid":"hw-jwk-e2e","tenant_id":"writer","ttl_seconds":3600}`)
	req := httptest.NewRequest(http.MethodPost, "/platform/devices/bootstrap-tokens", bootstrapBody)
	req.Header.Set("Authorization", "Bearer operator-key")
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusCreated {
		t.Fatalf("bootstrap status = %d", resp.Code)
	}
	var bootstrap struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &bootstrap); err != nil {
		t.Fatalf("decode bootstrap response: %v", err)
	}

	enrollBody := []byte(`{"bootstrap_token":"` + bootstrap.Token +
		`","hardware_uuid":"hw-jwk-e2e","os_type":"darwin","device_key":` + jwkBody + `}`)
	req = httptest.NewRequest(http.MethodPost, "/platform/devices/enroll", bytes.NewReader(enrollBody))
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("enroll status = %d, body=%s", resp.Code, resp.Body.String())
	}
	var enroll struct {
		AccessToken string `json:"access_token"`
		DeviceID    string `json:"device_id"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &enroll); err != nil {
		t.Fatalf("decode enroll: %v", err)
	}
	verifier := app.deviceService.Verifier()
	tok, err := verifier.Verify(enroll.AccessToken)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	if tok.DPoPJKT == "" {
		t.Fatal("access token cnf.jkt is empty; expected sender-constrained binding")
	}
	wantJKT := jwkThumbprint(jwkBody)
	if tok.DPoPJKT != wantJKT {
		t.Fatalf("cnf.jkt = %q, want %q", tok.DPoPJKT, wantJKT)
	}

	// Reject RSA out-of-band: bootstrap is preserved on a malformed JWK.
	rsaBootstrapBody := bytes.NewBufferString(`{"hardware_uuid":"hw-rsa-reject","tenant_id":"writer","ttl_seconds":3600}`)
	req = httptest.NewRequest(http.MethodPost, "/platform/devices/bootstrap-tokens", rsaBootstrapBody)
	req.Header.Set("Authorization", "Bearer operator-key")
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusCreated {
		t.Fatalf("rsa bootstrap status = %d", resp.Code)
	}
	var rsaBootstrap struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &rsaBootstrap); err != nil {
		t.Fatalf("decode rsa bootstrap: %v", err)
	}
	rsaEnroll := []byte(`{"bootstrap_token":"` + rsaBootstrap.Token +
		`","hardware_uuid":"hw-rsa-reject","os_type":"darwin","device_key":{"kty":"RSA","n":"abc","e":"AQAB"}}`)
	req = httptest.NewRequest(http.MethodPost, "/platform/devices/enroll", bytes.NewReader(rsaEnroll))
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("rsa enroll status = %d, want 400; body=%s", resp.Code, resp.Body.String())
	}
	// Retry with a valid Ed25519 jwk -- bootstrap must still be live.
	retry := []byte(`{"bootstrap_token":"` + rsaBootstrap.Token +
		`","hardware_uuid":"hw-rsa-reject","os_type":"darwin","device_key":` + jwkBody + `}`)
	req = httptest.NewRequest(http.MethodPost, "/platform/devices/enroll", bytes.NewReader(retry))
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("retry enroll status = %d, want 200 (bootstrap should not have been consumed); body=%s", resp.Code, resp.Body.String())
	}
}

type testDeviceDPoPKey struct {
	jwkJSON string
	jwk     map[string]string
	private ed25519.PrivateKey
}

func newTestDeviceDPoPKey(t *testing.T) testDeviceDPoPKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwk := map[string]string{
		"crv": "Ed25519",
		"kty": "OKP",
		"x":   base64Raw(pub),
	}
	raw, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	return testDeviceDPoPKey{jwkJSON: string(raw), jwk: jwk, private: priv}
}

func setDPoPHeader(t *testing.T, req *http.Request, key testDeviceDPoPKey, jti string, accessToken string) {
	t.Helper()
	req.Header.Set("DPoP", makeTestDPoPProof(t, key, req.Method, testRequestHTU(req), jti, accessToken))
}

func testRequestHTU(req *http.Request) string {
	if req.URL.IsAbs() {
		return req.URL.String()
	}
	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	return scheme + "://" + host + req.URL.RequestURI()
}

func makeTestDPoPProof(t *testing.T, key testDeviceDPoPKey, method string, htu string, jti string, accessToken string) string {
	t.Helper()
	header := map[string]any{
		"typ": "dpop+jwt",
		"alg": "EdDSA",
		"jwk": key.jwk,
	}
	payload := map[string]any{
		"htm": method,
		"htu": htu,
		"iat": time.Now().UTC().Unix(),
		"jti": jti,
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		payload["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal DPoP header: %v", err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal DPoP payload: %v", err)
	}
	signingInput := base64Raw(headerJSON) + "." + base64Raw(payloadJSON)
	signature := ed25519.Sign(key.private, []byte(signingInput))
	return signingInput + "." + base64Raw(signature)
}

func base64Raw(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func jwkThumbprint(jwkJSON string) string {
	sum := sha256.Sum256([]byte(jwkJSON))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
