package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/deviceauth"
	"github.com/writer/cerebro/internal/ports"
)

func newAppForDeviceTest(t *testing.T) (*App, []byte, []byte) {
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
	return app, []byte(pubPEM), []byte(privPEM)
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
	app, _, _ := newAppForDeviceTest(t)
	handler := app.Handler()

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
	enrollBody := []byte(`{"bootstrap_token":"` + bootstrap.Token + `","hardware_uuid":"hw-1","hostname":"laptop-1","os_type":"darwin"}`)
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
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusConflict {
		t.Fatalf("conflicting ingest status = %d, body=%s", resp.Code, resp.Body.String())
	}

	// Rotate the refresh token.
	rotateBody := []byte(`{"grant_type":"refresh_token","refresh_token":"` + enroll.RefreshToken + `"}`)
	req = httptest.NewRequest(http.MethodPost, "/platform/devices/token", bytes.NewReader(rotateBody))
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("token rotate status = %d, body=%s", resp.Code, resp.Body.String())
	}

	// Replay the original refresh token, expect 401.
	resp = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/platform/devices/token", bytes.NewReader(rotateBody))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), "refresh_token_replayed") {
		t.Errorf("replay body missing replay code: %s", resp.Body.String())
	}
}

func TestDeviceAuthEnrollRejectsWrongHardware(t *testing.T) {
	app, _, _ := newAppForDeviceTest(t)
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
	app, _, _ := newAppForDeviceTest(t)
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
	app, _, _ := newAppForDeviceTest(t)
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
