package bootstrap

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/connectorcredentials"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type connectorTestStore struct {
	*stubRuntimeStore
	credentials map[string]*ports.ConnectorCredentialRecord
}

func (s *connectorTestStore) PutConnectorCredential(_ context.Context, record *ports.ConnectorCredentialRecord) error {
	if s.credentials == nil {
		s.credentials = map[string]*ports.ConnectorCredentialRecord{}
	}
	cloned := *record
	cloned.Sealed = append([]byte{}, record.Sealed...)
	cloned.CreatedAt = time.Now().UTC()
	cloned.UpdatedAt = cloned.CreatedAt
	s.credentials[record.ID] = &cloned
	return nil
}

func (s *connectorTestStore) GetConnectorCredential(_ context.Context, id string) (*ports.ConnectorCredentialRecord, error) {
	record, ok := s.credentials[id]
	if !ok {
		return nil, ports.ErrConnectorCredentialNotFound
	}
	cloned := *record
	cloned.Sealed = append([]byte{}, record.Sealed...)
	return &cloned, nil
}

func TestConnectorConnectionStoresCredentialReference(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{}}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		ConnectorCredentials: config.ConnectorCredentialConfig{
			Key:               "test-connector-vault-key",
			TransitPrivateKey: testConnectorTransitPrivateKeyPEM(t),
		},
	}, Dependencies{StateStore: store}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	key := app.connectorTransitKey.PublicKey()
	encrypted, err := encryptConnectorCredentialsForTestWithAAD(
		key,
		map[string]string{"token": "secret-token"},
		connectorCredentialAdditionalData(key.KeyID, "bootstrap_token", "tenant-a", "runtime-a", defaultConnectorCredentialStoreID),
	)
	if err != nil {
		t.Fatalf("encrypt credentials: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"runtime_id":            "runtime-a",
		"tenant_id":             "tenant-a",
		"credential_store_id":   defaultConnectorCredentialStoreID,
		"config":                map[string]string{"family": "audit"},
		"encrypted_credentials": encrypted,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	resp, err := server.Client().Post(server.URL+"/connectors/bootstrap_token/connections", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /connectors/{sourceID}/connections error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /connectors status = %d, want 200", resp.StatusCode)
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	runtimePayload, ok := payload["runtime"].(map[string]any)
	if !ok {
		t.Fatalf("runtime payload = %#v", payload["runtime"])
	}
	configPayload, ok := runtimePayload["config"].(map[string]any)
	if !ok {
		t.Fatalf("runtime config payload = %#v", runtimePayload["config"])
	}
	if got := configPayload["token"]; got != "[redacted]" {
		t.Fatalf("response token = %#v, want [redacted]", got)
	}
	credentialPayload, ok := payload["credential"].(map[string]any)
	if !ok {
		t.Fatalf("credential payload = %#v", payload["credential"])
	}
	if got := credentialPayload["credential_store_id"]; got != defaultConnectorCredentialStoreID {
		t.Fatalf("credential_store_id = %#v, want %q", got, defaultConnectorCredentialStoreID)
	}
	runtime := store.runtimes["runtime-a"]
	if runtime == nil {
		t.Fatal("stored runtime missing")
	}
	if got := runtime.GetConfig()["token"]; !strings.HasPrefix(got, "credential:") {
		t.Fatalf("stored runtime token = %q, want credential reference", got)
	}
	if strings.Contains(runtime.GetConfig()["token"], "secret-token") {
		t.Fatalf("stored runtime token leaked secret: %q", runtime.GetConfig()["token"])
	}
	if source.checkToken != "secret-token" {
		t.Fatalf("source check token = %q, want decrypted secret", source.checkToken)
	}
}

func TestConnectorConnectionRejectsPlaintextSensitiveConfig(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{}}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		ConnectorCredentials: config.ConnectorCredentialConfig{
			Key:               "test-connector-vault-key",
			TransitPrivateKey: testConnectorTransitPrivateKeyPEM(t),
		},
	}, Dependencies{StateStore: store}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	body := []byte(`{"runtime_id":"runtime-a","tenant_id":"tenant-a","config":{"token":"secret-token"}}`)
	resp, err := server.Client().Post(server.URL+"/connectors/bootstrap_token/connections", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /connectors plaintext config error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /connectors plaintext status = %d, want 400", resp.StatusCode)
	}
}

func TestConnectorConnectionRejectsLegacyAADEncryptedSubmission(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{}}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		ConnectorCredentials: config.ConnectorCredentialConfig{
			Key:               "test-connector-vault-key",
			TransitPrivateKey: testConnectorTransitPrivateKeyPEM(t),
		},
	}, Dependencies{StateStore: store}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	key := app.connectorTransitKey.PublicKey()
	encrypted, err := encryptConnectorCredentialsForTest(key, map[string]string{"token": "secret-token"})
	if err != nil {
		t.Fatalf("encrypt credentials: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"runtime_id":            "runtime-a",
		"tenant_id":             "tenant-a",
		"auth_method":           connectorAuthMethodEncryptedSubmission,
		"credential_store_id":   defaultConnectorCredentialStoreID,
		"config":                map[string]string{"family": "audit"},
		"encrypted_credentials": encrypted,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	resp, err := server.Client().Post(server.URL+"/connectors/bootstrap_token/connections", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /connectors legacy AAD error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /connectors legacy AAD status = %d, want 400", resp.StatusCode)
	}
	if source.checkToken != "" {
		t.Fatalf("source check token = %q, want no source check", source.checkToken)
	}
	if len(store.runtimes) != 0 {
		t.Fatalf("stored runtimes len = %d, want 0", len(store.runtimes))
	}
	if len(store.credentials) != 0 {
		t.Fatalf("stored credentials len = %d, want 0", len(store.credentials))
	}
}

func TestConnectorConnectionRejectsUnsupportedCredentialStore(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		ConnectorCredentials: config.ConnectorCredentialConfig{
			Key:               "test-connector-vault-key",
			TransitPrivateKey: testConnectorTransitPrivateKeyPEM(t),
		},
	}, Dependencies{StateStore: &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{}}}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	body := []byte(`{"runtime_id":"runtime-a","tenant_id":"tenant-a","credential_store_id":"google_secret_manager","encrypted_credentials":{"key_id":"ignored","algorithm":"RSA-OAEP-256+A256GCM"}}`)
	resp, err := server.Client().Post(server.URL+"/connectors/bootstrap_token/connections", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /connectors unsupported credential store error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /connectors unsupported credential store status = %d, want 400", resp.StatusCode)
	}
}

func TestConnectorCatalogAdvertisesConnectionMethods(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		ConnectorCredentials: config.ConnectorCredentialConfig{
			Key:               "test-connector-vault-key",
			TransitPrivateKey: testConnectorTransitPrivateKeyPEM(t),
		},
	}, Dependencies{StateStore: &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{}}}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/connectors")
	if err != nil {
		t.Fatalf("GET /connectors error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /connectors status = %d, want 200", resp.StatusCode)
	}
	var payload struct {
		Connectors []struct {
			SourceID          string `json:"source_id"`
			DisplayName       string `json:"display_name"`
			ConnectionMethods []struct {
				ID       string `json:"id"`
				Saveable bool   `json:"saveable"`
			} `json:"connection_methods"`
		} `json:"connectors"`
		CredentialStores []struct {
			ID        string `json:"id"`
			Available bool   `json:"available"`
		} `json:"credential_stores"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Connectors) != 1 {
		t.Fatalf("connectors len = %d, want 1", len(payload.Connectors))
	}
	if got := payload.Connectors[0].DisplayName; got != "Bootstrap token source" {
		t.Fatalf("display_name = %q, want fallback source name", got)
	}
	methods := map[string]bool{}
	for _, method := range payload.Connectors[0].ConnectionMethods {
		methods[method.ID] = method.Saveable
	}
	if !methods[connectorAuthMethodEncryptedSubmission] {
		t.Fatalf("encrypted submission method not saveable: %#v", methods)
	}
	if !methods[connectorAuthMethodEnvironmentManaged] {
		t.Fatalf("environment-managed method not saveable: %#v", methods)
	}
	stores := map[string]bool{}
	for _, store := range payload.CredentialStores {
		stores[store.ID] = store.Available
	}
	if !stores[connectorStoreEnvironmentManaged] {
		t.Fatalf("environment-managed store not advertised available: %#v", stores)
	}
}

func TestConnectorDetailSummarizesOperationsWithoutConfig(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	now := time.Date(2026, 6, 15, 16, 0, 0, 0, time.UTC)
	store := &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"runtime-a": {
			Id:           "runtime-a",
			SourceId:     "bootstrap_token",
			TenantId:     "tenant-a",
			LastSyncedAt: timestamppb.New(now),
			Config: map[string]string{
				"family":                           "audit",
				"token":                            "env:CEREBRO_SOURCE_BOOTSTRAP_TOKEN_TOKEN",
				runtimeRecordsAcceptedConfigKey:    "42",
				runtimeRecordsRejectedConfigKey:    "1",
				runtimeEntitiesProjectedConfigKey:  "40",
				runtimeLinksProjectedConfigKey:     "8",
				runtimeContractProbeStateConfigKey: "passing",
				"expected_cadence_seconds":         "14400",
			},
		},
	}}}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
	}, Dependencies{StateStore: store}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/connectors/bootstrap_token?tenant_id=tenant-a")
	if err != nil {
		t.Fatalf("GET /connectors/{sourceID} error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /connectors/{sourceID} status = %d, want 200", resp.StatusCode)
	}
	var payload struct {
		Connector struct {
			SourceID string `json:"source_id"`
		} `json:"connector"`
		Summary struct {
			Status               string `json:"status"`
			TotalConnections     int    `json:"total_connections"`
			NeedsAttention       int    `json:"needs_attention"`
			SyncFrequencySeconds *int64 `json:"sync_frequency_seconds"`
		} `json:"summary"`
		Connections []struct {
			RuntimeID       string `json:"runtime_id"`
			RecordsAccepted uint32 `json:"records_accepted"`
			NextAction      string `json:"next_action"`
		} `json:"connections"`
		Activity []struct {
			Type            string `json:"type"`
			Status          string `json:"status"`
			RecordsAccepted uint32 `json:"records_accepted"`
		} `json:"activity"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got := payload.Connector.SourceID; got != "bootstrap_token" {
		t.Fatalf("connector source_id = %q, want bootstrap_token", got)
	}
	if got := payload.Summary.TotalConnections; got != 1 {
		t.Fatalf("summary total_connections = %d, want 1", got)
	}
	if got := payload.Summary.Status; got != "needs_refresh" {
		t.Fatalf("summary status = %q, want needs_refresh because graph ingest is not observed", got)
	}
	if payload.Summary.SyncFrequencySeconds == nil || *payload.Summary.SyncFrequencySeconds != 14400 {
		t.Fatalf("summary sync_frequency_seconds = %#v, want 14400", payload.Summary.SyncFrequencySeconds)
	}
	if len(payload.Connections) != 1 || payload.Connections[0].RuntimeID != "runtime-a" {
		t.Fatalf("connections = %#v, want runtime-a", payload.Connections)
	}
	if got := payload.Connections[0].RecordsAccepted; got != 42 {
		t.Fatalf("records_accepted = %d, want 42", got)
	}
	if got := payload.Connections[0].NextAction; got != "run_graph_ingest" {
		t.Fatalf("next_action = %q, want run_graph_ingest", got)
	}
	if len(payload.Activity) == 0 || payload.Activity[0].Type != "sync" {
		t.Fatalf("activity = %#v, want sync activity", payload.Activity)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal decoded payload: %v", err)
	}
	if strings.Contains(string(encoded), "CEREBRO_SOURCE_BOOTSTRAP_TOKEN_TOKEN") || strings.Contains(string(encoded), "env:") {
		t.Fatalf("connector detail leaked credential reference: %s", encoded)
	}
}

func TestConnectorDetailToleratesUnavailableRuntimeStore(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
	}, Dependencies{}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/connectors/bootstrap_token")
	if err != nil {
		t.Fatalf("GET /connectors/{sourceID} error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /connectors/{sourceID} status = %d, want 200", resp.StatusCode)
	}
	var payload struct {
		Summary struct {
			Status           string `json:"status"`
			TotalConnections int    `json:"total_connections"`
		} `json:"summary"`
		Connections []struct{} `json:"connections"`
		Activity    []struct{} `json:"activity"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got := payload.Summary.Status; got != "not_configured" {
		t.Fatalf("summary status = %q, want not_configured", got)
	}
	if got := payload.Summary.TotalConnections; got != 0 {
		t.Fatalf("summary total_connections = %d, want 0", got)
	}
	if len(payload.Connections) != 0 || len(payload.Activity) != 0 {
		t.Fatalf("connections/activity = %d/%d, want empty", len(payload.Connections), len(payload.Activity))
	}
}

func TestConnectorActivityRejectsUnknownSource(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
	}, Dependencies{StateStore: &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{}}}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/connectors/missing/activity")
	if err != nil {
		t.Fatalf("GET /connectors/{sourceID}/activity error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /connectors/{sourceID}/activity status = %d, want 404", resp.StatusCode)
	}
}

func TestConnectorConnectionStoresEnvironmentManagedReference(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{}}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
	}, Dependencies{StateStore: store}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()
	t.Setenv("CEREBRO_SOURCE_BOOTSTRAP_TOKEN_TOKEN", "resolved-env-token")

	body, err := json.Marshal(map[string]any{
		"runtime_id":          "runtime-env",
		"tenant_id":           "tenant-a",
		"auth_method":         connectorAuthMethodInfisicalCLI,
		"credential_store_id": connectorStoreEnvironmentManaged,
		"config":              map[string]string{"family": "audit"},
		"credential_references": map[string]string{
			"token": "env:CEREBRO_SOURCE_BOOTSTRAP_TOKEN_TOKEN", // #nosec G101 -- env reference string, not a secret value.
		},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	resp, err := server.Client().Post(server.URL+"/connectors/bootstrap_token/connections", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /connectors environment reference error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /connectors environment reference status = %d, want 200", resp.StatusCode)
	}
	if source.checkToken != "resolved-env-token" {
		t.Fatalf("source check token = %q, want resolved-env-token", source.checkToken)
	}
	runtime := store.runtimes["runtime-env"]
	if runtime == nil {
		t.Fatal("stored runtime missing")
	}
	if got := runtime.GetConfig()["token"]; got != "env:CEREBRO_SOURCE_BOOTSTRAP_TOKEN_TOKEN" {
		t.Fatalf("stored runtime token = %q, want env reference", got)
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	credentialPayload, ok := payload["credential"].(map[string]any)
	if !ok {
		t.Fatalf("credential payload = %#v", payload["credential"])
	}
	if got := credentialPayload["auth_method"]; got != connectorAuthMethodInfisicalCLI {
		t.Fatalf("credential auth_method = %#v, want %q", got, connectorAuthMethodInfisicalCLI)
	}
	if got := credentialPayload["credential_store_id"]; got != connectorStoreEnvironmentManaged {
		t.Fatalf("credential_store_id = %#v, want %q", got, connectorStoreEnvironmentManaged)
	}
}

func TestConnectorConnectionCheckOnlyDoesNotPersistCredentialOrRuntime(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{}}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		ConnectorCredentials: config.ConnectorCredentialConfig{
			Key:               "test-connector-vault-key",
			TransitPrivateKey: testConnectorTransitPrivateKeyPEM(t),
		},
	}, Dependencies{StateStore: store}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	key := app.connectorTransitKey.PublicKey()
	encrypted, err := encryptConnectorCredentialsForTestWithAAD(
		key,
		map[string]string{"token": "secret-token"},
		connectorCredentialAdditionalData(key.KeyID, "bootstrap_token", "tenant-a", "runtime-check", defaultConnectorCredentialStoreID),
	)
	if err != nil {
		t.Fatalf("encrypt credentials: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"runtime_id":            "runtime-check",
		"tenant_id":             "tenant-a",
		"check_only":            true,
		"auth_method":           connectorAuthMethodEncryptedSubmission,
		"credential_store_id":   defaultConnectorCredentialStoreID,
		"config":                map[string]string{"family": "audit"},
		"encrypted_credentials": encrypted,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	resp, err := server.Client().Post(server.URL+"/connectors/bootstrap_token/connections", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /connectors check-only error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /connectors check-only status = %d, want 200", resp.StatusCode)
	}
	if source.checkToken != "secret-token" {
		t.Fatalf("source check token = %q, want decrypted secret", source.checkToken)
	}
	if len(store.runtimes) != 0 {
		t.Fatalf("stored runtimes len = %d, want 0", len(store.runtimes))
	}
	if len(store.credentials) != 0 {
		t.Fatalf("stored credentials len = %d, want 0", len(store.credentials))
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got := payload["status"]; got != "checked" {
		t.Fatalf("status = %#v, want checked", got)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal response payload: %v", err)
	}
	if strings.Contains(string(encoded), "secret-token") {
		t.Fatalf("check-only response leaked secret: %s", encoded)
	}
}

func TestConnectorConnectionStoresExternalStoreReference(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{}}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
	}, Dependencies{StateStore: store}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()
	t.Setenv("CEREBRO_SOURCE_BOOTSTRAP_TOKEN_TOKEN", "resolved-external-token")

	body, err := json.Marshal(map[string]any{
		"runtime_id":          "runtime-external",
		"tenant_id":           "tenant-a",
		"auth_method":         connectorAuthMethodExternalReference,
		"credential_store_id": connectorStoreInfisical,
		"config":              map[string]string{"family": "audit"},
		"credential_references": map[string]string{
			"token": "env:CEREBRO_SOURCE_BOOTSTRAP_TOKEN_TOKEN", // #nosec G101 -- env reference string, not a secret value.
		},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	resp, err := server.Client().Post(server.URL+"/connectors/bootstrap_token/connections", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /connectors external reference error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /connectors external reference status = %d, want 200", resp.StatusCode)
	}
	if source.checkToken != "resolved-external-token" {
		t.Fatalf("source check token = %q, want resolved-external-token", source.checkToken)
	}
	runtime := store.runtimes["runtime-external"]
	if runtime == nil {
		t.Fatal("stored runtime missing")
	}
	if got := runtime.GetConfig()["token"]; got != "env:CEREBRO_SOURCE_BOOTSTRAP_TOKEN_TOKEN" {
		t.Fatalf("stored runtime token = %q, want env reference", got)
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	credentialPayload, ok := payload["credential"].(map[string]any)
	if !ok {
		t.Fatalf("credential payload = %#v", payload["credential"])
	}
	if got := credentialPayload["auth_method"]; got != connectorAuthMethodExternalReference {
		t.Fatalf("credential auth_method = %#v, want %q", got, connectorAuthMethodExternalReference)
	}
	if got := credentialPayload["credential_store_id"]; got != connectorStoreInfisical {
		t.Fatalf("credential_store_id = %#v, want %q", got, connectorStoreInfisical)
	}
}

func TestConnectorConnectionRejectsInternalConfigAndUnsupportedAuth(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
	}, Dependencies{StateStore: &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{}}}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	for name, body := range map[string]string{
		"internal_config": `{"runtime_id":"runtime-a","tenant_id":"tenant-a","auth_method":"environment_managed","credential_store_id":"environment_managed","config":{"__cerebro_aws_assume_role_arns":"caller-controlled"}}`,
		"wrong_source":    `{"runtime_id":"runtime-a","tenant_id":"tenant-a","auth_method":"aws_sso_profile","credential_store_id":"environment_managed","config":{"account_id":"123456789012","profile":"cerebro"}}`,
	} {
		resp, err := server.Client().Post(server.URL+"/connectors/bootstrap_token/connections", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("%s: POST /connectors error = %v", name, err)
		}
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("%s: close response: %v", name, closeErr)
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: POST /connectors status = %d, want 400", name, resp.StatusCode)
		}
	}
}

func TestConnectorTransitKeyIsSharedAcrossReplicas(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	credentialConfig := config.ConnectorCredentialConfig{
		Key:               "test-connector-vault-key",
		TransitPrivateKey: testConnectorTransitPrivateKeyPEM(t),
	}
	appA, err := NewWithError(config.Config{
		HTTPAddr:             "127.0.0.1:0",
		ShutdownTimeout:      time.Second,
		ConnectorCredentials: credentialConfig,
	}, Dependencies{StateStore: &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{}}}, registry)
	if err != nil {
		t.Fatalf("NewWithError(appA) error = %v", err)
	}
	appB, err := NewWithError(config.Config{
		HTTPAddr:             "127.0.0.1:0",
		ShutdownTimeout:      time.Second,
		ConnectorCredentials: credentialConfig,
	}, Dependencies{StateStore: &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{}}}, registry)
	if err != nil {
		t.Fatalf("NewWithError(appB) error = %v", err)
	}
	keyA := appA.connectorTransitKey.PublicKey()
	keyB := appB.connectorTransitKey.PublicKey()
	if keyA.KeyID == "" || keyA.KeyID != keyB.KeyID {
		t.Fatalf("transit key IDs = %q and %q, want shared stable key ID", keyA.KeyID, keyB.KeyID)
	}
	additionalData := connectorCredentialAdditionalData(keyA.KeyID, "bootstrap_token", "tenant-a", "runtime-a", defaultConnectorCredentialStoreID)
	encrypted, err := encryptConnectorCredentialsForTestWithAAD(keyA, map[string]string{"token": "secret-token"}, additionalData)
	if err != nil {
		t.Fatalf("encrypt credentials: %v", err)
	}
	decrypted, err := appB.connectorTransitKey.DecryptWithExactAdditionalData(encrypted, additionalData)
	if err != nil {
		t.Fatalf("DecryptWithExactAdditionalData() on second app error = %v", err)
	}
	var fields map[string]string
	if err := json.Unmarshal(decrypted, &fields); err != nil {
		t.Fatalf("unmarshal decrypted fields: %v", err)
	}
	if fields["token"] != "secret-token" {
		t.Fatalf("decrypted token = %q, want secret-token", fields["token"])
	}
}

func TestConnectorCredentialKeyUnavailableWithoutTransitKey(t *testing.T) {
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		ConnectorCredentials: config.ConnectorCredentialConfig{
			Key: "test-connector-vault-key",
		},
	}, Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/connectors/credential-key")
	if err != nil {
		t.Fatalf("GET /connectors/credential-key error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("GET /connectors/credential-key status = %d, want 503", resp.StatusCode)
	}
}

func testConnectorTransitPrivateKeyPEM(t *testing.T) string {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)}
	return string(pem.EncodeToMemory(block))
}

func encryptConnectorCredentialsForTest(key connectorcredentials.PublicKey, fields map[string]string) (connectorcredentials.EncryptedPayload, error) {
	return encryptConnectorCredentialsForTestWithAAD(key, fields, []byte(key.KeyID))
}

func encryptConnectorCredentialsForTestWithAAD(key connectorcredentials.PublicKey, fields map[string]string, additionalData []byte) (connectorcredentials.EncryptedPayload, error) {
	plaintext, err := json.Marshal(fields)
	if err != nil {
		return connectorcredentials.EncryptedPayload{}, err
	}
	publicKey, err := rsaPublicKeyFromJWK(key.JWK)
	if err != nil {
		return connectorcredentials.EncryptedPayload{}, err
	}
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return connectorcredentials.EncryptedPayload{}, err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return connectorcredentials.EncryptedPayload{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return connectorcredentials.EncryptedPayload{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return connectorcredentials.EncryptedPayload{}, err
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, aesKey, nil)
	if err != nil {
		return connectorcredentials.EncryptedPayload{}, err
	}
	return connectorcredentials.EncryptedPayload{
		KeyID:      key.KeyID,
		Algorithm:  key.Algorithm,
		WrappedKey: base64.StdEncoding.EncodeToString(wrapped),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, plaintext, additionalData)),
	}, nil
}

func rsaPublicKeyFromJWK(jwk map[string]any) (*rsa.PublicKey, error) {
	modulus, ok := jwk["n"].(string)
	if !ok {
		return nil, errInvalidHTTPRequest
	}
	exponent, ok := jwk["e"].(string)
	if !ok {
		return nil, errInvalidHTTPRequest
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(modulus)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(exponent)
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}

var _ ports.ConnectorCredentialStore = (*connectorTestStore)(nil)
