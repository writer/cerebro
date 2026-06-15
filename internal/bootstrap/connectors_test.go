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

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/connectorcredentials"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
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
	encrypted, err := encryptConnectorCredentialsForTest(keyA, map[string]string{"token": "secret-token"})
	if err != nil {
		t.Fatalf("encrypt credentials: %v", err)
	}
	decrypted, err := appB.connectorTransitKey.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt() on second app error = %v", err)
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
