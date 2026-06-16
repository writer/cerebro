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
	"sort"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/connectorcredentials"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/resourcescope"
	"github.com/writer/cerebro/internal/sourcecdk"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type connectorTestStore struct {
	*stubRuntimeStore
	credentials map[string]*ports.ConnectorCredentialRecord
	audit       []*ports.ConnectorCredentialAuditRecord
	definitions map[string]*ports.ConnectorDefinitionRecord
}

func (s *connectorTestStore) PutConnectorCredential(_ context.Context, record *ports.ConnectorCredentialRecord) error {
	if s.credentials == nil {
		s.credentials = map[string]*ports.ConnectorCredentialRecord{}
	}
	cloned := cloneConnectorTestCredential(record)
	if cloned.CreatedAt.IsZero() {
		cloned.CreatedAt = time.Now().UTC()
	}
	if cloned.UpdatedAt.IsZero() {
		cloned.UpdatedAt = cloned.CreatedAt
	}
	s.credentials[record.ID] = &cloned
	return nil
}

func (s *connectorTestStore) GetConnectorCredential(_ context.Context, id string) (*ports.ConnectorCredentialRecord, error) {
	record, ok := s.credentials[id]
	if !ok {
		return nil, ports.ErrConnectorCredentialNotFound
	}
	cloned := cloneConnectorTestCredential(record)
	return &cloned, nil
}

func (s *connectorTestStore) ListConnectorCredentials(_ context.Context, filter ports.ConnectorCredentialFilter) ([]*ports.ConnectorCredentialRecord, error) {
	records := []*ports.ConnectorCredentialRecord{}
	for _, record := range s.credentials {
		if !connectorCredentialRecordMatches(record, filter) {
			continue
		}
		cloned := cloneConnectorTestCredential(record)
		records = append(records, &cloned)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].UpdatedAt.After(records[j].UpdatedAt)
	})
	if filter.Limit > 0 && len(records) > filter.Limit {
		records = records[:filter.Limit]
	}
	return records, nil
}

func (s *connectorTestStore) UpdateConnectorCredentialMetadata(_ context.Context, id string, update ports.ConnectorCredentialMetadataUpdate) (*ports.ConnectorCredentialRecord, error) {
	record, ok := s.credentials[id]
	if !ok {
		return nil, ports.ErrConnectorCredentialNotFound
	}
	if update.Status != "" {
		record.Status = update.Status
	}
	if update.Fields != nil {
		record.Fields = append([]string{}, update.Fields...)
	}
	if update.UpdatedBy != "" {
		record.UpdatedBy = update.UpdatedBy
	}
	if update.RevokedBy != "" {
		record.RevokedBy = update.RevokedBy
	}
	if update.PreviousCredentialID != "" {
		record.PreviousCredentialID = update.PreviousCredentialID
	}
	if update.RevokedAt != nil {
		record.RevokedAt = *update.RevokedAt
	}
	if update.LastUsedAt != nil {
		record.LastUsedAt = *update.LastUsedAt
	}
	if update.LastValidatedAt != nil {
		record.LastValidatedAt = *update.LastValidatedAt
	}
	record.UpdatedAt = time.Now().UTC()
	cloned := cloneConnectorTestCredential(record)
	return &cloned, nil
}

func (s *connectorTestStore) AppendConnectorCredentialAuditEvent(_ context.Context, event *ports.ConnectorCredentialAuditRecord) error {
	if event == nil {
		return nil
	}
	cloned := *event
	s.audit = append(s.audit, &cloned)
	return nil
}

func (s *connectorTestStore) ListConnectorCredentialAuditEvents(_ context.Context, credentialID string, limit int) ([]*ports.ConnectorCredentialAuditRecord, error) {
	events := []*ports.ConnectorCredentialAuditRecord{}
	for _, event := range s.audit {
		if event.CredentialID != credentialID {
			continue
		}
		cloned := *event
		events = append(events, &cloned)
	}
	sort.Slice(events, func(i, j int) bool {
		return events[i].CreatedAt.After(events[j].CreatedAt)
	})
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

func cloneConnectorTestCredential(record *ports.ConnectorCredentialRecord) ports.ConnectorCredentialRecord {
	cloned := *record
	cloned.Sealed = append([]byte{}, record.Sealed...)
	cloned.Fields = append([]string{}, record.Fields...)
	return cloned
}

func connectorCredentialRecordMatches(record *ports.ConnectorCredentialRecord, filter ports.ConnectorCredentialFilter) bool {
	if record == nil {
		return false
	}
	if filter.ID != "" && record.ID != filter.ID {
		return false
	}
	if filter.TenantID != "" && record.TenantID != filter.TenantID {
		return false
	}
	if filter.SourceID != "" && record.SourceID != filter.SourceID {
		return false
	}
	if filter.RuntimeID != "" && record.RuntimeID != filter.RuntimeID {
		return false
	}
	if filter.Status != "" && record.Status != filter.Status {
		return false
	}
	if filter.IdempotencyKey != "" && record.IdempotencyKey != filter.IdempotencyKey {
		return false
	}
	return true
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

func TestConnectorCredentialBrokerStoresReferencesWithoutLeakingSecret(t *testing.T) {
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
		"encrypted_credentials": encrypted,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/connectors/bootstrap_token/credentials", bytes.NewReader(body))
	req.SetPathValue("sourceID", "bootstrap_token")
	recorder := httptest.NewRecorder()
	app.handleCreateConnectorCredential(recorder, req)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("POST /connectors/{sourceID}/credentials status = %d, want 201: %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "secret-token") {
		t.Fatalf("credential broker response leaked secret: %s", recorder.Body.String())
	}
	var payload connectorCredentialBrokerResponse
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Status != "stored" {
		t.Fatalf("status = %q, want stored", payload.Status)
	}
	if payload.TenantID != "tenant-a" || payload.SourceID != "bootstrap_token" || payload.RuntimeID != "runtime-a" {
		t.Fatalf("response identity = tenant %q source %q runtime %q", payload.TenantID, payload.SourceID, payload.RuntimeID)
	}
	reference := payload.CredentialReferences["token"]
	if want := connectorcredentials.Reference(payload.Credential.ID, "token"); reference != want {
		t.Fatalf("token reference = %q, want %q", reference, want)
	}
	record := store.credentials[payload.Credential.ID]
	if record == nil {
		t.Fatalf("stored credential %q missing", payload.Credential.ID)
	}
	if record.TenantID != "tenant-a" || record.SourceID != "bootstrap_token" || record.RuntimeID != "runtime-a" {
		t.Fatalf("stored credential identity = tenant %q source %q runtime %q", record.TenantID, record.SourceID, record.RuntimeID)
	}
	if strings.Contains(string(record.Sealed), "secret-token") {
		t.Fatalf("sealed credential leaked secret: %s", string(record.Sealed))
	}
	vault, err := connectorCredentialVault(app.cfg.ConnectorCredentials, app.deps.StateStore)
	if err != nil {
		t.Fatalf("connectorCredentialVault() error = %v", err)
	}
	resolved, err := vault.ResolveReferences(context.Background(), "bootstrap_token", "tenant-a", "runtime-a", map[string]string{"token": reference})
	if err != nil {
		t.Fatalf("ResolveReferences() error = %v", err)
	}
	if resolved["token"] != "secret-token" {
		t.Fatalf("resolved token = %q, want secret-token", resolved["token"])
	}
	if _, err := vault.ResolveReferences(context.Background(), "bootstrap_token", "tenant-b", "runtime-a", map[string]string{"token": reference}); err == nil {
		t.Fatal("ResolveReferences() succeeded for the wrong tenant")
	}
}

func TestConnectorCredentialBrokerListsAndDeduplicatesByIdempotencyKey(t *testing.T) {
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
		"idempotency_key":       "request-1",
		"encrypted_credentials": encrypted,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	for i, wantStatus := range []int{http.StatusCreated, http.StatusOK} {
		req := httptest.NewRequest(http.MethodPost, "/connectors/bootstrap_token/credentials", bytes.NewReader(body))
		req.SetPathValue("sourceID", "bootstrap_token")
		recorder := httptest.NewRecorder()
		app.handleCreateConnectorCredential(recorder, req)
		if recorder.Code != wantStatus {
			t.Fatalf("request %d status = %d, want %d: %s", i+1, recorder.Code, wantStatus, recorder.Body.String())
		}
	}
	if got := len(store.credentials); got != 1 {
		t.Fatalf("stored credentials = %d, want 1", got)
	}
	req := httptest.NewRequest(http.MethodGet, "/connectors/bootstrap_token/credentials?tenant_id=tenant-a", nil)
	req.SetPathValue("sourceID", "bootstrap_token")
	recorder := httptest.NewRecorder()
	app.handleListConnectorCredentials(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /connectors/{sourceID}/credentials status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var payload connectorCredentialListResponse
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(payload.Credentials) != 1 {
		t.Fatalf("listed credentials = %d, want 1", len(payload.Credentials))
	}
	if got := payload.Credentials[0].Status; got != connectorcredentials.StatusValid {
		t.Fatalf("listed credential status = %q, want valid", got)
	}
	if got := payload.Credentials[0].Fields; len(got) != 1 || got[0] != "token" {
		t.Fatalf("listed credential fields = %#v, want token", got)
	}
	if strings.Contains(recorder.Body.String(), "secret-token") {
		t.Fatalf("list response leaked secret: %s", recorder.Body.String())
	}
}

func TestConnectorCredentialBrokerRevocationBlocksUse(t *testing.T) {
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
		"encrypted_credentials": encrypted,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	createReq := httptest.NewRequest(http.MethodPost, "/connectors/bootstrap_token/credentials", bytes.NewReader(body))
	createReq.SetPathValue("sourceID", "bootstrap_token")
	createRecorder := httptest.NewRecorder()
	app.handleCreateConnectorCredential(createRecorder, createReq)
	if createRecorder.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201: %s", createRecorder.Code, createRecorder.Body.String())
	}
	var created connectorCredentialBrokerResponse
	if err := json.NewDecoder(createRecorder.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}

	revokeReq := httptest.NewRequest(http.MethodPost, "/connectors/bootstrap_token/credentials/"+created.Credential.ID+"/revoke", strings.NewReader(`{"reason":"operator requested"}`))
	revokeReq.SetPathValue("sourceID", "bootstrap_token")
	revokeReq.SetPathValue("credentialID", created.Credential.ID)
	revokeRecorder := httptest.NewRecorder()
	app.handleRevokeConnectorCredential(revokeRecorder, revokeReq)
	if revokeRecorder.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200: %s", revokeRecorder.Code, revokeRecorder.Body.String())
	}
	if got := store.credentials[created.Credential.ID].Status; got != connectorcredentials.StatusRevoked {
		t.Fatalf("stored status = %q, want revoked", got)
	}
	broker, err := connectorCredentialBroker(app.cfg.ConnectorCredentials, app.deps.StateStore, nil)
	if err != nil {
		t.Fatalf("connectorCredentialBroker() error = %v", err)
	}
	if _, err := broker.ResolveReferences(context.Background(), "bootstrap_token", "tenant-a", "runtime-a", map[string]string{"token": created.CredentialReferences["token"]}); err == nil {
		t.Fatal("ResolveReferences() after revoke error = nil, want error")
	}
}

func TestConnectorCredentialBrokerRotatesCredential(t *testing.T) {
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

	key := app.connectorTransitKey.PublicKey()
	initialEncrypted, err := encryptConnectorCredentialsForTestWithAAD(
		key,
		map[string]string{"token": "old-token"},
		connectorCredentialAdditionalData(key.KeyID, "bootstrap_token", "tenant-a", "runtime-a", defaultConnectorCredentialStoreID),
	)
	if err != nil {
		t.Fatalf("encrypt initial credentials: %v", err)
	}
	initialBody, err := json.Marshal(map[string]any{
		"runtime_id":            "runtime-a",
		"tenant_id":             "tenant-a",
		"credential_store_id":   defaultConnectorCredentialStoreID,
		"encrypted_credentials": initialEncrypted,
	})
	if err != nil {
		t.Fatalf("marshal initial request: %v", err)
	}
	createReq := httptest.NewRequest(http.MethodPost, "/connectors/bootstrap_token/credentials", bytes.NewReader(initialBody))
	createReq.SetPathValue("sourceID", "bootstrap_token")
	createRecorder := httptest.NewRecorder()
	app.handleCreateConnectorCredential(createRecorder, createReq)
	if createRecorder.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201: %s", createRecorder.Code, createRecorder.Body.String())
	}
	var created connectorCredentialBrokerResponse
	if err := json.NewDecoder(createRecorder.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}

	rotatedEncrypted, err := encryptConnectorCredentialsForTestWithAAD(
		key,
		map[string]string{"token": "new-token"},
		connectorCredentialAdditionalData(key.KeyID, "bootstrap_token", "tenant-a", "runtime-a", defaultConnectorCredentialStoreID),
	)
	if err != nil {
		t.Fatalf("encrypt rotated credentials: %v", err)
	}
	rotateBody, err := json.Marshal(map[string]any{
		"runtime_id":            "runtime-a",
		"tenant_id":             "tenant-a",
		"credential_store_id":   defaultConnectorCredentialStoreID,
		"revoke_previous":       true,
		"encrypted_credentials": rotatedEncrypted,
	})
	if err != nil {
		t.Fatalf("marshal rotate request: %v", err)
	}
	rotateReq := httptest.NewRequest(http.MethodPost, "/connectors/bootstrap_token/credentials/"+created.Credential.ID+"/rotate", bytes.NewReader(rotateBody))
	rotateReq.SetPathValue("sourceID", "bootstrap_token")
	rotateReq.SetPathValue("credentialID", created.Credential.ID)
	rotateRecorder := httptest.NewRecorder()
	app.handleRotateConnectorCredential(rotateRecorder, rotateReq)
	if rotateRecorder.Code != http.StatusCreated {
		t.Fatalf("rotate status = %d, want 201: %s", rotateRecorder.Code, rotateRecorder.Body.String())
	}
	var rotated connectorCredentialBrokerResponse
	if err := json.NewDecoder(rotateRecorder.Body).Decode(&rotated); err != nil {
		t.Fatalf("decode rotate response: %v", err)
	}
	if rotated.Credential.ID == created.Credential.ID {
		t.Fatalf("rotated credential reused previous id %q", rotated.Credential.ID)
	}
	if got := rotated.Credential.PreviousCredentialID; got != created.Credential.ID {
		t.Fatalf("previous credential id = %q, want %q", got, created.Credential.ID)
	}
	if got := store.credentials[created.Credential.ID].Status; got != connectorcredentials.StatusRevoked {
		t.Fatalf("previous credential status = %q, want revoked", got)
	}
	broker, err := connectorCredentialBroker(app.cfg.ConnectorCredentials, app.deps.StateStore, nil)
	if err != nil {
		t.Fatalf("connectorCredentialBroker() error = %v", err)
	}
	resolved, err := broker.ResolveReferences(context.Background(), "bootstrap_token", "tenant-a", "runtime-a", map[string]string{"token": rotated.CredentialReferences["token"]})
	if err != nil {
		t.Fatalf("ResolveReferences() rotated error = %v", err)
	}
	if got := resolved["token"]; got != "new-token" {
		t.Fatalf("resolved rotated token = %q, want new-token", got)
	}
}

func TestConnectorCredentialBrokerRejectsCrossTenantRequest(t *testing.T) {
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

	key := app.connectorTransitKey.PublicKey()
	encrypted, err := encryptConnectorCredentialsForTestWithAAD(
		key,
		map[string]string{"token": "secret-token"},
		connectorCredentialAdditionalData(key.KeyID, "bootstrap_token", "tenant-b", "runtime-a", defaultConnectorCredentialStoreID),
	)
	if err != nil {
		t.Fatalf("encrypt credentials: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"runtime_id":            "runtime-a",
		"tenant_id":             "tenant-b",
		"credential_store_id":   defaultConnectorCredentialStoreID,
		"encrypted_credentials": encrypted,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/connectors/bootstrap_token/credentials", bytes.NewReader(body))
	req.SetPathValue("sourceID", "bootstrap_token")
	req = req.WithContext(context.WithValue(req.Context(), authContextKey{}, authContext{
		principal: authPrincipal{TenantID: "tenant-a"},
	}))
	recorder := httptest.NewRecorder()
	app.handleCreateConnectorCredential(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant credential status = %d, want 403", recorder.Code)
	}
	if len(store.credentials) != 0 {
		t.Fatalf("stored credentials after forbidden request = %#v, want none", store.credentials)
	}
}

func TestConnectorCredentialBrokerRejectsExistingRuntimeTenantMismatch(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"runtime-a": {
			Id:       "runtime-a",
			SourceId: "bootstrap_token",
			TenantId: "tenant-b",
		},
	}}}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		ConnectorCredentials: config.ConnectorCredentialConfig{
			Key:               "test-connector-vault-key",
			TransitPrivateKey: testConnectorTransitPrivateKeyPEM(t),
		},
	}, Dependencies{StateStore: store}, registry)

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
		"encrypted_credentials": encrypted,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/connectors/bootstrap_token/credentials", bytes.NewReader(body))
	req.SetPathValue("sourceID", "bootstrap_token")
	recorder := httptest.NewRecorder()
	app.handleCreateConnectorCredential(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("runtime tenant mismatch status = %d, want 403", recorder.Code)
	}
	if len(store.credentials) != 0 {
		t.Fatalf("stored credentials after runtime mismatch = %#v, want none", store.credentials)
	}
}

func TestConnectorCredentialBrokerRejectsCredentialPayloadAADMismatch(t *testing.T) {
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

	key := app.connectorTransitKey.PublicKey()
	encrypted, err := encryptConnectorCredentialsForTestWithAAD(
		key,
		map[string]string{"token": "secret-token"},
		connectorCredentialAdditionalData(key.KeyID, "bootstrap_token", "tenant-b", "runtime-a", defaultConnectorCredentialStoreID),
	)
	if err != nil {
		t.Fatalf("encrypt credentials: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"runtime_id":            "runtime-a",
		"tenant_id":             "tenant-a",
		"credential_store_id":   defaultConnectorCredentialStoreID,
		"encrypted_credentials": encrypted,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/connectors/bootstrap_token/credentials", bytes.NewReader(body))
	req.SetPathValue("sourceID", "bootstrap_token")
	recorder := httptest.NewRecorder()
	app.handleCreateConnectorCredential(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("AAD mismatch status = %d, want 400", recorder.Code)
	}
	if len(store.credentials) != 0 {
		t.Fatalf("stored credentials after AAD mismatch = %#v, want none", store.credentials)
	}
}

func TestConnectorConnectionStoresValidatedScopePolicy(t *testing.T) {
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
		"runtime_id":          "runtime-a",
		"tenant_id":           "tenant-a",
		"credential_store_id": defaultConnectorCredentialStoreID,
		"config":              map[string]string{"family": "audit"},
		"scope_policy": map[string]any{
			"excluded_families":      []string{"audit"},
			"excluded_resource_urns": []string{"urn:cerebro:tenant-a:external_asset:test"},
		},
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
	var payload struct {
		Runtime map[string]any `json:"runtime"`
		Scope   struct {
			ExcludedFamilies []string `json:"excluded_families"`
		} `json:"scope_policy"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Scope.ExcludedFamilies) != 1 || payload.Scope.ExcludedFamilies[0] != "audit" {
		t.Fatalf("scope_policy excluded_families = %#v, want [audit]", payload.Scope.ExcludedFamilies)
	}
	if configPayload, ok := payload.Runtime["config"].(map[string]any); ok {
		if _, leaked := configPayload[resourcescope.ConfigKey]; leaked {
			t.Fatalf("runtime payload leaked internal scope config: %#v", configPayload)
		}
	}
	runtime := store.runtimes["runtime-a"]
	if runtime == nil {
		t.Fatal("stored runtime missing")
	}
	storedPolicy, err := resourcescope.FromConfig(runtime.GetConfig())
	if err != nil {
		t.Fatalf("FromConfig(stored runtime) error = %v", err)
	}
	if !storedPolicy.ExcludesFamily("bootstrap_token", "audit") {
		t.Fatalf("stored scope policy does not exclude audit: %#v", storedPolicy)
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

func TestConnectorConnectionMissingTransitKeyIsUnavailable(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		ConnectorCredentials: config.ConnectorCredentialConfig{
			Key: "test-connector-vault-key",
		},
	}, Dependencies{StateStore: &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{}}}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	body := []byte(`{"runtime_id":"runtime-a","tenant_id":"tenant-a","credential_store_id":"cerebro_vault","encrypted_credentials":{"key_id":"ignored","algorithm":"RSA-OAEP-256+A256GCM"}}`)
	resp, err := server.Client().Post(server.URL+"/connectors/bootstrap_token/connections", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /connectors missing transit key error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("POST /connectors missing transit key status = %d, want 503", resp.StatusCode)
	}
}

func TestConnectorCatalogAdvertisesConnectionMethods(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token", emittedKinds: []string{"bootstrap.token"}}
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
			ScopeOptions []struct {
				ID       string   `json:"id"`
				Families []string `json:"families"`
			} `json:"scope_options"`
		} `json:"connectors"`
		CredentialStores []struct {
			ID                        string   `json:"id"`
			Available                 bool     `json:"available"`
			Status                    string   `json:"status"`
			ReferencePrefixes         []string `json:"reference_prefixes"`
			NativeResolutionAvailable bool     `json:"native_resolution_available"`
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
	if len(payload.Connectors[0].ScopeOptions) != 1 || payload.Connectors[0].ScopeOptions[0].ID != "bootstrap.token" {
		t.Fatalf("scope_options = %#v, want bootstrap.token option", payload.Connectors[0].ScopeOptions)
	}
	if got := payload.Connectors[0].ScopeOptions[0].Families; len(got) != 1 || got[0] != "bootstrap.token" {
		t.Fatalf("scope option families = %#v, want [bootstrap.token]", got)
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
	storePrefixes := map[string][]string{}
	storeStatuses := map[string]string{}
	for _, store := range payload.CredentialStores {
		stores[store.ID] = store.Available
		storePrefixes[store.ID] = store.ReferencePrefixes
		storeStatuses[store.ID] = store.Status
	}
	if !stores[connectorStoreEnvironmentManaged] {
		t.Fatalf("environment-managed store not advertised available: %#v", stores)
	}
	if stores[connectorStoreAWSSecretsManager] {
		t.Fatalf("aws secrets manager unexpectedly advertised available without opt-in: %#v", stores)
	}
	if got := storeStatuses[connectorStoreAWSSecretsManager]; got != "needs_configuration" {
		t.Fatalf("aws secrets manager status = %q, want needs_configuration", got)
	}
	if got := storePrefixes[connectorStoreAWSSecretsManager]; len(got) != 1 || got[0] != "env:" {
		t.Fatalf("aws secrets manager prefixes = %#v, want env only until native resolver is configured", got)
	}
}

func TestConnectorCatalogAdvertisesAWSSecretStoreEnvProjectionUntilNativeConfigured(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		ConnectorSecretStores: config.ConnectorSecretStoreConfig{
			Enabled: []string{connectorStoreAWSSecretsManager},
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
		CredentialStores []struct {
			ID                         string   `json:"id"`
			Available                  bool     `json:"available"`
			Detail                     string   `json:"detail"`
			ReferencePrefixes          []string `json:"reference_prefixes"`
			ReferenceNamespaceTemplate string   `json:"reference_namespace_template"`
			ReferenceFieldTemplate     string   `json:"reference_field_template"`
			NativeResolutionAvailable  bool     `json:"native_resolution_available"`
		} `json:"credential_stores"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	for _, store := range payload.CredentialStores {
		if store.ID != connectorStoreAWSSecretsManager {
			continue
		}
		if !store.Available || store.NativeResolutionAvailable || store.Detail != "ready via env projection" {
			t.Fatalf("aws secret store = %#v, want env projection availability", store)
		}
		if len(store.ReferencePrefixes) != 1 || store.ReferencePrefixes[0] != "env:" {
			t.Fatalf("aws reference prefixes = %#v, want env only", store.ReferencePrefixes)
		}
		if store.ReferenceNamespaceTemplate != "CEREBRO_SOURCE_<SOURCE>_*" {
			t.Fatalf("aws reference namespace template = %q", store.ReferenceNamespaceTemplate)
		}
		if store.ReferenceFieldTemplate != "env:CEREBRO_SOURCE_<SOURCE>_<FIELD>" {
			t.Fatalf("aws reference field template = %q", store.ReferenceFieldTemplate)
		}
		return
	}
	t.Fatalf("aws secret store missing: %#v", payload.CredentialStores)
}

func TestConnectorCatalogAdvertisesConfiguredAWSSecretStore(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		ConnectorSecretStores: config.ConnectorSecretStoreConfig{
			Enabled: []string{connectorStoreAWSSecretsManager},
			AWSSecretsManager: config.AWSSecretsManagerStoreConfig{
				Region: "us-east-1",
			},
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
		CredentialStores []struct {
			ID                         string `json:"id"`
			Available                  bool   `json:"available"`
			Detail                     string `json:"detail"`
			ReferenceNamespaceTemplate string `json:"reference_namespace_template"`
			ReferenceFieldTemplate     string `json:"reference_field_template"`
			NativeResolutionAvailable  bool   `json:"native_resolution_available"`
		} `json:"credential_stores"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	for _, store := range payload.CredentialStores {
		if store.ID != connectorStoreAWSSecretsManager {
			continue
		}
		if !store.Available || !store.NativeResolutionAvailable || store.Detail != "native resolver ready" {
			t.Fatalf("aws secret store = %#v, want available native resolver", store)
		}
		if store.ReferenceNamespaceTemplate != "cerebro/<tenant>/<source>/<runtime>/credentials" {
			t.Fatalf("aws reference namespace template = %q", store.ReferenceNamespaceTemplate)
		}
		if store.ReferenceFieldTemplate != "aws-sm:<region>:cerebro/<tenant>/<source>/<runtime>/credentials#<field>" {
			t.Fatalf("aws reference field template = %q", store.ReferenceFieldTemplate)
		}
		return
	}
	t.Fatalf("aws secret store missing: %#v", payload.CredentialStores)
}

func TestConnectorCatalogAdvertisesAWSOnboardingGuidance(t *testing.T) {
	source := &bootstrapTokenSource{id: "aws", emittedKinds: []string{"aws.s3_bucket"}}
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
				ID            string `json:"id"`
				ShortLabel    string `json:"short_label"`
				Category      string `json:"category"`
				Recommended   bool   `json:"recommended"`
				Prerequisites []any  `json:"prerequisites"`
				Steps         []struct {
					ID       string   `json:"id"`
					Commands []string `json:"commands"`
				} `json:"steps"`
				Commands      []string `json:"commands"`
				ProductGroups []struct {
					ID       string   `json:"id"`
					Families []string `json:"families"`
				} `json:"product_groups"`
				DeploymentGuides []struct {
					ID   string `json:"id"`
					Body string `json:"body"`
				} `json:"deployment_guides"`
				RegionGuidance *struct {
					SupportsGlobal bool `json:"supports_global"`
				} `json:"region_guidance"`
				SecurityNotes []string `json:"security_notes"`
			} `json:"connection_methods"`
		} `json:"connectors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Connectors) != 1 || payload.Connectors[0].SourceID != "aws" {
		t.Fatalf("connectors = %#v, want aws", payload.Connectors)
	}
	if got := payload.Connectors[0].DisplayName; got != "Amazon Web Services" {
		t.Fatalf("display_name = %q, want Amazon Web Services", got)
	}
	var ssoMethod *struct {
		ID            string `json:"id"`
		ShortLabel    string `json:"short_label"`
		Category      string `json:"category"`
		Recommended   bool   `json:"recommended"`
		Prerequisites []any  `json:"prerequisites"`
		Steps         []struct {
			ID       string   `json:"id"`
			Commands []string `json:"commands"`
		} `json:"steps"`
		Commands      []string `json:"commands"`
		ProductGroups []struct {
			ID       string   `json:"id"`
			Families []string `json:"families"`
		} `json:"product_groups"`
		DeploymentGuides []struct {
			ID   string `json:"id"`
			Body string `json:"body"`
		} `json:"deployment_guides"`
		RegionGuidance *struct {
			SupportsGlobal bool `json:"supports_global"`
		} `json:"region_guidance"`
		SecurityNotes []string `json:"security_notes"`
	}
	for index := range payload.Connectors[0].ConnectionMethods {
		method := &payload.Connectors[0].ConnectionMethods[index]
		if method.ID == connectorAuthMethodAWSSSOProfile {
			ssoMethod = method
			break
		}
	}
	if ssoMethod == nil {
		t.Fatalf("aws_sso_profile method missing: %#v", payload.Connectors[0].ConnectionMethods)
	}
	if !ssoMethod.Recommended || ssoMethod.ShortLabel != "AWS SSO" || ssoMethod.Category != "Recommended" {
		t.Fatalf("aws sso method guidance = %#v, want recommended AWS SSO", ssoMethod)
	}
	if len(ssoMethod.Prerequisites) < 3 || len(ssoMethod.Steps) < 5 || len(ssoMethod.Commands) == 0 {
		t.Fatalf("aws sso guidance incomplete: %#v", ssoMethod)
	}
	if ssoMethod.RegionGuidance == nil || !ssoMethod.RegionGuidance.SupportsGlobal {
		t.Fatalf("region guidance = %#v, want global guidance", ssoMethod.RegionGuidance)
	}
	productGroups := map[string][]string{}
	for _, group := range ssoMethod.ProductGroups {
		productGroups[group.ID] = group.Families
	}
	if len(productGroups["identity_center"]) == 0 || len(productGroups["organization"]) == 0 {
		t.Fatalf("product groups = %#v, want identity_center and organization", productGroups)
	}
	guideBodies := strings.Join(func() []string {
		out := make([]string, 0, len(ssoMethod.DeploymentGuides))
		for _, guide := range ssoMethod.DeploymentGuides {
			out = append(out, guide.Body)
		}
		return out
	}(), "\n")
	if !strings.Contains(guideBodies, "<cerebro-deployment-principal-arn>") || !strings.Contains(guideBodies, "SecurityAudit") {
		t.Fatalf("deployment guides did not include expected placeholders: %s", guideBodies)
	}
	if strings.Contains(strings.ToLower(guideBodies), "secret-token") {
		t.Fatalf("deployment guides leaked secret-shaped fixture: %s", guideBodies)
	}
}

func TestConnectorScopeOptionsIncludeCoverageNotes(t *testing.T) {
	source := &connectorCoverageSource{
		bootstrapTokenSource: &bootstrapTokenSource{id: "coverage_source", emittedKinds: []string{"coverage_source.resource"}},
		contract: sourcecdk.CoverageContract{
			SourceID:        "coverage_source",
			OwnerDomain:     "cloud",
			AuthorityDomain: "coverage",
			Dimensions: []sourcecdk.CoverageDimension{{
				ID:                     "resource",
				Type:                   "entity_family",
				Title:                  "Coverage resources",
				Families:               []string{"resource"},
				Support:                sourcecdk.CoverageSupportPartial,
				HighValue:              true,
				KnownUnsupportedFields: []string{"deep configuration"},
				Notes:                  []string{"Uses provider list APIs."},
			}},
		},
	}
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
			ScopeOptions []struct {
				ID                     string   `json:"id"`
				Support                string   `json:"support"`
				KnownUnsupportedFields []string `json:"known_unsupported_fields"`
				Notes                  []string `json:"notes"`
			} `json:"scope_options"`
		} `json:"connectors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Connectors) != 1 || len(payload.Connectors[0].ScopeOptions) != 1 {
		t.Fatalf("scope options = %#v, want one option", payload.Connectors)
	}
	option := payload.Connectors[0].ScopeOptions[0]
	if option.Support != sourcecdk.CoverageSupportPartial {
		t.Fatalf("support = %q, want partial", option.Support)
	}
	if len(option.KnownUnsupportedFields) != 1 || option.KnownUnsupportedFields[0] != "deep configuration" {
		t.Fatalf("known unsupported fields = %#v", option.KnownUnsupportedFields)
	}
	if len(option.Notes) != 1 || option.Notes[0] != "Uses provider list APIs." {
		t.Fatalf("notes = %#v", option.Notes)
	}
}

func TestConnectorDetailSummarizesOperationsWithoutConfig(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	now := time.Date(2026, 6, 15, 16, 0, 0, 0, time.UTC)
	rawScopePolicy, err := resourcescope.ConfigValue(resourcescope.Policy{ExcludedFamilies: []string{"audit"}})
	if err != nil {
		t.Fatalf("ConfigValue() error = %v", err)
	}
	store := &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"runtime-a": {
			Id:           "runtime-a",
			SourceId:     "bootstrap_token",
			TenantId:     "tenant-a",
			LastSyncedAt: timestamppb.New(now),
			Config: map[string]string{
				"family":                           "audit",
				"internal_marker":                  "runtime-config-marker",
				runtimeRecordsAcceptedConfigKey:    "42",
				runtimeRecordsRejectedConfigKey:    "1",
				runtimeEntitiesProjectedConfigKey:  "40",
				runtimeLinksProjectedConfigKey:     "8",
				runtimeContractProbeStateConfigKey: "passing",
				"expected_cadence_seconds":         "14400",
				resourcescope.ConfigKey:            rawScopePolicy,
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
			ScopePolicy     struct {
				ExcludedFamilies []string `json:"excluded_families"`
			} `json:"scope_policy"`
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
	if len(payload.Connections[0].ScopePolicy.ExcludedFamilies) != 1 || payload.Connections[0].ScopePolicy.ExcludedFamilies[0] != "audit" {
		t.Fatalf("connection scope policy = %#v, want audit exclusion", payload.Connections[0].ScopePolicy)
	}
	if len(payload.Activity) == 0 || payload.Activity[0].Type != "sync" {
		t.Fatalf("activity = %#v, want sync activity", payload.Activity)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal decoded payload: %v", err)
	}
	if strings.Contains(string(encoded), "runtime-config-marker") {
		t.Fatalf("connector detail leaked runtime config: %s", encoded)
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

func TestConnectorActivityRejectsLimitAboveContract(t *testing.T) {
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

	resp, err := server.Client().Get(server.URL + "/connectors/bootstrap_token/activity?limit=501")
	if err != nil {
		t.Fatalf("GET /connectors/{sourceID}/activity error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("GET /connectors/{sourceID}/activity status = %d, want 400", resp.StatusCode)
	}
}

func TestConnectorActivityLimitTruncatesActivityRows(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	store := &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"runtime-a": {
			Id:           "runtime-a",
			SourceId:     "bootstrap_token",
			TenantId:     "tenant-a",
			LastSyncedAt: timestamppb.New(now.Add(-time.Hour)),
			Config: map[string]string{
				"family":                        "audit",
				runtimeRecordsAcceptedConfigKey: "10",
			},
		},
	}}}
	graph := &stubGraphStore{ingestRuns: map[string]graphstore.IngestRun{
		"graph-a": {
			ID:         "graph-a",
			RuntimeID:  "runtime-a",
			Status:     "completed",
			StartedAt:  now.Add(-30 * time.Minute).Format(time.RFC3339Nano),
			FinishedAt: now.Add(-25 * time.Minute).Format(time.RFC3339Nano),
		},
	}}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
	}, Dependencies{StateStore: store, GraphStore: graph}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/connectors/bootstrap_token/activity?tenant_id=tenant-a&limit=1")
	if err != nil {
		t.Fatalf("GET /connectors/{sourceID}/activity error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /connectors/{sourceID}/activity status = %d, want 200", resp.StatusCode)
	}
	var payload struct {
		Activity []struct {
			Type      string `json:"type"`
			RuntimeID string `json:"runtime_id"`
		} `json:"activity"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Activity) != 1 {
		t.Fatalf("activity length = %d, want 1: %#v", len(payload.Activity), payload.Activity)
	}
	if got := payload.Activity[0].RuntimeID; got != "runtime-a" {
		t.Fatalf("activity[0].runtime_id = %q, want runtime-a", got)
	}
	if got := store.sourceRuntimeListFilter.Limit; got != connectorActivityMaxLimit {
		t.Fatalf("runtime list limit = %d, want connector fetch limit %d", got, connectorActivityMaxLimit)
	}
	if got := graph.ingestRunListFilter.Limit; got != 1 {
		t.Fatalf("graph ingest run list limit = %d, want latest run lookup limit", got)
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
		ConnectorSecretStores: config.ConnectorSecretStoreConfig{
			Enabled: []string{connectorStoreInfisical},
		},
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
		ConnectorSecretStores: config.ConnectorSecretStoreConfig{
			Enabled: []string{connectorStoreInfisical},
		},
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

func TestConnectorConnectionRejectsMismatchedExternalStoreReference(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		ConnectorSecretStores: config.ConnectorSecretStoreConfig{
			Enabled: []string{connectorStoreInfisical},
		},
	}, Dependencies{StateStore: &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{}}}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	body := []byte(`{"runtime_id":"runtime-external","tenant_id":"tenant-a","auth_method":"external_reference","credential_store_id":"infisical","config":{"family":"audit"},"credential_references":{"token":"aws-sm:us-east-1:cerebro/bootstrap-token#token"}}`)
	resp, err := server.Client().Post(server.URL+"/connectors/bootstrap_token/connections", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /connectors mismatched external reference error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /connectors mismatched external reference status = %d, want 400", resp.StatusCode)
	}
	if source.checkToken != "" {
		t.Fatalf("source check token = %q, want no source check", source.checkToken)
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

func TestConnectorPreflightValidatesWithoutPersisting(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token", emittedKinds: []string{"bootstrap.token"}}
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
		"runtime_id":          "runtime-a",
		"tenant_id":           "tenant-a",
		"auth_method":         connectorAuthMethodEncryptedSubmission,
		"credential_store_id": defaultConnectorCredentialStoreID,
		"config":              map[string]string{"family": "audit"},
		"scope_policy": map[string]any{
			"excluded_families":      []string{"bootstrap.token"},
			"excluded_resource_urns": []string{"urn:cerebro:tenant-a:external_asset:test"},
		},
		"encrypted_credentials": encrypted,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	resp, err := server.Client().Post(server.URL+"/connectors/bootstrap_token/preflight", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /connectors/{sourceID}/preflight error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /connectors preflight status = %d, want 200", resp.StatusCode)
	}
	var payload struct {
		Status             string `json:"status"`
		NextAction         string `json:"next_action"`
		CredentialBoundary struct {
			SendsSecrets   bool     `json:"sends_secrets"`
			FieldsAccepted []string `json:"fields_accepted"`
		} `json:"credential_boundary"`
		ScopePreview struct {
			AvailableResourceTypes int `json:"available_resource_types"`
			DisabledResourceTypes  int `json:"disabled_resource_types"`
			ExactResourceCount     int `json:"exact_resource_count"`
		} `json:"scope_preview"`
		Checks []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"checks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Status != "warning" || payload.NextAction != "review_warnings_then_save" {
		t.Fatalf("preflight status/action = %q/%q, want warning/review_warnings_then_save", payload.Status, payload.NextAction)
	}
	if !payload.CredentialBoundary.SendsSecrets || len(payload.CredentialBoundary.FieldsAccepted) != 1 || payload.CredentialBoundary.FieldsAccepted[0] != "token" {
		t.Fatalf("credential boundary = %#v, want encrypted token field", payload.CredentialBoundary)
	}
	if payload.ScopePreview.AvailableResourceTypes != 1 || payload.ScopePreview.DisabledResourceTypes != 1 || payload.ScopePreview.ExactResourceCount != 1 {
		t.Fatalf("scope preview = %#v, want one disabled type and one exact resource", payload.ScopePreview)
	}
	if len(store.runtimes) != 0 {
		t.Fatalf("stored runtimes len = %d, want 0", len(store.runtimes))
	}
	if len(store.credentials) != 0 {
		t.Fatalf("stored credentials len = %d, want 0", len(store.credentials))
	}
	if source.checkToken != "secret-token" {
		t.Fatalf("source check token = %q, want decrypted secret", source.checkToken)
	}
	checks := map[string]string{}
	for _, check := range payload.Checks {
		checks[check.ID] = check.Status
	}
	if checks["source_check"] != "passed" {
		t.Fatalf("source_check status = %q, want passed; checks=%#v", checks["source_check"], checks)
	}
}

func TestConnectorPreflightReturnsReferencePlanWhenReferencesMissing(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		ConnectorSecretStores: config.ConnectorSecretStoreConfig{
			Enabled: []string{connectorStoreAWSSecretsManager},
			AWSSecretsManager: config.AWSSecretsManagerStoreConfig{
				Region: "us-west-2",
			},
		},
	}, Dependencies{StateStore: &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{}}}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	body, err := json.Marshal(map[string]any{
		"runtime_id":          "runtime-external",
		"tenant_id":           "tenant-a",
		"auth_method":         connectorAuthMethodExternalReference,
		"credential_store_id": connectorStoreAWSSecretsManager,
		"config":              map[string]string{"family": "audit"},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	resp, err := server.Client().Post(server.URL+"/connectors/bootstrap_token/preflight", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /connectors/{sourceID}/preflight error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /connectors preflight status = %d, want 200", resp.StatusCode)
	}
	var payload struct {
		Status             string `json:"status"`
		CredentialBoundary struct {
			ReferenceTemplates []struct {
				Field     string `json:"field"`
				Required  bool   `json:"required"`
				Reference string `json:"reference"`
			} `json:"reference_templates"`
		} `json:"credential_boundary"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Status != "blocked" {
		t.Fatalf("preflight status = %q, want blocked", payload.Status)
	}
	if len(payload.CredentialBoundary.ReferenceTemplates) != 1 {
		t.Fatalf("reference templates = %#v, want token template", payload.CredentialBoundary.ReferenceTemplates)
	}
	template := payload.CredentialBoundary.ReferenceTemplates[0]
	if template.Field != "token" || !template.Required || template.Reference != "aws-sm:us-west-2:cerebro/tenant-a/bootstrap_token/runtime-external/credentials#token" {
		t.Fatalf("reference template = %#v", template)
	}
}

func TestConnectorPreflightBlocksUnscopedAWSReferenceAsCredentialBoundary(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		ConnectorSecretStores: config.ConnectorSecretStoreConfig{
			Enabled: []string{connectorStoreAWSSecretsManager},
			AWSSecretsManager: config.AWSSecretsManagerStoreConfig{
				Region: "us-west-2",
			},
		},
	}, Dependencies{StateStore: &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{}}}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	body, err := json.Marshal(map[string]any{
		"runtime_id":          "runtime-external",
		"tenant_id":           "tenant-a",
		"auth_method":         connectorAuthMethodExternalReference,
		"credential_store_id": connectorStoreAWSSecretsManager,
		"config":              map[string]string{"family": "audit"},
		"credential_references": map[string]string{
			"token": "aws-sm:us-west-2:shared/credentials#token", // #nosec G101 -- reference string, not secret material.
		},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	resp, err := server.Client().Post(server.URL+"/connectors/bootstrap_token/preflight", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /connectors/{sourceID}/preflight error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /connectors preflight status = %d, want 200", resp.StatusCode)
	}
	var payload struct {
		Status string `json:"status"`
		Checks []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"checks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Status != "blocked" {
		t.Fatalf("preflight status = %q, want blocked", payload.Status)
	}
	checks := map[string]string{}
	for _, check := range payload.Checks {
		checks[check.ID] = check.Status
	}
	if checks["credential_boundary"] != "blocked" {
		t.Fatalf("credential_boundary status = %q, want blocked; checks=%#v", checks["credential_boundary"], checks)
	}
	if _, ok := checks["source_check"]; ok {
		t.Fatalf("source_check ran for unscoped reference; checks=%#v", checks)
	}
}

func TestConnectorPreflightReturnsExternalReferencePlan(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token", emittedKinds: []string{"bootstrap.token"}}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		ConnectorSecretStores: config.ConnectorSecretStoreConfig{
			Enabled: []string{connectorStoreAWSSecretsManager},
			AWSSecretsManager: config.AWSSecretsManagerStoreConfig{
				Region: "us-west-2",
			},
		},
	}, Dependencies{StateStore: &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{}}}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()
	t.Setenv("CEREBRO_SOURCE_BOOTSTRAP_TOKEN_TOKEN", "resolved-token")

	body, err := json.Marshal(map[string]any{
		"runtime_id":          "runtime-external",
		"tenant_id":           "tenant-a",
		"auth_method":         connectorAuthMethodExternalReference,
		"credential_store_id": connectorStoreAWSSecretsManager,
		"config":              map[string]string{"family": "audit"},
		"credential_references": map[string]string{
			"token": "env:CEREBRO_SOURCE_BOOTSTRAP_TOKEN_TOKEN", // #nosec G101 -- env reference string, not a secret value.
		},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	resp, err := server.Client().Post(server.URL+"/connectors/bootstrap_token/preflight", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /connectors/{sourceID}/preflight error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /connectors preflight status = %d, want 200", resp.StatusCode)
	}
	var payload struct {
		Status             string `json:"status"`
		CredentialBoundary struct {
			StoreID                   string   `json:"credential_store_id"`
			StoreStatus               string   `json:"store_status"`
			ReferenceNamespace        string   `json:"reference_namespace"`
			ReferencePrefixes         []string `json:"reference_prefixes"`
			NativeResolutionAvailable bool     `json:"native_resolution_available"`
			FieldsAccepted            []string `json:"fields_accepted"`
			ReferenceTemplates        []struct {
				Field       string `json:"field"`
				Label       string `json:"label"`
				Required    bool   `json:"required"`
				Reference   string `json:"reference"`
				Description string `json:"description"`
			} `json:"reference_templates"`
		} `json:"credential_boundary"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Status != "ready" {
		t.Fatalf("preflight status = %q, want ready", payload.Status)
	}
	boundary := payload.CredentialBoundary
	if boundary.StoreID != connectorStoreAWSSecretsManager || boundary.StoreStatus != "ready" || !boundary.NativeResolutionAvailable {
		t.Fatalf("credential boundary store metadata = %#v", boundary)
	}
	if boundary.ReferenceNamespace != "cerebro/tenant-a/bootstrap_token/runtime-external/credentials" {
		t.Fatalf("reference namespace = %q", boundary.ReferenceNamespace)
	}
	if len(boundary.ReferencePrefixes) != 2 || boundary.ReferencePrefixes[0] != "env:" || boundary.ReferencePrefixes[1] != "aws-sm:" {
		t.Fatalf("reference prefixes = %#v, want env and aws-sm", boundary.ReferencePrefixes)
	}
	if len(boundary.ReferenceTemplates) != 1 {
		t.Fatalf("reference templates = %#v, want one token template", boundary.ReferenceTemplates)
	}
	template := boundary.ReferenceTemplates[0]
	if template.Field != "token" || !template.Required || template.Reference != "aws-sm:us-west-2:cerebro/tenant-a/bootstrap_token/runtime-external/credentials#token" {
		t.Fatalf("reference template = %#v", template)
	}
	if source.checkToken != "resolved-token" {
		t.Fatalf("source check token = %q, want env-resolved token", source.checkToken)
	}
}

func TestConnectorPreflightReturnsBlockedChecks(t *testing.T) {
	source := &failingConnectorCheckSource{bootstrapTokenSource: bootstrapTokenSource{id: "bootstrap_token"}}
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

	body := []byte(`{"runtime_id":"runtime-a","tenant_id":"tenant-a","auth_method":"environment_managed","credential_store_id":"environment_managed","config":{"family":"audit"},"credential_references":{"token":"env:CEREBRO_SOURCE_BOOTSTRAP_TOKEN_TOKEN"}}`)
	resp, err := server.Client().Post(server.URL+"/connectors/bootstrap_token/preflight", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /connectors/{sourceID}/preflight error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /connectors preflight status = %d, want 200", resp.StatusCode)
	}
	var payload struct {
		Status string `json:"status"`
		Checks []struct {
			ID       string `json:"id"`
			Status   string `json:"status"`
			Blocking bool   `json:"blocking"`
		} `json:"checks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Status != "blocked" {
		t.Fatalf("preflight status = %q, want blocked", payload.Status)
	}
	checks := map[string]struct {
		status   string
		blocking bool
	}{}
	for _, check := range payload.Checks {
		checks[check.ID] = struct {
			status   string
			blocking bool
		}{status: check.Status, blocking: check.Blocking}
	}
	if got := checks["source_check"]; got.status != "blocked" || !got.blocking {
		t.Fatalf("source_check = %#v, want blocked blocking check; checks=%#v", got, checks)
	}
	if len(store.runtimes) != 0 {
		t.Fatalf("stored runtimes len = %d, want 0", len(store.runtimes))
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

type connectorCoverageSource struct {
	*bootstrapTokenSource
	contract sourcecdk.CoverageContract
}

func (s *connectorCoverageSource) CoverageContract() sourcecdk.CoverageContract {
	return s.contract
}

type failingConnectorCheckSource struct {
	bootstrapTokenSource
}

func (s *failingConnectorCheckSource) Check(context.Context, sourcecdk.Config) error {
	return sourcecdk.ErrInvalidConfig
}
