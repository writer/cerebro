package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/ports"
)

func (s *connectorTestStore) PutConnectorDefinition(_ context.Context, record *ports.ConnectorDefinitionRecord) (*ports.ConnectorDefinitionRecord, error) {
	if s.definitions == nil {
		s.definitions = map[string]*ports.ConnectorDefinitionRecord{}
	}
	cloned := cloneConnectorDefinitionRecord(record)
	now := time.Now().UTC()
	if existing := s.definitions[record.ID]; existing != nil {
		if !existing.CreatedAt.IsZero() {
			cloned.CreatedAt = existing.CreatedAt
		}
		cloned.CurrentVersion = existing.CurrentVersion + 1
	} else {
		cloned.CreatedAt = now
		cloned.CurrentVersion = 1
	}
	cloned.UpdatedAt = now
	s.definitions[record.ID] = cloned
	return cloneConnectorDefinitionRecord(cloned), nil
}

func (s *connectorTestStore) GetConnectorDefinition(_ context.Context, id string) (*ports.ConnectorDefinitionRecord, error) {
	record, ok := s.definitions[id]
	if !ok {
		return nil, ports.ErrConnectorDefinitionNotFound
	}
	return cloneConnectorDefinitionRecord(record), nil
}

func (s *connectorTestStore) ListConnectorDefinitions(_ context.Context, filter ports.ConnectorDefinitionFilter) ([]*ports.ConnectorDefinitionRecord, error) {
	var records []*ports.ConnectorDefinitionRecord
	for _, record := range s.definitions {
		if filter.TenantID != "" && record.TenantID != filter.TenantID {
			continue
		}
		if filter.Stage != "" && record.Stage != filter.Stage {
			continue
		}
		records = append(records, cloneConnectorDefinitionRecord(record))
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].ID < records[j].ID
	})
	if filter.Limit > 0 && len(records) > int(filter.Limit) {
		records = records[:filter.Limit]
	}
	return records, nil
}

func TestConnectorDefinitionCreateListAndPromote(t *testing.T) {
	store := &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{}}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	createBody, err := json.Marshal(connectordefinitions.Definition{
		TenantID:    "tenant-a",
		SourceID:    "example_api",
		DisplayName: "Example API",
		Description: "Read-only Example API connector definition.",
		ConfigFields: []connectordefinitions.Field{{
			Key:      "base_url",
			Label:    "Base URL",
			Required: true,
		}},
		Auth: connectordefinitions.AuthSpec{
			Model:             "bearer_token",
			SupportedStoreIDs: []string{defaultConnectorCredentialStoreID, connectorStoreHashiCorpVault},
			CredentialFields: []connectordefinitions.Field{{
				Key:           "token",
				Label:         "Token",
				Secret:        true,
				ReferenceOnly: true,
				Required:      true,
			}},
		},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:        "assets",
			Label:     "Assets",
			Path:      "/v1/assets",
			IDField:   "id",
			NameField: "name",
		}},
	})
	if err != nil {
		t.Fatalf("marshal create body: %v", err)
	}
	createResp, err := server.Client().Post(server.URL+"/connector-definitions", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatalf("POST /connector-definitions error = %v", err)
	}
	defer closeResponseBody(t, createResp)
	if createResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /connector-definitions status = %d, want 200", createResp.StatusCode)
	}
	var created connectorDefinitionResponse
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.Definition.ID != "tenant-a-example_api" {
		t.Fatalf("definition id = %q, want tenant-a-example_api", created.Definition.ID)
	}
	if created.Definition.Stage != connectordefinitions.StageDraft || created.Definition.CurrentVersion != 1 {
		t.Fatalf("definition stage/version = %q/%d, want draft/1", created.Definition.Stage, created.Definition.CurrentVersion)
	}
	if created.Definition.Validation.Status != connectordefinitions.ValidationReady {
		t.Fatalf("validation = %q, want ready", created.Definition.Validation.Status)
	}

	listResp, err := server.Client().Get(server.URL + "/connector-definitions?tenant_id=tenant-a")
	if err != nil {
		t.Fatalf("GET /connector-definitions error = %v", err)
	}
	defer closeResponseBody(t, listResp)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /connector-definitions status = %d, want 200", listResp.StatusCode)
	}
	var list connectorDefinitionListResponse
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(list.Definitions) != 1 || list.Definitions[0].ID != created.Definition.ID {
		t.Fatalf("definitions = %#v, want created definition", list.Definitions)
	}

	promoteBody := stringsReader(t, `{"target_stage":"sandbox","reason":"sandbox validation ready"}`)
	promoteResp, err := server.Client().Post(server.URL+"/connector-definitions/"+created.Definition.ID+"/promote", "application/json", promoteBody)
	if err != nil {
		t.Fatalf("POST /connector-definitions/{id}/promote error = %v", err)
	}
	defer closeResponseBody(t, promoteResp)
	if promoteResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /connector-definitions/{id}/promote status = %d, want 200", promoteResp.StatusCode)
	}
	var promoted connectorDefinitionPromotionResponse
	if err := json.NewDecoder(promoteResp.Body).Decode(&promoted); err != nil {
		t.Fatalf("decode promote response: %v", err)
	}
	if !promoted.Result.Promoted || promoted.Result.Definition.Stage != connectordefinitions.StageSandbox {
		t.Fatalf("promotion result = %#v, want sandbox promotion", promoted.Result)
	}
	if promoted.Result.Definition.CurrentVersion != 2 {
		t.Fatalf("promoted version = %d, want 2", promoted.Result.Definition.CurrentVersion)
	}
}

func TestConnectorDefinitionCreateUsesScopedPrincipalTenant(t *testing.T) {
	store := &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{}}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:       "admin-key",
				Principal: "admin",
				TenantID:  "tenant-a",
			}},
		},
	}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	createBody, err := json.Marshal(connectordefinitions.Definition{
		SourceID:    "example_api",
		DisplayName: "Example API",
		Auth: connectordefinitions.AuthSpec{
			Model: "none",
		},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:      "assets",
			Path:    "/v1/assets",
			IDField: "id",
		}},
	})
	if err != nil {
		t.Fatalf("marshal create body: %v", err)
	}
	createReq, err := http.NewRequest(http.MethodPost, server.URL+"/connector-definitions", bytes.NewReader(createBody))
	if err != nil {
		t.Fatalf("NewRequest create: %v", err)
	}
	createReq.Header.Set("Authorization", "Bearer admin-key")
	createReq.Header.Set("Content-Type", "application/json")
	createResp, err := server.Client().Do(createReq)
	if err != nil {
		t.Fatalf("POST /connector-definitions error = %v", err)
	}
	defer closeResponseBody(t, createResp)
	if createResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /connector-definitions status = %d, want 200", createResp.StatusCode)
	}
	var created connectorDefinitionResponse
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.Definition.TenantID != "tenant-a" {
		t.Fatalf("definition tenant_id = %q, want tenant-a", created.Definition.TenantID)
	}
}

func TestConnectorDefinitionCreateRejectsCrossTenantBody(t *testing.T) {
	store := &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{}}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:       "admin-key",
				Principal: "admin",
				TenantID:  "tenant-a",
			}},
		},
	}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	createReq, err := http.NewRequest(http.MethodPost, server.URL+"/connector-definitions", stringsReader(t, `{
		"tenant_id": "tenant-b",
		"source_id": "example_api",
		"display_name": "Example API",
		"runtime": "json_api",
		"auth": {"model": "none"},
		"resource_families": [{"id": "assets", "path": "/v1/assets", "id_field": "id"}]
	}`))
	if err != nil {
		t.Fatalf("NewRequest create: %v", err)
	}
	createReq.Header.Set("Authorization", "Bearer admin-key")
	createReq.Header.Set("Content-Type", "application/json")
	createResp, err := server.Client().Do(createReq)
	if err != nil {
		t.Fatalf("POST /connector-definitions error = %v", err)
	}
	defer closeResponseBody(t, createResp)
	if createResp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST /connector-definitions status = %d, want 403", createResp.StatusCode)
	}
}

func TestConnectorDefinitionUpdateRejectsTenantReassignment(t *testing.T) {
	store := &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{}}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	createResp, err := server.Client().Post(server.URL+"/connector-definitions", "application/json", stringsReader(t, `{
		"tenant_id": "tenant-a",
		"source_id": "example_api",
		"display_name": "Example API",
		"runtime": "json_api",
		"auth": {"model": "none"},
		"resource_families": [{"id": "assets", "path": "/v1/assets", "id_field": "id"}]
	}`))
	if err != nil {
		t.Fatalf("POST /connector-definitions error = %v", err)
	}
	defer closeResponseBody(t, createResp)
	if createResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /connector-definitions status = %d, want 200", createResp.StatusCode)
	}
	var created connectorDefinitionResponse
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}

	updateReq, err := http.NewRequest(http.MethodPut, server.URL+"/connector-definitions/"+created.Definition.ID, stringsReader(t, `{
		"id": "`+created.Definition.ID+`",
		"tenant_id": "tenant-b",
		"source_id": "example_api",
		"display_name": "Example API",
		"runtime": "json_api",
		"auth": {"model": "none"},
		"resource_families": [{"id": "assets", "path": "/v1/assets", "id_field": "id"}]
	}`))
	if err != nil {
		t.Fatalf("NewRequest update: %v", err)
	}
	updateReq.Header.Set("Content-Type", "application/json")
	updateResp, err := server.Client().Do(updateReq)
	if err != nil {
		t.Fatalf("PUT /connector-definitions/{id} error = %v", err)
	}
	defer closeResponseBody(t, updateResp)
	if updateResp.StatusCode != http.StatusForbidden {
		t.Fatalf("PUT /connector-definitions/{id} status = %d, want 403", updateResp.StatusCode)
	}
}

func TestConnectorDefinitionValidateDoesNotRequireStore(t *testing.T) {
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Post(server.URL+"/connector-definitions/validate", "application/json", stringsReader(t, `{
		"tenant_id": "tenant-a",
		"source_id": "example_api",
		"display_name": "Example API",
		"runtime": "json_api",
		"auth": {"model": "api_key", "credential_fields": [{"key": "api_key", "secret": true}]},
		"resource_families": [{"id": "assets", "path": "https://api.example.test/assets", "method": "POST"}]
	}`))
	if err != nil {
		t.Fatalf("POST /connector-definitions/validate error = %v", err)
	}
	defer closeResponseBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /connector-definitions/validate status = %d, want 200", resp.StatusCode)
	}
	var validation connectorDefinitionValidationResponse
	if err := json.NewDecoder(resp.Body).Decode(&validation); err != nil {
		t.Fatalf("decode validation response: %v", err)
	}
	if validation.Validation.Status != connectordefinitions.ValidationBlocked {
		t.Fatalf("validation status = %q, want blocked", validation.Validation.Status)
	}
	if validation.Support.Verdict != connectordefinitions.SupportVerdictBespokeRequired {
		t.Fatalf("support verdict = %q, want bespoke_required; report=%#v", validation.Support.Verdict, validation.Support)
	}
	if len(validation.Promotion.RequiredGates) == 0 {
		t.Fatalf("required gates = %#v, want blocking gates", validation.Promotion.RequiredGates)
	}
}

func TestConnectorDefinitionListRequiresDefinitionStore(t *testing.T) {
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/connector-definitions")
	if err != nil {
		t.Fatalf("GET /connector-definitions error = %v", err)
	}
	defer closeResponseBody(t, resp)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("GET /connector-definitions status = %d, want 503", resp.StatusCode)
	}
}

func cloneConnectorDefinitionRecord(record *ports.ConnectorDefinitionRecord) *ports.ConnectorDefinitionRecord {
	if record == nil {
		return nil
	}
	cloned := *record
	cloned.DefinitionJSON = append([]byte{}, record.DefinitionJSON...)
	return &cloned
}

func stringsReader(t *testing.T, value string) *bytes.Reader {
	t.Helper()
	return bytes.NewReader([]byte(value))
}

func closeResponseBody(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp == nil || resp.Body == nil {
		return
	}
	if err := resp.Body.Close(); err != nil {
		t.Errorf("close response body: %v", err)
	}
}

var _ ports.ConnectorDefinitionStore = (*connectorTestStore)(nil)
