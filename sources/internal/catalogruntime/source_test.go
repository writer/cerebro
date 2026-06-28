package catalogruntime

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckAndReadDefinition(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret"))
		if got := r.Header.Get("Authorization"); got != wantAuth {
			t.Fatalf("Authorization = %q, want %q", got, wantAuth)
		}
		switch r.URL.Path {
		case "/me":
			w.WriteHeader(http.StatusNoContent)
		case "/users":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"id": "U1", "email": "alice@example.com", "updated_at": "2026-06-01T00:00:00Z"}},
			})
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	source, err := NewDefinition(connectordefinitions.Definition{
		ID:          "tenant-example",
		TenantID:    "tenant",
		SourceID:    "example",
		DisplayName: "Example",
		Auth: connectordefinitions.AuthSpec{
			Model: "basic",
		},
		Transport: &connectordefinitions.TransportSpec{
			BaseURL: server.URL,
			Verification: &connectordefinitions.VerificationSpec{
				Path:         "/me",
				ExpectStatus: []int{http.StatusNoContent},
			},
		},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "users",
			Path:           "/users",
			RecordSelector: "$.data[*]",
			IDField:        "id",
			Event: connectordefinitions.EventMappingSpec{
				Kind:      "example.users",
				SchemaRef: "example/users/v1",
			},
			Projection: &connectordefinitions.ProjectionSpec{Template: "identity_user"},
			Coverage:   []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
		}},
	})
	if err != nil {
		t.Fatalf("NewDefinition() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"username":  "alice",
		"password":  "secret",
	})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.Events[0].Kind != "example.users" {
		t.Fatalf("events = %#v, want example.users event", pull.Events)
	}
}

func TestSourceDefinitionReadsSingletonFamily(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/account" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "account", "name": "Primary account"})
	}))
	defer server.Close()

	source, err := NewDefinition(connectordefinitions.Definition{
		ID:          "tenant-example",
		TenantID:    "tenant",
		SourceID:    "example",
		DisplayName: "Example",
		Auth:        connectordefinitions.AuthSpec{Model: "bearer_token"},
		Transport:   &connectordefinitions.TransportSpec{BaseURL: server.URL},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:        "account",
			Path:      "/account",
			IDField:   "id",
			Singleton: true,
			Event: connectordefinitions.EventMappingSpec{
				Kind:      "example.account",
				SchemaRef: "example/account/v1",
			},
			Projection: &connectordefinitions.ProjectionSpec{Template: "asset"},
			Coverage:   []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
		}},
	})
	if err != nil {
		t.Fatalf("NewDefinition() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "token": "token"}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.Events[0].Kind != "example.account" {
		t.Fatalf("events = %#v, want example.account event", pull.Events)
	}
}

func TestSourceDefinitionUsesPagePagination(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		if got := r.URL.Query().Get("per_page"); got != "2" {
			t.Fatalf("per_page query = %q, want 2", got)
		}
		switch r.URL.Query().Get("page") {
		case "1":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "A"}, {"id": "B"}})
		case "2":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "C"}})
		default:
			t.Fatalf("unexpected page %q", r.URL.Query().Get("page"))
		}
	}))
	defer server.Close()

	source, err := NewDefinition(connectordefinitions.Definition{
		ID:          "tenant-example",
		TenantID:    "tenant",
		SourceID:    "example",
		DisplayName: "Example",
		Auth:        connectordefinitions.AuthSpec{Model: "bearer_token"},
		Transport:   &connectordefinitions.TransportSpec{BaseURL: server.URL},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "training_enrollments",
			Path:           "/training/enrollments",
			RecordSelector: "$[*]",
			IDField:        "id",
			Event: connectordefinitions.EventMappingSpec{
				Kind:      "example.training_enrollments",
				SchemaRef: "example/training_enrollments/v1",
			},
			Projection: &connectordefinitions.ProjectionSpec{Template: "audit_event"},
			Coverage:   []connectordefinitions.CoverageDimensionSpec{{Type: "audit_event", Support: "partial"}},
			Pagination: &connectordefinitions.PaginationSpec{
				Type:          "page",
				PageParam:     "page",
				PageSizeParam: "per_page",
				StartPage:     1,
			},
		}},
	})
	if err != nil {
		t.Fatalf("NewDefinition() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"token":     "token",
		"per_page":  "2",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != "2" {
		t.Fatalf("first NextCursor = %q, want 2", first.NextCursor.GetOpaque())
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if len(requests) != 2 {
		t.Fatalf("requests len = %d, want 2", len(requests))
	}
}

func TestSourceDefinitionDoesNotSynthesizeCursorWithoutPageParam(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("cursor"); got != "" {
			t.Fatalf("cursor query = %q, want empty", got)
		}
		if got := r.URL.Query().Get("per_page"); got != "2" {
			t.Fatalf("per_page query = %q, want 2", got)
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "A"}, {"id": "B"}})
	}))
	defer server.Close()

	source, err := NewDefinition(connectordefinitions.Definition{
		ID:          "tenant-example",
		TenantID:    "tenant",
		SourceID:    "example",
		DisplayName: "Example",
		Auth:        connectordefinitions.AuthSpec{Model: "bearer_token"},
		Transport:   &connectordefinitions.TransportSpec{BaseURL: server.URL},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "records",
			Path:           "/records",
			RecordSelector: "$[*]",
			IDField:        "id",
			Event:          connectordefinitions.EventMappingSpec{Kind: "example.records", SchemaRef: "example/records/v1"},
			Projection:     &connectordefinitions.ProjectionSpec{Template: "audit_event"},
			Coverage:       []connectordefinitions.CoverageDimensionSpec{{Type: "audit_event", Support: "partial"}},
			Pagination: &connectordefinitions.PaginationSpec{
				Type:          "page",
				PageSizeParam: "per_page",
			},
		}},
	})
	if err != nil {
		t.Fatalf("NewDefinition() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"token":     "token",
		"per_page":  "2",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if pull.NextCursor != nil {
		t.Fatalf("NextCursor = %#v, want nil", pull.NextCursor)
	}
}

func TestSourceDefinitionUsesCursorJSONPath(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		switch r.URL.Query().Get("after") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"id": "item-1"}},
				"paging": map[string]any{
					"continuation": "item-1",
				},
			})
		case "item-1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"id": "item-2"}},
			})
		default:
			t.Fatalf("after = %q, want empty or item-1", r.URL.Query().Get("after"))
		}
	}))
	defer server.Close()

	source, err := NewDefinition(connectordefinitions.Definition{
		ID:          "tenant-example",
		TenantID:    "tenant",
		SourceID:    "example",
		DisplayName: "Example",
		Auth:        connectordefinitions.AuthSpec{Model: "bearer_token"},
		Transport:   &connectordefinitions.TransportSpec{BaseURL: server.URL},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "records",
			Path:           "/records",
			RecordSelector: "$.data[*]",
			IDField:        "id",
			Event:          connectordefinitions.EventMappingSpec{Kind: "example.records", SchemaRef: "example/records/v1"},
			Projection:     &connectordefinitions.ProjectionSpec{Template: "audit_event"},
			Coverage:       []connectordefinitions.CoverageDimensionSpec{{Type: "audit_event", Support: "partial"}},
			Pagination: &connectordefinitions.PaginationSpec{
				Type:           "cursor",
				CursorParam:    "after",
				CursorJSONPath: "$.paging.continuation",
				PageSizeParam:  "limit",
			},
		}},
	})
	if err != nil {
		t.Fatalf("NewDefinition() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	first, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"token":     "token",
		"per_page":  "1",
	}), nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != "item-1" {
		t.Fatalf("first NextCursor = %q, want item-1", first.NextCursor.GetOpaque())
	}
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"token":     "token",
		"per_page":  "1",
	}), first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(requests) != 2 || requests[1].URL.Query().Get("after") != "item-1" {
		t.Fatalf("requests = %#v, want second request with after=item-1", requests)
	}
}

func TestSourceDefinitionUsesLinkHeaderPagination(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		switch r.URL.Query().Get("cursor") {
		case "":
			w.Header().Set("Link", `<http://`+r.Host+`/records?cursor=item-1&limit=1>; rel="next"`)
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "item-1"}})
		case "item-1":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "item-2"}})
		default:
			t.Fatalf("cursor = %q, want empty or item-1", r.URL.Query().Get("cursor"))
		}
	}))
	defer server.Close()

	source, err := NewDefinition(connectordefinitions.Definition{
		ID:          "tenant-example",
		TenantID:    "tenant",
		SourceID:    "example",
		DisplayName: "Example",
		Auth:        connectordefinitions.AuthSpec{Model: "bearer_token"},
		Transport:   &connectordefinitions.TransportSpec{BaseURL: server.URL},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "records",
			Path:           "/records",
			RecordSelector: "$[*]",
			IDField:        "id",
			Event:          connectordefinitions.EventMappingSpec{Kind: "example.records", SchemaRef: "example/records/v1"},
			Projection:     &connectordefinitions.ProjectionSpec{Template: "audit_event"},
			Coverage:       []connectordefinitions.CoverageDimensionSpec{{Type: "audit_event", Support: "partial"}},
			Pagination: &connectordefinitions.PaginationSpec{
				Type:          "link",
				CursorParam:   "cursor",
				LinkHeader:    "Link",
				PageSizeParam: "limit",
			},
		}},
	})
	if err != nil {
		t.Fatalf("NewDefinition() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	first, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"token":     "token",
		"per_page":  "1",
	}), nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != "item-1" {
		t.Fatalf("first NextCursor = %q, want item-1", first.NextCursor.GetOpaque())
	}
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"token":     "token",
		"per_page":  "1",
	}), first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(requests) != 2 || requests[1].URL.Query().Get("cursor") != "item-1" {
		t.Fatalf("requests = %#v, want second request with cursor=item-1", requests)
	}
}

func TestSourceDefinitionUsesFamilyConfigQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/models" {
			t.Fatalf("path = %q, want /models", got)
		}
		if got := r.URL.Query().Get("author"); got != "writer" {
			t.Fatalf("author query = %q, want writer", got)
		}
		if got := r.URL.Query().Get("limit"); got != "" {
			t.Fatalf("limit query = %q, want empty", got)
		}
		if got := r.URL.Query().Get("per_page"); got != "" {
			t.Fatalf("per_page query = %q, want empty", got)
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "writer/model"}})
	}))
	defer server.Close()

	source, err := NewDefinition(connectordefinitions.Definition{
		ID:          "tenant-huggingface",
		TenantID:    "tenant",
		SourceID:    "huggingface",
		DisplayName: "Hugging Face",
		Auth:        connectordefinitions.AuthSpec{Model: "bearer_token"},
		Transport:   &connectordefinitions.TransportSpec{BaseURL: server.URL},
		ConfigFields: []connectordefinitions.Field{{
			Key:      "organization",
			Required: true,
		}},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "repositories",
			Path:           "/models",
			RecordSelector: "$[*]",
			IDField:        "id",
			ConfigQuery:    map[string]string{"author": "organization"},
			Event:          connectordefinitions.EventMappingSpec{Kind: "huggingface.repositories", SchemaRef: "huggingface/repositories/v1"},
			Projection:     &connectordefinitions.ProjectionSpec{Template: "repository"},
			Coverage:       []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
			Pagination: &connectordefinitions.PaginationSpec{
				Type:            "none",
				DisablePageSize: true,
			},
		}},
	})
	if err != nil {
		t.Fatalf("NewDefinition() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id":    "tenant",
		"token":        "token",
		"organization": "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.Events[0].Kind != "huggingface.repositories" {
		t.Fatalf("events = %#v, want huggingface.repositories event", pull.Events)
	}
}

func TestSourceAuthModels(t *testing.T) {
	tests := []struct {
		name           string
		authModel      string
		tokenHeader    string
		tokenScheme    string
		config         map[string]string
		wantHeaderName string
		wantAuthHeader string
		wantGrantType  string
	}{
		{
			name:           "bearer token",
			authModel:      "bearer_token",
			config:         map[string]string{"token": "bearer-token"},
			wantAuthHeader: "Bearer bearer-token",
		},
		{
			name:           "api key",
			authModel:      "api_key",
			config:         map[string]string{"api_key": "api-token"},
			wantAuthHeader: "Token api-token",
		},
		{
			name:           "custom api key header",
			authModel:      "api_key",
			tokenHeader:    "x-api-key",
			config:         map[string]string{"api_key": "api-token"},
			wantHeaderName: "x-api-key",
			wantAuthHeader: "api-token",
		},
		{
			name:           "basic",
			authModel:      "basic",
			config:         map[string]string{"username": "alice", "password": "secret"},
			wantAuthHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret")),
		},
		{
			name:           "oauth client credentials",
			authModel:      "oauth_client_credentials",
			config:         map[string]string{"client_id": "client", "client_secret": "secret"},
			wantAuthHeader: "Bearer test-token",
			wantGrantType:  "client_credentials",
		},
		{
			name:           "oauth authorization code refresh",
			authModel:      "oauth_authorization_code",
			config:         map[string]string{"client_id": "client", "client_secret": "secret", "refresh_token": "refresh"},
			wantAuthHeader: "Bearer test-token",
			wantGrantType:  "refresh_token",
		},
		{
			name:           "jwt",
			authModel:      "jwt",
			config:         map[string]string{"jwt": "jwt-token"},
			wantAuthHeader: "Bearer jwt-token",
		},
		{
			name:           "signature",
			authModel:      "signature",
			config:         map[string]string{"signature": "signature-token"},
			wantAuthHeader: "Signature signature-token",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tokenRequests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/oauth/token":
					tokenRequests++
					r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
					if err := r.ParseForm(); err != nil {
						t.Fatalf("ParseForm() error = %v", err)
					}
					if got := r.Form.Get("grant_type"); got != test.wantGrantType {
						t.Fatalf("grant_type = %q, want %q", got, test.wantGrantType)
					}
					if r.Form.Get("client_id") != "client" || r.Form.Get("client_secret") != "secret" {
						t.Fatalf("oauth client form = %#v", r.Form)
					}
					if test.wantGrantType == "refresh_token" && r.Form.Get("refresh_token") != "refresh" {
						t.Fatalf("refresh_token = %q, want refresh", r.Form.Get("refresh_token"))
					}
					_ = json.NewEncoder(w).Encode(map[string]any{
						"access_token": "test-token",
						"token_type":   "Bearer",
						"expires_in":   3600,
					})
				case "/me":
					headerName := firstNonEmpty(test.wantHeaderName, "Authorization")
					if got := r.Header.Get(headerName); got != test.wantAuthHeader {
						t.Fatalf("%s = %q, want %q", headerName, got, test.wantAuthHeader)
					}
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Fatalf("unexpected path %q", r.URL.Path)
				}
			}))
			defer server.Close()

			definition := authTestDefinition(server.URL, test.authModel)
			definition.Auth.TokenHeader = test.tokenHeader
			definition.Auth.TokenScheme = test.tokenScheme
			if test.wantGrantType != "" {
				definition.Auth.TokenURL = server.URL + "/oauth/token"
				definition.Auth.TokenRequestAuthMethod = "client_secret_post"
			}
			if test.authModel == "oauth_authorization_code" {
				definition.Auth.AuthorizationURL = server.URL + "/oauth/authorize"
			}
			source, err := NewDefinition(definition)
			if err != nil {
				t.Fatalf("NewDefinition() error = %v", err)
			}
			source.inner.AllowLoopbackBaseURL = true
			cfg := map[string]string{"tenant_id": "tenant"}
			for key, value := range test.config {
				cfg[key] = value
			}
			if err := source.Check(context.Background(), sourcecdk.NewConfig(cfg)); err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if test.wantGrantType != "" && tokenRequests != 1 {
				t.Fatalf("tokenRequests = %d, want 1", tokenRequests)
			}
		})
	}
}

func TestProjectionFieldsOverrideClassDefaults(t *testing.T) {
	attrs := attributePaths(connectordefinitions.ResourceFamily{
		ID: "findings",
		Projection: &connectordefinitions.ProjectionSpec{
			Template: "finding",
			Fields: map[string]string{
				"severity": "data.cvss_label",
				"status":   "data.lifecycle",
			},
		},
	}, "finding")
	if attrs["severity"] != "data.cvss_label" {
		t.Fatalf("severity = %q, want projection override", attrs["severity"])
	}
	if attrs["status"] != "data.lifecycle" {
		t.Fatalf("status = %q, want projection override", attrs["status"])
	}
	if attrs["title"] == "" {
		t.Fatal("title default missing")
	}
}

func TestSecretProjectionTemplateDefaults(t *testing.T) {
	resource := connectordefinitions.ResourceFamily{
		ID: "secrets",
		Projection: &connectordefinitions.ProjectionSpec{
			Template: "secret",
		},
	}
	if got := projectionClass(resource); got != "secret" {
		t.Fatalf("projectionClass() = %q, want secret", got)
	}
	keys := idKeys(resource, "secret")
	for _, want := range []string{"secret_id", "id"} {
		if !slices.Contains(keys, want) {
			t.Fatalf("idKeys() = %#v, want %q", keys, want)
		}
	}
	attrs := attributePaths(resource, "secret")
	for _, want := range []string{"secret_id", "secret_name"} {
		if attrs[want] == "" {
			t.Fatalf("attributePaths()[%q] missing in %#v", want, attrs)
		}
	}
}

func authTestDefinition(baseURL string, authModel string) connectordefinitions.Definition {
	return connectordefinitions.Definition{
		ID:          "tenant-example",
		TenantID:    "tenant",
		SourceID:    "example",
		DisplayName: "Example",
		Auth:        connectordefinitions.AuthSpec{Model: authModel},
		Transport: &connectordefinitions.TransportSpec{
			BaseURL: baseURL,
			Verification: &connectordefinitions.VerificationSpec{
				Path:         "/me",
				ExpectStatus: []int{http.StatusNoContent},
			},
		},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "users",
			Path:           "/users",
			RecordSelector: "$.data[*]",
			IDField:        "id",
			Event: connectordefinitions.EventMappingSpec{
				Kind:      "example.users",
				SchemaRef: "example/users/v1",
			},
			Projection: &connectordefinitions.ProjectionSpec{Template: "identity_user"},
		}},
	}
}
