package catalogruntime

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcecdk"
	"google.golang.org/protobuf/types/known/timestamppb"
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

func TestSourceDefinitionReadsNestedRecordSelector(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/connections" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"items": []map[string]any{{
					"id":         "connection-1",
					"service":    "postgres",
					"updated_at": "2026-06-01T00:00:00Z",
				}},
			},
		})
	}))
	defer server.Close()

	source, err := NewDefinition(connectordefinitions.Definition{
		ID:          "tenant-example",
		TenantID:    "tenant",
		SourceID:    "example",
		DisplayName: "Example",
		Auth:        connectordefinitions.AuthSpec{Model: "none"},
		Transport:   &connectordefinitions.TransportSpec{BaseURL: server.URL},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "connections",
			Path:           "/connections",
			RecordSelector: "$.data.items[*]",
			IDField:        "id",
			Event: connectordefinitions.EventMappingSpec{
				Kind:      "example.connections",
				SchemaRef: "example/connections/v1",
			},
			Projection: &connectordefinitions.ProjectionSpec{
				Template: "asset",
				Fields: map[string]string{
					"resource_id":   "id",
					"resource_type": "service",
				},
			},
			Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
		}},
	})
	if err != nil {
		t.Fatalf("NewDefinition() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant"}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "example.connections" || event.Attributes["resource_id"] != "connection-1" {
		t.Fatalf("event = %#v, want nested selector event", event)
	}
}

func TestSourceDefinitionRedactsSensitivePayloadPaths(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/keys" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":     "key-1",
				"name":   "Automation key",
				"key":    "public-material",
				"secret": "secret-material",
				"nested": map[string]any{"secret": "nested-secret"},
			}},
		})
	}))
	defer server.Close()

	source, err := NewDefinition(connectordefinitions.Definition{
		ID:          "tenant-example",
		TenantID:    "tenant",
		SourceID:    "example",
		DisplayName: "Example",
		Auth:        connectordefinitions.AuthSpec{Model: "none"},
		Transport:   &connectordefinitions.TransportSpec{BaseURL: server.URL},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "system_keys",
			Path:           "/keys",
			RecordSelector: "$.data[*]",
			IDField:        "id",
			Event:          connectordefinitions.EventMappingSpec{Kind: "example.system_keys", SchemaRef: "example/system_keys/v1"},
			Projection:     &connectordefinitions.ProjectionSpec{Template: "asset"},
			Coverage:       []connectordefinitions.CoverageDimensionSpec{{Type: "app_entitlement", Support: "partial"}},
			SensitivePayloadPaths: []string{
				"$.key",
				"$.secret",
				"$.nested.secret",
			},
		}},
	})
	if err != nil {
		t.Fatalf("NewDefinition() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant"}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	var payload map[string]any
	if err := json.Unmarshal(pull.Events[0].Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if _, ok := payload["key"]; ok {
		t.Fatalf("payload retained key: %#v", payload)
	}
	if _, ok := payload["secret"]; ok {
		t.Fatalf("payload retained secret: %#v", payload)
	}
	nested, _ := payload["nested"].(map[string]any)
	if _, ok := nested["secret"]; ok {
		t.Fatalf("payload retained nested secret: %#v", payload)
	}
}

func TestReadDefinitionFixtureSeedsRequiredConfigFields(t *testing.T) {
	result, err := ReadDefinitionFixture(context.Background(), connectordefinitions.Definition{
		ID:          "tenant-example",
		TenantID:    "tenant",
		SourceID:    "example",
		DisplayName: "Example",
		Auth: connectordefinitions.AuthSpec{
			Model: "oauth_client_credentials",
			CredentialFields: []connectordefinitions.Field{
				{Key: "client_id", Required: true, ReferenceOnly: true},
				{Key: "client_secret", Required: true, Secret: true, ReferenceOnly: true},
			},
			TokenParams: map[string]string{"subject": "${config.enterprise_id}"},
			TokenURL:    "https://example.test/oauth/token",
		},
		ConfigFields: []connectordefinitions.Field{{Key: "enterprise_id", Required: true}},
		Transport:    &connectordefinitions.TransportSpec{BaseURL: "https://example.test"},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "users",
			Path:           "/users",
			RecordSelector: "$.data[*]",
			IDField:        "id",
			Event: connectordefinitions.EventMappingSpec{
				Kind:      "example.users",
				SchemaRef: "example/users/v1",
			},
			Projection: &connectordefinitions.ProjectionSpec{
				Template: "identity_user",
				Fields:   map[string]string{"user_id": "id", "email": "email"},
			},
			Pagination: &connectordefinitions.PaginationSpec{
				Type:          "cursor",
				CursorParam:   "cursor",
				PageSizeParam: "limit",
				PageSize:      100,
			},
			Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
		}},
	}, "users", []byte(`{"data":[{"id":"user-1","email":"user@example.test"}]}`))
	if err != nil {
		t.Fatalf("ReadDefinitionFixture() error = %v", err)
	}
	if result.EventCount != 1 {
		t.Fatalf("EventCount = %d, want 1", result.EventCount)
	}
}

func TestSelectorListKeySupportsNestedSelectors(t *testing.T) {
	if got := selectorListKey("$.response.items[*]"); got != "response.items" {
		t.Fatalf("selectorListKey() = %q, want response.items", got)
	}
	if got := selectorListKey("$.response.authlogs[*]"); got != "response.authlogs" {
		t.Fatalf("selectorListKey() = %q, want response.authlogs", got)
	}
}

func TestSourceDefinitionUsesFamilyBaseURLOverride(t *testing.T) {
	defaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("default server received family override request at %q", r.URL.Path)
	}))
	defer defaultServer.Close()
	auditServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/audit/v1/logs" {
			t.Fatalf("audit path = %q, want /audit/v1/logs", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entries": []map[string]any{{"id": "A1", "action": "user_login"}},
		})
	}))
	defer auditServer.Close()

	source, err := NewDefinition(connectordefinitions.Definition{
		ID:          "tenant-example",
		TenantID:    "tenant",
		SourceID:    "example",
		DisplayName: "Example",
		Auth:        connectordefinitions.AuthSpec{Model: "none"},
		Transport:   &connectordefinitions.TransportSpec{BaseURL: defaultServer.URL},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "audit_log",
			Path:           "/logs",
			RecordSelector: "$.entries[*]",
			IDField:        "id",
			Config:         &connectordefinitions.FamilyConfigSpec{BaseURL: auditServer.URL + "/audit/v1"},
			Event: connectordefinitions.EventMappingSpec{
				Kind:      "example.audit_log",
				SchemaRef: "example/audit_log/v1",
			},
			Projection: &connectordefinitions.ProjectionSpec{Template: "audit_event"},
			Coverage:   []connectordefinitions.CoverageDimensionSpec{{Type: "audit_event", Support: "supported"}},
		}},
	})
	if err != nil {
		t.Fatalf("NewDefinition() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"family":    "audit_log",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.Events[0].Kind != "example.audit_log" {
		t.Fatalf("events = %#v, want example.audit_log event", pull.Events)
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

func TestSourceDefinitionUsesNextURLPagination(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		switch r.URL.Query().Get("page") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value":    []map[string]any{{"id": "item-1"}},
				"nextLink": "http://" + r.Host + "/records?page=2",
			})
		case "2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{{"id": "item-2"}},
			})
		default:
			t.Fatalf("page = %q, want empty or 2", r.URL.Query().Get("page"))
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
			RecordSelector: "$.value[*]",
			IDField:        "id",
			Event:          connectordefinitions.EventMappingSpec{Kind: "example.records", SchemaRef: "example/records/v1"},
			Projection:     &connectordefinitions.ProjectionSpec{Template: "asset"},
			Coverage:       []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
			Pagination: &connectordefinitions.PaginationSpec{
				Type:            "next_url",
				NextURLJSONPath: "$.nextLink",
				DisablePageSize: true,
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
	}), nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != server.URL+"/records?page=2" {
		t.Fatalf("first NextCursor = %q, want nextLink", first.NextCursor.GetOpaque())
	}
	second, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"token":     "token",
	}), first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 || second.Events[0].Id == first.Events[0].Id {
		t.Fatalf("second events = %#v, want second page", second.Events)
	}
	if len(requests) != 2 || requests[1].URL.Query().Get("page") != "2" {
		t.Fatalf("requests = %#v, want second request from nextLink", requests)
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

func TestSourceDefinitionUsesFamilyStaticHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept"); got != "application/json;version=2" {
			t.Fatalf("Accept = %q, want Fivetran v2 header", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"items": []map[string]any{{"id": "dest-1", "service": "snowflake"}},
			},
		})
	}))
	defer server.Close()

	source, err := NewDefinition(connectordefinitions.Definition{
		ID:          "tenant-fivetran",
		TenantID:    "tenant",
		SourceID:    "fivetran",
		DisplayName: "Fivetran",
		Auth:        connectordefinitions.AuthSpec{Model: "basic"},
		Transport: &connectordefinitions.TransportSpec{
			BaseURL: server.URL,
			Headers: map[string]string{
				"Accept": "application/json",
			},
		},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "destinations",
			Path:           "/v1/destinations",
			RecordSelector: "$.data.items[*]",
			IDField:        "id",
			StaticHeaders: map[string]string{
				"Accept": "application/json;version=2",
			},
			Event:      connectordefinitions.EventMappingSpec{Kind: "fivetran.destinations", SchemaRef: "fivetran/destinations/v1"},
			Projection: &connectordefinitions.ProjectionSpec{Template: "asset"},
			Coverage:   []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "supported"}},
		}},
	})
	if err != nil {
		t.Fatalf("NewDefinition() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"username":  "key",
		"password":  "secret",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.Events[0].Kind != "fivetran.destinations" {
		t.Fatalf("events = %#v, want fivetran.destinations event", pull.Events)
	}
}

func TestSourceDefinitionUsesFamilyIdentityKeys(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/sessions" {
			t.Fatalf("path = %q, want /sessions", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{
			{"user_id": "user-1", "ip": "203.0.113.10"},
			{"user_id": "user-1", "ip": "198.51.100.25"},
		}})
	}))
	defer server.Close()

	source, err := NewDefinition(connectordefinitions.Definition{
		ID:          "tenant-example",
		TenantID:    "tenant",
		SourceID:    "example",
		DisplayName: "Example",
		Auth:        connectordefinitions.AuthSpec{Model: "none"},
		Transport:   &connectordefinitions.TransportSpec{BaseURL: server.URL},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "sessions",
			Path:           "/sessions",
			RecordSelector: "$.data[*]",
			IDField:        "user_id",
			Event:          connectordefinitions.EventMappingSpec{Kind: "example.sessions", SchemaRef: "example/sessions/v1"},
			Config:         &connectordefinitions.FamilyConfigSpec{IdentityKeys: []string{"ip"}},
			Projection:     &connectordefinitions.ProjectionSpec{Template: "audit_event"},
			Coverage:       []connectordefinitions.CoverageDimensionSpec{{Type: "audit_event", Support: "partial"}},
		}},
	})
	if err != nil {
		t.Fatalf("NewDefinition() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant"}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(Events) = %d, want 2 identity-scoped events", len(pull.Events))
	}
	if pull.Events[0].Id == pull.Events[1].Id {
		t.Fatalf("event IDs collapsed across identity keys: %q", pull.Events[0].Id)
	}
}

func TestSourceDefinitionRejectsUnsupportedMethods(t *testing.T) {
	_, err := NewDefinition(connectordefinitions.Definition{
		ID:          "tenant-example",
		TenantID:    "tenant",
		SourceID:    "example",
		DisplayName: "Example",
		Auth:        connectordefinitions.AuthSpec{Model: "none"},
		Transport:   &connectordefinitions.TransportSpec{BaseURL: "https://api.example.test"},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "records",
			Path:           "/records",
			Method:         http.MethodDelete,
			RecordSelector: "$.data[*]",
			IDField:        "id",
			Event:          connectordefinitions.EventMappingSpec{Kind: "example.records", SchemaRef: "example/records/v1"},
			Projection:     &connectordefinitions.ProjectionSpec{Template: "asset"},
			Coverage:       []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
		}},
	})
	if err == nil {
		t.Fatal("NewDefinition() error = nil, want unsupported method error")
	}
	if got := err.Error(); !strings.Contains(got, `method "DELETE" is not supported`) {
		t.Fatalf("NewDefinition() error = %q, want unsupported method", got)
	}
}

func TestSourceDefinitionUsesDeclarativeRuntimeDepthFields(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		switch r.URL.EscapedPath() {
		case "/accounts/account%2Fone/users/search":
			if r.Method != http.MethodPost {
				t.Fatalf("method = %q, want POST", r.Method)
			}
			if got := r.URL.Query().Get("include"); got != "profile" {
				t.Fatalf("include query = %q, want profile", got)
			}
			if got := r.URL.Query()["scope[]"]; len(got) != 2 || got[0] != "read" || got[1] != "write" {
				t.Fatalf("scope[] query = %#v, want read/write", got)
			}
			if got := r.URL.Query().Get("limit"); got != "2" {
				t.Fatalf("limit query = %q, want 2", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data":     []map[string]any{{"id": "U1", "updated_at": "2026-06-15T13:00:00Z"}},
				"has_more": true,
				"last_id":  "U1",
			})
		case "/users/U1/detail":
			if r.Method != http.MethodPost {
				t.Fatalf("detail method = %q, want POST", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"email": "alice@example.com", "display_name": "Alice"})
		default:
			t.Fatalf("unexpected path %q", r.URL.EscapedPath())
		}
	}))
	defer server.Close()

	source, err := NewDefinition(connectordefinitions.Definition{
		ID:          "tenant-example",
		TenantID:    "tenant",
		SourceID:    "example",
		DisplayName: "Example",
		Auth:        connectordefinitions.AuthSpec{Model: "none"},
		Transport:   &connectordefinitions.TransportSpec{BaseURL: server.URL},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "users",
			Path:           "/accounts/{account_id}/users/search",
			Read:           &connectordefinitions.ResourceReadSpec{DetailPath: "/users/{id}/detail", AllowBareDetailRecord: true, PathParams: []string{"account_id"}},
			Method:         http.MethodPost,
			RecordSelector: "$.data[*]",
			IDField:        "id",
			NameField:      "display_name",
			Event:          connectordefinitions.EventMappingSpec{Kind: "example.users", SchemaRef: "example/users/v1"},
			Config: &connectordefinitions.FamilyConfigSpec{
				StaticQuery:      map[string]string{"include": "profile"},
				ConfigQuery:      map[string]string{"scope[]": "scopes"},
				ConfigAttributes: map[string]string{"account_label": "account_label"},
			},
			Pagination: &connectordefinitions.PaginationSpec{
				Type:           "cursor",
				CursorParam:    "after",
				PageSizeParam:  "limit",
				NextCursorKeys: []string{"last_id"},
				HasMoreKey:     "has_more",
			},
			Incremental: &connectordefinitions.IncrementalSpec{CursorField: "updated_at"},
			Projection:  &connectordefinitions.ProjectionSpec{Template: "identity_user"},
			Coverage:    []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
		}},
	})
	if err != nil {
		t.Fatalf("NewDefinition() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":      "tenant",
		"account_id":     "account/one",
		"account_label":  "Primary account",
		"scopes":         "read,write",
		"per_page":       "2",
		"family":         "users",
		"source_runtime": "runtime-1",
	})
	pull, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, &cerebrov1.SourceCheckpoint{
		Watermark: timestamppb.New(time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %#v, want one event", pull.Events)
	}
	event := pull.Events[0]
	if event.Attributes["email"] != "alice@example.com" || event.Attributes["account_id"] != "account/one" || event.Attributes["account_label"] != "Primary account" {
		t.Fatalf("event attributes = %#v, want detail, path, and config attributes", event.Attributes)
	}
	envelope, ok := sourcecdk.DecodeCursorEnvelope(pull.NextCursor.GetOpaque())
	if !ok || envelope.Token != "U1" || !envelope.ResumableCheckpoint {
		t.Fatalf("next cursor envelope = %#v ok=%t, want resumable token U1", envelope, ok)
	}
	if got := pull.Checkpoint.GetWatermark().AsTime(); !got.Equal(time.Date(2026, 6, 15, 13, 0, 0, 0, time.UTC)) {
		t.Fatalf("checkpoint watermark = %s, want event updated_at", got)
	}
	if len(requests) != 2 {
		t.Fatalf("requests = %d, want list and detail", len(requests))
	}
}

func TestSourceDefinitionCustomCursorHonorsHasMoreAndNativeToken(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		switch r.URL.Query().Get("after") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items":    []map[string]any{{"id": "A"}},
				"has_next": true,
				"marker":   "M2",
			})
		case "M2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items":    []map[string]any{{"id": "B"}},
				"has_next": false,
				"marker":   "M3",
			})
		default:
			t.Fatalf("after query = %q, want empty or M2", r.URL.Query().Get("after"))
		}
	}))
	defer server.Close()

	source, err := NewDefinition(connectordefinitions.Definition{
		ID:          "tenant-example",
		TenantID:    "tenant",
		SourceID:    "example",
		DisplayName: "Example",
		Auth:        connectordefinitions.AuthSpec{Model: "none"},
		Transport:   &connectordefinitions.TransportSpec{BaseURL: server.URL},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "records",
			Path:           "/records",
			RecordSelector: "$.items[*]",
			IDField:        "id",
			Event:          connectordefinitions.EventMappingSpec{Kind: "example.records", SchemaRef: "example/records/v1"},
			Pagination: &connectordefinitions.PaginationSpec{
				Type:           "cursor",
				CursorParam:    "after",
				NextCursorKeys: []string{"marker"},
				HasMoreKey:     "has_next",
			},
			Projection: &connectordefinitions.ProjectionSpec{Template: "asset"},
			Coverage:   []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
		}},
	})
	if err != nil {
		t.Fatalf("NewDefinition() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "per_page": "1"})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if got := first.NextCursor.GetOpaque(); got != "M2" {
		t.Fatalf("first NextCursor = %q, want native marker", got)
	}
	if _, ok := sourcecdk.DecodeCursorEnvelope(first.NextCursor.GetOpaque()); ok {
		t.Fatalf("first NextCursor = %q, want native cursor not checkpoint envelope", first.NextCursor.GetOpaque())
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil when has_next=false", second.NextCursor)
	}
	if len(requests) != 2 {
		t.Fatalf("requests = %d, want two cursor pages", len(requests))
	}
}

func TestSourceDefinitionUsesOffsetPaginationMetadata(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		if got := r.URL.Query().Get("limit"); got != "2" {
			t.Fatalf("limit query = %q, want 2", got)
		}
		switch r.URL.Query().Get("offset") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"records": []map[string]any{{"id": "A"}, {"id": "B"}},
				"total":   3,
				"offset":  0,
				"limit":   2,
			})
		case "2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"records": []map[string]any{{"id": "C"}},
				"total":   3,
				"offset":  2,
				"limit":   2,
			})
		default:
			t.Fatalf("offset query = %q, want empty or 2", r.URL.Query().Get("offset"))
		}
	}))
	defer server.Close()

	source, err := NewDefinition(connectordefinitions.Definition{
		ID:          "tenant-example",
		TenantID:    "tenant",
		SourceID:    "example",
		DisplayName: "Example",
		Auth:        connectordefinitions.AuthSpec{Model: "none"},
		Transport:   &connectordefinitions.TransportSpec{BaseURL: server.URL},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "records",
			Path:           "/records",
			RecordSelector: "$.records[*]",
			IDField:        "id",
			Event:          connectordefinitions.EventMappingSpec{Kind: "example.records", SchemaRef: "example/records/v1"},
			Pagination: &connectordefinitions.PaginationSpec{
				Type:        "offset",
				OffsetParam: "offset",
				LimitParam:  "limit",
			},
			Projection: &connectordefinitions.ProjectionSpec{Template: "asset"},
			Coverage:   []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
		}},
	})
	if err != nil {
		t.Fatalf("NewDefinition() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "per_page": "2"})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if got := first.NextCursor.GetOpaque(); got != "2" {
		t.Fatalf("first NextCursor = %q, want offset 2", got)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil at total", second.NextCursor)
	}
	if len(requests) != 2 {
		t.Fatalf("requests = %d, want two offset pages", len(requests))
	}
}

func TestSourceDefinitionDetailPathFallsBackWhenDetailUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/users":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"id": "U1", "email": "base@example.com"}},
			})
		case "/users/U1/detail":
			http.Error(w, "temporarily unavailable", http.StatusBadGateway)
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
		Auth:        connectordefinitions.AuthSpec{Model: "none"},
		Transport:   &connectordefinitions.TransportSpec{BaseURL: server.URL},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "users",
			Path:           "/users",
			Read:           &connectordefinitions.ResourceReadSpec{DetailPath: "/users/{id}/detail", AllowBareDetailRecord: true},
			RecordSelector: "$.data[*]",
			IDField:        "id",
			Event:          connectordefinitions.EventMappingSpec{Kind: "example.users", SchemaRef: "example/users/v1"},
			Projection:     &connectordefinitions.ProjectionSpec{Template: "identity_user"},
			Coverage:       []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
		}},
	})
	if err != nil {
		t.Fatalf("NewDefinition() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant"}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.Events[0].Attributes["email"] != "base@example.com" {
		t.Fatalf("events = %#v, want base record when detail request fails", pull.Events)
	}
}

func TestSourceDefinitionConfigQuerySplitsOnlyArrayStyleKeys(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if got := query["scope[]"]; len(got) != 2 || got[0] != "read" || got[1] != "write" {
			t.Fatalf("scope[] query = %#v, want split read/write", got)
		}
		if got := query["tag"]; len(got) != 1 || got[0] != "alpha,beta" {
			t.Fatalf("tag query = %#v, want unsplit scalar", got)
		}
		if got := query.Get("empty"); got != "" {
			t.Fatalf("empty query = %q, want omitted", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "A"}}})
	}))
	defer server.Close()

	source, err := NewDefinition(connectordefinitions.Definition{
		ID:          "tenant-example",
		TenantID:    "tenant",
		SourceID:    "example",
		DisplayName: "Example",
		Auth:        connectordefinitions.AuthSpec{Model: "none"},
		Transport:   &connectordefinitions.TransportSpec{BaseURL: server.URL},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "records",
			Path:           "/records",
			RecordSelector: "$.data[*]",
			IDField:        "id",
			Event:          connectordefinitions.EventMappingSpec{Kind: "example.records", SchemaRef: "example/records/v1"},
			Config: &connectordefinitions.FamilyConfigSpec{
				ConfigQuery: map[string]string{
					"scope[]": "scopes",
					"tag":     "tags",
					"empty":   "empty",
				},
			},
			Projection: &connectordefinitions.ProjectionSpec{Template: "asset"},
			Coverage:   []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
		}},
	})
	if err != nil {
		t.Fatalf("NewDefinition() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	if _, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"scopes":    " read, write ",
		"tags":      "alpha,beta",
		"empty":     " ",
	}), nil); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
}

func TestSourceDefinitionSupportsSingletonAndMapRecords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/settings":
			if got := r.URL.RawQuery; got != "" {
				t.Fatalf("settings raw query = %q, want none", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "Tenant settings"})
		case "/groups":
			_ = json.NewEncoder(w).Encode(map[string]any{"groups": map[string]any{"admins": []string{"alice"}, "devs": []string{"bob"}}})
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	definition := connectordefinitions.Definition{
		ID:          "tenant-example",
		TenantID:    "tenant",
		SourceID:    "example",
		DisplayName: "Example",
		Auth:        connectordefinitions.AuthSpec{Model: "none"},
		Transport:   &connectordefinitions.TransportSpec{BaseURL: server.URL},
		ResourceFamilies: []connectordefinitions.ResourceFamily{
			{
				ID:         "settings",
				Path:       "/settings",
				Read:       &connectordefinitions.ResourceReadSpec{Singleton: true, DisablePageSize: true},
				IDField:    "id",
				Event:      connectordefinitions.EventMappingSpec{Kind: "example.settings", SchemaRef: "example/settings/v1"},
				Projection: &connectordefinitions.ProjectionSpec{Template: "asset"},
				Coverage:   []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
			},
			{
				ID:      "groups",
				Path:    "/groups",
				Read:    &connectordefinitions.ResourceReadSpec{MapRecords: map[string]string{"groups": "members"}},
				IDField: "id",
				Event:   connectordefinitions.EventMappingSpec{Kind: "example.groups", SchemaRef: "example/groups/v1"},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "identity_group",
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
			},
		},
	}
	source, err := NewDefinition(definition)
	if err != nil {
		t.Fatalf("NewDefinition() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "family": "settings"})
	settingsPull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(settings) error = %v", err)
	}
	if len(settingsPull.Events) != 1 || settingsPull.Events[0].Attributes["external_id"] != "settings" {
		t.Fatalf("settings events = %#v, want singleton fallback id", settingsPull.Events)
	}
	groupsPull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "family": "groups"}), nil)
	if err != nil {
		t.Fatalf("Read(groups) error = %v", err)
	}
	var firstPayload map[string]any
	if len(groupsPull.Events) > 0 {
		if err := json.Unmarshal(groupsPull.Events[0].Payload, &firstPayload); err != nil {
			t.Fatalf("unmarshal first group payload: %v", err)
		}
	}
	if len(groupsPull.Events) != 2 || groupsPull.Events[0].Attributes["external_id"] != "admins" || firstPayload["members"] == nil {
		t.Fatalf("groups events = %#v, want sorted object-map records", groupsPull.Events)
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

func TestSourceFamilyDuoHMACV5Override(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/v3/integrations" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		if got := r.Header.Get("Date"); got == "" {
			t.Fatal("Date header is empty")
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Header.Get("Authorization"), "Basic "))
		if err != nil {
			t.Fatalf("decode Authorization: %v", err)
		}
		username, signature, ok := strings.Cut(string(decoded), ":")
		if !ok {
			t.Fatalf("Authorization payload = %q, want username:signature", decoded)
		}
		if username != "DIXXXXXXXXXXXXXXXXXX" {
			t.Fatalf("Duo integration key = %q, want DIXXXXXXXXXXXXXXXXXX", username)
		}
		if len(signature) != 128 {
			t.Fatalf("Duo signature length = %d, want SHA-512 hex signature", len(signature))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"response": []map[string]any{{
				"integration_key": "DIAPP",
				"name":            "Admin Panel",
			}},
		})
	}))
	defer server.Close()

	source, err := NewDefinition(connectordefinitions.Definition{
		ID:          "tenant-duo",
		TenantID:    "tenant",
		SourceID:    "duo",
		DisplayName: "Duo",
		Auth: connectordefinitions.AuthSpec{
			Model: "duo_hmac",
			CredentialFields: []connectordefinitions.Field{
				{Key: "client_id", Secret: true, ReferenceOnly: true},
				{Key: "client_secret", Secret: true, ReferenceOnly: true},
			},
		},
		Transport: &connectordefinitions.TransportSpec{
			BaseURL: server.URL,
			Verification: &connectordefinitions.VerificationSpec{
				Path: "/admin/v1/users",
			},
		},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "application",
			Path:           "/admin/v3/integrations",
			Config:         &connectordefinitions.FamilyConfigSpec{AuthModel: "duo_hmac_v5"},
			RecordSelector: "$.response[*]",
			IDField:        "integration_key",
			Event: connectordefinitions.EventMappingSpec{
				Kind:      "duo.application",
				SchemaRef: "duo/application/v1",
			},
			Projection: &connectordefinitions.ProjectionSpec{Template: "asset"},
			Coverage:   []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "supported"}},
		}},
	})
	if err != nil {
		t.Fatalf("NewDefinition() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "tenant",
		"family":        "application",
		"client_id":     "DIXXXXXXXXXXXXXXXXXX",
		"client_secret": "deadbeefsecret",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
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
