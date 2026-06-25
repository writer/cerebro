package langfuse

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := source.Spec().GetId(); got != "langfuse" {
		t.Fatalf("Spec().Id = %q, want langfuse", got)
	}
}

func TestProjectFamiliesUsePageCursor(t *testing.T) {
	want := map[string]bool{
		"project":        true,
		"project_member": true,
		"api_key":        true,
	}
	for _, family := range langfuseFamilies() {
		if !want[family.Name] {
			continue
		}
		delete(want, family.Name)
		if got := family.CursorParam; got != "page" {
			t.Fatalf("%s CursorParam = %q, want page", family.Name, got)
		}
		if got := family.PageFirstCursor; got != "1" {
			t.Fatalf("%s PageFirstCursor = %q, want 1", family.Name, got)
		}
		if len(family.NextCursorKeys) != 2 || family.NextCursorKeys[0] != "nextPage" || family.NextCursorKeys[1] != "next_page" {
			t.Fatalf("%s NextCursorKeys = %#v, want nextPage/next_page", family.Name, family.NextCursorKeys)
		}
	}
	for name := range want {
		t.Fatalf("missing family %s", name)
	}
}

func TestReadProjectAPIKeysUsesBasicAuthAndProjectScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/api/public/projects/project_123/apiKeys" {
			t.Fatalf("request path = %q, want /api/public/projects/project_123/apiKeys", got)
		}
		wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("pk-lf:test-secret"))
		if got := r.Header.Get("Authorization"); got != wantAuth {
			t.Fatalf("Authorization = %q, want %q", got, wantAuth)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":        "key_123",
				"publicKey": "pk-lf-key",
				"createdAt": "2026-06-24T12:00:00Z",
			}},
			"meta": map[string]any{"page": 1, "totalPages": 1},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder secret.
		"base_url":   server.URL,
		"family":     "api_key",
		"project_id": "project_123",
		"public_key": "pk-lf",
		"secret_key": "test-secret",
		"tenant_id":  "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "langfuse.api_key" {
		t.Fatalf("Kind = %q, want langfuse.api_key", event.Kind)
	}
	for key, want := range map[string]string{
		"api_key_id":      "key_123",
		"credential_type": "langfuse_project_api_key",
		"project_id":      "project_123",
		"public_key":      "pk-lf-key",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestReadProjectMemberEmitsStaticPrincipalType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/api/public/projects/project_123/memberships" {
			t.Fatalf("request path = %q, want /api/public/projects/project_123/memberships", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":        "member_123",
				"userId":    "user_123",
				"email":     "owner@example.com",
				"role":      "OWNER",
				"createdAt": "2026-06-24T12:00:00Z",
			}},
			"meta": map[string]any{"page": 1, "totalPages": 1},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder secret.
		"base_url":   server.URL,
		"family":     "project_member",
		"project_id": "project_123",
		"public_key": "pk-lf",
		"secret_key": "test-secret",
		"tenant_id":  "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "langfuse.project_member" {
		t.Fatalf("Kind = %q, want langfuse.project_member", event.Kind)
	}
	if got := event.Attributes["principal_type"]; got != "user" {
		t.Fatalf("principal_type = %q, want user", got)
	}
}

func TestReadObservationMapsUsageAttributes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/api/public/v2/observations" {
			t.Fatalf("request path = %q, want /api/public/v2/observations", got)
		}
		if got := r.URL.Query().Get("fromStartTime"); got != "2026-06-24T00:00:00Z" {
			t.Fatalf("fromStartTime = %q, want 2026-06-24T00:00:00Z", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":        "obs_123",
				"traceId":   "trace_123",
				"name":      "completion",
				"type":      "GENERATION",
				"model":     "gpt-4.1",
				"startTime": "2026-06-24T12:00:00Z",
				"usage": map[string]any{
					"input":  12,
					"output": 34,
					"total":  46,
				},
			}},
			"meta": map[string]any{"page": 1, "totalPages": 1},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder secret.
		"base_url":        server.URL,
		"family":          "observation",
		"from_start_time": "2026-06-24T00:00:00Z",
		"public_key":      "pk-lf",
		"secret_key":      "test-secret",
		"tenant_id":       "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	event := pull.Events[0]
	if event.Kind != "langfuse.observation" {
		t.Fatalf("Kind = %q, want langfuse.observation", event.Kind)
	}
	for key, want := range map[string]string{
		"input_tokens":   "12",
		"model":          "gpt-4.1",
		"observation_id": "obs_123",
		"output_tokens":  "34",
		"total_tokens":   "46",
		"trace_id":       "trace_123",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
}
