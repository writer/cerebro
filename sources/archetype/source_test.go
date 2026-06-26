package archetype

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceReadEmitsScanAndVulnerabilityEvents(t *testing.T) {
	var sawAuth bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer token" {
			sawAuth = true
		}
		switch r.URL.Path {
		case "/api/v1/scans":
			writeJSON(t, w, []map[string]any{{"id": 1, "repository_id": 7, "status": "completed", "completed_at": "2026-06-17T12:05:00Z"}})
		case "/api/v1/repositories":
			writeJSON(t, w, []map[string]any{{"id": 7, "owner": "WriterInternal", "name": "Archetype"}})
		case "/api/v1/scans/1/vulnerabilities":
			body, err := os.ReadFile("testdata/sample_vulnerability.json")
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("[" + string(body) + "]"))
		case "/api/v1/repositories/7/knowledge":
			writeJSON(t, w, map[string]any{
				"entries": []map[string]any{{
					"slug":            "repository-commit-learning",
					"title":           "Repository commit learning",
					"summary":         "Archetype learned the latest repository head.",
					"repository_id":   7,
					"repository_name": "Archetype",
					"owner":           "WriterInternal",
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	pull, err := source.ReadWithCheckpoint(context.Background(), sourcecdk.NewConfig(map[string]string{
		"__cerebro_runtime_tenant_id": "writer",
		"base_url":                    server.URL,
		"token":                       "token",
	}), nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if !sawAuth {
		t.Fatal("server did not receive bearer token")
	}
	if len(pull.Events) != 3 {
		t.Fatalf("len(Events) = %d, want 3", len(pull.Events))
	}
	if pull.Events[0].GetKind() != "archetype.scan" || pull.Events[1].GetKind() != "archetype.vulnerability" || pull.Events[2].GetKind() != "archetype.library_note" {
		t.Fatalf("event kinds = %q, %q, %q", pull.Events[0].GetKind(), pull.Events[1].GetKind(), pull.Events[2].GetKind())
	}
	if got := pull.Events[1].GetAttributes()["repo"]; got != "Archetype" {
		t.Fatalf("vulnerability repo attr = %q, want Archetype", got)
	}
	if got := pull.Checkpoint.GetCursorOpaque(); got != "1" {
		t.Fatalf("checkpoint cursor = %q, want 1", got)
	}
}

func TestSourceReadEmitsLibraryNoteEvents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/scans":
			writeJSON(t, w, []map[string]any{{"id": 1, "repository_id": 7, "status": "completed", "completed_at": "2026-06-17T12:05:00Z"}})
		case "/api/v1/repositories":
			writeJSON(t, w, []map[string]any{{"id": 7, "owner": "WriterInternal", "name": "Archetype"}})
		case "/api/v1/scans/1/vulnerabilities":
			writeJSON(t, w, []map[string]any{})
		case "/api/v1/repositories/7/knowledge":
			writeJSON(t, w, map[string]any{
				"entries": []map[string]any{{
					"slug":              "repository-commit-learning",
					"title":             "Repository commit learning",
					"summary":           "Archetype learned the latest repository head.",
					"topics":            []string{"gitops", "commits", "librarian"},
					"generated_at":      "2026-06-17T12:04:00Z",
					"repository_id":     7,
					"repository_name":   "Archetype",
					"owner":             "WriterInternal",
					"dominant_severity": "info",
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	pull, err := source.ReadWithCheckpoint(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "writer", "base_url": server.URL}), nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(Events) = %d, want 2", len(pull.Events))
	}
	if pull.Events[0].GetKind() != "archetype.scan" || pull.Events[1].GetKind() != "archetype.library_note" {
		t.Fatalf("event kinds = %q, %q", pull.Events[0].GetKind(), pull.Events[1].GetKind())
	}
	attrs := pull.Events[1].GetAttributes()
	if got := attrs["owner"] + "/" + attrs["repo"]; got != "WriterInternal/Archetype" {
		t.Fatalf("library repository attrs = %q, want WriterInternal/Archetype", got)
	}
	if got := attrs["knowledge_slug"]; got != "repository-commit-learning" {
		t.Fatalf("library slug attr = %q, want repository-commit-learning", got)
	}
	if got := pull.Events[1].GetId(); got != "archetype-library-7-repository-commit-learning" {
		t.Fatalf("library event id = %q, want stable repository note id", got)
	}
	if got := attrs["repository_id"]; got != "7" {
		t.Fatalf("library repository_id attr = %q, want 7", got)
	}
	if got := attrs["dominant_severity"]; got != "info" {
		t.Fatalf("library dominant_severity attr = %q, want info", got)
	}
	var payload map[string]any
	if err := json.Unmarshal(pull.Events[1].GetPayload(), &payload); err != nil {
		t.Fatalf("decode library payload: %v", err)
	}
	topics, ok := payload["topics"].([]any)
	if !ok || len(topics) != 3 || topics[0] != "gitops" {
		t.Fatalf("library payload topics = %#v, want gitops/commits/librarian", payload["topics"])
	}
}

func TestLibraryNoteEventEscapesProviderSlugInID(t *testing.T) {
	event := libraryNoteEvent(settings{tenantID: "writer"}, scanRecord{ID: 1, RepositoryID: 7}, knowledgeEntryRecord{
		Slug:           "security:sql/injection",
		Title:          "SQL injection context",
		Summary:        "Repository query handling context.",
		RepositoryID:   7,
		RepositoryName: "Archetype",
		Owner:          "WriterInternal",
	}, repositoryRecord{ID: 7, Owner: "WriterInternal", Name: "Archetype"})
	if event == nil {
		t.Fatal("libraryNoteEvent() = nil")
	}
	if got, want := event.GetId(), "archetype-library-7-security%3Asql%2Finjection"; got != want {
		t.Fatalf("event ID = %q, want %q", got, want)
	}
	if got := event.GetAttributes()["knowledge_slug"]; got != "security:sql/injection" {
		t.Fatalf("knowledge_slug attr = %q, want raw provider slug", got)
	}
	var payload map[string]any
	if err := json.Unmarshal(event.GetPayload(), &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if got := payload["slug"]; got != "security:sql/injection" {
		t.Fatalf("payload slug = %q, want raw provider slug", got)
	}
}

func TestSourceReadFetchesRepositoryKnowledgeOncePerRepo(t *testing.T) {
	knowledgeRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/scans":
			writeJSON(t, w, []map[string]any{
				{"id": 1, "repository_id": 7, "status": "completed", "completed_at": "2026-06-17T12:05:00Z"},
				{"id": 2, "repository_id": 7, "status": "completed", "completed_at": "2026-06-17T13:05:00Z"},
			})
		case "/api/v1/repositories":
			writeJSON(t, w, []map[string]any{{"id": 7, "owner": "WriterInternal", "name": "Archetype"}})
		case "/api/v1/scans/1/vulnerabilities", "/api/v1/scans/2/vulnerabilities":
			writeJSON(t, w, []map[string]any{})
		case "/api/v1/repositories/7/knowledge":
			knowledgeRequests++
			writeJSON(t, w, map[string]any{
				"entries": []map[string]any{{
					"slug":            "repository-commit-learning",
					"title":           "Repository commit learning",
					"summary":         "Archetype learned the latest repository head.",
					"repository_id":   7,
					"repository_name": "Archetype",
					"owner":           "WriterInternal",
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	pull, err := source.ReadWithCheckpoint(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "writer", "base_url": server.URL}), nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if knowledgeRequests != 1 {
		t.Fatalf("knowledge requests = %d, want 1", knowledgeRequests)
	}
	var libraryEvents int
	for _, event := range pull.Events {
		if event.GetKind() == "archetype.library_note" {
			libraryEvents++
		}
	}
	if libraryEvents != 1 {
		t.Fatalf("library note events = %d, want 1", libraryEvents)
	}
}

func TestSourceReadSkipsLibraryNoteWithoutRepositoryIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/scans":
			writeJSON(t, w, []map[string]any{{"id": 1, "repository_id": 7, "status": "completed", "completed_at": "2026-06-17T12:05:00Z"}})
		case "/api/v1/scans/1/vulnerabilities":
			writeJSON(t, w, []map[string]any{})
		case "/api/v1/repositories/7/knowledge":
			writeJSON(t, w, map[string]any{
				"entries": []map[string]any{
					{
						"slug":    "repository-commit-learning",
						"title":   "Repository commit learning",
						"summary": "Archetype learned the latest repository head.",
					},
					{
						"slug":            " ",
						"title":           "Repository commit learning",
						"summary":         "Archetype learned the latest repository head.",
						"repository_name": "Archetype",
						"owner":           "WriterInternal",
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	pull, err := source.ReadWithCheckpoint(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "writer", "base_url": server.URL}), nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.Events[0].GetKind() != "archetype.scan" {
		t.Fatalf("events = %#v, want only scan event", pull.Events)
	}
}

func TestSourceReadContinuesWhenKnowledgeEndpointIsMissing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/scans":
			writeJSON(t, w, []map[string]any{{"id": 1, "repository_id": 7, "status": "completed", "completed_at": "2026-06-17T12:05:00Z"}})
		case "/api/v1/repositories":
			writeJSON(t, w, []map[string]any{{"id": 7, "owner": "WriterInternal", "name": "Archetype"}})
		case "/api/v1/scans/1/vulnerabilities":
			body, err := os.ReadFile("testdata/sample_vulnerability.json")
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("[" + string(body) + "]"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	pull, err := source.ReadWithCheckpoint(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "writer", "base_url": server.URL}), nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(Events) = %d, want scan and vulnerability events", len(pull.Events))
	}
	if pull.Events[0].GetKind() != "archetype.scan" || pull.Events[1].GetKind() != "archetype.vulnerability" {
		t.Fatalf("event kinds = %q, %q", pull.Events[0].GetKind(), pull.Events[1].GetKind())
	}
}

func TestSourceReadContinuesWhenKnowledgeEndpointFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/scans":
			writeJSON(t, w, []map[string]any{{"id": 1, "repository_id": 7, "status": "completed", "completed_at": "2026-06-17T12:05:00Z"}})
		case "/api/v1/repositories":
			writeJSON(t, w, []map[string]any{{"id": 7, "owner": "WriterInternal", "name": "Archetype"}})
		case "/api/v1/scans/1/vulnerabilities":
			body, err := os.ReadFile("testdata/sample_vulnerability.json")
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("[" + string(body) + "]"))
		case "/api/v1/repositories/7/knowledge":
			http.Error(w, "try later", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	pull, err := source.ReadWithCheckpoint(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "writer", "base_url": server.URL}), nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(Events) = %d, want scan and vulnerability events", len(pull.Events))
	}
	if pull.Events[0].GetKind() != "archetype.scan" || pull.Events[1].GetKind() != "archetype.vulnerability" {
		t.Fatalf("event kinds = %q, %q", pull.Events[0].GetKind(), pull.Events[1].GetKind())
	}
}

func TestSourceReadContinuesWhenKnowledgeEndpointReturnsMalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/scans":
			writeJSON(t, w, []map[string]any{{"id": 1, "repository_id": 7, "status": "completed", "completed_at": "2026-06-17T12:05:00Z"}})
		case "/api/v1/repositories":
			writeJSON(t, w, []map[string]any{{"id": 7, "owner": "WriterInternal", "name": "Archetype"}})
		case "/api/v1/scans/1/vulnerabilities":
			body, err := os.ReadFile("testdata/sample_vulnerability.json")
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("[" + string(body) + "]"))
		case "/api/v1/repositories/7/knowledge":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"entries":[`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	pull, err := source.ReadWithCheckpoint(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "writer", "base_url": server.URL}), nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(Events) = %d, want scan and vulnerability events", len(pull.Events))
	}
	if pull.Events[0].GetKind() != "archetype.scan" || pull.Events[1].GetKind() != "archetype.vulnerability" {
		t.Fatalf("event kinds = %q, %q", pull.Events[0].GetKind(), pull.Events[1].GetKind())
	}
}

func TestSourceReadReturnsCanceledContextAfterKnowledgeFetch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/scans":
			writeJSON(t, w, []map[string]any{{"id": 1, "repository_id": 7, "status": "completed", "completed_at": "2026-06-17T12:05:00Z"}})
		case "/api/v1/repositories":
			writeJSON(t, w, []map[string]any{{"id": 7, "owner": "WriterInternal", "name": "Archetype"}})
		case "/api/v1/scans/1/vulnerabilities":
			writeJSON(t, w, []map[string]any{})
		case "/api/v1/repositories/7/knowledge":
			cancel()
			writeJSON(t, w, map[string]any{"entries": []map[string]any{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	if _, err := source.ReadWithCheckpoint(ctx, sourcecdk.NewConfig(map[string]string{"tenant_id": "writer", "base_url": server.URL}), nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("ReadWithCheckpoint() error = %v, want context canceled", err)
	}
}

func TestSourceReadRetriesKnowledgeAfterTransientMissWithinRead(t *testing.T) {
	knowledgeRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/scans":
			writeJSON(t, w, []map[string]any{
				{"id": 1, "repository_id": 7, "status": "completed", "completed_at": "2026-06-17T12:05:00Z"},
				{"id": 2, "repository_id": 7, "status": "completed", "completed_at": "2026-06-17T13:05:00Z"},
			})
		case "/api/v1/repositories":
			writeJSON(t, w, []map[string]any{{"id": 7, "owner": "WriterInternal", "name": "Archetype"}})
		case "/api/v1/scans/1/vulnerabilities", "/api/v1/scans/2/vulnerabilities":
			writeJSON(t, w, []map[string]any{})
		case "/api/v1/repositories/7/knowledge":
			knowledgeRequests++
			if knowledgeRequests <= 3 {
				http.Error(w, "try later", http.StatusInternalServerError)
				return
			}
			writeJSON(t, w, map[string]any{
				"entries": []map[string]any{{
					"slug":            "repository-commit-learning",
					"title":           "Repository commit learning",
					"summary":         "Archetype learned the latest repository head.",
					"repository_id":   7,
					"repository_name": "Archetype",
					"owner":           "WriterInternal",
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	pull, err := source.ReadWithCheckpoint(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "writer", "base_url": server.URL}), nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if knowledgeRequests != 4 {
		t.Fatalf("knowledge requests = %d, want exhausted retry plus second scan retry", knowledgeRequests)
	}
	var libraryEvents int
	for _, event := range pull.Events {
		if event.GetKind() == "archetype.library_note" {
			libraryEvents++
		}
	}
	if libraryEvents != 1 {
		t.Fatalf("library note events = %d, want 1", libraryEvents)
	}
}

func TestSourceReadHonorsCheckpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/scans" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		writeJSON(t, w, []map[string]any{{"id": 1, "repository_id": 7, "status": "completed"}})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	pull, err := source.ReadWithCheckpoint(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"base_url":  server.URL,
	}), nil, &cerebrov1.SourceCheckpoint{CursorOpaque: "1"})
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("len(Events) = %d, want 0", len(pull.Events))
	}
}

func TestSourceCheckRejectsBadFamily(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"base_url":  "https://archetype.example.com",
		"family":    "repository",
	}))
	if err == nil {
		t.Fatal("Check() error = nil, want error")
	}
}

func TestParseSettingsSupportsPrivateEndpointAllowlist(t *testing.T) {
	settings, err := parseSettings(sourcecdk.NewConfig(map[string]string{
		"tenant_id":                  "writer",
		"base_url":                   "https://archetype.internal.example",
		"private_endpoint_allowlist": "archetype.internal.example",
	}), false)
	if err != nil {
		t.Fatalf("parseSettings() error = %v", err)
	}
	if settings.baseURL != "https://archetype.internal.example" {
		t.Fatalf("baseURL = %q, want normalized private endpoint origin", settings.baseURL)
	}
	if got := settings.privateEndpointAllowlist; len(got) != 1 || got[0] != "archetype.internal.example" {
		t.Fatalf("privateEndpointAllowlist = %#v, want archetype.internal.example", got)
	}
}

func TestParseSettingsRejectsPrivateEndpointAllowlistMismatch(t *testing.T) {
	_, err := parseSettings(sourcecdk.NewConfig(map[string]string{
		"tenant_id":                  "writer",
		"base_url":                   "https://archetype.internal.example",
		"private_endpoint_allowlist": "other.internal.example",
	}), false)
	if err == nil {
		t.Fatal("parseSettings() error = nil, want mismatch error")
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}
