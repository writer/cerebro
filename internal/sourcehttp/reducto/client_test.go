package reducto

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/grcupload"
)

func TestReductoClientParseUploadsAndParsesDocument(t *testing.T) {
	var sawUpload bool
	var sawExtract bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer reducto-token" {
			t.Fatalf("Authorization = %q, want bearer token", got)
		}
		switch r.URL.Path {
		case "/upload":
			sawUpload = true
			if r.Method != http.MethodPost {
				t.Fatalf("upload method = %s, want POST", r.Method)
			}
			file, header, err := r.FormFile("file")
			if err != nil {
				t.Fatalf("upload file field: %v", err)
			}
			defer func() { _ = file.Close() }()
			if header.Filename != "Access Policy.pdf" {
				t.Fatalf("filename = %q, want Access Policy.pdf", header.Filename)
			}
			body, err := io.ReadAll(file)
			if err != nil {
				t.Fatalf("read upload file: %v", err)
			}
			if string(body) != "policy body" {
				t.Fatalf("uploaded body = %q, want policy body", string(body))
			}
			writeJSON(t, w, map[string]string{"file_id": "file-1"})
		case "/extract":
			sawExtract = true
			if r.Method != http.MethodPost {
				t.Fatalf("extract method = %s, want POST", r.Method)
			}
			var request map[string]any
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatalf("decode extract request: %v", err)
			}
			if request["input"] != "file-1" {
				t.Fatalf("extract input = %q, want file-1", request["input"])
			}
			instructions, ok := request["instructions"].(map[string]any)
			if !ok {
				t.Fatalf("extract instructions = %#v, want object", request["instructions"])
			}
			schema, ok := instructions["schema"].(map[string]any)
			if !ok || schema["type"] != "object" {
				t.Fatalf("extract schema = %#v, want object schema", instructions["schema"])
			}
			writeJSON(t, w, map[string]any{
				"parse_id": "parse-1",
				"status":   "completed",
				"result": map[string]any{
					"summary":       "Access policy summary",
					"document_type": "policy",
					"chunks": []map[string]string{
						{"content": "Access control policy"},
						{"content": "Review access quarterly"},
					},
					"page_count": 3,
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		APIKey:  "reducto-token",
		BaseURL: server.URL,
		Timeout: time.Second,
	}, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	parsed, err := client.Parse(context.Background(), "Access Policy.pdf", "application/pdf", strings.NewReader("policy body"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !sawUpload || !sawExtract {
		t.Fatalf("sawUpload=%v sawExtract=%v, want both true", sawUpload, sawExtract)
	}
	if parsed.ProviderFileID != "file-1" || parsed.ParseID != "parse-1" || parsed.Status != "completed" {
		t.Fatalf("parsed IDs/status = %#v", parsed)
	}
	if parsed.ChunkCount != 2 || parsed.PageCount != 3 {
		t.Fatalf("parsed counts = %#v", parsed)
	}
	if parsed.TextPreview != "Access control policy Review access quarterly" {
		t.Fatalf("TextPreview = %q", parsed.TextPreview)
	}
	if parsed.StructureStatus != "structured" || parsed.StructureSchema != "grc_upload_v1" {
		t.Fatalf("structured status/schema = %#v", parsed)
	}
	if len(parsed.StructuredFields) != 2 {
		t.Fatalf("structured fields = %#v, want summary and document_type", parsed.StructuredFields)
	}
	if parsed.StructuredSummary != "Access policy summary" {
		t.Fatalf("StructuredSummary = %q", parsed.StructuredSummary)
	}
	if len(parsed.Chunks) != 2 || parsed.Chunks[0].Index != 1 || parsed.Chunks[0].TextPreview != "Access control policy" {
		t.Fatalf("chunks = %#v", parsed.Chunks)
	}
}

func TestReductoClientMarksUnstructuredWhenNoFieldsExtracted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/upload":
			writeJSON(t, w, map[string]string{"file_id": "file-1"})
		case "/extract":
			writeJSON(t, w, map[string]any{
				"parse_id": "parse-1",
				"status":   "completed",
				"result": map[string]any{
					"chunks": []map[string]string{
						{"content": "Policy content only"},
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		APIKey:  "reducto-token",
		BaseURL: server.URL,
		Timeout: time.Second,
	}, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	parsed, err := client.Parse(context.Background(), "Access Policy.pdf", "application/pdf", strings.NewReader("policy body"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.StructureStatus != "unstructured" {
		t.Fatalf("StructureStatus = %q, want unstructured", parsed.StructureStatus)
	}
	if len(parsed.StructuredFields) != 0 {
		t.Fatalf("StructuredFields = %#v, want none", parsed.StructuredFields)
	}
}

func TestStructuredFieldsFromPayloadIndexesArrayObjects(t *testing.T) {
	fields := structuredFieldsFromPayload(map[string]any{
		"result": map[string]any{
			"controls": []any{
				map[string]any{"name": "Access review", "owner": "Security"},
				map[string]any{"name": "Vendor review", "owner": "GRC"},
			},
		},
	})
	got := map[string]string{}
	for _, field := range fields {
		got[field.Key] = field.Value
	}
	want := map[string]string{
		"controls.1.name":  "Access review",
		"controls.1.owner": "Security",
		"controls.2.name":  "Vendor review",
		"controls.2.owner": "GRC",
	}
	for key, value := range want {
		if got[key] != value {
			t.Fatalf("field %s = %q, want %q; fields=%#v", key, got[key], value, fields)
		}
	}
}

func TestReductoClientFetchesSameOriginResultURL(t *testing.T) {
	var serverURL string
	var sawResult bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/upload":
			writeJSON(t, w, map[string]string{"file_id": "file-1"})
		case "/extract":
			writeJSON(t, w, map[string]any{
				"parse_id":   "parse-1",
				"status":     "completed",
				"result_url": serverURL + "/result",
			})
		case "/result":
			sawResult = true
			if r.Method != http.MethodGet {
				t.Fatalf("result method = %s, want GET", r.Method)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer reducto-token" {
				t.Fatalf("result Authorization = %q, want bearer token", got)
			}
			writeJSON(t, w, map[string]any{
				"chunks": []map[string]string{
					{"content": "Downloaded policy content"},
				},
				"page_count": 5,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	client, err := NewClient(Config{
		APIKey:  "reducto-token",
		BaseURL: server.URL,
		Timeout: time.Second,
	}, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	parsed, err := client.Parse(context.Background(), "Access Policy.pdf", "application/pdf", strings.NewReader("policy body"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !sawResult {
		t.Fatal("result URL was not fetched")
	}
	if parsed.ChunkCount != 1 || parsed.PageCount != 5 || parsed.TextPreview != "Downloaded policy content" {
		t.Fatalf("parsed result payload = %#v", parsed)
	}
}

func TestReductoClientReturnsResultURLFetchError(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/upload":
			writeJSON(t, w, map[string]string{"file_id": "file-1"})
		case "/extract":
			writeJSON(t, w, map[string]any{
				"parse_id":   "parse-1",
				"status":     "completed",
				"result_url": serverURL + "/result",
			})
		case "/result":
			http.Error(w, "result unavailable", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	client, err := NewClient(Config{
		APIKey:  "reducto-token",
		BaseURL: server.URL,
		Timeout: time.Second,
	}, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	_, err = client.Parse(context.Background(), "Access Policy.pdf", "application/pdf", strings.NewReader("policy body"))
	if !errors.Is(err, grcupload.ErrRemote) {
		t.Fatalf("Parse() error = %v, want ErrRemote", err)
	}
}

func TestReductoClientRejectsCrossOriginResultURL(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	client, err := NewClient(Config{
		APIKey:  "reducto-token",
		BaseURL: server.URL,
		Timeout: time.Second,
	}, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	_, err = client.fetchResultURL(context.Background(), "https://platform.reducto.ai/result")
	if !errors.Is(err, grcupload.ErrRemote) {
		t.Fatalf("fetchResultURL() error = %v, want ErrRemote", err)
	}
}

func TestReductoClientPreservesNumericIdentifiers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/upload":
			writeJSON(t, w, map[string]any{"file_id": 12345})
		case "/extract":
			var request map[string]any
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatalf("decode extract request: %v", err)
			}
			if request["input"] != "12345" {
				t.Fatalf("extract input = %q, want 12345", request["input"])
			}
			writeJSON(t, w, map[string]any{
				"parse_id": 67890,
				"status":   "completed",
				"chunks": []map[string]string{
					{"content": "Numeric identifier policy content"},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		APIKey:  "reducto-token",
		BaseURL: server.URL,
		Timeout: time.Second,
	}, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	parsed, err := client.Parse(context.Background(), "Access Policy.pdf", "application/pdf", strings.NewReader("policy body"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.ProviderFileID != "12345" || parsed.ParseID != "67890" {
		t.Fatalf("parsed numeric identifiers = %#v", parsed)
	}
}

func TestNewReductoClientRequiresAPIKey(t *testing.T) {
	_, err := NewClient(Config{BaseURL: "https://platform.reducto.ai"})
	if !errors.Is(err, grcupload.ErrRuntimeUnavailable) {
		t.Fatalf("NewClient() error = %v, want ErrRuntimeUnavailable", err)
	}
}

func TestReductoClientRejectsNonLoopbackHTTPBaseURL(t *testing.T) {
	_, err := NewClient(Config{
		APIKey:  "token",
		BaseURL: "http://reducto.example.com",
	})
	if !errors.Is(err, grcupload.ErrInvalidRequest) {
		t.Fatalf("NewClient() error = %v, want ErrInvalidRequest", err)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("write json: %v", err)
	}
}
