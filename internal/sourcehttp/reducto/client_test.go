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
	var sawParse bool
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
			writeJSON(t, w, http.StatusOK, map[string]string{"file_id": "file-1"})
		case "/parse":
			sawParse = true
			if r.Method != http.MethodPost {
				t.Fatalf("parse method = %s, want POST", r.Method)
			}
			var request map[string]string
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatalf("decode parse request: %v", err)
			}
			if request["input"] != "file-1" {
				t.Fatalf("parse input = %q, want file-1", request["input"])
			}
			writeJSON(t, w, http.StatusOK, map[string]any{
				"parse_id": "parse-1",
				"status":   "completed",
				"result": map[string]any{
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
	if !sawUpload || !sawParse {
		t.Fatalf("sawUpload=%v sawParse=%v, want both true", sawUpload, sawParse)
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

func writeJSON(t *testing.T, w http.ResponseWriter, status int, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("write json: %v", err)
	}
}
