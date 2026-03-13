package cli

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSanitizeSourceLabel(t *testing.T) {
	if got := sanitizeSourceLabel("https://user:secret@example.com/feed.csv?token=abc#frag"); got != "https://example.com/feed.csv" {
		t.Fatalf("expected sanitized source label, got %q", got)
	}
	if got := sanitizeSourceLabel("/tmp/feed.csv"); got != "/tmp/feed.csv" {
		t.Fatalf("expected local path to remain unchanged, got %q", got)
	}
}

func TestOpenImportReaderRejectsInsecureHTTPByDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	_, _, _, err := openImportReader(context.Background(), server.URL, "", "osv", false)
	if err == nil || !strings.Contains(err.Error(), "--allow-insecure-http") {
		t.Fatalf("expected insecure http rejection, got %v", err)
	}
}

func TestOpenImportReaderAllowsInsecureHTTPWithOptIn(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("feed-body"))
	}))
	defer server.Close()

	reader, closer, source, err := openImportReader(context.Background(), server.URL, "", "osv", true)
	if err != nil {
		t.Fatalf("openImportReader: %v", err)
	}
	if closer != nil {
		defer func() { _ = closer() }()
	}
	payload, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(payload) != "feed-body" {
		t.Fatalf("expected feed-body, got %q", string(payload))
	}
	if source != "osv" {
		t.Fatalf("expected logical source label %q, got %q", "osv", source)
	}
}

func TestOpenImportReaderRejectsHTTPSRedirectToHTTP(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("insecure"))
	}))
	defer httpServer.Close()

	httpsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, httpServer.URL, http.StatusFound)
	}))
	defer httpsServer.Close()

	previousTransport := importHTTPTransport
	importHTTPTransport = httpsServer.Client().Transport
	t.Cleanup(func() {
		importHTTPTransport = previousTransport
	})

	_, _, _, err := openImportReader(context.Background(), httpsServer.URL, "", "osv", false)
	if err == nil || !strings.Contains(err.Error(), "--allow-insecure-http") {
		t.Fatalf("expected redirect downgrade rejection, got %v", err)
	}
}

func TestOpenImportReaderUsesExplicitSourceLabel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("feed-body"))
	}))
	defer server.Close()

	_, closer, source, err := openImportReader(context.Background(), server.URL, "custom-source", "osv", true)
	if err != nil {
		t.Fatalf("openImportReader: %v", err)
	}
	if closer != nil {
		defer func() { _ = closer() }()
	}
	if source != "custom-source" {
		t.Fatalf("expected explicit source label, got %q", source)
	}
}
