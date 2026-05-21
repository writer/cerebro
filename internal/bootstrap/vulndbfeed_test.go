package bootstrap

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenVulnDBFeedFetchesSuccessfulHTTPWhenExplicitlyAllowed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	body, err := OpenVulnDBFeed(context.Background(), server.URL, true)
	if err != nil {
		t.Fatalf("OpenVulnDBFeed() error = %v", err)
	}
	defer func() {
		_ = body.Close()
	}()
	data, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if string(data) != `{"ok":true}` {
		t.Fatalf("body = %q, want ok payload", data)
	}
}

func TestOpenVulnDBFeedRejectsNonSuccessStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusTeapot)
	}))
	defer server.Close()

	_, err := OpenVulnDBFeed(context.Background(), server.URL, true)
	if err == nil {
		t.Fatal("OpenVulnDBFeed() error = nil, want status error")
	}
}

func TestOpenVulnDBFeedValidatesRedirectTargets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "file:///tmp/vulndb.json", http.StatusFound)
	}))
	defer server.Close()

	_, err := OpenVulnDBFeed(context.Background(), server.URL, true)
	if err == nil {
		t.Fatal("OpenVulnDBFeed() error = nil, want redirect policy error")
	}
}

func TestOpenVulnDBFeedRejectsHTTPSDowngradeRedirect(t *testing.T) {
	targetHit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHit = true
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer target.Close()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer server.Close()

	previousTransport := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() {
		http.DefaultTransport = previousTransport
	}()

	body, err := OpenVulnDBFeed(context.Background(), server.URL, true)
	if body != nil {
		_ = body.Close()
	}
	if err == nil {
		t.Fatal("OpenVulnDBFeed() error = nil, want https-to-http downgrade rejection")
	}
	if targetHit {
		t.Fatal("OpenVulnDBFeed() followed https-to-http downgrade redirect")
	}
}
