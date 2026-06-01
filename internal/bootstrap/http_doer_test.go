package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPDoerRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxHTTPDoerResponseBytes+1)))
	}))
	defer server.Close()

	doer := &stdHTTPDoer{client: server.Client()}
	status, body, err := doer.Post(context.Background(), server.URL, nil, []byte("{}"))
	if err == nil {
		t.Fatal("Post() error = nil, want oversized response error")
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if body != nil {
		t.Fatalf("body = %d bytes, want nil on oversized response", len(body))
	}
}
