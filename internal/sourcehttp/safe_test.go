package sourcehttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNormalizeBaseURLRejectsUnsafeHosts(t *testing.T) {
	for _, raw := range []string{
		"http://169.254.169.254",
		"https://127.0.0.1",
		"https://localhost",
		"https://10.0.0.1",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, _, err := NormalizeBaseURL("test_source", raw, false); err == nil {
				t.Fatal("NormalizeBaseURL() error = nil, want unsafe host error")
			}
		})
	}
}

func TestSameOriginAbsoluteURLRejectsHostChanges(t *testing.T) {
	if _, err := SameOriginAbsoluteURL("test_source", "https://api.example.com", "https://metadata.google.internal/latest"); err == nil {
		t.Fatal("SameOriginAbsoluteURL() error = nil, want host mismatch")
	}
	if got, err := SameOriginAbsoluteURL("test_source", "https://api.example.com", "https://api.example.com/v1/page?$skiptoken=1"); err != nil || got == "" {
		t.Fatalf("SameOriginAbsoluteURL() = %q, %v; want same-host URL", got, err)
	}
}

func TestReadLimitedBodyRejectsOversizedResponse(t *testing.T) {
	_, err := ReadLimitedBody(strings.NewReader(strings.Repeat("x", MaxBodyBytes+1)))
	if err == nil {
		t.Fatal("ReadLimitedBody() error = nil, want oversized response error")
	}
}

func TestReadLimitedBodyWithLimitRejectsCustomOversizedResponse(t *testing.T) {
	_, err := ReadLimitedBodyWithLimit(strings.NewReader("abcdef"), 5)
	if err == nil {
		t.Fatal("ReadLimitedBodyWithLimit() error = nil, want oversized response error")
	}
}

func TestDoWithRetryRetriesRetryableStatus(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts == 1 {
			http.Error(w, "try again", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	resp, err := DoWithRetry(context.Background(), server.Client(), req, RetryOptions{Backoff: time.Nanosecond})
	if err != nil {
		t.Fatalf("DoWithRetry() error = %v", err)
	}
	if resp.StatusCode != http.StatusOK || string(resp.Body) != `{"ok":true}` {
		t.Fatalf("DoWithRetry() response = %d %q, want 200 body", resp.StatusCode, string(resp.Body))
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

func TestDoWithRetryPreservesCustomBodyLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("abcdef"))
	}))
	defer server.Close()
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if _, err := DoWithRetry(context.Background(), server.Client(), req, RetryOptions{MaxBodyBytes: 5}); err == nil {
		t.Fatal("DoWithRetry() error = nil, want oversized response error")
	}
}
