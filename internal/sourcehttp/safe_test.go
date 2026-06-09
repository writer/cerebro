package sourcehttp

import (
	"context"
	"io"
	"net"
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

func TestNormalizeBaseURLAllowsExactPrivateEndpointHostsOnly(t *testing.T) {
	allowlist, err := ParsePrivateEndpointAllowlist("evidence_cas", "cas.internal.example")
	if err != nil {
		t.Fatalf("ParsePrivateEndpointAllowlist() error = %v", err)
	}
	if got, host, err := NormalizeBaseURLWithOptions("evidence_cas", "https://cas.internal.example", URLValidationOptions{PrivateEndpointAllowlist: allowlist}); err != nil || got != "https://cas.internal.example" || host != "cas.internal.example" {
		t.Fatalf("NormalizeBaseURLWithOptions() = %q, %q, %v; want exact origin", got, host, err)
	}
	for name, raw := range map[string]string{
		"http scheme":     "http://cas.internal.example",
		"custom port":     "https://cas.internal.example:8443",
		"path":            "https://cas.internal.example/v1",
		"allowlist miss":  "https://other.internal.example",
		"private literal": "https://10.0.0.10",
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := NormalizeBaseURLWithOptions("evidence_cas", raw, URLValidationOptions{PrivateEndpointAllowlist: allowlist})
			if err == nil {
				t.Fatal("NormalizeBaseURLWithOptions() error = nil, want rejection")
			}
		})
	}
}

func TestParsePrivateEndpointAllowlistAcceptsHttpsOrigins(t *testing.T) {
	hosts, err := ParsePrivateEndpointAllowlist("evidence_cas", "https://cas.internal.example/")
	if err != nil {
		t.Fatalf("ParsePrivateEndpointAllowlist() error = %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "cas.internal.example" {
		t.Fatalf("hosts = %#v, want extracted origin host", hosts)
	}
}

func TestParsePrivateEndpointAllowlistRejectsUnsafeOrAmbiguousEntries(t *testing.T) {
	for _, raw := range []string{
		"http://cas.internal.example",
		"https://cas.internal.example/path",
		"https://cas.internal.example:8443",
		"cas.internal.example:443",
		"localhost",
		"127.0.0.1",
		"10.0.0.10",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := ParsePrivateEndpointAllowlist("evidence_cas", raw); err == nil {
				t.Fatal("ParsePrivateEndpointAllowlist() error = nil, want invalid allowlist entry")
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

func TestDoWithRetryReplaysRequestBodyWithGetBody(t *testing.T) {
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll request body: %v", err)
		}
		bodies = append(bodies, string(body))
		if len(bodies) == 1 {
			http.Error(w, "try again", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	req, err := http.NewRequest(http.MethodPost, server.URL, strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	resp, err := DoWithRetry(context.Background(), server.Client(), req, RetryOptions{Backoff: time.Nanosecond})
	if err != nil {
		t.Fatalf("DoWithRetry() error = %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := strings.Join(bodies, ","); got != "payload,payload" {
		t.Fatalf("request bodies = %q, want payload replayed on retry", got)
	}
}

func TestDoWithRetryDoesNotRetryNonReplayableBody(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		_, _ = io.ReadAll(r.Body)
		http.Error(w, "try again", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	req, err := http.NewRequest(http.MethodPost, server.URL, io.NopCloser(strings.NewReader("payload")))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	resp, err := DoWithRetry(context.Background(), server.Client(), req, RetryOptions{Backoff: time.Nanosecond})
	if err != nil {
		t.Fatalf("DoWithRetry() error = %v", err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1 for non-replayable body", attempts)
	}
}

func TestPinnedHostTransportDisablesKeepAlives(t *testing.T) {
	rt, err := pinnedHostTransport(&http.Transport{}, "api.example.com", net.ParseIP("203.0.113.10"))
	if err != nil {
		t.Fatalf("pinnedHostTransport() error = %v", err)
	}
	transport, ok := rt.(*http.Transport)
	if !ok {
		t.Fatalf("pinnedHostTransport() returned %T, want *http.Transport", rt)
	}
	if !transport.DisableKeepAlives {
		t.Fatal("pinned transport must disable keep-alives")
	}
}

func TestSafeResolvedHostAddrsAllowsPrivateOnlyForExactAllowlistedHost(t *testing.T) {
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.0.0.10")}}, nil
	}
	allowlist := []string{"cas.internal.example"}
	if _, err := SafeResolvedHostAddrsWithOptions(context.Background(), "evidence_cas", "cas.internal.example", HostResolutionOptions{PrivateEndpointAllowlist: allowlist, LookupIPAddrs: lookup}); err != nil {
		t.Fatalf("SafeResolvedHostAddrsWithOptions() allowlisted private error = %v", err)
	}
	if _, err := SafeResolvedHostAddrsWithOptions(context.Background(), "evidence_cas", "other.internal.example", HostResolutionOptions{PrivateEndpointAllowlist: allowlist, LookupIPAddrs: lookup}); err == nil {
		t.Fatal("SafeResolvedHostAddrsWithOptions() unallowlisted private error = nil, want rejection")
	}
}

func TestSafeResolvedHostAddrsRejectsLoopbackAndLinkLocalEvenWhenAllowlisted(t *testing.T) {
	for name, ip := range map[string]string{
		"loopback":    "127.0.0.1",
		"link local":  "169.254.169.254",
		"metadata":    "169.254.169.254",
		"unspecified": "0.0.0.0",
		"multicast":   "224.0.0.1",
	} {
		t.Run(name, func(t *testing.T) {
			lookup := func(context.Context, string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
			}
			_, err := SafeResolvedHostAddrsWithOptions(context.Background(), "evidence_cas", "cas.internal.example", HostResolutionOptions{PrivateEndpointAllowlist: []string{"cas.internal.example"}, LookupIPAddrs: lookup})
			if err == nil {
				t.Fatal("SafeResolvedHostAddrsWithOptions() error = nil, want unsafe address rejection")
			}
		})
	}
}
