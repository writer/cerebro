package sourcehttp

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/telemetry"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

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

func TestNewRequestNormalizesOriginPathQueryAndBody(t *testing.T) {
	req, err := NewRequest(context.Background(), "test_source", "https://api.example.com", false, http.MethodPost, "/v1/items", url.Values{"page": {"1"}}, []byte("payload"))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if got := req.URL.String(); got != "https://api.example.com/v1/items?page=1" {
		t.Fatalf("URL = %q, want normalized endpoint with query", got)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll(request body) error = %v", err)
	}
	if string(body) != "payload" {
		t.Fatalf("body = %q, want payload", string(body))
	}
	if _, err := NewRequest(context.Background(), "test_source", "https://127.0.0.1", false, http.MethodGet, "/v1/items", nil, nil); err == nil {
		t.Fatal("NewRequest() error = nil, want unsafe base_url rejection")
	}
	if _, err := NewRequest(context.Background(), "test_source", "https://api.example.com", false, http.MethodGet, "https://evil.example/v1", nil, nil); err == nil {
		t.Fatal("NewRequest() error = nil, want absolute request path rejection")
	}
}

func TestSafeRoundTripperPropagatesTraceWithoutLeakingURLQuery(t *testing.T) {
	var propagated string
	ctx, parent := telemetry.StartMain(context.Background(), "test.parent", telemetry.Attrs())
	req := httptest.NewRequest(http.MethodGet, "https://93.184.216.34/v1/items?token=secret", nil).WithContext(ctx)
	_, stderr := captureSourceHTTPStderr(t, func() {
		resp, err := SafeRoundTripper{
			SourceID: "test_source",
			Base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				propagated = req.Header.Get("Traceparent")
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Header:     http.Header{},
					Body:       io.NopCloser(strings.NewReader("")),
					Request:    req,
				}, nil
			}),
		}.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip() error = %v", err)
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		telemetry.End(parent, "completed", telemetry.Attrs())
	})
	if propagated == "" {
		t.Fatal("traceparent was not propagated")
	}
	if strings.Contains(stderr, "token=secret") || strings.Contains(stderr, "/v1/items") {
		t.Fatalf("telemetry leaked URL path/query: %s", stderr)
	}
	if !strings.Contains(stderr, `"name":"source.http.request"`) {
		t.Fatalf("source HTTP span missing from telemetry: %s", stderr)
	}
	for _, expected := range []string{
		`"dependency.outbound_http.operation.count":1`,
		`"dependency.last_component":"sourcehttp"`,
		`"dependency.last_operation":"round_trip"`,
		`"dependency.last_status":"completed"`,
		`"http.response.status_class":"2xx"`,
	} {
		if !strings.Contains(stderr, expected) {
			t.Fatalf("telemetry missing %s: %s", expected, stderr)
		}
	}
}

func TestReadLimitedBodyRejectsOversizedResponse(t *testing.T) {
	_, err := ReadLimitedBody(strings.NewReader(strings.Repeat("x", MaxBodyBytes+1)))
	if err == nil {
		t.Fatal("ReadLimitedBody() error = nil, want oversized response error")
	}
}

func captureSourceHTTPStderr(t *testing.T, fn func()) (string, string) {
	t.Helper()
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stderr: %v", err)
	}
	os.Stdout = stdoutWriter
	os.Stderr = stderrWriter
	fn()
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr
	stdout, _ := io.ReadAll(stdoutReader)
	stderr, _ := io.ReadAll(stderrReader)
	return string(stdout), string(stderr)
}

func TestReadLimitedBodyWithLimitRejectsCustomOversizedResponse(t *testing.T) {
	_, err := ReadLimitedBodyWithLimit(strings.NewReader("abcdef"), 5)
	if err == nil {
		t.Fatal("ReadLimitedBodyWithLimit() error = nil, want oversized response error")
	}
}

func TestResponseBodyTruncatedUsesContentRangeTotal(t *testing.T) {
	for _, tt := range []struct {
		name         string
		statusCode   int
		contentRange string
		bytesRead    int
		maxBytes     int
		want         bool
	}{
		{name: "complete partial response", statusCode: http.StatusPartialContent, contentRange: "bytes 0-64/65", bytesRead: 65, maxBytes: 65536, want: false},
		{name: "truncated partial response", statusCode: http.StatusPartialContent, contentRange: "bytes 0-65535/70000", bytesRead: 65536, maxBytes: 65536, want: true},
		{name: "non partial response", statusCode: http.StatusOK, contentRange: "", bytesRead: 65536, maxBytes: 65536, want: false},
		{name: "unknown total falls back to max", statusCode: http.StatusPartialContent, contentRange: "bytes 0-65535/*", bytesRead: 65536, maxBytes: 65536, want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResponseBodyTruncated(tt.statusCode, tt.contentRange, tt.bytesRead, tt.maxBytes); got != tt.want {
				t.Fatalf("ResponseBodyTruncated() = %v, want %v", got, tt.want)
			}
		})
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

func TestSafeRoundTripperFailsClosedWhenBaseCannotBePinned(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.example.com/v1", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	resp, err := SafeRoundTripper{
		SourceID: "test",
		Base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("base RoundTrip should not be called when pinning fails")
			return nil, nil
		}),
		LookupIPAddrs: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}, nil
		},
	}.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, ErrTransportPinningUnsupported) {
		t.Fatalf("SafeRoundTripper.RoundTrip() error = %v, want pinned host dialing error", err)
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
