package providers

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewProviderHTTPClientUsesSharedTransport(t *testing.T) {
	clientA := newProviderHTTPClient(30 * time.Second)
	clientB := newProviderHTTPClient(60 * time.Second)

	if clientA.Transport != sharedProviderTransport {
		t.Fatal("expected clientA to use shared provider transport")
	}
	if clientB.Transport != sharedProviderTransport {
		t.Fatal("expected clientB to use shared provider transport")
	}
	if clientA.Timeout != 30*time.Second {
		t.Fatalf("clientA timeout = %s, want 30s", clientA.Timeout)
	}
	if clientB.Timeout != 60*time.Second {
		t.Fatalf("clientB timeout = %s, want 60s", clientB.Timeout)
	}
}

func TestNewProviderHTTPClientDefaultsTimeout(t *testing.T) {
	client := newProviderHTTPClient(0)
	if client.Timeout != 30*time.Second {
		t.Fatalf("default timeout = %s, want 30s", client.Timeout)
	}
}

func TestBaseProviderNewHTTPClientUsesConfiguredResilience(t *testing.T) {
	bp := NewBaseProvider("okta", ProviderTypeIdentity)
	if err := bp.Configure(context.Background(), map[string]interface{}{
		"http_timeout":                   "45s",
		"http_retry_attempts":            4,
		"http_retry_backoff":             "250ms",
		"http_retry_max_backoff":         "2s",
		"http_circuit_failure_threshold": 3,
		"http_circuit_open_timeout":      "90s",
	}); err != nil {
		t.Fatalf("configure base provider: %v", err)
	}

	client := bp.NewHTTPClient(30 * time.Second)
	if client.Timeout != 45*time.Second {
		t.Fatalf("client timeout = %s, want 45s", client.Timeout)
	}
	transport, ok := client.Transport.(*providerResilientTransport)
	if !ok {
		t.Fatalf("expected resilient transport, got %T", client.Transport)
	}
	if transport.options.RetryAttempts != 4 {
		t.Fatalf("retry attempts = %d, want 4", transport.options.RetryAttempts)
	}
	if transport.options.CircuitFailureThreshold != 3 {
		t.Fatalf("failure threshold = %d, want 3", transport.options.CircuitFailureThreshold)
	}
	if transport.options.CircuitOpenTimeout != 90*time.Second {
		t.Fatalf("open timeout = %s, want 90s", transport.options.CircuitOpenTimeout)
	}
}

func TestProviderResilientTransportOpensCircuitAfterFailures(t *testing.T) {
	var attempts atomic.Int32
	transport := &providerResilientTransport{
		base: providerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			attempts.Add(1)
			return nil, errors.New("connection reset by peer")
		}),
		options: ProviderHTTPClientOptions{
			Provider:                "okta",
			RetryAttempts:           1,
			RetryBackoff:            time.Millisecond,
			RetryMaxBackoff:         time.Millisecond,
			CircuitFailureThreshold: 2,
			CircuitOpenTimeout:      time.Minute,
		},
		circuit: newProviderCircuitBreaker("okta", 2, time.Minute),
		sleep: func(context.Context, time.Duration) error {
			return nil
		},
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := transport.RoundTrip(req)
	if resp != nil {
		closeTestResponse(t, resp)
	}
	if err == nil {
		t.Fatal("expected first request error")
		return
	}
	resp, err = transport.RoundTrip(req)
	if resp != nil {
		closeTestResponse(t, resp)
	}
	if err == nil {
		t.Fatal("expected second request error")
		return
	}
	resp, err = transport.RoundTrip(req)
	if resp != nil {
		closeTestResponse(t, resp)
	}
	if !errors.Is(err, ErrProviderCircuitOpen) {
		t.Fatalf("expected circuit-open error, got %v", err)
	}
	if attempts.Load() != 2 {
		t.Fatalf("expected underlying transport to run twice before opening circuit, got %d", attempts.Load())
	}
}

func TestProviderResilientTransportRetriesTransientResponse(t *testing.T) {
	var attempts atomic.Int32
	var slept time.Duration
	transport := &providerResilientTransport{
		base: providerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			current := attempts.Add(1)
			if current == 1 {
				return &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Header:     http.Header{"Retry-After": []string{"0"}},
					Body:       io.NopCloser(strings.NewReader("rate limited")),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		}),
		options: ProviderHTTPClientOptions{
			Provider:                "okta",
			RetryAttempts:           2,
			RetryBackoff:            time.Millisecond,
			RetryMaxBackoff:         time.Millisecond,
			CircuitFailureThreshold: 5,
			CircuitOpenTimeout:      time.Minute,
		},
		circuit: newProviderCircuitBreaker("okta", 5, time.Minute),
		sleep: func(_ context.Context, delay time.Duration) error {
			slept = delay
			return nil
		},
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected retry to recover, got %v", err)
	}
	defer closeTestResponse(t, resp)
	if resp == nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected OK response, got %#v", resp)
	}
	if attempts.Load() != 2 {
		t.Fatalf("expected two attempts, got %d", attempts.Load())
	}
	if slept != 0 {
		t.Fatalf("expected immediate retry for Retry-After=0, got sleep %s", slept)
	}
}

func TestProviderResilientTransportDoesNotResetCircuitOnNonRetryableError(t *testing.T) {
	var attempts atomic.Int32
	transport := &providerResilientTransport{
		base: providerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch attempts.Add(1) {
			case 1, 3:
				return nil, errors.New("connection reset by peer")
			case 2:
				return nil, context.Canceled
			default:
				return nil, errors.New("unexpected extra call")
			}
		}),
		options: ProviderHTTPClientOptions{
			Provider:                "okta",
			RetryAttempts:           1,
			RetryBackoff:            time.Millisecond,
			RetryMaxBackoff:         time.Millisecond,
			CircuitFailureThreshold: 2,
			CircuitOpenTimeout:      time.Minute,
		},
		circuit: newProviderCircuitBreaker("okta", 2, time.Minute),
		sleep:   func(context.Context, time.Duration) error { return nil },
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := transport.RoundTrip(req)
	if resp != nil {
		closeTestResponse(t, resp)
	}
	if err == nil {
		t.Fatal("expected first request error")
		return
	}
	resp, err = transport.RoundTrip(req)
	if resp != nil {
		closeTestResponse(t, resp)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}
	resp, err = transport.RoundTrip(req)
	if resp != nil {
		closeTestResponse(t, resp)
	}
	if err == nil {
		t.Fatal("expected third request error")
		return
	}
	resp, err = transport.RoundTrip(req)
	if resp != nil {
		closeTestResponse(t, resp)
	}
	if !errors.Is(err, ErrProviderCircuitOpen) {
		t.Fatalf("expected circuit-open error after preserved failures, got %v", err)
	}
}

func TestProviderResilientTransportReturnsNilResponseWhenRetrySleepFails(t *testing.T) {
	transport := &providerResilientTransport{
		base: providerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     http.Header{"Retry-After": []string{"0"}},
				Body:       io.NopCloser(strings.NewReader("rate limited")),
			}, nil
		}),
		options: ProviderHTTPClientOptions{
			Provider:                "okta",
			RetryAttempts:           2,
			RetryBackoff:            time.Millisecond,
			RetryMaxBackoff:         time.Millisecond,
			CircuitFailureThreshold: 5,
			CircuitOpenTimeout:      time.Minute,
		},
		circuit: newProviderCircuitBreaker("okta", 5, time.Minute),
		sleep:   func(context.Context, time.Duration) error { return context.Canceled },
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := transport.RoundTrip(req)
	if resp != nil {
		closeTestResponse(t, resp)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}
	if resp != nil {
		t.Fatalf("expected nil response when retry sleep fails, got %#v", resp)
	}
}

func TestProviderResilientTransportReleasesHalfOpenProbeOnRateLimitExhaustion(t *testing.T) {
	transport := &providerResilientTransport{
		base: providerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     http.Header{"Retry-After": []string{"0"}},
				Body:       io.NopCloser(strings.NewReader("rate limited")),
			}, nil
		}),
		options: ProviderHTTPClientOptions{
			Provider:                "okta",
			RetryAttempts:           1,
			RetryBackoff:            time.Millisecond,
			RetryMaxBackoff:         time.Millisecond,
			CircuitFailureThreshold: 2,
			CircuitOpenTimeout:      time.Minute,
		},
		circuit: newProviderCircuitBreaker("okta", 2, time.Minute),
		sleep:   func(context.Context, time.Duration) error { return nil },
	}
	transport.circuit.state = providerCircuitHalfOpen

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected terminal 429 response, got %v", err)
	}
	if resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 response, got %#v", resp)
	}
	closeTestResponse(t, resp)
	if transport.circuit.state != providerCircuitHalfOpen {
		t.Fatalf("circuit state = %s, want half_open", transport.circuit.state)
	}
	if transport.circuit.halfOpenInFlight {
		t.Fatal("expected half-open probe to be released after terminal 429")
	}
	if probeAcquired, err := transport.circuit.beforeRequest(); err != nil {
		t.Fatalf("expected another half-open probe to be allowed, got %v", err)
	} else if !probeAcquired {
		t.Fatal("expected another half-open probe to be reacquired")
	}
}

func TestProviderResilientTransportDoesNotSelfBlockHalfOpenProbeRetries(t *testing.T) {
	var attempts atomic.Int32
	transport := &providerResilientTransport{
		base: providerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			attempts.Add(1)
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     http.Header{"Retry-After": []string{"0"}},
				Body:       io.NopCloser(strings.NewReader("rate limited")),
			}, nil
		}),
		options: ProviderHTTPClientOptions{
			Provider:                "okta",
			RetryAttempts:           2,
			RetryBackoff:            time.Millisecond,
			RetryMaxBackoff:         time.Millisecond,
			CircuitFailureThreshold: 2,
			CircuitOpenTimeout:      time.Minute,
		},
		circuit: newProviderCircuitBreaker("okta", 2, time.Minute),
		sleep:   func(context.Context, time.Duration) error { return nil },
	}
	transport.circuit.state = providerCircuitHalfOpen

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected retry loop to return terminal 429 response, got %v", err)
	}
	if resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected terminal 429 response, got %#v", resp)
	}
	closeTestResponse(t, resp)
	if attempts.Load() != 2 {
		t.Fatalf("expected half-open probe to consume both retry attempts, got %d", attempts.Load())
	}
	if transport.circuit.halfOpenInFlight {
		t.Fatal("expected half-open probe to be released after retry exhaustion")
	}
}

func TestProviderResilientTransportDoesNotOpenCircuitOnRateLimitResponses(t *testing.T) {
	transport := &providerResilientTransport{
		base: providerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     http.Header{"Retry-After": []string{"0"}},
				Body:       io.NopCloser(strings.NewReader("rate limited")),
			}, nil
		}),
		options: ProviderHTTPClientOptions{
			Provider:                "okta",
			RetryAttempts:           1,
			RetryBackoff:            time.Millisecond,
			RetryMaxBackoff:         time.Millisecond,
			CircuitFailureThreshold: 2,
			CircuitOpenTimeout:      time.Minute,
		},
		circuit: newProviderCircuitBreaker("okta", 2, time.Minute),
		sleep:   func(context.Context, time.Duration) error { return nil },
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	for attempt := 0; attempt < 3; attempt++ {
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("expected retryable 429 response, got error %v", err)
		}
		if resp == nil || resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("expected 429 response, got %#v", resp)
		}
		closeTestResponse(t, resp)
	}
	if _, err := transport.circuit.beforeRequest(); err != nil {
		t.Fatalf("expected circuit to remain closed after repeated 429s, got %v", err)
	}
}

func TestProviderCircuitBreakerOpenFailureDoesNotExtendOpenWindow(t *testing.T) {
	circuit := newProviderCircuitBreaker("okta", 1, time.Minute)

	circuit.recordFailure()
	initialOpenedAt := circuit.openedAt
	if circuit.state != providerCircuitOpen {
		t.Fatalf("expected circuit to open, got %s", circuit.state)
	}

	time.Sleep(10 * time.Millisecond)
	circuit.recordFailure()

	if !circuit.openedAt.Equal(initialOpenedAt) {
		t.Fatalf("expected open-state failures to preserve openedAt, got %s want %s", circuit.openedAt, initialOpenedAt)
	}
}

func TestProviderConstructorsAvoidInlineHTTPClientTimeoutAllocations(t *testing.T) {
	providersDir := providersDirectory(t)
	entries, err := os.ReadDir(providersDir)
	if err != nil {
		t.Fatalf("read providers directory: %v", err)
	}

	violations := make([]string, 0)
	usesFactory := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "http_client.go" {
			continue
		}

		path := filepath.Join(providersDir, name)
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read %s: %v", name, readErr)
		}
		text := string(content)

		if strings.Contains(text, "newProviderHTTPClient(") {
			usesFactory++
		}
		if strings.Contains(text, "&http.Client{Timeout:") {
			violations = append(violations, name)
		}
	}

	if usesFactory == 0 {
		t.Fatal("expected provider constructors to use newProviderHTTPClient")
	}
	if len(violations) > 0 {
		t.Fatalf("found inline http.Client timeout allocations in providers: %s", strings.Join(violations, ", "))
	}
}

func providersDirectory(t *testing.T) string {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(thisFile)
}

type providerRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn providerRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func closeTestResponse(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp == nil || resp.Body == nil {
		return
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close response body: %v", err)
	}
}
