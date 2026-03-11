package providers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/evalops/cerebro/internal/metrics"
	"github.com/evalops/cerebro/internal/telemetry"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

var sharedProviderTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          200,
	MaxIdleConnsPerHost:   20,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

var tracedProviderTransport = otelhttp.NewTransport(sharedProviderTransport)

const (
	defaultProviderHTTPTimeout             = 30 * time.Second
	defaultProviderHTTPRetryAttempts       = 3
	defaultProviderHTTPRetryBackoff        = 500 * time.Millisecond
	defaultProviderHTTPRetryMaxBackoff     = 5 * time.Second
	defaultProviderCircuitFailureThreshold = 5
	defaultProviderCircuitOpenTimeout      = 2 * time.Minute
)

type ProviderHTTPClientOptions struct {
	Provider                string
	Timeout                 time.Duration
	RetryAttempts           int
	RetryBackoff            time.Duration
	RetryMaxBackoff         time.Duration
	CircuitFailureThreshold int
	CircuitOpenTimeout      time.Duration
}

type providerCircuitState string

const (
	providerCircuitClosed   providerCircuitState = "closed"
	providerCircuitOpen     providerCircuitState = "open"
	providerCircuitHalfOpen providerCircuitState = "half_open"
)

var ErrProviderCircuitOpen = errors.New("provider circuit open")

type ProviderCircuitOpenError struct {
	Provider string
	RetryAt  time.Time
}

func (e *ProviderCircuitOpenError) Error() string {
	if e == nil {
		return ErrProviderCircuitOpen.Error()
	}
	if strings.TrimSpace(e.Provider) == "" {
		return ErrProviderCircuitOpen.Error()
	}
	if e.RetryAt.IsZero() {
		return fmt.Sprintf("%s for %s", ErrProviderCircuitOpen, e.Provider)
	}
	return fmt.Sprintf("%s for %s until %s", ErrProviderCircuitOpen, e.Provider, e.RetryAt.UTC().Format(time.RFC3339))
}

func (e *ProviderCircuitOpenError) Unwrap() error {
	return ErrProviderCircuitOpen
}

func newProviderHTTPClient(timeout time.Duration) *http.Client {
	return newProviderHTTPClientWithOptions(ProviderHTTPClientOptions{Timeout: timeout})
}

func newProviderHTTPClientWithOptions(opts ProviderHTTPClientOptions) *http.Client {
	if opts.Timeout <= 0 {
		opts.Timeout = defaultProviderHTTPTimeout
	}
	if opts.RetryAttempts <= 0 {
		opts.RetryAttempts = defaultProviderHTTPRetryAttempts
	}
	if opts.RetryBackoff <= 0 {
		opts.RetryBackoff = defaultProviderHTTPRetryBackoff
	}
	if opts.RetryMaxBackoff <= 0 {
		opts.RetryMaxBackoff = defaultProviderHTTPRetryMaxBackoff
	}
	if opts.CircuitFailureThreshold <= 0 {
		opts.CircuitFailureThreshold = defaultProviderCircuitFailureThreshold
	}
	if opts.CircuitOpenTimeout <= 0 {
		opts.CircuitOpenTimeout = defaultProviderCircuitOpenTimeout
	}

	transport := providerBaseTransport()
	if strings.TrimSpace(opts.Provider) != "" {
		transport = &providerResilientTransport{
			base:    transport,
			options: opts,
			circuit: newProviderCircuitBreaker(opts.Provider, opts.CircuitFailureThreshold, opts.CircuitOpenTimeout),
			sleep:   sleepWithContext,
		}
	}

	return &http.Client{Timeout: opts.Timeout, Transport: transport}
}

func providerBaseTransport() http.RoundTripper {
	if telemetry.Enabled() {
		return tracedProviderTransport
	}
	return sharedProviderTransport
}

type providerResilientTransport struct {
	base    http.RoundTripper
	options ProviderHTTPClientOptions
	circuit *providerCircuitBreaker
	sleep   func(context.Context, time.Duration) error
}

type providerRetryDecision struct {
	Retryable        bool
	Delay            time.Duration
	HasExplicitDelay bool
	CountsAsFailure  bool
}

var errProviderRetryLoopExhausted = errors.New("provider retry loop exhausted without response")

func (t *providerResilientTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	attempts := t.options.RetryAttempts
	if attempts <= 0 {
		attempts = 1
	}

	halfOpenProbe := false
	for attempt := 1; attempt <= attempts; attempt++ {
		currentReq, err := cloneRequestForAttempt(req, attempt)
		if err != nil {
			return nil, err
		}
		if !halfOpenProbe {
			probeAcquired, err := t.circuit.beforeRequest()
			if err != nil {
				return nil, err
			}
			halfOpenProbe = probeAcquired
		}

		resp, err := t.base.RoundTrip(currentReq)
		decision := classifyProviderHTTPRetry(resp, err)
		if !decision.Retryable {
			if err == nil {
				t.circuit.recordSuccess()
			} else if halfOpenProbe {
				t.circuit.releaseHalfOpenProbe()
			}
			return resp, err
		}

		if decision.CountsAsFailure {
			t.circuit.recordFailure()
			halfOpenProbe = false
		}
		if attempt == attempts {
			if halfOpenProbe {
				t.circuit.releaseHalfOpenProbe()
			}
			return resp, err
		}

		if resp != nil {
			drainAndCloseBody(resp.Body)
		}

		delay := decision.Delay
		if !decision.HasExplicitDelay {
			delay = providerRetryDelay(t.options.RetryBackoff, t.options.RetryMaxBackoff, attempt)
		}
		if err := t.sleep(req.Context(), delay); err != nil {
			if halfOpenProbe {
				t.circuit.releaseHalfOpenProbe()
			}
			return nil, err
		}
	}

	return nil, errProviderRetryLoopExhausted
}

type providerCircuitBreaker struct {
	provider         string
	failureThreshold int
	openTimeout      time.Duration

	mu                  sync.Mutex
	state               providerCircuitState
	consecutiveFailures int
	openedAt            time.Time
	halfOpenInFlight    bool
}

func newProviderCircuitBreaker(provider string, threshold int, openTimeout time.Duration) *providerCircuitBreaker {
	cb := &providerCircuitBreaker{
		provider:         strings.TrimSpace(provider),
		failureThreshold: threshold,
		openTimeout:      openTimeout,
		state:            providerCircuitClosed,
	}
	metrics.SetProviderCircuitState(cb.provider, string(cb.state))
	return cb
}

func (c *providerCircuitBreaker) beforeRequest() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	switch c.state {
	case providerCircuitOpen:
		if c.openTimeout > 0 && now.Sub(c.openedAt) >= c.openTimeout {
			c.state = providerCircuitHalfOpen
			c.halfOpenInFlight = false
			metrics.SetProviderCircuitState(c.provider, string(c.state))
		} else {
			return false, &ProviderCircuitOpenError{
				Provider: c.provider,
				RetryAt:  c.openedAt.Add(c.openTimeout),
			}
		}
	}

	if c.state == providerCircuitHalfOpen {
		if c.halfOpenInFlight {
			return false, &ProviderCircuitOpenError{
				Provider: c.provider,
				RetryAt:  c.openedAt.Add(c.openTimeout),
			}
		}
		c.halfOpenInFlight = true
		return true, nil
	}

	return false, nil
}

func (c *providerCircuitBreaker) recordSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.consecutiveFailures = 0
	c.openedAt = time.Time{}
	c.halfOpenInFlight = false
	if c.state != providerCircuitClosed {
		c.state = providerCircuitClosed
		metrics.SetProviderCircuitState(c.provider, string(c.state))
	}
}

func (c *providerCircuitBreaker) releaseHalfOpenProbe() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == providerCircuitHalfOpen {
		c.halfOpenInFlight = false
	}
}

func (c *providerCircuitBreaker) recordFailure() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	switch c.state {
	case providerCircuitHalfOpen:
		c.state = providerCircuitOpen
		c.openedAt = now
		c.halfOpenInFlight = false
		c.consecutiveFailures = c.failureThreshold
		metrics.SetProviderCircuitState(c.provider, string(c.state))
		return
	case providerCircuitOpen:
		return
	}

	c.consecutiveFailures++
	if c.failureThreshold > 0 && c.consecutiveFailures >= c.failureThreshold {
		c.state = providerCircuitOpen
		c.openedAt = now
		c.halfOpenInFlight = false
		metrics.SetProviderCircuitState(c.provider, string(c.state))
	}
}

func classifyProviderHTTPRetry(resp *http.Response, err error) providerRetryDecision {
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return providerRetryDecision{}
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return providerRetryDecision{Retryable: true, CountsAsFailure: true}
		}
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "timeout") ||
			strings.Contains(lower, "connection reset") ||
			strings.Contains(lower, "connection refused") ||
			strings.Contains(lower, "server misbehaving") ||
			strings.Contains(lower, "eof") {
			return providerRetryDecision{Retryable: true, CountsAsFailure: true}
		}
		return providerRetryDecision{}
	}
	if resp == nil {
		return providerRetryDecision{}
	}
	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		delay, ok := retryAfterDelay(resp.Header)
		return providerRetryDecision{Retryable: true, Delay: delay, HasExplicitDelay: ok}
	case http.StatusRequestTimeout, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		delay, ok := retryAfterDelay(resp.Header)
		return providerRetryDecision{Retryable: true, Delay: delay, HasExplicitDelay: ok, CountsAsFailure: true}
	}
	if resp.StatusCode >= 500 {
		delay, ok := retryAfterDelay(resp.Header)
		return providerRetryDecision{Retryable: true, Delay: delay, HasExplicitDelay: ok, CountsAsFailure: true}
	}
	return providerRetryDecision{}
}

func providerRetryDelay(base, max time.Duration, attempt int) time.Duration {
	if base <= 0 {
		base = defaultProviderHTTPRetryBackoff
	}
	if max <= 0 {
		max = defaultProviderHTTPRetryMaxBackoff
	}
	delay := base
	for step := 1; step < attempt; step++ {
		if delay >= max/2 {
			delay = max
			break
		}
		delay *= 2
	}
	if delay > max {
		delay = max
	}
	jitterWindow := delay / 5
	if jitterWindow <= 0 {
		return delay
	}
	offset := time.Duration(time.Now().UnixNano()%int64(jitterWindow*2+1)) - jitterWindow
	delay += offset
	if delay < base {
		delay = base
	}
	if delay > max {
		delay = max
	}
	return delay
}

func cloneRequestForAttempt(req *http.Request, attempt int) (*http.Request, error) {
	if attempt <= 1 || req.Body == nil {
		return req.Clone(req.Context()), nil
	}
	if req.GetBody == nil {
		return nil, fmt.Errorf("provider request body is not replayable for retry")
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	cloned := req.Clone(req.Context())
	cloned.Body = body
	return cloned, nil
}

func sleepWithContext(ctx context.Context, wait time.Duration) error {
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func drainAndCloseBody(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 4096))
	_ = body.Close()
}
