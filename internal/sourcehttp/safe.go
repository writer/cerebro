package sourcehttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/telemetry"
)

const MaxBodyBytes = 8 << 20
const DefaultTimeout = 30 * time.Second
const DefaultRetryMaxAttempts = 3
const DefaultRetryBackoff = 250 * time.Millisecond
const MaxRetryAfter = 5 * time.Second

var ErrTransportPinningUnsupported = errors.New("source transport must support pinned host dialing")

type ClientOptions struct {
	SourceID                 string
	Timeout                  time.Duration
	BaseTransport            http.RoundTripper
	AllowLoopback            bool
	PrivateEndpointAllowlist []string
	LookupIPAddrs            func(context.Context, string) ([]net.IPAddr, error)
}

type RetryOptions struct {
	MaxAttempts  int
	Backoff      time.Duration
	MaxBodyBytes int
}

type URLValidationOptions struct {
	AllowLoopback            bool
	PrivateEndpointAllowlist []string
}

type HostResolutionOptions struct {
	AllowLoopback            bool
	PrivateEndpointAllowlist []string
	LookupIPAddrs            func(context.Context, string) ([]net.IPAddr, error)
}

type ResponseBody struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

func NewClient(options ClientOptions) *http.Client {
	return HardenClient(nil, options)
}

func HardenClient(client *http.Client, options ClientOptions) *http.Client {
	if client == nil {
		client = &http.Client{}
	}
	cloned := *client
	if cloned.Timeout <= 0 {
		cloned.Timeout = firstDuration(options.Timeout, DefaultTimeout)
	}
	if cloned.CheckRedirect == nil {
		cloned.CheckRedirect = NoRedirect
	}
	transport := options.BaseTransport
	if transport == nil {
		transport = cloned.Transport
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	cloned.Transport = SafeRoundTripper{
		Base:                     transport,
		SourceID:                 strings.TrimSpace(options.SourceID),
		AllowLoopback:            options.AllowLoopback,
		PrivateEndpointAllowlist: options.PrivateEndpointAllowlist,
		LookupIPAddrs:            options.LookupIPAddrs,
	}
	return &cloned
}

func firstDuration(values ...time.Duration) time.Duration {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

// NormalizeBaseURL validates source-configured API origins before credentials are
// attached to requests.
func NormalizeBaseURL(sourceID string, raw string, allowLoopback bool) (string, string, error) {
	return NormalizeBaseURLWithOptions(sourceID, raw, URLValidationOptions{AllowLoopback: allowLoopback})
}

func NormalizeBaseURLWithOptions(sourceID string, raw string, options URLValidationOptions) (string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", fmt.Errorf("parse %s base_url: %w", sourceID, err)
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	allowInsecureLoopback := options.AllowLoopback && parsed.Scheme == "http" && IsLoopbackHost(host)
	if parsed.Scheme != "https" && !allowInsecureLoopback {
		return "", "", fmt.Errorf("%s base_url must use https", sourceID)
	}
	if host == "" {
		return "", "", fmt.Errorf("%s base_url must include a host", sourceID)
	}
	privateEndpointAllowed := privateEndpointHostAllowed(host, options.PrivateEndpointAllowlist)
	if len(options.PrivateEndpointAllowlist) > 0 && !privateEndpointAllowed {
		return "", "", fmt.Errorf("%s private endpoint host must exactly match the configured allowlist", sourceID)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", "", fmt.Errorf("%s base_url must not include user info, query, or fragment", sourceID)
	}
	if privateEndpointAllowed && strings.Trim(strings.TrimSpace(host), "[]") != host {
		return "", "", fmt.Errorf("%s private endpoint allowlist must use DNS hostnames, not IP literals", sourceID)
	}
	if privateEndpointAllowed && net.ParseIP(strings.Trim(host, "[]")) != nil {
		return "", "", fmt.Errorf("%s private endpoint allowlist must use DNS hostnames, not IP literals", sourceID)
	}
	if privateEndpointAllowed && strings.Trim(parsed.EscapedPath(), "/") != "" {
		return "", "", fmt.Errorf("%s private endpoint base_url must be an HTTPS origin without a path", sourceID)
	}
	if strings.TrimSpace(parsed.Port()) != "" && parsed.Port() != "443" && (!options.AllowLoopback || !IsLoopbackHost(host)) {
		return "", "", fmt.Errorf("%s base_url must not include a custom port", sourceID)
	}
	if IsUnsafeHost(host) && (!options.AllowLoopback || !IsLoopbackHost(host)) {
		return "", "", fmt.Errorf("%s base_url must not target loopback, private, or link-local hosts", sourceID)
	}
	return strings.TrimRight(parsed.String(), "/"), host, nil
}

func NormalizeRequestPath(sourceID string, raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("%s request path is required", sourceID)
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("parse %s request path: %w", sourceID, err)
	}
	if parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", fmt.Errorf("%s request path must be an absolute path without query or fragment", sourceID)
	}
	if !strings.HasPrefix(value, "/") {
		return "", fmt.Errorf("%s request path must start with /", sourceID)
	}
	return value, nil
}

func SameOriginAbsoluteURL(sourceID string, baseURL string, raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse %s url: %w", sourceID, err)
	}
	if !parsed.IsAbs() {
		return "", fmt.Errorf("%s url must be absolute", sourceID)
	}
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", fmt.Errorf("parse %s base_url: %w", sourceID, err)
	}
	if !strings.EqualFold(parsed.Scheme, base.Scheme) || !strings.EqualFold(parsed.Host, base.Host) {
		return "", fmt.Errorf("%s paged url must stay on the configured API host", sourceID)
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return "", fmt.Errorf("%s paged url must not include user info or fragment", sourceID)
	}
	return parsed.String(), nil
}

type SafeRoundTripper struct {
	Base                     http.RoundTripper
	SourceID                 string
	AllowLoopback            bool
	PrivateEndpointAllowlist []string
	LookupIPAddrs            func(context.Context, string) ([]net.IPAddr, error)
}

func (rt SafeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	base := rt.Base
	if base == nil {
		base = http.DefaultTransport
	}
	if req != nil {
		if traceparent := telemetry.TraceParent(req.Context()); traceparent != "" && req.Header.Get("Traceparent") == "" {
			req = req.Clone(req.Context())
			req.Header.Set("Traceparent", traceparent)
		}
	}
	if req != nil && req.URL != nil {
		if privateEndpointHostAllowed(req.URL.Hostname(), rt.PrivateEndpointAllowlist) {
			if req.URL.Scheme != "https" {
				return nil, fmt.Errorf("%s private endpoint requests must use https", rt.SourceID)
			}
			if port := strings.TrimSpace(req.URL.Port()); port != "" && port != "443" {
				return nil, fmt.Errorf("%s private endpoint requests must not use a custom port", rt.SourceID)
			}
		}
		addrs, err := SafeResolvedHostAddrsWithOptions(req.Context(), rt.SourceID, req.URL.Hostname(), HostResolutionOptions{
			AllowLoopback:            rt.AllowLoopback,
			PrivateEndpointAllowlist: rt.PrivateEndpointAllowlist,
			LookupIPAddrs:            rt.LookupIPAddrs,
		})
		if err != nil {
			return nil, err
		}
		if len(addrs) > 0 {
			pinned, err := pinnedHostTransport(base, req.URL.Hostname(), addrs[0].IP)
			if err != nil {
				return nil, err
			}
			base = pinned
		}
	}
	return base.RoundTrip(req)
}

func pinnedHostTransport(base http.RoundTripper, host string, ip net.IP) (http.RoundTripper, error) {
	transport, ok := base.(*http.Transport)
	if !ok {
		return nil, ErrTransportPinningUnsupported
	}
	clone := transport.Clone()
	clone.Proxy = nil
	clone.DisableKeepAlives = true
	clone.DialTLSContext = nil
	dialContext := clone.DialContext
	if dialContext == nil {
		dialer := &net.Dialer{}
		dialContext = dialer.DialContext
	}
	requestHost := strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	pinnedIP := ip.String()
	clone.DialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
		addressHost, addressPort, err := net.SplitHostPort(address)
		if err == nil && strings.EqualFold(strings.Trim(addressHost, "[]"), requestHost) {
			return dialContext(ctx, network, net.JoinHostPort(pinnedIP, addressPort))
		}
		return dialContext(ctx, network, address)
	}
	return clone, nil
}

func SafeResolvedHostAddrs(ctx context.Context, sourceID string, host string, allowLoopback bool, lookup func(context.Context, string) ([]net.IPAddr, error)) ([]net.IPAddr, error) {
	return SafeResolvedHostAddrsWithOptions(ctx, sourceID, host, HostResolutionOptions{AllowLoopback: allowLoopback, LookupIPAddrs: lookup})
}

func SafeResolvedHostAddrsWithOptions(ctx context.Context, sourceID string, host string, options HostResolutionOptions) ([]net.IPAddr, error) {
	normalized := strings.ToLower(strings.TrimSpace(host))
	if normalized == "" {
		return nil, fmt.Errorf("%s host is required", sourceID)
	}
	if ip := net.ParseIP(strings.Trim(normalized, "[]")); ip != nil {
		if unsafeIP(ip, options.AllowLoopback) {
			return nil, fmt.Errorf("%s host must not target loopback, private, or link-local addresses", sourceID)
		}
		return nil, nil
	}
	lookup := options.LookupIPAddrs
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	addrs, err := lookup(ctx, normalized)
	if err != nil {
		return nil, fmt.Errorf("resolve %s host %q: %w", sourceID, normalized, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %s host %q: no addresses", sourceID, normalized)
	}
	allowPrivate := privateEndpointHostAllowed(normalized, options.PrivateEndpointAllowlist)
	for _, addr := range addrs {
		if unsafeResolvedIP(addr.IP, options.AllowLoopback, allowPrivate) {
			return nil, fmt.Errorf("%s host must not resolve to loopback, private, or link-local addresses", sourceID)
		}
	}
	return addrs, nil
}

func ParsePrivateEndpointAllowlist(sourceID string, raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	seen := map[string]struct{}{}
	hosts := []string{}
	for _, entry := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t' || r == ' '
	}) {
		host := strings.ToLower(strings.TrimSpace(entry))
		if host == "" {
			continue
		}
		if strings.Contains(host, "://") {
			parsed, err := url.Parse(host)
			if err != nil {
				return nil, fmt.Errorf("parse %s private endpoint allowlist entry: %w", sourceID, err)
			}
			if parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Trim(parsed.EscapedPath(), "/") != "" {
				return nil, fmt.Errorf("%s private endpoint allowlist URL entries must be HTTPS origins", sourceID)
			}
			if port := strings.TrimSpace(parsed.Port()); port != "" && port != "443" {
				return nil, fmt.Errorf("%s private endpoint allowlist URL entries must not include a custom port", sourceID)
			}
			host = strings.ToLower(strings.TrimSpace(parsed.Hostname()))
		}
		if strings.Contains(host, "://") || strings.Contains(host, "/") || strings.Contains(host, "?") || strings.Contains(host, "#") || strings.Contains(host, ":") {
			return nil, fmt.Errorf("%s private endpoint allowlist entries must be exact DNS hostnames", sourceID)
		}
		if net.ParseIP(strings.Trim(host, "[]")) != nil || IsUnsafeHost(host) {
			return nil, fmt.Errorf("%s private endpoint allowlist entries must be non-loopback DNS hostnames", sourceID)
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	return hosts, nil
}

func privateEndpointHostAllowed(host string, allowlist []string) bool {
	normalized := strings.ToLower(strings.TrimSpace(host))
	if normalized == "" {
		return false
	}
	for _, allowed := range allowlist {
		if normalized == strings.ToLower(strings.TrimSpace(allowed)) {
			return true
		}
	}
	return false
}

func IsUnsafeHost(host string) bool {
	value := strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if value == "" || value == "localhost" || strings.HasSuffix(value, ".localhost") {
		return true
	}
	ip := net.ParseIP(value)
	return ip != nil && unsafeIP(ip, false)
}

func unsafeIP(ip net.IP, allowLoopback bool) bool {
	if ip == nil {
		return true
	}
	if allowLoopback && ip.IsLoopback() {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

func unsafeResolvedIP(ip net.IP, allowLoopback bool, allowPrivate bool) bool {
	if ip == nil {
		return true
	}
	if allowLoopback && ip.IsLoopback() {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	if ip.IsPrivate() && !allowPrivate {
		return true
	}
	return false
}

func IsLoopbackHost(host string) bool {
	value := strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if value == "localhost" || strings.HasSuffix(value, ".localhost") {
		return true
	}
	ip := net.ParseIP(value)
	return ip != nil && ip.IsLoopback()
}

func ReadLimitedBody(body io.Reader) ([]byte, error) {
	return ReadLimitedBodyWithLimit(body, MaxBodyBytes)
}

func DoWithRetry(ctx context.Context, client *http.Client, req *http.Request, options RetryOptions) (ResponseBody, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if req == nil {
		return ResponseBody{}, fmt.Errorf("request is required")
	}
	attempts := options.MaxAttempts
	if attempts <= 0 {
		attempts = DefaultRetryMaxAttempts
	}
	backoff := options.Backoff
	if backoff <= 0 {
		backoff = DefaultRetryBackoff
	}
	if !requestBodyReplayable(req) {
		attempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		nextReq, err := requestForRetryAttempt(ctx, req, attempt)
		if err != nil {
			return ResponseBody{}, err
		}
		resp, err := client.Do(nextReq) // #nosec G704 -- callers must pass URLs normalized by this package's allowlist helpers.
		if err != nil {
			lastErr = err
		} else {
			body, readErr := ReadLimitedBodyWithLimit(resp.Body, options.MaxBodyBytes)
			_ = resp.Body.Close()
			if readErr != nil {
				return ResponseBody{}, readErr
			}
			result := ResponseBody{StatusCode: resp.StatusCode, Header: resp.Header.Clone(), Body: body}
			if attempt == attempts || !RetryableStatus(resp.StatusCode) {
				return result, nil
			}
			if err := sleepRetry(ctx, retryDelay(resp.Header.Get("Retry-After"), backoff, attempt)); err != nil {
				return ResponseBody{}, err
			}
			continue
		}
		if attempt == attempts {
			return ResponseBody{}, lastErr
		}
		if err := sleepRetry(ctx, retryDelay("", backoff, attempt)); err != nil {
			return ResponseBody{}, err
		}
	}
	return ResponseBody{}, lastErr
}

func requestBodyReplayable(req *http.Request) bool {
	if req == nil || req.Body == nil || req.Body == http.NoBody {
		return true
	}
	return req.GetBody != nil
}

func requestForRetryAttempt(ctx context.Context, req *http.Request, attempt int) (*http.Request, error) {
	nextReq := req.Clone(ctx)
	if req.Body == nil || req.Body == http.NoBody {
		return nextReq, nil
	}
	if attempt == 1 {
		nextReq.Body = req.Body
		return nextReq, nil
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	nextReq.Body = body
	return nextReq, nil
}

func RetryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout || status >= 500
}

func retryDelay(rawRetryAfter string, backoff time.Duration, attempt int) time.Duration {
	if seconds, err := strconv.Atoi(strings.TrimSpace(rawRetryAfter)); err == nil && seconds > 0 {
		if delay := time.Duration(seconds) * time.Second; delay < MaxRetryAfter {
			return delay
		}
		return MaxRetryAfter
	}
	delay := backoff
	for i := 1; i < attempt; i++ {
		delay *= 2
	}
	if delay > MaxRetryAfter {
		return MaxRetryAfter
	}
	return delay
}

func sleepRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func ReadLimitedBodyWithLimit(body io.Reader, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = MaxBodyBytes
	}
	limited := io.LimitReader(body, int64(maxBytes)+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(payload) > maxBytes {
		return nil, fmt.Errorf("response body exceeds %d bytes", maxBytes)
	}
	return payload, nil
}

func NoRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}
