package sourceworker

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

const (
	maxPublicConfigEntries  = 32
	maxPublicConfigBytes    = 16 << 10
	maxRequestBodyBytes     = 1 << 20
	maxSafeHeaderEntries    = 32
	maxSafeHeaderBytes      = 16 << 10
	maxSafeHeaderValueBytes = 4096
)

func validateScope(plan *cerebrov1.SourceExecutionPlanV1, reference string, scope CredentialScope, now time.Time) error {
	if strings.TrimSpace(reference) == "" || strings.TrimSpace(scope.TenantID) == "" || !safeIdentifier(scope.RuntimeID) || !safeIdentifier(scope.LeaseOwner) || !safeIdentifier(scope.LogicalPageID) || (scope.RequestIntentDigest != "" && !lowerSHA256(scope.RequestIntentDigest)) {
		return fmt.Errorf("%w: execution scope is incomplete", ErrInvalidExecution)
	}
	if scope.SourceID != plan.GetSourceId() || scope.FamilyID != plan.GetFamilyId() || scope.PlanDigestSHA256 != plan.GetPlanDigestSha256() {
		return fmt.Errorf("%w: execution scope does not match the compiled plan", ErrInvalidExecution)
	}
	if scope.RuntimeGeneration == 0 || scope.LeaseGeneration == 0 || !scope.LeaseExpiresAt.UTC().After(now) {
		return fmt.Errorf("%w: execution lease fence is invalid", ErrInvalidExecution)
	}
	if scope.PriorTerminalWatermarkUnixMillis < 0 || !safeOpaque(scope.PriorCursor) || !safeOpaque(scope.PriorCheckpoint) {
		return fmt.Errorf("%w: durable resume metadata is invalid", ErrInvalidExecution)
	}
	if err := validatePublicConfig(scope.PublicConfig); err != nil {
		return err
	}
	return nil
}

func validateWorkerRequest(plan *cerebrov1.SourceExecutionPlanV1, request *cerebrov1.SourceWorkerHTTPRequestV1) (*url.URL, error) {
	if request == nil || request.GetPlanId() != plan.GetPlanId() || request.GetPlanDigestSha256() != plan.GetPlanDigestSha256() || request.GetMethod() != plan.GetMethod() || (request.GetMethod() != http.MethodGet && request.GetMethod() != http.MethodPost) || request.GetAccept() != "application/json" || request.GetMaxResponseBytes() != plan.GetMaxResponseBytes() || request.GetMaxResponseBytes() == 0 || request.GetMaxResponseBytes() > maxResponseBytes {
		return nil, fmt.Errorf("%w: worker request does not match the compiled plan", ErrInvalidExecution)
	}
	origin, err := url.Parse(plan.GetOrigin())
	if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.Port() != "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" {
		return nil, fmt.Errorf("%w: provider origin is invalid", ErrInvalidExecution)
	}
	actual, err := url.Parse(request.GetUrl())
	if err != nil || actual.Scheme != origin.Scheme || actual.Hostname() != origin.Hostname() || actual.Port() != origin.Port() || actual.User != nil || actual.Fragment != "" || (actual.Path != plan.GetPath() && actual.Path != origin.ResolveReference(&url.URL{Path: plan.GetPath()}).Path) {
		return nil, fmt.Errorf("%w: worker request escaped the compiled origin", ErrInvalidExecution)
	}
	if !lowerSHA256(request.GetRequestIntentDigest()) {
		return nil, fmt.Errorf("%w: worker request intent digest is invalid", ErrWorkerContract)
	}
	return actual, nil
}

func validateHTTPExecution(plan *cerebrov1.SourceExecutionPlanV1, context *cerebrov1.SourceWorkerExecutionContextV1, metadata *cerebrov1.SourceWorkerRuntimeMetadataV2, execution *cerebrov1.SourceWorkerHTTPExecutionV2) (*url.URL, error) {
	if execution == nil || metadata == nil || context == nil {
		return nil, fmt.Errorf("%w: metadata-aware worker request is incomplete", ErrInvalidExecution)
	}
	if err := validatePublicConfig(metadata.GetPublicConfig()); err != nil || metadata.GetPriorTerminalWatermarkUnixMillis() < 0 || !safeOpaque(metadata.GetPriorCheckpoint()) {
		return nil, fmt.Errorf("%w: durable runtime metadata is invalid", ErrInvalidExecution)
	}
	requestURL, err := validateWorkerRequest(plan, execution.GetRequest())
	if err != nil {
		return nil, err
	}
	if err := validateDeclaredHeaders(execution.GetDeclaredHeaders()); err != nil {
		return nil, err
	}
	if len(execution.GetBody()) > maxRequestBodyBytes || (execution.GetRequest().GetMethod() == http.MethodGet && len(execution.GetBody()) != 0) {
		return nil, fmt.Errorf("%w: worker request body is invalid", ErrInvalidExecution)
	}
	if execution.GetCredentialOperation() != "source.bearer" && execution.GetCredentialOperation() != "jumpcloud.x_api_key" {
		return nil, fmt.Errorf("%w: credential operation is not registered", ErrWorkerContract)
	}
	if !lowerSHA256(execution.GetExecutionIntentDigestSha256()) || execution.GetExecutionIntentDigestSha256() != executionIntentSHA256(metadata, execution) {
		return nil, fmt.Errorf("%w: execution intent digest is invalid", ErrWorkerContract)
	}
	return requestURL, nil
}

func validatePublicConfig(config map[string]string) error {
	if len(config) > maxPublicConfigEntries {
		return fmt.Errorf("%w: public configuration exceeds its entry bound", ErrInvalidExecution)
	}
	total := 0
	for key, value := range config {
		if !safeConfigKey(key) || len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("%w: public configuration is invalid", ErrInvalidExecution)
		}
		total += len(key) + len(value)
	}
	if total > maxPublicConfigBytes {
		return fmt.Errorf("%w: public configuration exceeds its byte bound", ErrInvalidExecution)
	}
	return nil
}

func validateDeclaredHeaders(headers map[string]string) error {
	return validateHeaderMap(headers, false)
}

func safeResponseHeaders(headers http.Header) (map[string]string, error) {
	result := make(map[string]string)
	for name, values := range headers {
		name = strings.ToLower(strings.TrimSpace(name))
		if !safeResponseHeaderName(name) || sensitiveHeaderName(name) {
			continue
		}
		value := strings.Join(values, ", ")
		result[name] = value
	}
	if err := validateHeaderMap(result, true); err != nil {
		return nil, err
	}
	return result, nil
}

func validateHeaderMap(headers map[string]string, response bool) error {
	if len(headers) > maxSafeHeaderEntries {
		return fmt.Errorf("%w: safe headers exceed their entry bound", ErrProviderResponseTooLarge)
	}
	total := 0
	for name, value := range headers {
		if name != strings.ToLower(name) || !safeHeaderName(name) || sensitiveHeaderName(name) || (!response && !safeDeclaredHeaderName(name)) || (response && !safeResponseHeaderName(name)) || len(value) > maxSafeHeaderValueBytes || strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("%w: safe header metadata is invalid", ErrInvalidExecution)
		}
		total += len(name) + len(value)
	}
	if total > maxSafeHeaderBytes {
		return fmt.Errorf("%w: safe headers exceed their byte bound", ErrProviderResponseTooLarge)
	}
	return nil
}

func safeDeclaredHeaderName(name string) bool {
	return name == "content-type" || name == "x-org-id"
}

func safeConfigKey(key string) bool {
	if key == "" || len(key) > 64 || key != strings.ToLower(key) || !safeHeaderName(key) {
		return false
	}
	for _, fragment := range []string{"api_key", "apikey", "authorization", "client_secret", "cookie", "credential", "password", "private_key", "secret", "token"} {
		if strings.Contains(key, fragment) {
			return false
		}
	}
	return true
}

func safeHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, character := range name {
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && !strings.ContainsRune("!#$%&'*+-.^_`|~", character) {
			return false
		}
	}
	return true
}

func sensitiveHeaderName(name string) bool {
	switch name {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "www-authenticate", "proxy-authenticate", "x-api-key", "api-key", "x-auth-token", "x-access-token", "host", "content-length", "transfer-encoding", "connection":
		return true
	default:
		return false
	}
}

func safeResponseHeaderName(name string) bool {
	switch name {
	case "content-type", "date", "etag", "last-modified", "link", "retry-after", "x-limit", "x-result-count", "x-search-after", "x-search_after":
		return true
	}
	for _, prefix := range []string{"ratelimit-", "x-ratelimit-", "x-next-", "x-page-", "x-pagination-", "x-total-"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func safeOpaque(value string) bool {
	return len(value) <= 4096 && !strings.ContainsAny(value, "\r\n\x00")
}

func sortedHeaderKeys(headers map[string]string) []string {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func safeHTTPClient(resolver *net.Resolver) *http.Client {
	dialer := &net.Dialer{Timeout: executionTimeout}
	transport := &http.Transport{Proxy: nil, TLSHandshakeTimeout: executionTimeout, DisableCompression: true}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("%w: provider address is invalid", ErrProviderEgress)
		}
		addresses, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("%w: provider DNS lookup failed", ErrProviderEgress)
		}
		if err := validatePublicAddresses(addresses); err != nil {
			return nil, err
		}
		var lastErr error
		for _, resolved := range addresses {
			connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(resolved.IP.String(), port))
			if dialErr == nil {
				return connection, nil
			}
			lastErr = dialErr
		}
		if lastErr != nil {
			return nil, fmt.Errorf("%w: provider connection failed: %w", ErrProviderEgress, lastErr)
		}
		return nil, fmt.Errorf("%w: provider connection failed", ErrProviderEgress)
	}
	return &http.Client{Transport: transport, Timeout: executionTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return fmt.Errorf("%w: provider redirects are not allowed", ErrProviderEgress)
	}}
}

func validatePublicAddresses(addresses []net.IPAddr) error {
	if len(addresses) == 0 {
		return fmt.Errorf("%w: provider DNS returned no addresses", ErrProviderEgress)
	}
	for _, address := range addresses {
		ip := address.IP
		if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("%w: provider DNS returned a non-public address", ErrProviderEgress)
		}
	}
	return nil
}
