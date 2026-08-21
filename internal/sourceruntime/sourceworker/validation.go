package sourceworker

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func validateScope(plan *cerebrov1.SourceExecutionPlanV1, reference string, scope CredentialScope, now time.Time) error {
	if strings.TrimSpace(reference) == "" || strings.TrimSpace(scope.TenantID) == "" || strings.TrimSpace(scope.RuntimeID) == "" || strings.TrimSpace(scope.LeaseOwner) == "" || strings.TrimSpace(scope.LogicalPageID) == "" || strings.TrimSpace(scope.RequestIntentDigest) == "" {
		return fmt.Errorf("%w: execution scope is incomplete", ErrInvalidExecution)
	}
	if scope.SourceID != plan.GetSourceId() || scope.FamilyID != plan.GetFamilyId() || scope.PlanDigestSHA256 != plan.GetPlanDigestSha256() {
		return fmt.Errorf("%w: execution scope does not match the compiled plan", ErrInvalidExecution)
	}
	if scope.RuntimeGeneration == 0 || scope.LeaseGeneration == 0 || !scope.LeaseExpiresAt.UTC().After(now) {
		return fmt.Errorf("%w: execution lease fence is invalid", ErrInvalidExecution)
	}
	return nil
}

func validateWorkerRequest(plan *cerebrov1.SourceExecutionPlanV1, request *cerebrov1.SourceWorkerHTTPRequestV1) (*url.URL, error) {
	if request == nil || request.GetPlanId() != plan.GetPlanId() || request.GetPlanDigestSha256() != plan.GetPlanDigestSha256() || request.GetMethod() != http.MethodGet || request.GetAccept() != "application/json" || request.GetMaxResponseBytes() != plan.GetMaxResponseBytes() || request.GetMaxResponseBytes() == 0 || request.GetMaxResponseBytes() > maxResponseBytes {
		return nil, fmt.Errorf("%w: worker request does not match the compiled plan", ErrInvalidExecution)
	}
	if plan.GetSourceId() != "azure" || plan.GetFamilyId() != "authorization_policy" || plan.GetProviderKernel() != "azure.authorization_policy" || plan.GetPath() != "/v1.0/policies/authorizationPolicy" {
		return nil, fmt.Errorf("%w: provider family intent is not allowed", ErrInvalidExecution)
	}
	origin, err := url.Parse(plan.GetOrigin())
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return nil, fmt.Errorf("%w: provider origin is invalid", ErrInvalidExecution)
	}
	expected := origin.ResolveReference(&url.URL{Path: plan.GetPath()})
	actual, err := url.Parse(request.GetUrl())
	if err != nil || actual.String() != expected.String() || actual.User != nil || actual.RawQuery != "" || actual.Fragment != "" {
		return nil, fmt.Errorf("%w: worker request escaped the compiled origin", ErrInvalidExecution)
	}
	return actual, nil
}

func validateWorkerResult(plan *cerebrov1.SourceExecutionPlanV1, scope CredentialScope, result *cerebrov1.SourceWorkerDecodeResultV1) error {
	if result == nil || result.GetPlanId() != plan.GetPlanId() || result.GetPlanDigestSha256() != plan.GetPlanDigestSha256() || result.GetLogicalPageId() != scope.LogicalPageID || result.GetRequestIntentDigest() != scope.RequestIntentDigest || result.GetNextCursor() != "" || len(result.GetRecords()) != 1 || len(result.GetResultDigestSha256()) != 64 {
		return fmt.Errorf("%w: worker result is not bound to the execution", ErrInvalidExecution)
	}
	return nil
}

func safeHTTPClient(resolver *net.Resolver) *http.Client {
	dialer := &net.Dialer{Timeout: executionTimeout}
	transport := &http.Transport{Proxy: nil, TLSHandshakeTimeout: executionTimeout, DisableCompression: true}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("%w: provider address is invalid", ErrInvalidExecution)
		}
		addresses, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("%w: provider DNS lookup failed", ErrInvalidExecution)
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
		return nil, fmt.Errorf("%w: provider connection failed: %v", ErrInvalidExecution, lastErr)
	}
	return &http.Client{Transport: transport, Timeout: executionTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return fmt.Errorf("%w: provider redirects are not allowed", ErrInvalidExecution)
	}}
}

func validatePublicAddresses(addresses []net.IPAddr) error {
	if len(addresses) == 0 {
		return fmt.Errorf("%w: provider DNS returned no addresses", ErrInvalidExecution)
	}
	for _, address := range addresses {
		ip := address.IP
		if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("%w: provider DNS returned a non-public address", ErrInvalidExecution)
		}
	}
	return nil
}
