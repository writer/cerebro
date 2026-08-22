package sourceworker

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
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
	return nil
}

func executionContextFor(scope CredentialScope, observedAt time.Time) *cerebrov1.SourceWorkerExecutionContextV1 {
	return &cerebrov1.SourceWorkerExecutionContextV1{
		TenantId: scope.TenantID, RuntimeId: scope.RuntimeID, LogicalPageId: scope.LogicalPageID,
		PriorCursor: scope.PriorCursor, RuntimeGeneration: scope.RuntimeGeneration,
		LeaseGeneration: scope.LeaseGeneration, ObservedAtUnixMillis: observedAt.UTC().UnixMilli(),
	}
}

func validateCanonicalPlan(plan *cerebrov1.SourceExecutionPlanV1) error {
	if plan == nil || !proto.Equal(plan, AzureAuthorizationPolicyPlan()) {
		return fmt.Errorf("%w: plan is not the registered Azure authorization policy plan", ErrWorkerContract)
	}
	return nil
}

func validateWorkerRequest(plan *cerebrov1.SourceExecutionPlanV1, executionContext *cerebrov1.SourceWorkerExecutionContextV1, request *cerebrov1.SourceWorkerHTTPRequestV1) (*url.URL, error) {
	if request == nil || request.GetPlanId() != plan.GetPlanId() || request.GetPlanDigestSha256() != plan.GetPlanDigestSha256() || request.GetMethod() != http.MethodGet || request.GetAccept() != "application/json" || request.GetMaxResponseBytes() != plan.GetMaxResponseBytes() || request.GetMaxResponseBytes() == 0 || request.GetMaxResponseBytes() > maxResponseBytes {
		return nil, fmt.Errorf("%w: worker request does not match the compiled plan", ErrInvalidExecution)
	}
	if plan.GetSourceId() != "azure" || plan.GetFamilyId() != "authorization_policy" || plan.GetProviderKernel() != "azure.authorization_policy" || plan.GetPath() != "/v1.0/policies/authorizationPolicy" {
		return nil, fmt.Errorf("%w: provider family intent is not allowed", ErrInvalidExecution)
	}
	origin, err := url.Parse(plan.GetOrigin())
	if err != nil || origin.Scheme != "https" || origin.Hostname() != "graph.microsoft.com" || origin.Port() != "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return nil, fmt.Errorf("%w: provider origin is invalid", ErrInvalidExecution)
	}
	expected := origin.ResolveReference(&url.URL{Path: plan.GetPath()})
	actual, err := url.Parse(request.GetUrl())
	if err != nil || actual.String() != expected.String() || actual.User != nil || actual.RawQuery != "" || actual.Fragment != "" {
		return nil, fmt.Errorf("%w: worker request escaped the compiled origin", ErrInvalidExecution)
	}
	intentDigest, err := canonicalRequestIntentDigestForContext(plan, executionContext, request)
	if err != nil || !lowerSHA256(request.GetRequestIntentDigest()) || subtle.ConstantTimeCompare([]byte(intentDigest), []byte(request.GetRequestIntentDigest())) != 1 {
		return nil, fmt.Errorf("%w: worker request intent digest is invalid", ErrWorkerContract)
	}
	return actual, nil
}

func validateWorkerResult(plan *cerebrov1.SourceExecutionPlanV1, executionContext *cerebrov1.SourceWorkerExecutionContextV1, receipt SafeReceipt, result *cerebrov1.SourceWorkerDecodeResultV1) error {
	if executionContext == nil || result == nil || result.GetPlanId() != plan.GetPlanId() || result.GetPlanDigestSha256() != plan.GetPlanDigestSha256() || result.GetLogicalPageId() != executionContext.GetLogicalPageId() || result.GetRequestIntentDigest() != receipt.RequestIntentDigest || result.GetTenantId() != executionContext.GetTenantId() || result.GetRuntimeId() != executionContext.GetRuntimeId() || result.GetRuntimeGeneration() != executionContext.GetRuntimeGeneration() || result.GetLeaseGeneration() != executionContext.GetLeaseGeneration() || result.GetObservedAtUnixMillis() != executionContext.GetObservedAtUnixMillis() || result.GetNextCursor() != "" || len(result.GetRecords()) != 1 || !lowerSHA256(result.GetResultDigestSha256()) {
		return fmt.Errorf("%w: worker result is not bound to the execution", ErrInvalidExecution)
	}
	for _, record := range result.GetRecords() {
		if record == nil || strings.TrimSpace(record.GetEventId()) == "" || record.GetOccurredAtUnixMillis() != executionContext.GetObservedAtUnixMillis() {
			return fmt.Errorf("%w: worker record identity is not bound to the execution", ErrInvalidExecution)
		}
	}
	expected, err := CanonicalResultDigest(result, receipt)
	if err != nil || subtle.ConstantTimeCompare([]byte(expected), []byte(result.GetResultDigestSha256())) != 1 {
		return fmt.Errorf("%w: worker result digest does not match the safe receipt", ErrWorkerContract)
	}
	return nil
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
