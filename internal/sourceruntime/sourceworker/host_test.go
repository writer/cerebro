package sourceworker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestHostKeepsCredentialInGoAndReturnsSafeReceipt(t *testing.T) {
	plan := AzureAuthorizationPolicyPlan()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	secret := "not-in-worker-or-receipt"
	worker := &fakeWorker{responseBody: []byte(exactGoAuthorizationPolicyResponse)}
	lease := &fakeCredentialLease{token: []byte(secret), operationID: "lease-operation-1", expiresAt: now.Add(time.Minute)}
	redeemer := &fakeCredentialRedeemer{lease: lease}
	host := &Host{
		worker: worker, redeemer: redeemer, now: func() time.Time { return now },
		client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if got := request.Header.Get("Authorization"); got != "Bearer "+secret {
				t.Fatalf("Authorization = %q", got)
			}
			if request.URL.String() != "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" {
				t.Fatalf("URL = %s", request.URL)
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(exactGoAuthorizationPolicyResponse)), Header: make(http.Header)}, nil
		}), CheckRedirect: func(*http.Request, []*http.Request) error { return errorsNewRedirect() }},
	}
	scope := exactScope(plan, now)
	output, err := host.Execute(context.Background(), ExecutionInput{Plan: plan, CredentialReference: "opaque://azure/runtime-1", Scope: scope})
	if err != nil {
		t.Fatal(err)
	}
	if redeemer.calls != 1 || lease.closeCalls != 1 {
		t.Fatalf("redeem calls = %d, close calls = %d", redeemer.calls, lease.closeCalls)
	}
	if worker.planSawSecret || worker.decodeSawSecret {
		t.Fatal("credential crossed into worker protocol")
	}
	if receipt := fmt.Sprintf("%+v", output.Receipt); strings.Contains(receipt, secret) || strings.Contains(receipt, "opaque://") {
		t.Fatalf("receipt leaked credential material: %s", receipt)
	}
	if output.Receipt.StatusCode != 200 || output.Receipt.ResponseBytes != len(exactGoAuthorizationPolicyResponse) || len(output.Receipt.ResponseSHA256) != 64 {
		t.Fatalf("receipt = %#v", output.Receipt)
	}

	event, err := AuthorizationPolicyEvent(plan, scope, output.Receipt, output.Result, now)
	if err != nil {
		t.Fatal(err)
	}
	if event.GetId() != "azure-authorization-policy-authorizationPolicy" || event.GetTenantId() != "tenant-1" || event.GetSourceId() != "azure" || event.GetKind() != "azure.authorization_policy" || event.GetSchemaRef() != "azure/authorization_policy/v1" {
		t.Fatalf("event identity = %#v", event)
	}
	for key, want := range map[string]string{
		"domain": "tenant-1", "family": "authorization_policy", "resource_id": "authorizationPolicy",
		"resource_name": "authorizationPolicy", "resource_provider": "azure", "resource_type": "authorization_policy",
		"allow_invites_from": "adminsAndGuestInviters", "default_user_can_read_bitlocker": "true",
	} {
		if got := event.GetAttributes()[key]; got != want {
			t.Fatalf("attribute %s = %q, want %q", key, got, want)
		}
	}
	if !bytes.Contains(event.GetPayload(), []byte(`"tenant_id":"tenant-1"`)) || !bytes.Contains(event.GetPayload(), []byte(`"raw":`)) {
		t.Fatalf("payload = %s", event.GetPayload())
	}
}

func TestHostRejectsRecomputedOriginTamperBeforeCredentialRedemption(t *testing.T) {
	plan := AzureAuthorizationPolicyPlan()
	plan.Origin = "https://example.com"
	plan.PlanDigestSha256 = executionPlanDigest(plan)
	now := time.Now().UTC()
	scope := exactScope(plan, now)
	redeemer := &fakeCredentialRedeemer{lease: &fakeCredentialLease{token: []byte("secret"), operationID: "operation-1", expiresAt: now.Add(time.Minute)}}
	host := &Host{worker: &fakeWorker{}, redeemer: redeemer, client: &http.Client{}, now: func() time.Time { return now }}
	_, err := host.Execute(context.Background(), ExecutionInput{Plan: plan, CredentialReference: "opaque", Scope: scope})
	if !errors.Is(err, ErrWorkerContract) || redeemer.calls != 0 {
		t.Fatalf("Execute() error = %v, redeem calls = %d", err, redeemer.calls)
	}
}

func TestHostRejectsForgedResultDigest(t *testing.T) {
	plan := AzureAuthorizationPolicyPlan()
	now := time.Now().UTC()
	worker := &fakeWorker{responseBody: []byte(exactGoAuthorizationPolicyResponse), tamperedDigest: true}
	redeemer := &fakeCredentialRedeemer{lease: &fakeCredentialLease{token: []byte("secret"), operationID: "operation-1", expiresAt: now.Add(time.Minute)}}
	host := &Host{worker: worker, redeemer: redeemer, now: func() time.Time { return now }, client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(exactGoAuthorizationPolicyResponse)), Header: make(http.Header)}, nil
	})}}
	_, err := host.Execute(context.Background(), ExecutionInput{Plan: plan, CredentialReference: "opaque", Scope: exactScope(plan, now)})
	if err == nil || !strings.Contains(err.Error(), ErrWorkerContract.Error()) {
		t.Fatalf("Execute() error = %v, want worker contract failure", err)
	}
}

func TestHostRejectsIntentTamperBeforeCredentialRedemption(t *testing.T) {
	plan := AzureAuthorizationPolicyPlan()
	now := time.Now().UTC()
	scope := exactScope(plan, now)
	scope.RequestIntentDigest = strings.Repeat("b", 64)
	redeemer := &fakeCredentialRedeemer{lease: &fakeCredentialLease{token: []byte("secret"), operationID: "operation-1", expiresAt: now.Add(time.Minute)}}
	host := &Host{worker: &fakeWorker{}, redeemer: redeemer, client: &http.Client{}, now: func() time.Time { return now }}
	_, err := host.Execute(context.Background(), ExecutionInput{Plan: plan, CredentialReference: "opaque", Scope: scope})
	if !errors.Is(err, ErrWorkerContract) || redeemer.calls != 0 {
		t.Fatalf("Execute() error = %v, redeem calls = %d", err, redeemer.calls)
	}
}

func TestHostClassifiesProviderStatus(t *testing.T) {
	for status, want := range map[int]error{401: ErrProviderAuthentication, 403: ErrProviderPermission, 429: ErrProviderRateLimited} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			plan := AzureAuthorizationPolicyPlan()
			now := time.Now().UTC()
			host := &Host{worker: &fakeWorker{}, redeemer: &fakeCredentialRedeemer{lease: &fakeCredentialLease{token: []byte("secret"), operationID: "operation-1", expiresAt: now.Add(time.Minute)}}, now: func() time.Time { return now }, client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			})}}
			_, err := host.Execute(context.Background(), ExecutionInput{Plan: plan, CredentialReference: "opaque", Scope: exactScope(plan, now)})
			if !errors.Is(err, want) {
				t.Fatalf("Execute() error = %v, want %v", err, want)
			}
		})
	}
}

func TestBoundedGetPreservesTimeoutEgressAndSizeFailures(t *testing.T) {
	for name, transportErr := range map[string]struct {
		err  error
		want error
	}{
		"timeout": {err: context.DeadlineExceeded, want: ErrProviderTimeout},
		"egress":  {err: errors.New("dial failed"), want: ErrProviderEgress},
	} {
		t.Run(name, func(t *testing.T) {
			host := &Host{client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, transportErr.err })}}
			_, _, err := host.get(context.Background(), mustURL(t, "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"), "application/json", 16, []byte("secret"))
			if !errors.Is(err, transportErr.want) {
				t.Fatalf("get() error = %v, want %v", err, transportErr.want)
			}
		})
	}
	host := &Host{client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("too large")), Header: make(http.Header)}, nil
	})}}
	if _, _, err := host.get(context.Background(), mustURL(t, "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"), "application/json", 2, []byte("secret")); !errors.Is(err, ErrProviderResponseTooLarge) {
		t.Fatalf("get() error = %v, want response-too-large", err)
	}
}

func mustURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestHostRejectsEscapedRequestBeforeCredentialRedemption(t *testing.T) {
	plan := AzureAuthorizationPolicyPlan()
	now := time.Now().UTC()
	worker := &fakeWorker{escapedURL: "https://example.com/v1.0/policies/authorizationPolicy"}
	redeemer := &fakeCredentialRedeemer{lease: &fakeCredentialLease{token: []byte("secret"), expiresAt: now.Add(time.Minute)}}
	host := &Host{worker: worker, redeemer: redeemer, client: &http.Client{}, now: func() time.Time { return now }}
	_, err := host.Execute(context.Background(), ExecutionInput{Plan: plan, CredentialReference: "opaque", Scope: exactScope(plan, now)})
	if !errorsIsInvalid(err) || redeemer.calls != 0 {
		t.Fatalf("Execute() error = %v, redeem calls = %d", err, redeemer.calls)
	}
}

func TestPublicDNSValidationRejectsPrivateAndMixedAnswers(t *testing.T) {
	for name, addresses := range map[string][]net.IPAddr{
		"loopback": {{IP: net.ParseIP("127.0.0.1")}}, "private": {{IP: net.ParseIP("10.1.2.3")}},
		"linklocal": {{IP: net.ParseIP("169.254.169.254")}}, "mixed": {{IP: net.ParseIP("20.190.128.1")}, {IP: net.ParseIP("10.1.2.3")}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validatePublicAddresses(addresses); !errors.Is(err, ErrProviderEgress) {
				t.Fatalf("validatePublicAddresses() error = %v", err)
			}
		})
	}
	if err := validatePublicAddresses([]net.IPAddr{{IP: net.ParseIP("20.190.128.1")}}); err != nil {
		t.Fatalf("public address rejected: %v", err)
	}
}
