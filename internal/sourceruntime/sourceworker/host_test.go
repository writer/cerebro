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

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestHostKeepsCredentialInsideBoundedEgressBridge(t *testing.T) {
	plan, now, secret := AzureAuthorizationPolicyPlan(), time.Now().UTC(), "host-only-secret"
	worker := newFakeWorker()
	host := NewHost(worker, "opaque-reference", []byte(secret), now.Add(time.Minute))
	host.now, host.client = func() time.Time { return now }, &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer "+secret {
			t.Fatal("host did not apply the redeemed credential")
		}
		return response(http.StatusOK, `{}`), nil
	})}
	output, err := host.Execute(context.Background(), ExecutionInput{Plan: plan, CredentialReference: "opaque-reference", PageNumber: 1, Scope: exactScope(plan, now)})
	if err != nil {
		t.Fatal(err)
	}
	if worker.sawSecret || host.credential != nil || output.Program == nil {
		t.Fatalf("secret crossed boundary or Rust did not seal the page: %#v", output.Program)
	}
	if encoded := fmt.Sprintf("%+v", output.Receipt); strings.Contains(encoded, secret) || strings.Contains(encoded, "opaque-reference") {
		t.Fatal("safe receipt leaked credential material")
	}
}

func TestHostRejectsOriginEscapeAndIntentTamperBeforeRedemption(t *testing.T) {
	plan, now := AzureAuthorizationPolicyPlan(), time.Now().UTC()
	for name, mutate := range map[string]func(*fakeWorker, *CredentialScope){
		"origin": func(worker *fakeWorker, _ *CredentialScope) { worker.endpoint = "https://example.com/escape" },
		"intent": func(_ *fakeWorker, scope *CredentialScope) { scope.RequestIntentDigest = strings.Repeat("b", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			worker, scope := newFakeWorker(), exactScope(plan, now)
			mutate(worker, &scope)
			host := NewHost(worker, "opaque", []byte("secret"), now.Add(time.Minute))
			host.client, host.now = &http.Client{}, func() time.Time { return now }
			if _, err := host.Execute(context.Background(), ExecutionInput{Plan: plan, CredentialReference: "opaque", PageNumber: 1, Scope: scope}); err == nil || host.credential == nil {
				t.Fatalf("Execute() error = %v, credential consumed before validation", err)
			}
		})
	}
}

func TestHostClassifiesProviderAndNetworkBounds(t *testing.T) {
	for status, want := range map[int]error{401: ErrProviderAuthentication, 403: ErrProviderPermission, 429: ErrProviderRateLimited} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			plan, now := AzureAuthorizationPolicyPlan(), time.Now().UTC()
			host := NewHost(newFakeWorker(), "opaque", []byte("secret"), now.Add(time.Minute))
			host.now, host.client = func() time.Time { return now }, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return response(status, `{}`), nil })}
			_, err := host.Execute(context.Background(), ExecutionInput{Plan: plan, CredentialReference: "opaque", PageNumber: 1, Scope: exactScope(plan, now)})
			if !errors.Is(err, want) {
				t.Fatalf("Execute() error = %v, want %v", err, want)
			}
		})
	}
	for name, test := range map[string]struct{ err, want error }{"timeout": {context.DeadlineExceeded, ErrProviderTimeout}, "egress": {errors.New("dial failed"), ErrProviderEgress}} {
		t.Run(name, func(t *testing.T) {
			host := &Host{client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, test.err })}}
			_, _, err := host.get(context.Background(), mustURL(t), "application/json", 16, []byte("secret"))
			if !errors.Is(err, test.want) {
				t.Fatalf("get() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestPublicDNSValidationRejectsPrivateAndMixedAnswers(t *testing.T) {
	for _, addresses := range [][]net.IPAddr{{{IP: net.ParseIP("127.0.0.1")}}, {{IP: net.ParseIP("10.1.2.3")}}, {{IP: net.ParseIP("20.190.128.1")}, {IP: net.ParseIP("10.1.2.3")}}} {
		if err := validatePublicAddresses(addresses); !errors.Is(err, ErrProviderEgress) {
			t.Fatalf("private address accepted: %v", err)
		}
	}
}

type fakeWorker struct {
	endpoint  string
	sawSecret bool
}

func newFakeWorker() *fakeWorker {
	return &fakeWorker{endpoint: "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"}
}
func (w *fakeWorker) Compile(context.Context, SelectionRequest) (*cerebrov1.SourceExecutionPlanV1, error) {
	return AzureAuthorizationPolicyPlan(), nil
}
func (w *fakeWorker) Context(_ context.Context, request ContextRequest) (*cerebrov1.SourceWorkerExecutionContextV1, error) {
	return &cerebrov1.SourceWorkerExecutionContextV1{TenantId: request.TenantID, RuntimeId: request.RuntimeID, LogicalPageId: "logical-page-1", RuntimeGeneration: request.RuntimeGeneration, LeaseGeneration: request.LeaseGeneration, ObservedAtUnixMillis: request.ObservedAtUnixMillis}, nil
}
func (w *fakeWorker) Plan(_ context.Context, request *cerebrov1.SourceWorkerPlanRequestV1) (*cerebrov1.SourceWorkerHTTPRequestV1, error) {
	result := &cerebrov1.SourceWorkerHTTPRequestV1{PlanId: request.GetPlan().GetPlanId(), Method: "GET", Url: w.endpoint, Accept: "application/json", MaxResponseBytes: request.GetPlan().GetMaxResponseBytes(), PlanDigestSha256: request.GetPlan().GetPlanDigestSha256(), RequestIntentDigest: strings.Repeat("1", 64)}
	return result, nil
}
func (w *fakeWorker) Decode(_ context.Context, request *cerebrov1.SourceWorkerDecodeRequestV1) (*cerebrov1.SourceWorkerDecodeResultV1, error) {
	wire, _ := proto.Marshal(request)
	w.sawSecret = bytes.Contains(wire, []byte("host-only-secret"))
	return &cerebrov1.SourceWorkerDecodeResultV1{PlanId: request.GetPlan().GetPlanId(), PlanDigestSha256: request.GetPlan().GetPlanDigestSha256(), LogicalPageId: request.GetContext().GetLogicalPageId(), RequestIntentDigest: request.GetRequestIntentDigest(), ResultDigestSha256: strings.Repeat("2", 64), TenantId: request.GetContext().GetTenantId(), RuntimeId: request.GetContext().GetRuntimeId(), RuntimeGeneration: request.GetContext().GetRuntimeGeneration(), LeaseGeneration: request.GetContext().GetLeaseGeneration(), ObservedAtUnixMillis: request.GetContext().GetObservedAtUnixMillis(), Records: []*cerebrov1.SourceWorkerRecordV1{{ProviderId: "authorizationPolicy", EventId: "azure-authorization-policy-authorizationPolicy", OccurredAtUnixMillis: request.GetContext().GetObservedAtUnixMillis(), Attributes: map[string]string{"family": "authorization_policy"}, PayloadJson: []byte(`{"id":"authorizationPolicy"}`)}}}, nil
}
func (w *fakeWorker) SealPage(context.Context, PageProgramRequest) (*PageProgram, error) {
	return &PageProgram{TransitionDigest: strings.Repeat("3", 64), AdmittedRecords: []*cerebrov1.SourceWorkerRecordV1{{ProviderId: "authorizationPolicy"}}}, nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }
func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}
func mustURL(t *testing.T) *url.URL {
	t.Helper()
	parsed, err := url.Parse("https://graph.microsoft.com/v1.0/policies/authorizationPolicy")
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
func exactScope(plan *cerebrov1.SourceExecutionPlanV1, now time.Time) CredentialScope {
	return CredentialScope{TenantID: "tenant-1", RuntimeID: "runtime-1", SourceID: plan.GetSourceId(), FamilyID: plan.GetFamilyId(), PlanDigestSHA256: plan.GetPlanDigestSha256(), LogicalPageID: "logical-page-1", LeaseOwner: "owner-1", RuntimeGeneration: 7, LeaseGeneration: 11, LeaseExpiresAt: now.Add(time.Minute)}
}
