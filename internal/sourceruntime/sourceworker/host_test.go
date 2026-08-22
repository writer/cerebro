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
			_, _, _, err := host.get(context.Background(), mustURL(t), "GET", "application/json", nil, nil, 16, "source.bearer", []byte("secret"))
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
	endpoint            string
	method              string
	body                []byte
	declaredHeaders     map[string]string
	credentialOperation string
	sawSecret           bool
	contextRequest      ContextRequest
	planEnvelope        *cerebrov1.SourceWorkerPlanEnvelopeV2
	decodeEnvelope      *cerebrov1.SourceWorkerDecodeEnvelopeV2
}

func newFakeWorker() *fakeWorker {
	return &fakeWorker{endpoint: "https://graph.microsoft.com/v1.0/policies/authorizationPolicy", method: http.MethodGet, credentialOperation: "source.bearer"}
}
func (w *fakeWorker) Compile(context.Context, SelectionRequest) (*cerebrov1.SourceExecutionPlanV1, error) {
	return AzureAuthorizationPolicyPlan(), nil
}
func (w *fakeWorker) Context(_ context.Context, request ContextRequest) (*cerebrov1.SourceWorkerExecutionContextV1, error) {
	w.contextRequest = request
	return &cerebrov1.SourceWorkerExecutionContextV1{TenantId: request.TenantID, RuntimeId: request.RuntimeID, LogicalPageId: "logical-page-1", RuntimeGeneration: request.RuntimeGeneration, LeaseGeneration: request.LeaseGeneration, ObservedAtUnixMillis: request.ObservedAtUnixMillis}, nil
}
func (w *fakeWorker) PlanV2(ctx context.Context, envelope *cerebrov1.SourceWorkerPlanEnvelopeV2) (*cerebrov1.SourceWorkerHTTPExecutionV2, error) {
	w.planEnvelope = proto.Clone(envelope).(*cerebrov1.SourceWorkerPlanEnvelopeV2)
	request, err := w.Plan(ctx, envelope.GetRequest())
	if err != nil {
		return nil, err
	}
	execution := &cerebrov1.SourceWorkerHTTPExecutionV2{Request: request, Body: w.body, DeclaredHeaders: w.declaredHeaders, CredentialOperation: w.credentialOperation}
	execution.ExecutionIntentDigestSha256 = executionIntentSHA256(envelope.GetMetadata(), execution)
	return execution, nil
}
func (w *fakeWorker) Plan(_ context.Context, request *cerebrov1.SourceWorkerPlanRequestV1) (*cerebrov1.SourceWorkerHTTPRequestV1, error) {
	result := &cerebrov1.SourceWorkerHTTPRequestV1{PlanId: request.GetPlan().GetPlanId(), Method: w.method, Url: w.endpoint, Accept: "application/json", MaxResponseBytes: request.GetPlan().GetMaxResponseBytes(), PlanDigestSha256: request.GetPlan().GetPlanDigestSha256(), RequestIntentDigest: strings.Repeat("1", 64)}
	return result, nil
}
func (w *fakeWorker) Decode(_ context.Context, request *cerebrov1.SourceWorkerDecodeRequestV1) (*cerebrov1.SourceWorkerDecodeResultV1, error) {
	wire, _ := proto.Marshal(request)
	w.sawSecret = bytes.Contains(wire, []byte("host-only-secret"))
	return &cerebrov1.SourceWorkerDecodeResultV1{PlanId: request.GetPlan().GetPlanId(), PlanDigestSha256: request.GetPlan().GetPlanDigestSha256(), LogicalPageId: request.GetContext().GetLogicalPageId(), RequestIntentDigest: request.GetRequestIntentDigest(), ResultDigestSha256: strings.Repeat("2", 64), TenantId: request.GetContext().GetTenantId(), RuntimeId: request.GetContext().GetRuntimeId(), RuntimeGeneration: request.GetContext().GetRuntimeGeneration(), LeaseGeneration: request.GetContext().GetLeaseGeneration(), ObservedAtUnixMillis: request.GetContext().GetObservedAtUnixMillis(), Records: []*cerebrov1.SourceWorkerRecordV1{{ProviderId: "authorizationPolicy", EventId: "azure-authorization-policy-authorizationPolicy", OccurredAtUnixMillis: request.GetContext().GetObservedAtUnixMillis(), Attributes: map[string]string{"family": "authorization_policy"}, PayloadJson: []byte(`{"id":"authorizationPolicy"}`)}}}, nil
}
func (w *fakeWorker) DecodeV2(ctx context.Context, envelope *cerebrov1.SourceWorkerDecodeEnvelopeV2) (*cerebrov1.SourceWorkerDecodeResultV1, error) {
	w.decodeEnvelope = proto.Clone(envelope).(*cerebrov1.SourceWorkerDecodeEnvelopeV2)
	switch envelope.GetRequest().GetStatusCode() {
	case http.StatusUnauthorized:
		return nil, ErrProviderAuthentication
	case http.StatusForbidden:
		return nil, ErrProviderPermission
	case http.StatusTooManyRequests:
		return nil, ErrProviderRateLimited
	}
	return w.Decode(ctx, envelope.GetRequest())
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

func TestHostCarriesPublicResumeMetadataAndRedactedResponseHeaders(t *testing.T) {
	plan, now := AzureAuthorizationPolicyPlan(), time.Now().UTC()
	worker, scope := newFakeWorker(), exactScope(plan, now)
	scope.PublicConfig = map[string]string{"insights_base_url": "https://api.jumpcloud.com/insights/directory/v1"}
	scope.PriorTerminalWatermarkUnixMillis = 1_782_000_000_000
	scope.PriorCheckpoint = "audit-terminal-1"
	host := NewHost(worker, "opaque", []byte("secret"), now.Add(time.Minute))
	host.now, host.client = func() time.Time { return now }, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		result := response(http.StatusOK, `{}`)
		result.Header.Set("X-Result-Count", "2")
		result.Header.Set("X-Limit", "2")
		result.Header.Set("X-Search_after", `{"id":"event-2"}`)
		result.Header.Set("Retry-After", "30")
		result.Header.Set("Set-Cookie", "secret-cookie")
		result.Header.Set("Www-Authenticate", "secret-challenge")
		result.Header.Set("X-Api-Key", "secret")
		return result, nil
	})}
	if _, err := host.Execute(context.Background(), ExecutionInput{Plan: plan, CredentialReference: "opaque", PageNumber: 1, Scope: scope}); err != nil {
		t.Fatal(err)
	}
	if worker.contextRequest.PriorTerminalWatermarkUnixMillis != scope.PriorTerminalWatermarkUnixMillis || worker.contextRequest.PriorCheckpoint != scope.PriorCheckpoint {
		t.Fatalf("context metadata was dropped: %#v", worker.contextRequest)
	}
	if got := worker.planEnvelope.GetMetadata(); got.GetPriorCheckpoint() != scope.PriorCheckpoint || got.GetPublicConfig()["insights_base_url"] == "" {
		t.Fatalf("planning metadata was dropped: %#v", got)
	}
	headers := worker.decodeEnvelope.GetResponseHeaders()
	for _, name := range []string{"x-result-count", "x-limit", "x-search_after", "retry-after"} {
		if headers[name] == "" {
			t.Fatalf("safe response header %q was dropped: %#v", name, headers)
		}
	}
	for _, name := range []string{"set-cookie", "www-authenticate", "x-api-key"} {
		if _, ok := headers[name]; ok {
			t.Fatalf("sensitive response header %q crossed the wire", name)
		}
	}
}

func TestHostCarriesCredentialFreeBodyAndHeadersBeforeApplyingJumpCloudAuth(t *testing.T) {
	plan, now := AzureAuthorizationPolicyPlan(), time.Now().UTC()
	plan.Method = http.MethodPost
	worker := newFakeWorker()
	worker.method = http.MethodPost
	worker.body = []byte(`{"service":["all"],"start_time":"2026-06-01T00:00:00Z"}`)
	worker.declaredHeaders = map[string]string{"content-type": "application/json", "x-org-id": "org-1"}
	worker.credentialOperation = "jumpcloud.x_api_key"
	host := NewHost(worker, "opaque", []byte("jumpcloud-secret"), now.Add(time.Minute))
	host.now, host.client = func() time.Time { return now }, &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("X-Api-Key") != "jumpcloud-secret" || request.Header.Get("Authorization") != "" {
			t.Fatal("host did not apply only the closed JumpCloud credential operation")
		}
		if request.Header.Get("Content-Type") != "application/json" || request.Header.Get("X-Org-Id") != "org-1" {
			t.Fatalf("declared headers were not preserved: %#v", request.Header)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil || !bytes.Equal(body, worker.body) {
			t.Fatalf("request body = %q, error = %v", body, err)
		}
		return response(http.StatusOK, `{}`), nil
	})}
	if _, err := host.Execute(context.Background(), ExecutionInput{Plan: plan, CredentialReference: "opaque", PageNumber: 1, Scope: exactScope(plan, now)}); err != nil {
		t.Fatal(err)
	}
}

func TestSafeResponseHeadersRedactsAndBounds(t *testing.T) {
	headers := http.Header{
		"X-Result-Count": {"2"}, "X-Limit": {"2"}, "X-Search_after": {`{"id":"event-2"}`}, "Retry-After": {"30"},
		"Authorization": {"secret"}, "Set-Cookie": {"secret"}, "Www-Authenticate": {"secret"}, "X-Api-Key": {"secret"},
	}
	safe, err := safeResponseHeaders(headers)
	if err != nil {
		t.Fatal(err)
	}
	if len(safe) != 4 {
		t.Fatalf("safe headers = %#v, want four JumpCloud headers", safe)
	}
	tooMany := make(http.Header)
	for index := 0; index <= maxSafeHeaderEntries; index++ {
		tooMany.Set(fmt.Sprintf("X-Next-%d", index), "value")
	}
	if _, err := safeResponseHeaders(tooMany); !errors.Is(err, ErrProviderResponseTooLarge) {
		t.Fatalf("safeResponseHeaders() error = %v, want response bound", err)
	}
}
