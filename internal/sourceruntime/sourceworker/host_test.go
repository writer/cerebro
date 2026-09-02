package sourceworker

import (
	"bytes"
	"context"
	"encoding/base64"
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
	worker, scope := newFakeWorker(), exactScope(plan, now)
	scope.PublicConfig = map[string]string{"insights_base_url": "https://api.jumpcloud.com/insights/directory/v1"}
	scope.PriorTerminalWatermarkUnixMillis, scope.PriorCheckpoint = 1_782_000_000_000, "audit-terminal-1"
	host := NewHost(worker, "opaque-reference", []byte(secret), now.Add(time.Minute))
	host.now, host.client = func() time.Time { return now }, &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer "+secret {
			t.Fatal("host did not apply the redeemed credential")
		}
		result := response(http.StatusOK)
		for name, value := range map[string]string{"X-Result-Count": "2", "X-Limit": "2", "X-Search_after": `{"id":"event-2"}`, "Retry-After": "30", "Set-Cookie": "secret-cookie", "Www-Authenticate": "secret-challenge", "X-Api-Key": "secret"} {
			result.Header.Set(name, value)
		}
		return result, nil
	})}
	output, err := host.Execute(context.Background(), ExecutionInput{Plan: plan, CredentialReference: "opaque-reference", PageNumber: 1, Scope: scope})
	if err != nil {
		t.Fatal(err)
	}
	if worker.sawSecret || host.credential != nil || output.Program == nil {
		t.Fatalf("secret crossed boundary or Rust did not seal the page: %#v", output.Program)
	}
	if encoded := fmt.Sprintf("%+v", output.Receipt); strings.Contains(encoded, secret) || strings.Contains(encoded, "opaque-reference") {
		t.Fatal("safe receipt leaked credential material")
	}
	if got := worker.planEnvelope.GetMetadata(); got.GetPriorCheckpoint() != scope.PriorCheckpoint || got.GetPriorTerminalWatermarkUnixMillis() != scope.PriorTerminalWatermarkUnixMillis || got.GetPublicConfig()["insights_base_url"] == "" {
		t.Fatalf("planning metadata was dropped: %#v", got)
	}
	for _, name := range []string{"x-result-count", "x-limit", "x-search_after", "retry-after"} {
		if worker.decodeEnvelope.GetResponseHeaders()[name] == "" {
			t.Fatalf("safe response header %q was dropped", name)
		}
	}
	for _, name := range []string{"set-cookie", "www-authenticate", "x-api-key"} {
		if _, ok := worker.decodeEnvelope.GetResponseHeaders()[name]; ok {
			t.Fatalf("sensitive response header %q crossed the wire", name)
		}
	}
}

func TestHostRejectsOriginEscapeBeforeRedemption(t *testing.T) {
	plan, now, worker := AzureAuthorizationPolicyPlan(), time.Now().UTC(), newFakeWorker()
	worker.endpoint = "https://example.com/escape"
	host := NewHost(worker, "opaque", []byte("secret"), now.Add(time.Minute))
	host.client, host.now = &http.Client{}, func() time.Time { return now }
	if _, err := host.Execute(context.Background(), ExecutionInput{Plan: plan, CredentialReference: "opaque", PageNumber: 1, Scope: exactScope(plan, now)}); err == nil || host.credential == nil {
		t.Fatalf("Execute() error = %v, credential consumed before validation", err)
	}
}

func TestHostClassifiesProviderAndNetworkBounds(t *testing.T) {
	for status, want := range map[int]error{401: ErrProviderAuthentication, 403: ErrProviderPermission, 429: ErrProviderRateLimited} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			plan, now := AzureAuthorizationPolicyPlan(), time.Now().UTC()
			host := NewHost(newFakeWorker(), "opaque", []byte("secret"), now.Add(time.Minute))
			host.now, host.client = func() time.Time { return now }, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return response(status), nil })}
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
	return &cerebrov1.SourceWorkerExecutionContextV1{TenantId: request.TenantID, RuntimeId: request.RuntimeID, LogicalPageId: "logical-page-1", RuntimeGeneration: request.RuntimeGeneration, LeaseGeneration: request.LeaseGeneration, ObservedAtUnixMillis: request.ObservedAtUnixMillis}, nil
}
func (w *fakeWorker) PlanV2(_ context.Context, envelope *cerebrov1.SourceWorkerPlanEnvelopeV2) (*cerebrov1.SourceWorkerHTTPExecutionV2, error) {
	w.planEnvelope = proto.Clone(envelope).(*cerebrov1.SourceWorkerPlanEnvelopeV2)
	request := envelope.GetRequest()
	plan := request.GetPlan()
	planned := &cerebrov1.SourceWorkerHTTPRequestV1{PlanId: plan.GetPlanId(), Method: w.method, Url: w.endpoint, Accept: "application/json", MaxResponseBytes: plan.GetMaxResponseBytes(), PlanDigestSha256: plan.GetPlanDigestSha256(), RequestIntentDigest: strings.Repeat("1", 64)}
	execution := &cerebrov1.SourceWorkerHTTPExecutionV2{Request: planned, Body: w.body, DeclaredHeaders: w.declaredHeaders, CredentialOperation: w.credentialOperation, AllowedOrigin: plan.GetOrigin()}
	execution.ExecutionIntentDigestSha256 = strings.Repeat("4", 64)
	return execution, nil
}
func (w *fakeWorker) DecodeV2(_ context.Context, envelope *cerebrov1.SourceWorkerDecodeEnvelopeV2) (*cerebrov1.SourceWorkerDecodeOutputV2, error) {
	w.decodeEnvelope = proto.Clone(envelope).(*cerebrov1.SourceWorkerDecodeEnvelopeV2)
	switch envelope.GetRequest().GetStatusCode() {
	case http.StatusUnauthorized:
		return nil, ErrProviderAuthentication
	case http.StatusForbidden:
		return nil, ErrProviderPermission
	case http.StatusTooManyRequests:
		return nil, ErrProviderRateLimited
	}
	request := envelope.GetRequest()
	wire, _ := proto.Marshal(request)
	w.sawSecret = bytes.Contains(wire, []byte("host-only-secret"))
	context := request.GetContext()
	result := &cerebrov1.SourceWorkerDecodeResultV1{PlanId: request.GetPlan().GetPlanId(), PlanDigestSha256: request.GetPlan().GetPlanDigestSha256(), LogicalPageId: context.GetLogicalPageId(), RequestIntentDigest: request.GetRequestIntentDigest(), ResultDigestSha256: strings.Repeat("2", 64), TenantId: context.GetTenantId(), RuntimeId: context.GetRuntimeId(), RuntimeGeneration: context.GetRuntimeGeneration(), LeaseGeneration: context.GetLeaseGeneration(), ObservedAtUnixMillis: context.GetObservedAtUnixMillis(), Records: []*cerebrov1.SourceWorkerRecordV1{{ProviderId: "authorizationPolicy", EventId: "azure-authorization-policy-authorizationPolicy", OccurredAtUnixMillis: context.GetObservedAtUnixMillis(), Attributes: map[string]string{"family": "authorization_policy"}, PayloadJson: []byte(`{"id":"authorizationPolicy"}`)}}}
	return &cerebrov1.SourceWorkerDecodeOutputV2{
		Receipt: &cerebrov1.SourceWorkerSafeReceiptV1{
			PlanDigestSha256: envelope.GetRequest().GetPlan().GetPlanDigestSha256(),
			LogicalPageId:    context.GetLogicalPageId(), RequestIntentDigest: envelope.GetRequest().GetRequestIntentDigest(),
			RuntimeGeneration: context.GetRuntimeGeneration(), LeaseGeneration: context.GetLeaseGeneration(),
			CredentialOperation: w.credentialOperation, StatusCode: envelope.GetRequest().GetStatusCode(),
			TenantId: context.GetTenantId(), RuntimeId: context.GetRuntimeId(), ObservedAtUnixMillis: context.GetObservedAtUnixMillis(),
		},
		Result: result,
	}, nil
}
func (w *fakeWorker) SealPage(context.Context, PageProgramRequest) (*PageProgram, error) {
	return &PageProgram{TransitionDigest: strings.Repeat("3", 64), AdmittedRecords: []*cerebrov1.SourceWorkerRecordV1{{ProviderId: "authorizationPolicy"}}}, nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }
func response(status int) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}
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
		return response(http.StatusOK), nil
	})}
	if _, err := host.Execute(context.Background(), ExecutionInput{Plan: plan, CredentialReference: "opaque", PageNumber: 1, Scope: exactScope(plan, now)}); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialHeaderAppliesOnlyTheClosedSentinelOneScheme(t *testing.T) {
	header, value, err := credentialHeader("sentinelone.api_token", []byte("synthetic-secret"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(value)
	if header != "Authorization" || string(value) != "ApiToken synthetic-secret" {
		t.Fatal("SentinelOne credential operation did not produce the exact provider scheme")
	}
	if _, _, err := credentialHeader("sentinelone.bearer", []byte("synthetic-secret")); !errors.Is(err, ErrWorkerContract) {
		t.Fatalf("unregistered credential operation error = %v, want ErrWorkerContract", err)
	}
}

func TestCredentialHeaderAppliesGenericXAPIKeyOnlyInsideTheTrustedHost(t *testing.T) {
	header, value, err := credentialHeader("source.x_api_key", []byte("synthetic-secret"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(value)
	if header != "X-Api-Key" || string(value) != "synthetic-secret" {
		t.Fatal("generic x-api-key operation did not produce the exact host-owned header")
	}
}

func TestCredentialHeaderAppliesAbuseIPDBKeyOnlyInsideTheTrustedHost(t *testing.T) {
	header, value, err := credentialHeader("abuseipdb.key", []byte("synthetic-secret"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(value)
	if header != "Key" || string(value) != "synthetic-secret" {
		t.Fatal("abuseipdb key operation did not produce the exact host-owned header")
	}
	if _, _, err := credentialHeader("abuseipdb.bearer", []byte("synthetic-secret")); !errors.Is(err, ErrWorkerContract) {
		t.Fatalf("unregistered abuseipdb operation error = %v, want ErrWorkerContract", err)
	}
}

func TestCredentialHeaderAppliesOnlyClosedAnthropicSchemes(t *testing.T) {
	for _, operation := range []string{"anthropic.admin_x_api_key", "anthropic.compliance_x_api_key"} {
		header, value, err := credentialHeader(operation, []byte("synthetic-secret"))
		if err != nil {
			t.Fatal(err)
		}
		if header != "X-Api-Key" || string(value) != "synthetic-secret" {
			t.Fatalf("%s header = %q, value = %q", operation, header, value)
		}
		clear(value)
	}
	header, value, err := credentialHeader("anthropic.org_admin_bearer", []byte("synthetic-secret"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(value)
	if header != "Authorization" || string(value) != "Bearer synthetic-secret" {
		t.Fatalf("Anthropic bearer header = %q, value = %q", header, value)
	}
	if err := validateDeclaredHeaders(map[string]string{"anthropic-version": "2023-06-01"}); err != nil {
		t.Fatalf("Anthropic public version header was rejected: %v", err)
	}
	if _, _, err := credentialHeader("anthropic.api_key", []byte("synthetic-secret")); !errors.Is(err, ErrWorkerContract) {
		t.Fatalf("unregistered Anthropic credential operation error = %v", err)
	}
}

func TestCredentialHeaderAppliesOnlyTheClosedOpenAIScheme(t *testing.T) {
	header, value, err := credentialHeader("openai.admin_api_key_bearer", []byte("synthetic-secret"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(value)
	if header != "Authorization" || string(value) != "Bearer synthetic-secret" {
		t.Fatalf("OpenAI header = %q, value = %q", header, value)
	}
	if _, _, err := credentialHeader("openai.api_key", []byte("synthetic-secret")); !errors.Is(err, ErrWorkerContract) {
		t.Fatalf("unregistered OpenAI credential operation error = %v", err)
	}
}

func TestCredentialHeaderAppliesOnlyTheClosedDiscordScheme(t *testing.T) {
	header, value, err := credentialHeader("discord.bot_token", []byte("synthetic-secret"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(value)
	if header != "Authorization" || string(value) != "Bot synthetic-secret" {
		t.Fatal("Discord credential operation did not produce the exact provider scheme")
	}
	if _, _, err := credentialHeader("discord.bearer", []byte("synthetic-secret")); !errors.Is(err, ErrWorkerContract) {
		t.Fatalf("unregistered credential operation error = %v, want ErrWorkerContract", err)
	}
}

func TestCredentialHeaderAppliesOnlyTheClosedTwilioScheme(t *testing.T) {
	header, value, err := credentialHeader("twilio.basic", []byte("synthetic-basic-value"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(value)
	if header != "Authorization" || string(value) != "Basic synthetic-basic-value" {
		t.Fatal("Twilio credential operation did not produce the exact provider scheme")
	}
	if _, _, err := credentialHeader("twilio.bearer", []byte("synthetic-basic-value")); !errors.Is(err, ErrWorkerContract) {
		t.Fatalf("unregistered credential operation error = %v, want ErrWorkerContract", err)
	}
}

func TestCredentialHeaderAppliesOnlyTheClosedPagerDutyScheme(t *testing.T) {
	header, value, err := credentialHeader("pagerduty.token", []byte("synthetic-token"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(value)
	if header != "Authorization" || string(value) != "Token token=synthetic-token" {
		t.Fatal("PagerDuty credential operation did not produce the exact provider scheme")
	}
	if _, _, err := credentialHeader("pagerduty.bearer", []byte("synthetic-token")); !errors.Is(err, ErrWorkerContract) {
		t.Fatalf("unregistered credential operation error = %v, want ErrWorkerContract", err)
	}
}

func TestCredentialHeaderAppliesGeminiKeyOnlyInsideTheTrustedHost(t *testing.T) {
	header, value, err := credentialHeader("google.api_key_header", []byte("synthetic-api-key"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(value)
	if header != "X-Goog-Api-Key" || string(value) != "synthetic-api-key" {
		t.Fatal("Gemini credential operation did not produce the exact provider header")
	}
	if _, _, err := credentialHeader("google.api_key_query", []byte("synthetic-api-key")); !errors.Is(err, ErrWorkerContract) {
		t.Fatalf("query credential operation error = %v, want ErrWorkerContract", err)
	}
}

func TestCredentialHeaderAppliesLangfuseBasicOnlyInsideTheTrustedHost(t *testing.T) {
	header, value, err := credentialHeader("langfuse.basic", []byte("synthetic-basic-value"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(value)
	if header != "Authorization" || string(value) != "Basic synthetic-basic-value" {
		t.Fatalf("Langfuse header = %q, value = %q", header, value)
	}
}

func TestCredentialHeaderAppliesPortableAIProviderSchemesOnlyInsideTheTrustedHost(t *testing.T) {
	for name, test := range map[string]struct {
		operation, header, value string
	}{
		"ElevenLabs":        {"elevenlabs.xi_api_key", "Xi-Api-Key", "synthetic-secret"},
		"LangSmith":         {"langsmith.x_api_key", "X-Api-Key", "synthetic-secret"},
		"Microsoft Foundry": {"microsoft_foundry.api_key", "Api-Key", "synthetic-secret"},
		"Pinecone":          {"pinecone.api_key", "Api-Key", "synthetic-secret"},
		"Qdrant":            {"qdrant.api_key", "Authorization", "apikey synthetic-secret"},
	} {
		t.Run(name, func(t *testing.T) {
			header, value, err := credentialHeader(test.operation, []byte("synthetic-secret"))
			if err != nil {
				t.Fatal(err)
			}
			defer clear(value)
			if header != test.header || string(value) != test.value {
				t.Fatalf("credential header = (%q, %q), want (%q, %q)", header, value, test.header, test.value)
			}
		})
	}
	if err := validateDeclaredHeaders(map[string]string{
		"x-organization-id":      "org-1",
		"x-pinecone-api-version": "2025-10",
		"x-tenant-id":            "workspace-1",
	}); err != nil {
		t.Fatalf("portable AI public headers were rejected: %v", err)
	}
}

func TestAWSBedrockSigningStaysInsideTheTrustedHostAndBindsTheOrigin(t *testing.T) {
	credential := []byte(base64.RawStdEncoding.EncodeToString([]byte("AKIDEXAMPLE")) + "." + base64.RawStdEncoding.EncodeToString([]byte("synthetic-secret"))) // #nosec G101 -- synthetic signer fixture.
	request, err := http.NewRequest(http.MethodGet, "https://bedrock.us-east-1.amazonaws.com/foundation-models", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signAWSBedrockRequest(context.Background(), request, credential, time.Date(2026, time.August, 24, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	authorization := request.Header.Get("Authorization")
	if !strings.Contains(authorization, "AWS4-HMAC-SHA256") || !strings.Contains(authorization, "Credential=AKIDEXAMPLE/20260824/us-east-1/bedrock/aws4_request") {
		t.Fatalf("AWS authorization scope = %q", authorization)
	}
	if strings.Contains(request.URL.String(), "AKIDEXAMPLE") || strings.Contains(request.URL.String(), "synthetic-secret") {
		t.Fatal("AWS credential entered the request URL")
	}
	wrongOrigin, _ := http.NewRequest(http.MethodGet, "https://s3.us-east-1.amazonaws.com/", nil)
	if err := signAWSBedrockRequest(context.Background(), wrongOrigin, credential, time.Now()); !errors.Is(err, ErrProviderEgress) {
		t.Fatalf("wrong AWS origin error = %v, want ErrProviderEgress", err)
	}
	if err := signAWSBedrockRequest(context.Background(), request, []byte("malformed"), time.Now()); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("malformed AWS credential error = %v, want ErrCredentialUnavailable", err)
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
	headers.Set("X-Result-Count", strings.Repeat("x", maxSafeHeaderValueBytes+1))
	if _, err := safeResponseHeaders(headers); !errors.Is(err, ErrInvalidExecution) {
		t.Fatalf("safeResponseHeaders() error = %v, want header value bound", err)
	}
}
