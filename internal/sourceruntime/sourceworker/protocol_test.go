package sourceworker

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
)

func TestGeneratedAzurePlanMatchesCatalogCompiler(t *testing.T) {
	entry, ok, err := connectorcatalog.BuiltinEntry("azure")
	if err != nil || !ok {
		t.Fatalf("BuiltinEntry(azure) = ok %v, err %v", ok, err)
	}
	compiled, err := connectordefinitions.CompileSourceExecutionPlanV1(entry.Definition, "authorization_policy")
	if err != nil {
		t.Fatal(err)
	}
	if generated := AzureAuthorizationPolicyPlan(); !proto.Equal(generated, compiled) {
		t.Fatalf("generated plan = %#v, compiled = %#v", generated, compiled)
	}
	wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(compiled)
	if err != nil {
		t.Fatal(err)
	}
	hexFixture, err := os.ReadFile("../../../proto/cerebro/v1/testdata/azure_authorization_policy_plan_v1.hex")
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := hex.DecodeString(strings.TrimSpace(string(hexFixture)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, fixture) {
		t.Fatal("canonical Go plan wire fixture is stale")
	}
}

func TestProcessWorkerProtocol(t *testing.T) {
	path := strings.TrimSpace(os.Getenv("SOURCE_WORKER_BINARY"))
	if path == "" {
		t.Skip("SOURCE_WORKER_BINARY is not set")
	}
	worker := NewProcessWorker(path)
	plan := AzureAuthorizationPolicyPlan()
	now := time.Now().UTC()
	scope := exactScope(plan, now)
	request, err := worker.Plan(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if request.GetUrl() != "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" {
		t.Fatalf("worker URL = %s", request.GetUrl())
	}
	receipt := exactReceipt(plan, scope, []byte(exactGoAuthorizationPolicyResponse))
	result, err := worker.Decode(context.Background(), &cerebrov1.SourceWorkerDecodeRequestV1{
		Plan: plan, StatusCode: 200, ResponseBody: []byte(exactGoAuthorizationPolicyResponse), LogicalPageId: scope.LogicalPageID, RequestIntentDigest: scope.RequestIntentDigest, Receipt: receipt.protobuf(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.GetRecords()) != 1 || result.GetRecords()[0].GetProviderId() != "authorizationPolicy" {
		t.Fatalf("worker result = %#v", result)
	}
	if err := validateWorkerResult(plan, scope, receipt, result); err != nil {
		t.Fatalf("worker result contract: %v", err)
	}
}

func TestWorkerStderrClassesRemainTypedAndBounded(t *testing.T) {
	for stderr, want := range map[string]error{
		"source_worker.invalid_provider_response: bad JSON": ErrProviderMalformedResponse,
		"source_worker.response_too_large: over bound": ErrProviderResponseTooLarge,
		"source_worker.invalid_plan: mismatch": ErrWorkerContract,
		"arbitrary process failure with private detail": ErrWorkerInternal,
	} {
		if err := classifyWorkerFailure(stderr); !errors.Is(err, want) {
			t.Fatalf("classifyWorkerFailure(%q) = %v, want %v", stderr, err, want)
		}
	}
}
