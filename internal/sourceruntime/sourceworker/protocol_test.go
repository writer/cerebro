package sourceworker

import (
	"context"
	"os"
	"strings"
	"testing"

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
}

func TestProcessWorkerProtocol(t *testing.T) {
	path := strings.TrimSpace(os.Getenv("SOURCE_WORKER_BINARY"))
	if path == "" {
		t.Skip("SOURCE_WORKER_BINARY is not set")
	}
	worker := NewProcessWorker(path)
	plan := AzureAuthorizationPolicyPlan()
	request, err := worker.Plan(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if request.GetUrl() != "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" {
		t.Fatalf("worker URL = %s", request.GetUrl())
	}
	result, err := worker.Decode(context.Background(), &cerebrov1.SourceWorkerDecodeRequestV1{
		Plan: plan, StatusCode: 200, ResponseBody: []byte(exactGoAuthorizationPolicyResponse), LogicalPageId: "page-1", RequestIntentDigest: "intent-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.GetRecords()) != 1 || result.GetRecords()[0].GetProviderId() != "authorizationPolicy" {
		t.Fatalf("worker result = %#v", result)
	}
}
