package cloudidentitysource

import (
	"context"
	"strings"
	"testing"

	ci "github.com/writer/cerebro/internal/cloudidentity"
	"github.com/writer/cerebro/internal/cloudidentity/requirements"
	"github.com/writer/cerebro/internal/graphagent"
)

type stubStructuredClient struct {
	response []byte
	err      error
	lastReq  graphagent.StructuredJSONRequest
}

func (s *stubStructuredClient) DraftStructuredJSON(_ context.Context, req graphagent.StructuredJSONRequest) ([]byte, error) {
	s.lastReq = req
	if s.err != nil {
		return nil, s.err
	}
	return s.response, nil
}

func defsForTest() ci.Definitions {
	return ci.Definitions{Complete: true, Operations: []ci.OperationDefinition{
		{Provider: ci.AWS, Service: "s3", Operation: "GetObject", Permissions: []string{"s3:GetObject"}, DependenciesComplete: true},
	}}
}

func requestForTest() ci.InvestigationRequest {
	src := "package app\n\nimport (\n\t\"context\"\n\n\t\"github.com/aws/aws-sdk-go-v2/aws\"\n\t\"github.com/aws/aws-sdk-go-v2/service/s3\"\n)\n\nfunc run(ctx context.Context, cfg aws.Config) {\n\tclient := s3.NewFromConfig(cfg)\n\tclient.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(\"my-bucket\")})\n}\n"
	return ci.InvestigationRequest{
		Workload: ci.Workload{ID: "consumer-1", Service: "svc", Cluster: "prod", Namespace: "ns", Name: "app", Kind: "Deployment", ServiceAccount: "app-sa"},
		Repository: ci.Repository{
			Pin:   ci.SourcePin{Repository: "writer/app", Revision: "deadbeef", Exact: true},
			Files: []ci.SourceFile{{Path: "main.go", Content: []byte(src)}},
		},
		Definitions: defsForTest(),
	}
}

func TestInvestigateDecodesValidClaimsAndCorroboratesStaticFinding(t *testing.T) {
	client := &stubStructuredClient{response: []byte(`{"claims":[{"provider":"aws","service":"s3","operation":"GetObject","action":"s3:GetObject","resources":["*"],"citations":[{"path":"main.go","start_line":12,"end_line":12,"quote":"\tclient.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(\"my-bucket\")})"}]}]}`)}
	investigator, err := NewRequirementInvestigator(InvestigatorOptions{Client: client, Model: "test-model", TenantID: "tenant-a"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	inv, err := investigator.Investigate(context.Background(), requestForTest())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(inv.Requirements) != 1 || inv.Requirements[0].Operation != "GetObject" {
		t.Fatalf("want one GetObject requirement, got %+v", inv.Requirements)
	}
	if inv.Requirements[0].Resources[0] != "arn:aws:s3:::my-bucket/*" {
		t.Fatalf("independently-extracted resource must be used, not the model's wildcard claim: %+v", inv.Requirements[0])
	}
}

// TestInvestigateRejectsModelSpoofedValidationField simulates a model trying
// to set a trusted validation/promotion field directly on the response; the
// strict schema (no such field exists) plus DisallowUnknownFields decoding
// must reject the whole response rather than silently ignoring the extra
// field or trusting it.
func TestInvestigateRejectsModelSpoofedValidationField(t *testing.T) {
	client := &stubStructuredClient{response: []byte(`{"claims":[],"validation":{"scope_complete":true,"citations_verified":true}}`)}
	investigator, err := NewRequirementInvestigator(InvestigatorOptions{Client: client})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	inv, err := investigator.Investigate(context.Background(), requestForTest())
	if err != nil {
		t.Fatalf("Investigate must degrade gracefully, not hard-fail: %v", err)
	}
	var found bool
	for _, g := range inv.Validation.Gaps {
		if g.Code == requirements.GapModelResponseRejected {
			found = true
		}
	}
	if !found {
		t.Fatalf("want model_response_rejected gap when the model sends an unexpected top-level field, got %+v", inv.Validation.Gaps)
	}
	// The real, independently-verified static finding must still be present.
	if len(inv.Requirements) != 1 {
		t.Fatalf("static ground truth must survive a rejected model response, got %+v", inv.Requirements)
	}
}

func TestInvestigateRejectsClaimWithUnknownField(t *testing.T) {
	client := &stubStructuredClient{response: []byte(`{"claims":[{"provider":"aws","service":"s3","operation":"GetObject","action":"s3:GetObject","resources":["*"],"citations":[],"trusted":true}]}`)}
	investigator, err := NewRequirementInvestigator(InvestigatorOptions{Client: client})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	inv, err := investigator.Investigate(context.Background(), requestForTest())
	if err != nil {
		t.Fatalf("Investigate must degrade gracefully: %v", err)
	}
	var found bool
	for _, g := range inv.Validation.Gaps {
		if g.Code == requirements.GapModelResponseRejected {
			found = true
		}
	}
	if !found {
		t.Fatalf("a claim with an unexpected 'trusted' field must be rejected at decode time, got %+v", inv.Validation.Gaps)
	}
}

func TestInvestigateModelTransportErrorDegradesToStaticOnly(t *testing.T) {
	client := &stubStructuredClient{err: context.DeadlineExceeded}
	investigator, err := NewRequirementInvestigator(InvestigatorOptions{Client: client})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	inv, err := investigator.Investigate(context.Background(), requestForTest())
	if err != nil {
		t.Fatalf("a model transport error must not fail the whole investigation: %v", err)
	}
	if len(inv.Requirements) != 1 {
		t.Fatalf("static ground truth must still be returned on model failure, got %+v", inv.Requirements)
	}
}

func TestNewRequirementInvestigatorRequiresClient(t *testing.T) {
	if _, err := NewRequirementInvestigator(InvestigatorOptions{}); err == nil {
		t.Fatalf("want error when Client is nil")
	}
}

// TestInvestigatePromptNeverIncludesBinaryContent ensures a file containing
// a NUL byte (a conservative binary heuristic) is excluded from the prompt
// sent to the model.
func TestInvestigatePromptExcludesBinaryContent(t *testing.T) {
	client := &stubStructuredClient{response: []byte(`{"claims":[]}`)}
	investigator, err := NewRequirementInvestigator(InvestigatorOptions{Client: client})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	req := requestForTest()
	req.Repository.Files = append(req.Repository.Files, ci.SourceFile{Path: "blob.bin", Content: []byte{0x00, 0x01, 0x02}})
	if _, err := investigator.Investigate(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := client.lastReq.Prompt; strings.Contains(got, "blob.bin") {
		t.Fatalf("binary-looking file must never be forwarded into the model prompt")
	}
}
