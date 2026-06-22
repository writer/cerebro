package agentauthoring

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/findingdsl"
)

type stubDraftModel struct {
	raw []byte
	req StructuredDraftRequest
	err error
}

func (m *stubDraftModel) DraftJSON(_ context.Context, request StructuredDraftRequest) ([]byte, error) {
	m.req = request
	return append([]byte(nil), m.raw...), m.err
}

func TestDraftPolicyRuleValidatesAndFormatsSchemaBoundDraft(t *testing.T) {
	rule := findingdsl.NewPolicyRule(findingdsl.NewPolicyRuleInput{
		ID:          "ai-generated-control",
		Name:        "AI Generated Control",
		Description: "Flags generated control evidence with a failed state.",
		Severity:    "medium",
		Conditions:  []string{`eq(path(resource, "encrypted"), false)`},
		Frameworks:  []findingdsl.PolicyFramework{{Name: "SOC2", Controls: []string{"CC6.1"}}},
	})
	raw, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	model := &stubDraftModel{raw: raw}
	result, err := (Service{Model: model}).DraftPolicyRule(context.Background(), PolicyRuleDraftRequest{Prompt: "draft a control rule"})
	if err != nil {
		t.Fatalf("DraftPolicyRule() error = %v", err)
	}
	if model.req.Kind != "policy_finding_rule" || !strings.Contains(model.req.SchemaJSON, "PolicyFindingRule") {
		t.Fatalf("model request = %#v, want policy rule schema-bound request", model.req)
	}
	if result.Rule.Metadata.ID != "ai-generated-control" {
		t.Fatalf("rule id = %q", result.Rule.Metadata.ID)
	}
	if !strings.Contains(string(result.YAML), "ai-generated-control") {
		t.Fatalf("formatted YAML missing rule id:\n%s", result.YAML)
	}
}

func TestDraftPolicyRuleRejectsInvalidDraft(t *testing.T) {
	raw, err := json.Marshal(findingdsl.PolicyFindingRule{APIVersion: findingdsl.APIVersion, Kind: findingdsl.KindPolicyFindingRule})
	if err != nil {
		t.Fatal(err)
	}
	result, err := (Service{Model: &stubDraftModel{raw: raw}}).DraftPolicyRule(context.Background(), PolicyRuleDraftRequest{Prompt: "draft"})
	if !errors.Is(err, ErrDraftValidationFail) {
		t.Fatalf("DraftPolicyRule() error = %v, want ErrDraftValidationFail", err)
	}
	if result == nil || len(result.Issues) == 0 {
		t.Fatalf("result issues = %#v, want validation issues", result)
	}
}

func TestDraftConnectorDefinitionClassifiesAndDryRunsSourcegen(t *testing.T) {
	definition := connectordefinitions.Definition{
		ID:          "tenant-a-demo",
		TenantID:    "tenant-a",
		SourceID:    "demoai",
		DisplayName: "Demo AI",
		Runtime:     connectordefinitions.RuntimeJSONAPI,
		Auth: connectordefinitions.AuthSpec{
			Model: "bearer_token",
			CredentialFields: []connectordefinitions.Field{
				{Key: "api_token", Secret: true, ReferenceOnly: true, Required: true},
			},
		},
		Transport: &connectordefinitions.TransportSpec{
			BaseURL:      "https://api.example.test",
			Verification: &connectordefinitions.VerificationSpec{Path: "/healthz"},
		},
		ResourceFamilies: []connectordefinitions.ResourceFamily{
			{
				ID:             "assets",
				Path:           "/v1/assets",
				Method:         "GET",
				RecordSelector: "$.assets[*]",
				IDField:        "id",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "demoai.assets",
					SchemaRef: "demoai/assets/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "asset",
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{
					{Type: "assets", Support: "full"},
				},
			},
		},
	}
	raw, err := json.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	result, err := (Service{Model: &stubDraftModel{raw: raw}, OutputDir: "/tmp/cerebro-agentauthoring-test"}).DraftConnectorDefinition(context.Background(), ConnectorDefinitionDraftRequest{Prompt: "draft connector"})
	if err != nil {
		t.Fatalf("DraftConnectorDefinition() error = %v", err)
	}
	if result.Report.Verdict != connectordefinitions.SupportVerdictSupported {
		t.Fatalf("verdict = %q", result.Report.Verdict)
	}
	if result.Plan == nil || !result.Plan.DryRun || len(result.Plan.Files) == 0 {
		t.Fatalf("sourcegen plan = %#v, want dry-run file plan", result.Plan)
	}
}
