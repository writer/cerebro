package agentauthoring

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/findingdsl"
	"github.com/writer/cerebro/internal/ports"
	policyauthor "github.com/writer/cerebro/internal/testauthor/policy"
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

func TestDraftPolicyBundleAuthorsRunnableTestsAndProof(t *testing.T) {
	rule := findingdsl.NewPolicyRule(findingdsl.NewPolicyRuleInput{ID: "agent-public-bucket", Name: "Agent public bucket", Description: "Flags public buckets drafted by the agent.", Severity: "high", Conditions: []string{`cmp_eq(path(resource, "public"), true)`, `cmp_eq(path(resource, "approved"), false)`}, Frameworks: []findingdsl.PolicyFramework{{Name: "CIS", Controls: []string{"2.1.5"}}}})
	raw, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	model := &stubDraftModel{raw: raw}
	result, err := (Service{Model: model}).DraftPolicyBundle(context.Background(), PolicyBundleDraftRequest{Prompt: "author a policy for public buckets", Domain: "aws", Context: map[string]any{"source_kind": "aws.s3.bucket"}})
	if err != nil {
		t.Fatal(err)
	}
	if model.req.Kind != "policy_finding_rule" || model.req.Context["source_kind"] != "aws.s3.bucket" || model.req.Context["test_author_contract"] == nil {
		t.Fatalf("model request = %#v", model.req)
	}
	contract, ok := model.req.Context["test_author_contract"].(map[string]any)
	if !ok || contract["grounding"] == nil {
		t.Fatalf("test author contract grounding = %#v, want source-backed redaction and causality requirements", contract["grounding"])
	}
	if result.PolicyPath != "policies/aws/agent-public-bucket.yaml" || result.TestPath != "policies/aws/agent-public-bucket.test.yaml" {
		t.Fatalf("paths = %q %q", result.PolicyPath, result.TestPath)
	}
	if len(result.Suite.Cases) != 2 || len(result.Proof.Receipts) != 2 || !result.Proof.Receipts[0].Passed || !result.Proof.Receipts[1].Passed {
		t.Fatalf("bundle = %#v", result)
	}
}

func TestDraftPolicyBundleRejectsPolicyWithoutSafeFixtureContract(t *testing.T) {
	rule := findingdsl.NewPolicyRule(findingdsl.NewPolicyRuleInput{ID: "agent-complex", Name: "Agent complex", Description: "Complex agent policy.", Severity: "high", Conditions: []string{`cmp_eq(path(resource, "state"), path(resource, "expected_state"))`}, Frameworks: []findingdsl.PolicyFramework{{Name: "CIS", Controls: []string{"1"}}}})
	raw, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	result, err := (Service{Model: &stubDraftModel{raw: raw}}).DraftPolicyBundle(context.Background(), PolicyBundleDraftRequest{Prompt: "author complex policy", Domain: "aws"})
	if !errors.Is(err, ErrDraftValidationFail) || result != nil {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
}

func TestDraftPolicyBundleAuthorsAndExecutesGraphEvidence(t *testing.T) {
	rule := findingdsl.NewPolicyRule(findingdsl.NewPolicyRuleInput{
		ID: "agent-graph-path", Name: "Agent graph path", Description: "Finds a causal graph path.", Severity: "high",
		Graph: findingdsl.PolicyRuleGraphFinding{
			Query: `MATCH (actor:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'acted_on'}]->(task:Entity)-[:RELATION {relation: 'depends_on'}]->(definition:Entity)-[:RELATION {relation: 'runs_as'}]->(role:Entity)
RETURN definition.urn AS primary_urn, definition.urn + '|' + role.urn AS fingerprint_key, 'causal path' AS summary, [actor.urn, task.urn, definition.urn, role.urn] AS resource_urns, [{urn: actor.urn}, {urn: task.urn}, {urn: definition.urn}, {urn: role.urn}] AS evidence LIMIT $row_limit`,
			RowLimit: 10, RequiredColumns: []string{"primary_urn", "fingerprint_key", "summary", "resource_urns"},
		}, Frameworks: []findingdsl.PolicyFramework{{Name: "SOC 2", Controls: []string{"CC6.1"}}},
	})
	raw, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	evidence := &policyauthor.GraphEvidence{
		Nodes: []policyauthor.GraphEvidenceNode{
			{ID: "private-actor", SourceID: "aws", EntityType: "aws.assumed_role_session"},
			{ID: "private-task", SourceID: "aws", EntityType: "aws.ecs.task"},
			{ID: "private-definition", SourceID: "aws", EntityType: "aws.ecs.task_definition", Attributes: map[string]string{"has_secret_bindings": "true"}},
			{ID: "private-role", SourceID: "aws", EntityType: "aws.role"},
		},
		Edges: []policyauthor.GraphEvidenceEdge{
			{FromID: "private-actor", ToID: "private-task", SourceID: "aws", Relation: "acted_on"},
			{FromID: "private-task", ToID: "private-definition", SourceID: "aws", Relation: "depends_on"},
			{FromID: "private-definition", ToID: "private-role", SourceID: "aws", Relation: "runs_as"},
		},
		CriticalEdge:    policyauthor.GraphEvidenceEdgeRef{FromID: "private-definition", ToID: "private-role", Relation: "runs_as"},
		EvidenceNodeIDs: []string{"private-actor", "private-task", "private-definition", "private-role"},
	}
	store := &agentGraphStore{}
	model := &stubDraftModel{raw: raw}
	result, err := (Service{Model: model, PolicyGraphStore: store}).DraftPolicyBundle(context.Background(), PolicyBundleDraftRequest{
		Prompt: "author a causal graph policy", Domain: "aws", GraphEvidence: evidence,
	})
	if err != nil {
		t.Fatal(err)
	}
	if store.executions != 2 {
		t.Fatalf("graph executions = %d, want 2", store.executions)
	}
	if len(result.Proof.Receipts) != 2 || result.Proof.Receipts[1].Execution != "graph_store" || !result.Proof.Receipts[1].Passed {
		t.Fatalf("graph proof = %#v", result.Proof.Receipts)
	}
	modelGraphContext, err := json.Marshal(model.req.Context["graph_evidence"])
	if err != nil {
		t.Fatal(err)
	}
	modelGraphJSON := string(modelGraphContext)
	for _, forbidden := range []string{"private-actor", "private-task", "private-definition", "private-role"} {
		if strings.Contains(string(result.TestYAML), forbidden) {
			t.Fatalf("authored graph fixture exposes source handle %q", forbidden)
		}
		if strings.Contains(modelGraphJSON, forbidden) {
			t.Fatalf("model graph context exposes source handle %q: %s", forbidden, modelGraphJSON)
		}
	}
	for _, required := range []string{`"ref":"node-1"`, `"relation":"acted_on"`, `"entity_type":"aws.ecs.task_definition"`, `"has_secret_bindings":"true"`} {
		if !strings.Contains(modelGraphJSON, required) {
			t.Fatalf("model graph context missing %q: %s", required, modelGraphJSON)
		}
	}
}

type agentGraphStore struct {
	entities   []*ports.ProjectedEntity
	executions int
}

func (s *agentGraphStore) Ping(context.Context) error { return nil }
func (s *agentGraphStore) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	return nil, nil
}
func (s *agentGraphStore) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	s.entities = append(s.entities, entity)
	return nil
}
func (s *agentGraphStore) UpsertProjectedLink(context.Context, *ports.ProjectedLink) error {
	return nil
}
func (s *agentGraphStore) DeleteProjectedEntity(context.Context, string) error { return nil }
func (s *agentGraphStore) ExecuteReadCypher(context.Context, ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	s.executions++
	if s.executions != 1 {
		return nil, nil
	}
	evidence := make([]any, 0, len(s.entities))
	resourceURNs := make([]string, 0, len(s.entities))
	for _, entity := range s.entities {
		evidence = append(evidence, map[string]any{"urn": entity.URN})
		resourceURNs = append(resourceURNs, entity.URN)
	}
	return []ports.CypherRow{{Values: map[string]any{
		"primary_urn": resourceURNs[2], "fingerprint_key": resourceURNs[2] + "|" + resourceURNs[3],
		"summary": "causal path", "resource_urns": resourceURNs, "evidence": evidence,
	}}}, nil
}

func TestDraftPolicyBundleRedactsSourceEvidenceBeforeModelCall(t *testing.T) {
	rule := findingdsl.NewPolicyRule(findingdsl.NewPolicyRuleInput{ID: "agent-grounded-aws", Name: "Agent grounded AWS", Description: "Flags a source-grounded AWS state.", Severity: "high", Conditions: []string{`cmp_eq(path(resource, "has_secret_bindings"), true)`, `cmp_eq(path(resource, "status"), "ACTIVE")`}, Frameworks: []findingdsl.PolicyFramework{{Name: "SOC 2", Controls: []string{"CC6.1"}}}})
	raw, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	model := &stubDraftModel{raw: raw}
	_, err = (Service{Model: model}).DraftPolicyBundle(context.Background(), PolicyBundleDraftRequest{
		Prompt: "author from source evidence",
		Domain: "aws",
		Context: map[string]any{"source_evidence": []map[string]any{
			map[string]any{
				"source_kind": "aws.cloudtrail", "event_type": "RunTask", "account_id": 123456789012,
				"task_definition_arn": "arn:aws:ecs:us-east-1:123456789012:task-definition/private-candidate:7", "started_by": "operator@example.test",
			},
			map[string]any{
				"source_kind": "aws.ecs_task_definition", "status": "ACTIVE", "has_candidate_marker": "true", "has_secret_bindings": "true", "secret_binding_count": 2,
				"resource_id": "arn:aws:ecs:us-east-1:123456789012:task-definition/private-candidate:7", "container_images": "123456789012.dkr.ecr.us-east-1.amazonaws.com/private:candidate-7", "secret_name": "DATABASE_TOKEN",
				"arn:aws:iam::123456789012:role/private-role": "dynamic-key-value",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(model.req.Context["source_evidence"])
	if err != nil {
		t.Fatal(err)
	}
	contextJSON := string(encoded)
	for _, forbidden := range []string{"123456789012", "private-candidate", "operator@example.test", "DATABASE_TOKEN", "dkr.ecr", "dynamic-key-value"} {
		if strings.Contains(contextJSON, forbidden) {
			t.Fatalf("source evidence sent to model contains %q: %s", forbidden, contextJSON)
		}
	}
	for _, required := range []string{`"event_type":"RunTask"`, `"status":"ACTIVE"`, `"has_secret_bindings":"true"`, `"secret_binding_count":2`, "aws-ref-", "evidence-key-"} {
		if !strings.Contains(contextJSON, required) {
			t.Fatalf("source evidence sent to model missing %q: %s", required, contextJSON)
		}
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
