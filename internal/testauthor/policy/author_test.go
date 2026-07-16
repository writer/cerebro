package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/findingdsl"
)

func TestAuthorWritesRunnablePolicyAndTestsDeterministically(t *testing.T) {
	intent := Intent{ID: "aws-s3-public-access", Domain: "aws", Name: "S3 public access", Description: "Flags buckets with public access enabled.", Severity: "high", Resource: "aws::s3::bucket", Conditions: []string{`cmp_eq(path(resource, "public"), true)`}, Frameworks: []findingdsl.PolicyFramework{{Name: "CIS", Controls: []string{"2.1.5"}}}, Remediation: "Block public access."}
	first, err := Author(intent)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Author(intent)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.PolicyYAML, second.PolicyYAML) || !bytes.Equal(first.TestYAML, second.TestYAML) {
		t.Fatal("authored artifacts are not deterministic")
	}
	if first.PolicyPath != "policies/aws/aws-s3-public-access.yaml" || first.TestPath != "policies/aws/aws-s3-public-access.test.yaml" {
		t.Fatalf("unexpected paths: %s %s", first.PolicyPath, first.TestPath)
	}
	for _, testCase := range first.Suite.Cases {
		got, err := findingdsl.EvaluatePolicyRuleTestCase(first.Rule, testCase)
		if err != nil || got != testCase.WantFinding {
			t.Fatalf("case %q got %t want %t err %v", testCase.Name, got, testCase.WantFinding, err)
		}
	}
}

func TestArtifactsForRuleWithGraphEvidenceAuthorsCausalIdentifierSafeFixtures(t *testing.T) {
	rule := authoredGraphRule()
	evidence := authoredGraphEvidence()
	artifacts, err := ArtifactsForRuleWithGraphEvidence(context.Background(), "aws", rule, &evidence)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts.Suite.Cases) != 7 {
		t.Fatalf("cases = %d, want canonical pair plus bounded proof battery", len(artifacts.Suite.Cases))
	}
	findingCase, passingCase := artifacts.Suite.Cases[0], artifacts.Suite.Cases[1]
	if findingCase.GraphFixture == nil || passingCase.GraphFixture == nil {
		t.Fatal("authored graph cases are missing topology fixtures")
	}
	if !reflect.DeepEqual(findingCase.GraphFixture.Nodes, passingCase.GraphFixture.Nodes) {
		t.Fatal("finding and passing graph fixtures changed nodes")
	}
	if len(findingCase.GraphFixture.Edges) != len(passingCase.GraphFixture.Edges)+1 {
		t.Fatalf("edge counts = %d and %d, want one critical edge removed", len(findingCase.GraphFixture.Edges), len(passingCase.GraphFixture.Edges))
	}
	caseNames := make([]string, 0, len(artifacts.Suite.Cases))
	for _, testCase := range artifacts.Suite.Cases {
		caseNames = append(caseNames, testCase.Name)
	}
	for _, required := range []string{graphCriticalEdgeCaseName, graphEdgeAblationCasePrefix, graphPredicateCasePrefix, graphNeighborIsolationCaseName} {
		if !strings.Contains(strings.Join(caseNames, "\n"), required) {
			t.Fatalf("authored cases = %#v, missing %q", caseNames, required)
		}
	}
	yaml := string(artifacts.TestYAML)
	for _, forbidden := range []string{"123456789012", "operator@example.test", "arn:aws:", "private-candidate"} {
		if strings.Contains(yaml, forbidden) {
			t.Fatalf("authored fixture contains source identifier %q:\n%s", forbidden, yaml)
		}
	}
	for _, required := range []string{"fixture-candidate-marker", "has_secret_bindings", "role_usage", "node-4"} {
		if !strings.Contains(yaml, required) {
			t.Fatalf("authored fixture missing predicate evidence %q:\n%s", required, yaml)
		}
	}
}

func TestSuiteForGraphRuleAuthorsBoundedCurrentStateCloseout(t *testing.T) {
	rule := authoredGraphRule()
	rule.Spec.Graph.Query = strings.Replace(rule.Spec.Graph.Query,
		`WHERE task_attrs CONTAINS 'candidate'`,
		`WHERE task_attrs CONTAINS 'candidate' AND definition_attrs CONTAINS '"status":"active"'`, 1)
	evidence := authoredGraphEvidence()
	suite, err := SuiteForGraphRule(context.Background(), rule, evidence)
	if err != nil {
		t.Fatal(err)
	}
	closeouts := 0
	for _, testCase := range suite.Cases {
		if strings.HasPrefix(testCase.Name, graphCurrentStateCasePrefix) {
			closeouts++
			if got := testCase.GraphFixture.Nodes[2].Attributes["status"]; got != "INACTIVE" {
				t.Fatalf("closeout status = %q, want INACTIVE", got)
			}
			if len(testCase.GraphFixture.Edges) != len(evidence.Edges) {
				t.Fatalf("closeout edges = %d, want historical topology retained", len(testCase.GraphFixture.Edges))
			}
		}
	}
	if closeouts != 1 {
		t.Fatalf("current-state closeouts = %d, want 1", closeouts)
	}
	if len(suite.Cases) > 2+maxGraphEdgeAblations+maxGraphPredicateMutants+1 {
		t.Fatalf("suite cases = %d, exceeded proof budgets", len(suite.Cases))
	}
}

func TestSuiteForGraphRuleRequiresTenantScopedQuery(t *testing.T) {
	rule := authoredGraphRule()
	rule.Spec.Graph.Query = strings.ReplaceAll(rule.Spec.Graph.Query, "$tenant_id", "fixture")
	evidence := authoredGraphEvidence()
	if _, err := SuiteForGraphRule(context.Background(), rule, evidence); !errors.Is(err, ErrGraphTenantScopeRequired) {
		t.Fatalf("SuiteForGraphRule() error = %v, want tenant-scope error", err)
	}
}

func TestSuiteForGraphRuleRejectsScopeEscapes(t *testing.T) {
	tests := map[string]string{
		"unscoped second node":   `MATCH (actor:Entity {tenant_id: $tenant_id}) MATCH (task:Entity) RETURN task.urn AS primary_urn LIMIT $row_limit`,
		"unscoped union branch":  `MATCH (actor:Entity {tenant_id: $tenant_id}) RETURN actor.urn AS primary_urn LIMIT $row_limit UNION MATCH (task) RETURN task.urn AS primary_urn LIMIT $row_limit`,
		"unscoped comprehension": `MATCH (actor:Entity {tenant_id: $tenant_id}) RETURN [(task:Entity)-[:RELATION]->(definition:Entity) | task.urn] AS primary_urn LIMIT $row_limit`,
		"scope dropping with":    `MATCH (actor:Entity {tenant_id: $tenant_id}) WITH count(*) AS total MATCH (actor) RETURN actor.urn AS primary_urn LIMIT $row_limit`,
	}
	for name, query := range tests {
		t.Run(name, func(t *testing.T) {
			rule := authoredGraphRule()
			rule.Spec.Graph.Query = query
			if _, err := SuiteForGraphRule(context.Background(), rule, authoredGraphEvidence()); !errors.Is(err, ErrGraphTenantScopeRequired) {
				t.Fatalf("SuiteForGraphRule() error = %v, want tenant-scope refusal", err)
			}
		})
	}
}

func TestSuiteForGraphRuleRejectsOneHopQueryOverMultiHopEvidence(t *testing.T) {
	rule := authoredGraphRule()
	rule.Spec.Graph.Query = `MATCH (definition:Entity {tenant_id: $tenant_id})-[role_use:RELATION {relation: 'runs_as'}]->(role:Entity {tenant_id: $tenant_id})
RETURN definition.urn AS primary_urn, definition.urn + '|' + role.urn AS fingerprint_key, 'one hop' AS summary, [definition.urn, role.urn] AS resource_urns
LIMIT $row_limit`
	if _, err := SuiteForGraphRule(context.Background(), rule, authoredGraphEvidence()); !errors.Is(err, ErrGraphMultiHopQueryRequired) {
		t.Fatalf("SuiteForGraphRule() error = %v, want multi-hop query error", err)
	}
}

func TestSuiteForGraphRuleBoundsEdgeAblations(t *testing.T) {
	evidence := authoredGraphEvidence()
	for index := 0; index < maxGraphEdgeAblations+3; index++ {
		fromID := fmt.Sprintf("context-from-%d", index)
		toID := fmt.Sprintf("context-to-%d", index)
		evidence.Nodes = append(evidence.Nodes,
			GraphEvidenceNode{ID: fromID, SourceID: "aws", EntityType: "aws.context"},
			GraphEvidenceNode{ID: toID, SourceID: "aws", EntityType: "aws.context"},
		)
		evidence.Edges = append(evidence.Edges, GraphEvidenceEdge{FromID: fromID, ToID: toID, SourceID: "aws", Relation: "depends_on"})
	}
	suite, err := SuiteForGraphRule(context.Background(), authoredGraphRule(), evidence)
	if err != nil {
		t.Fatal(err)
	}
	ablations := 0
	for _, testCase := range suite.Cases {
		if testCase.Name == graphCriticalEdgeCaseName || strings.HasPrefix(testCase.Name, graphEdgeAblationCasePrefix) {
			ablations++
		}
	}
	if ablations != maxGraphEdgeAblations {
		t.Fatalf("edge ablations = %d, want budget %d", ablations, maxGraphEdgeAblations)
	}
}

func authoredGraphRule() findingdsl.PolicyFindingRule {
	return findingdsl.NewPolicyRule(findingdsl.NewPolicyRuleInput{
		ID: "authored-ecs-path", Name: "Authored ECS path", Description: "Finds a causal ECS role path.", Severity: "high",
		Graph: findingdsl.PolicyRuleGraphFinding{
			Query: `MATCH (actor:Entity {tenant_id: $tenant_id, source_id: 'aws'})-[launch:RELATION {relation: 'acted_on'}]->(task:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'depends_on'}]->(definition:Entity {tenant_id: $tenant_id})-[role_use:RELATION {relation: 'runs_as'}]->(role:Entity {tenant_id: $tenant_id})
WITH actor, launch, task, definition, role_use, role, toLower(coalesce(task.attributes_json, '')) AS task_attrs, toLower(coalesce(definition.attributes_json, '')) AS definition_attrs, toLower(coalesce(role_use.attributes_json, '')) AS role_attrs
WHERE task_attrs CONTAINS 'candidate' AND definition_attrs CONTAINS '"has_secret_bindings":"true"' AND role_attrs CONTAINS '"role_usage":"execution"'
RETURN definition.urn AS primary_urn, definition.urn + '|' + role.urn AS fingerprint_key, 'causal ECS role path' AS summary, [actor.urn, task.urn, definition.urn, role.urn] AS resource_urns, [{urn: actor.urn}, {urn: task.urn}, {urn: definition.urn}, {urn: role.urn}] AS evidence
LIMIT $row_limit`,
			RowLimit: 10, RequiredColumns: []string{"primary_urn", "fingerprint_key", "summary", "resource_urns"},
		}, Frameworks: []findingdsl.PolicyFramework{{Name: "SOC 2", Controls: []string{"CC6.1"}}},
	})
}

func authoredGraphEvidence() GraphEvidence {
	return GraphEvidence{
		Nodes: []GraphEvidenceNode{
			{ID: "arn:aws:sts::123456789012:assumed-role/Operator/operator@example.test", SourceID: "aws", EntityType: "aws.assumed_role_session"},
			{ID: "arn:aws:ecs:us-east-1:123456789012:task/private-candidate", SourceID: "aws", EntityType: "aws.ecs.task", Attributes: map[string]string{"started_by": "operator-private-candidate"}},
			{ID: "arn:aws:ecs:us-east-1:123456789012:task-definition/private-candidate:7", SourceID: "aws", EntityType: "aws.ecs.task_definition", Attributes: map[string]string{"status": "ACTIVE", "has_secret_bindings": "true", "secret_binding_count": "2"}},
			{ID: "arn:aws:iam::123456789012:role/PrivateExecutionRole", SourceID: "aws", EntityType: "aws.role"},
		},
		Edges: []GraphEvidenceEdge{
			{FromID: "arn:aws:sts::123456789012:assumed-role/Operator/operator@example.test", ToID: "arn:aws:ecs:us-east-1:123456789012:task/private-candidate", SourceID: "aws", Relation: "acted_on", Attributes: map[string]string{"event_type": "RunTask"}},
			{FromID: "arn:aws:ecs:us-east-1:123456789012:task/private-candidate", ToID: "arn:aws:ecs:us-east-1:123456789012:task-definition/private-candidate:7", SourceID: "aws", Relation: "depends_on"},
			{FromID: "arn:aws:ecs:us-east-1:123456789012:task-definition/private-candidate:7", ToID: "arn:aws:iam::123456789012:role/PrivateExecutionRole", SourceID: "aws", Relation: "runs_as", Attributes: map[string]string{"role_usage": "execution"}},
		},
		CriticalEdge: GraphEvidenceEdgeRef{FromID: "arn:aws:ecs:us-east-1:123456789012:task-definition/private-candidate:7", ToID: "arn:aws:iam::123456789012:role/PrivateExecutionRole", Relation: "runs_as"},
		EvidenceNodeIDs: []string{
			"arn:aws:sts::123456789012:assumed-role/Operator/operator@example.test",
			"arn:aws:ecs:us-east-1:123456789012:task/private-candidate",
			"arn:aws:ecs:us-east-1:123456789012:task-definition/private-candidate:7",
			"arn:aws:iam::123456789012:role/PrivateExecutionRole",
		},
	}
}

func TestAuthorRejectsUnsupportedPolicySemantics(t *testing.T) {
	intent := Intent{ID: "complex", Domain: "aws", Name: "Complex", Description: "Complex policy.", Severity: "high", Conditions: []string{`matches_value(path(resource, "state"), "unsafe.*")`}, Frameworks: []findingdsl.PolicyFramework{{Name: "CIS", Controls: []string{"1"}}}}
	if _, err := Author(intent); err == nil {
		t.Fatal("Author() error = nil")
	}
}

func TestAuthorRejectsDomainOutsidePolicyDirectory(t *testing.T) {
	intent := Intent{ID: "example", Domain: "../docs", Name: "Example", Description: "Example policy.", Severity: "high", Conditions: []string{`cmp_eq(path(resource, "enabled"), false)`}, Frameworks: []findingdsl.PolicyFramework{{Name: "CIS", Controls: []string{"1"}}}}
	if _, err := Author(intent); err == nil {
		t.Fatal("Author() error = nil")
	}
}

func TestAuthorBuildsNestedResourceFixtures(t *testing.T) {
	intent := Intent{ID: "nested", Domain: "aws", Name: "Nested", Description: "Nested policy.", Severity: "high", Conditions: []string{`cmp_eq(path(resource, "authentication.type"), "API_KEY")`, `cmp_eq(path(resource, "providers.length"), 0)`}, Frameworks: []findingdsl.PolicyFramework{{Name: "CIS", Controls: []string{"1"}}}}
	artifacts, err := Author(intent)
	if err != nil {
		t.Fatal(err)
	}
	for _, testCase := range artifacts.Suite.Cases {
		got, err := findingdsl.EvaluatePolicyRuleTestCase(artifacts.Rule, testCase)
		if err != nil || got != testCase.WantFinding {
			t.Fatalf("case %q got %t want %t err %v", testCase.Name, got, testCase.WantFinding, err)
		}
	}
	if _, flat := artifacts.Suite.Cases[0].Resource["authentication.type"]; flat {
		t.Fatalf("fixture used a flat nested path: %#v", artifacts.Suite.Cases[0].Resource)
	}
}

func TestAuthorBuildsScalarComparisonFixtures(t *testing.T) {
	tests := []struct{ name, condition string }{
		{name: "not equal", condition: `cmp_ne(path(resource, "compliant"), true)`},
		{name: "greater", condition: `cmp_gt(path(resource, "age_days"), 90)`},
		{name: "less", condition: `cmp_lt(path(resource, "score"), 10)`},
		{name: "greater equal", condition: `cmp_ge(path(resource, "count"), 2)`},
		{name: "less equal", condition: `cmp_le(path(resource, "count"), 2)`},
		{name: "membership", condition: `in_list(path(resource, "state"), ["open","pending"])`},
		{name: "null equality", condition: `cmp_eq(path(resource, "key_id"), null)`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			intent := Intent{ID: "scalar", Domain: "aws", Name: "Scalar", Description: "Scalar policy.", Severity: "high", Conditions: []string{test.condition}, Frameworks: []findingdsl.PolicyFramework{{Name: "CIS", Controls: []string{"1"}}}}
			artifacts, err := Author(intent)
			if err != nil {
				t.Fatal(err)
			}
			for _, testCase := range artifacts.Suite.Cases {
				got, err := findingdsl.EvaluatePolicyRuleTestCase(artifacts.Rule, testCase)
				if err != nil || got != testCase.WantFinding {
					t.Fatalf("case %q got %t want %t err %v", testCase.Name, got, testCase.WantFinding, err)
				}
			}
		})
	}
}
