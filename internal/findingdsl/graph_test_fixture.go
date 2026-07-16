package findingdsl

import (
	"context"
	"fmt"
	"maps"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

func validatePolicyGraphFixture(path string, caseIndex int, testCase PolicyRuleTestCase) []Issue {
	fixture := testCase.GraphFixture
	prefix := fmt.Sprintf("cases[%d] %q graphFixture", caseIndex, testCase.Name)
	var issues []Issue
	if strings.TrimSpace(fixture.TenantID) == "" {
		issues = append(issues, Issue{Path: path, Message: prefix + ".tenantId is required"})
	}
	if len(fixture.Nodes) < 3 {
		issues = append(issues, Issue{Path: path, Message: prefix + " must contain at least three nodes"})
	}
	if testCase.WantFinding && len(fixture.Edges) < 2 {
		issues = append(issues, Issue{Path: path, Message: prefix + " must contain at least two edges"})
	}
	nodes := make(map[string]struct{}, len(fixture.Nodes))
	for nodeIndex, node := range fixture.Nodes {
		urn := strings.TrimSpace(node.URN)
		if urn == "" || strings.TrimSpace(node.SourceID) == "" || strings.TrimSpace(node.EntityType) == "" {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("%s.nodes[%d] requires urn, sourceId, and entityType", prefix, nodeIndex)})
		}
		if _, exists := nodes[urn]; exists && urn != "" {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("%s.nodes[%d].urn %q is duplicated", prefix, nodeIndex, urn)})
		}
		nodes[urn] = struct{}{}
	}
	adjacency := map[string][]string{}
	edges := map[string]struct{}{}
	for edgeIndex, edge := range fixture.Edges {
		from, to := strings.TrimSpace(edge.FromURN), strings.TrimSpace(edge.ToURN)
		if _, ok := nodes[from]; !ok {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("%s.edges[%d].fromUrn does not reference a fixture node", prefix, edgeIndex)})
		}
		if _, ok := nodes[to]; !ok {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("%s.edges[%d].toUrn does not reference a fixture node", prefix, edgeIndex)})
		}
		if strings.TrimSpace(edge.SourceID) == "" || strings.TrimSpace(edge.Relation) == "" {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("%s.edges[%d] requires sourceId and relation", prefix, edgeIndex)})
		}
		if from != "" && from == to {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("%s.edges[%d] must connect two distinct nodes", prefix, edgeIndex)})
		}
		edgeKey := from + "\x00" + strings.TrimSpace(edge.Relation) + "\x00" + to
		if _, exists := edges[edgeKey]; exists {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("%s.edges[%d] duplicates an earlier edge", prefix, edgeIndex)})
		}
		edges[edgeKey] = struct{}{}
		adjacency[from] = append(adjacency[from], to)
		adjacency[to] = append(adjacency[to], from)
	}
	if testCase.WantFinding && !containsTwoEdgePath(adjacency) {
		issues = append(issues, Issue{Path: path, Message: prefix + " must contain a connected path spanning two edges"})
	}
	return issues
}

func containsTwoEdgePath(adjacency map[string][]string) bool {
	for _, neighbors := range adjacency {
		if len(neighbors) >= 2 {
			return true
		}
	}
	return false
}

func validatePolicyGraphMutationPair(path string, cases []PolicyRuleTestCase) []Issue {
	var findingCases, passingCases []PolicyRuleTestCase
	for _, testCase := range cases {
		if testCase.GraphFixture == nil {
			continue
		}
		if testCase.WantFinding {
			findingCases = append(findingCases, testCase)
		} else {
			passingCases = append(passingCases, testCase)
		}
	}
	if len(findingCases)+len(passingCases) == 0 {
		return nil
	}
	for _, findingCase := range findingCases {
		for _, passingCase := range passingCases {
			if graphFixtureSingleEdgeMutation(findingCase.GraphFixture, passingCase.GraphFixture) {
				return nil
			}
		}
	}
	return []Issue{{Path: path, Message: "graphFixture suites require a finding case and a passing case with identical nodes and exactly one policy-critical edge removed"}}
}

func graphFixtureSingleEdgeMutation(finding, passing *PolicyGraphFixture) bool {
	if finding == nil || passing == nil || strings.TrimSpace(finding.TenantID) != strings.TrimSpace(passing.TenantID) {
		return false
	}
	findingNodes, passingNodes := map[string]PolicyGraphFixtureNode{}, map[string]PolicyGraphFixtureNode{}
	for _, node := range finding.Nodes {
		findingNodes[strings.TrimSpace(node.URN)] = node
	}
	for _, node := range passing.Nodes {
		passingNodes[strings.TrimSpace(node.URN)] = node
	}
	if !sameGraphFixtureNodes(findingNodes, passingNodes) {
		return false
	}
	findingEdges, passingEdges := graphFixtureEdgeSet(finding.Edges), graphFixtureEdgeSet(passing.Edges)
	if len(findingEdges) != len(passingEdges)+1 {
		return false
	}
	for edge := range passingEdges {
		if _, ok := findingEdges[edge]; !ok {
			return false
		}
	}
	return true
}

func graphFixtureEdgeSet(edges []PolicyGraphFixtureEdge) map[string]struct{} {
	out := make(map[string]struct{}, len(edges))
	for _, edge := range edges {
		key := strings.TrimSpace(edge.FromURN) + "\x00" + strings.TrimSpace(edge.Relation) + "\x00" + strings.TrimSpace(edge.ToURN)
		out[key] = struct{}{}
	}
	return out
}

func sameGraphFixtureNodes(left, right map[string]PolicyGraphFixtureNode) bool {
	if len(left) != len(right) {
		return false
	}
	for urn, leftNode := range left {
		rightNode, ok := right[urn]
		if !ok || leftNode.URN != rightNode.URN || leftNode.SourceID != rightNode.SourceID || leftNode.RuntimeID != rightNode.RuntimeID || leftNode.EntityType != rightNode.EntityType || leftNode.Label != rightNode.Label || !maps.Equal(leftNode.Attributes, rightNode.Attributes) {
			return false
		}
	}
	return true
}

func runPolicyGraphFixture(ctx context.Context, store PolicyGraphTestStore, rule PolicyFindingRule, testCase PolicyRuleTestCase) (err error) {
	fixture := testCase.GraphFixture
	projectedURNs := make([]string, 0, len(fixture.Nodes))
	defer func() {
		cleanupCtx := context.WithoutCancel(ctx)
		for index := len(projectedURNs) - 1; index >= 0; index-- {
			if cleanupErr := store.DeleteProjectedEntity(cleanupCtx, projectedURNs[index]); cleanupErr != nil && err == nil {
				err = fmt.Errorf("delete fixture node %q: %w", projectedURNs[index], cleanupErr)
			}
		}
	}()
	for _, node := range fixture.Nodes {
		if err := store.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
			URN: node.URN, TenantID: fixture.TenantID, SourceID: node.SourceID, RuntimeID: node.RuntimeID,
			EntityType: node.EntityType, Label: node.Label, Attributes: node.Attributes,
		}); err != nil {
			return fmt.Errorf("project node %q: %w", node.URN, err)
		}
		projectedURNs = append(projectedURNs, node.URN)
	}
	for _, edge := range fixture.Edges {
		if err := store.UpsertProjectedLink(ctx, &ports.ProjectedLink{
			TenantID: fixture.TenantID, SourceID: edge.SourceID, RuntimeID: edge.RuntimeID,
			FromURN: edge.FromURN, ToURN: edge.ToURN, Relation: edge.Relation, Attributes: edge.Attributes,
		}); err != nil {
			return fmt.Errorf("project edge %q -[%s]-> %q: %w", edge.FromURN, edge.Relation, edge.ToURN, err)
		}
	}
	params := make(map[string]any, len(rule.Spec.Graph.Params)+2)
	for key, value := range rule.Spec.Graph.Params {
		params[key] = value
	}
	params["tenant_id"] = fixture.TenantID
	params["row_limit"] = int64(rule.Spec.Graph.RowLimit)
	rows, err := store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{Query: rule.Spec.Graph.Query, Params: params, RowLimit: rule.Spec.Graph.RowLimit})
	if err != nil {
		return fmt.Errorf("execute policy graph query: %w", err)
	}
	queryRows := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		queryRows = append(queryRows, row.Values)
	}
	rowCase := testCase
	rowCase.GraphFixture = nil
	rowCase.QueryRows = queryRows
	if issues := validatePolicyRuleTestCaseAgainstRule("<graph-fixture>", rule, 0, rowCase); len(issues) != 0 {
		return fmt.Errorf("query result violates graph finding contract: %s", issues[0].Message)
	}
	if err := validateGraphFixtureEvidence(rows, testCase.WantEvidenceURNs); err != nil {
		return err
	}
	got, err := EvaluatePolicyRuleTestCase(rule, rowCase)
	if err != nil {
		return err
	}
	if got != testCase.WantFinding {
		return fmt.Errorf("finding = %t, want %t (query returned %d row(s))", got, testCase.WantFinding, len(rows))
	}
	return nil
}

func validateGraphFixtureEvidence(rows []ports.CypherRow, expectedURNs []string) error {
	if len(expectedURNs) == 0 {
		return nil
	}
	actual := map[string]struct{}{}
	for _, row := range rows {
		items, _ := row.Values["evidence"].([]any)
		for _, item := range items {
			values, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if urn := strings.TrimSpace(fmt.Sprintf("%v", values["urn"])); urn != "" && urn != "<nil>" {
				actual[urn] = struct{}{}
			}
		}
	}
	for _, expected := range expectedURNs {
		if _, ok := actual[strings.TrimSpace(expected)]; !ok {
			return fmt.Errorf("query evidence missing expected URN %q", expected)
		}
	}
	return nil
}
