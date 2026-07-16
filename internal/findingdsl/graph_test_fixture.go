package findingdsl

import (
	"context"
	"fmt"
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
	if len(fixture.Edges) < 2 {
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
		adjacency[from] = append(adjacency[from], to)
		adjacency[to] = append(adjacency[to], from)
	}
	if !containsTwoEdgePath(adjacency) {
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

func runPolicyGraphFixture(ctx context.Context, store PolicyGraphTestStore, rule PolicyFindingRule, testCase PolicyRuleTestCase) (err error) {
	fixture := testCase.GraphFixture
	for _, node := range fixture.Nodes {
		if err := store.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
			URN: node.URN, TenantID: fixture.TenantID, SourceID: node.SourceID, RuntimeID: node.RuntimeID,
			EntityType: node.EntityType, Label: node.Label, Attributes: node.Attributes,
		}); err != nil {
			return fmt.Errorf("project node %q: %w", node.URN, err)
		}
	}
	defer func() {
		for index := len(fixture.Nodes) - 1; index >= 0; index-- {
			if cleanupErr := store.DeleteProjectedEntity(ctx, fixture.Nodes[index].URN); cleanupErr != nil && err == nil {
				err = fmt.Errorf("delete fixture node %q: %w", fixture.Nodes[index].URN, cleanupErr)
			}
		}
	}()
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
	got, err := EvaluatePolicyRuleTestCase(rule, rowCase)
	if err != nil {
		return err
	}
	if got != testCase.WantFinding {
		return fmt.Errorf("finding = %t, want %t (query returned %d row(s))", got, testCase.WantFinding, len(rows))
	}
	return nil
}
