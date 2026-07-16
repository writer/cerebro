package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/writer/cerebro/internal/findingdsl"
)

type ProofReceipt struct {
	Gate      string `json:"gate"`
	Passed    bool   `json:"passed"`
	Execution string `json:"execution"`
	Detail    string `json:"detail"`
}

var ErrGraphStoreRequired = errors.New("graph policy proof requires an injected graph store")

type ProofResult struct {
	PolicyID     string         `json:"policy_id"`
	PolicyPath   string         `json:"policy_path"`
	TestPath     string         `json:"test_path"`
	PolicyDigest string         `json:"policy_digest"`
	TestDigest   string         `json:"test_digest"`
	Receipts     []ProofReceipt `json:"receipts"`
}

func Prove(ctx context.Context, artifacts Artifacts) (ProofResult, error) {
	if strings.TrimSpace(artifacts.Rule.Spec.Graph.Query) != "" {
		return proveGraph(ctx, artifacts, nil)
	}
	return proveScalar(artifacts)
}

func proveScalar(artifacts Artifacts) (ProofResult, error) {
	result := ProofResult{
		PolicyID: artifacts.Rule.Metadata.ID, PolicyPath: artifacts.PolicyPath, TestPath: artifacts.TestPath,
		PolicyDigest: digest(artifacts.PolicyYAML), TestDigest: digest(artifacts.TestYAML),
	}
	protectedPassed, protectedDetail := suitePasses(artifacts.Rule, artifacts.Suite)
	result.Receipts = append(result.Receipts, ProofReceipt{Gate: "protected_target", Passed: protectedPassed, Execution: "in_process", Detail: protectedDetail})
	if !protectedPassed {
		return result, errors.New("authored tests do not pass against the authored policy")
	}

	weakened := artifacts.Rule
	if len(weakened.Spec.Match.Conditions) == 0 {
		return result, errors.New("authored policy has no condition to mutate")
	}
	weakened.Spec.Match.Conditions = append([]string(nil), weakened.Spec.Match.Conditions[1:]...)
	unprotectedPassed, unprotectedDetail := suitePasses(weakened, artifacts.Suite)
	killed := !unprotectedPassed
	result.Receipts = append(result.Receipts, ProofReceipt{Gate: "unprotected_target", Passed: killed, Execution: "in_process", Detail: "first policy condition removed: " + unprotectedDetail})
	if !killed {
		return result, errors.New("authored tests did not reject the weakened policy")
	}
	return result, nil
}

// ProveWithGraphStore executes graph fixtures through the production graph test
// boundary. Scalar policies retain the existing in-process proof behavior.
func ProveWithGraphStore(ctx context.Context, artifacts Artifacts, store findingdsl.PolicyGraphTestStore) (ProofResult, error) {
	if strings.TrimSpace(artifacts.Rule.Spec.Graph.Query) == "" {
		return proveScalar(artifacts)
	}
	return proveGraph(ctx, artifacts, store)
}

func proveGraph(ctx context.Context, artifacts Artifacts, store findingdsl.PolicyGraphTestStore) (ProofResult, error) {
	result, groups, err := prepareGraphProof(artifacts)
	if err != nil {
		return result, err
	}
	if store == nil {
		appendGraphBatteryNotRunReceipts(&result, groups, "a graph store was not injected")
		result.Receipts = append(result.Receipts, ProofReceipt{Gate: "graph_execution", Passed: false, Execution: "not_run", Detail: "graph store was not injected; authored Cypher and topology were not executed"})
		return result, ErrGraphStoreRequired
	}

	root, err := os.MkdirTemp("", "cerebro-authored-graph-proof-")
	if err != nil {
		appendGraphBatteryNotRunReceipts(&result, groups, "the isolated proof root could not be created")
		result.Receipts = append(result.Receipts, ProofReceipt{Gate: "graph_execution", Passed: false, Execution: "not_run", Detail: "create isolated proof root: " + err.Error()})
		return result, err
	}
	defer func() { _ = os.RemoveAll(root) }()
	if err := writeProofArtifact(root, artifacts.PolicyPath, artifacts.PolicyYAML); err != nil {
		appendGraphBatteryNotRunReceipts(&result, groups, "the authored policy artifact could not be staged")
		result.Receipts = append(result.Receipts, ProofReceipt{Gate: "graph_execution", Passed: false, Execution: "not_run", Detail: err.Error()})
		return result, err
	}
	executionArtifacts := artifacts
	executionArtifacts.Suite, err = isolateGraphProofSuite(artifacts.Suite, digest([]byte(root))[:16])
	if err != nil {
		appendGraphBatteryNotRunReceipts(&result, groups, "the graph fixtures could not be isolated for this execution")
		result.Receipts = append(result.Receipts, ProofReceipt{Gate: "graph_execution", Passed: false, Execution: "not_run", Detail: err.Error()})
		return result, err
	}
	executionGroups := graphProofCaseGroups(executionArtifacts.Suite)
	prepared, err := prepareGraphProofGroups(root, executionArtifacts, executionGroups)
	if err != nil {
		appendGraphBatteryNotRunReceipts(&result, groups, "the isolated proof suites could not be staged")
		result.Receipts = append(result.Receipts, ProofReceipt{Gate: "graph_execution", Passed: false, Execution: "not_run", Detail: err.Error()})
		return result, err
	}
	var executionIssues []findingdsl.Issue
	for _, group := range prepared {
		groupIssues := findingdsl.RunPolicyRuleTestSuiteWithGraphStore(ctx, root, filepath.Join(root, filepath.FromSlash(group.relPath)), store)
		passed := len(groupIssues) == 0
		detail := fmt.Sprintf("executed %d authored %s case(s) through an isolated graph-store suite", len(group.targets), group.label)
		if !passed {
			detail = fmt.Sprintf("%d authored %s case(s) failed their isolated graph-store suite", len(group.targets), group.label)
		}
		result.Receipts = append(result.Receipts, ProofReceipt{Gate: group.gate, Passed: passed, Execution: "graph_store", Detail: detail})
		executionIssues = append(executionIssues, groupIssues...)
	}
	passed := len(executionIssues) == 0
	detail := fmt.Sprintf("executed %d distinct authored graph cases across %d isolated proof gates", len(artifacts.Suite.Cases), len(prepared))
	if !passed {
		detail = "graph execution failed: " + joinIssues(executionIssues)
	}
	result.Receipts = append(result.Receipts, ProofReceipt{Gate: "graph_execution", Passed: passed, Execution: "graph_store", Detail: detail})
	if !passed {
		return result, errors.New("authored graph tests failed against injected graph store")
	}
	return result, nil
}

// isolateGraphProofSuite keeps checked-in authored fixtures reproducible while
// giving every proof execution a disjoint graph tenant and URN namespace.
// Concurrent proofs of the same policy therefore cannot overwrite or delete
// one another's temporary projected nodes.
func isolateGraphProofSuite(suite findingdsl.PolicyRuleTestSuite, namespace string) (findingdsl.PolicyRuleTestSuite, error) {
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return suite, errors.New("graph proof execution namespace is required")
	}
	isolated := suite
	isolated.Cases = make([]findingdsl.PolicyRuleTestCase, len(suite.Cases))
	for caseIndex, testCase := range suite.Cases {
		isolated.Cases[caseIndex] = testCase
		if testCase.GraphFixture == nil {
			continue
		}
		fixture := testCase.GraphFixture
		isolatedFixture := &findingdsl.PolicyGraphFixture{
			TenantID: strings.TrimSpace(fixture.TenantID) + "-proof-" + namespace,
			Nodes:    make([]findingdsl.PolicyGraphFixtureNode, len(fixture.Nodes)),
			Edges:    make([]findingdsl.PolicyGraphFixtureEdge, len(fixture.Edges)),
		}
		urns := make(map[string]string, len(fixture.Nodes))
		for nodeIndex, node := range fixture.Nodes {
			oldURN := strings.TrimSpace(node.URN)
			newURN := oldURN + ":proof-" + namespace
			urns[oldURN] = newURN
			node.URN = newURN
			isolatedFixture.Nodes[nodeIndex] = node
		}
		for edgeIndex, edge := range fixture.Edges {
			fromURN, fromOK := urns[strings.TrimSpace(edge.FromURN)]
			toURN, toOK := urns[strings.TrimSpace(edge.ToURN)]
			if !fromOK || !toOK {
				return suite, fmt.Errorf("isolate graph proof case %d edge %d: endpoint does not reference a fixture node", caseIndex, edgeIndex)
			}
			edge.FromURN = fromURN
			edge.ToURN = toURN
			isolatedFixture.Edges[edgeIndex] = edge
		}
		evidenceURNs := make([]string, len(testCase.WantEvidenceURNs))
		for evidenceIndex, rawURN := range testCase.WantEvidenceURNs {
			isolatedURN, ok := urns[strings.TrimSpace(rawURN)]
			if !ok {
				return suite, fmt.Errorf("isolate graph proof case %d evidence urn %q: does not reference a fixture node", caseIndex, rawURN)
			}
			evidenceURNs[evidenceIndex] = isolatedURN
		}
		isolated.Cases[caseIndex].GraphFixture = isolatedFixture
		isolated.Cases[caseIndex].WantEvidenceURNs = evidenceURNs
	}
	return isolated, nil
}

func prepareGraphProof(artifacts Artifacts) (ProofResult, graphProofGroups, error) {
	result := ProofResult{
		PolicyID: artifacts.Rule.Metadata.ID, PolicyPath: artifacts.PolicyPath, TestPath: artifacts.TestPath,
		PolicyDigest: digest(artifacts.PolicyYAML), TestDigest: digest(artifacts.TestYAML),
	}
	issues := findingdsl.ValidatePolicyRuleTestSuite(artifacts.Suite)
	contractPassed := len(issues) == 0
	groups := graphProofCaseGroups(artifacts.Suite)
	contractDetail := fmt.Sprintf("canonical finding/critical-edge pair plus %d additional edge ablations, %d predicate mutations, %d current-state closeouts, and %d neighbor-isolation cases are structurally valid", groups.targetCount("graph_edge_ablation")-1, groups.targetCount("graph_predicate_mutation"), groups.targetCount("graph_current_state_closeout"), groups.targetCount("graph_neighbor_isolation"))
	if !contractPassed {
		contractDetail = "graph fixture contract failed: " + joinIssues(issues)
	}
	result.Receipts = append(result.Receipts, ProofReceipt{Gate: "graph_fixture_contract", Passed: contractPassed, Execution: "in_process", Detail: contractDetail})
	if !contractPassed {
		return result, groups, errors.New("authored graph fixture contract failed")
	}
	multiHop := groups.targetCount("graph_edge_ablation") >= 2
	multiHopDetail := fmt.Sprintf("%d distinct causal edge removals must each make the authored query pass", groups.targetCount("graph_edge_ablation"))
	if !multiHop {
		multiHopDetail = "the authored suite does not prove at least two query-dependent causal edges"
	}
	result.Receipts = append(result.Receipts, ProofReceipt{Gate: "graph_multi_hop", Passed: multiHop, Execution: "in_process", Detail: multiHopDetail})
	if !multiHop {
		return result, groups, ErrGraphMultiHopQueryRequired
	}
	tenantScoped := strings.Contains(strings.ToLower(artifacts.Rule.Spec.Graph.Query), "$tenant_id")
	tenantDetail := "policy query binds the runtime tenant parameter; fixture projection and query execution use the same isolated tenant"
	if !tenantScoped {
		tenantDetail = "policy query does not reference the runtime $tenant_id parameter"
	}
	result.Receipts = append(result.Receipts, ProofReceipt{Gate: "graph_tenant_scope", Passed: tenantScoped, Execution: "in_process", Detail: tenantDetail})
	if !tenantScoped {
		return result, groups, ErrGraphTenantScopeRequired
	}
	return result, groups, nil
}

type graphProofGroup struct {
	gate    string
	label   string
	targets []findingdsl.PolicyRuleTestCase
}

type graphProofGroups struct {
	canonicalFinding findingdsl.PolicyRuleTestCase
	canonicalPassing findingdsl.PolicyRuleTestCase
	groups           []graphProofGroup
}

func graphProofCaseGroups(suite findingdsl.PolicyRuleTestSuite) graphProofGroups {
	groups := graphProofGroups{groups: []graphProofGroup{
		{gate: "graph_edge_ablation", label: "causal edge ablation"},
		{gate: "graph_predicate_mutation", label: "risk predicate mutation"},
		{gate: "graph_current_state_closeout", label: "current-state closeout with historical topology retained"},
		{gate: "graph_neighbor_isolation", label: "unrelated same-relation neighbor isolation"},
	}}
	for _, testCase := range suite.Cases {
		name := strings.TrimSpace(testCase.Name)
		if testCase.GraphFixture != nil && testCase.WantFinding && groups.canonicalFinding.GraphFixture == nil {
			groups.canonicalFinding = testCase
		}
		if testCase.GraphFixture != nil && !testCase.WantFinding && groups.canonicalPassing.GraphFixture == nil {
			groups.canonicalPassing = testCase
		}
		switch {
		case name == graphCriticalEdgeCaseName || strings.HasPrefix(name, graphEdgeAblationCasePrefix):
			groups.groups[0].targets = append(groups.groups[0].targets, testCase)
		case strings.HasPrefix(name, graphPredicateCasePrefix):
			groups.groups[1].targets = append(groups.groups[1].targets, testCase)
		case strings.HasPrefix(name, graphCurrentStateCasePrefix):
			groups.groups[2].targets = append(groups.groups[2].targets, testCase)
		case name == graphNeighborIsolationCaseName:
			groups.groups[3].targets = append(groups.groups[3].targets, testCase)
		}
	}
	if len(groups.groups[0].targets) == 0 && groups.canonicalPassing.GraphFixture != nil {
		groups.groups[0].targets = append(groups.groups[0].targets, groups.canonicalPassing)
	}
	return groups
}

func (groups graphProofGroups) targetCount(gate string) int {
	for _, group := range groups.groups {
		if group.gate == gate {
			return len(group.targets)
		}
	}
	return 0
}

func appendGraphBatteryNotRunReceipts(result *ProofResult, groups graphProofGroups, reason string) {
	for _, group := range groups.groups {
		if len(group.targets) == 0 {
			continue
		}
		result.Receipts = append(result.Receipts, ProofReceipt{Gate: group.gate, Passed: false, Execution: "not_run", Detail: fmt.Sprintf("%d authored %s case(s) were not executed because %s", len(group.targets), group.label, reason)})
	}
}

type preparedGraphProofGroup struct {
	graphProofGroup
	relPath string
}

func prepareGraphProofGroups(root string, artifacts Artifacts, groups graphProofGroups) ([]preparedGraphProofGroup, error) {
	prepared := make([]preparedGraphProofGroup, 0, len(groups.groups))
	for index, group := range groups.groups {
		if len(group.targets) == 0 {
			continue
		}
		cases := appendUniqueGraphCase(nil, groups.canonicalFinding)
		cases = appendUniqueGraphCase(cases, groups.canonicalPassing)
		for _, target := range group.targets {
			cases = appendUniqueGraphCase(cases, target)
		}
		suite := findingdsl.PolicyRuleTestSuite{
			APIVersion: artifacts.Suite.APIVersion, Kind: artifacts.Suite.Kind,
			Policy: artifacts.PolicyPath, Cases: cases,
		}
		content, err := findingdsl.FormatPolicyRuleTestSuiteYAML(suite)
		if err != nil {
			return nil, fmt.Errorf("format isolated %s proof suite: %w", group.gate, err)
		}
		relPath := fmt.Sprintf("policies/.authored-proof-%d.test.yaml", index+1)
		if err := writeProofArtifact(root, relPath, content); err != nil {
			return nil, err
		}
		prepared = append(prepared, preparedGraphProofGroup{graphProofGroup: group, relPath: relPath})
	}
	return prepared, nil
}

func appendUniqueGraphCase(cases []findingdsl.PolicyRuleTestCase, candidate findingdsl.PolicyRuleTestCase) []findingdsl.PolicyRuleTestCase {
	if candidate.GraphFixture == nil {
		return cases
	}
	for _, existing := range cases {
		if existing.Name == candidate.Name {
			return cases
		}
	}
	return append(cases, candidate)
}

func writeProofArtifact(root string, rel string, content []byte) error {
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create proof artifact directory: %w", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return fmt.Errorf("write proof artifact %q: %w", rel, err)
	}
	return nil
}

func suitePasses(rule findingdsl.PolicyFindingRule, suite findingdsl.PolicyRuleTestSuite) (bool, string) {
	for _, testCase := range suite.Cases {
		got, err := findingdsl.EvaluatePolicyRuleTestCase(rule, testCase)
		if err != nil {
			return false, fmt.Sprintf("case %q rejected policy: %v", testCase.Name, err)
		}
		if got != testCase.WantFinding {
			return false, fmt.Sprintf("case %q finding=%t want=%t", testCase.Name, got, testCase.WantFinding)
		}
	}
	return true, fmt.Sprintf("%d authored cases matched their expected outcomes", len(suite.Cases))
}

func digest(content []byte) string { sum := sha256.Sum256(content); return hex.EncodeToString(sum[:]) }
