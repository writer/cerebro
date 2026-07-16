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

func Prove(artifacts Artifacts) (ProofResult, error) {
	if strings.TrimSpace(artifacts.Rule.Spec.Graph.Query) != "" {
		return proveGraph(nil, artifacts, nil)
	}
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
		return Prove(artifacts)
	}
	return proveGraph(ctx, artifacts, store)
}

func proveGraph(ctx context.Context, artifacts Artifacts, store findingdsl.PolicyGraphTestStore) (ProofResult, error) {
	result := ProofResult{
		PolicyID: artifacts.Rule.Metadata.ID, PolicyPath: artifacts.PolicyPath, TestPath: artifacts.TestPath,
		PolicyDigest: digest(artifacts.PolicyYAML), TestDigest: digest(artifacts.TestYAML),
	}
	issues := findingdsl.ValidatePolicyRuleTestSuite(artifacts.Suite)
	contractPassed := len(issues) == 0
	contractDetail := "finding and passing graph fixtures have identical topology except for one critical edge"
	if !contractPassed {
		contractDetail = "graph fixture contract failed: " + joinIssues(issues)
	}
	result.Receipts = append(result.Receipts, ProofReceipt{Gate: "graph_fixture_contract", Passed: contractPassed, Execution: "in_process", Detail: contractDetail})
	if !contractPassed {
		return result, errors.New("authored graph fixture contract failed")
	}
	if store == nil {
		result.Receipts = append(result.Receipts, ProofReceipt{Gate: "graph_execution", Passed: false, Execution: "not_run", Detail: "graph store was not injected; authored Cypher and topology were not executed"})
		return result, ErrGraphStoreRequired
	}

	root, err := os.MkdirTemp("", "cerebro-authored-graph-proof-")
	if err != nil {
		result.Receipts = append(result.Receipts, ProofReceipt{Gate: "graph_execution", Passed: false, Execution: "not_run", Detail: "create isolated proof root: " + err.Error()})
		return result, err
	}
	defer os.RemoveAll(root)
	if err := writeProofArtifact(root, artifacts.PolicyPath, artifacts.PolicyYAML); err != nil {
		result.Receipts = append(result.Receipts, ProofReceipt{Gate: "graph_execution", Passed: false, Execution: "not_run", Detail: err.Error()})
		return result, err
	}
	if err := writeProofArtifact(root, artifacts.TestPath, artifacts.TestYAML); err != nil {
		result.Receipts = append(result.Receipts, ProofReceipt{Gate: "graph_execution", Passed: false, Execution: "not_run", Detail: err.Error()})
		return result, err
	}
	testPath := filepath.Join(root, filepath.FromSlash(artifacts.TestPath))
	executionIssues := findingdsl.RunPolicyRuleTestSuiteWithGraphStore(ctx, root, testPath, store)
	passed := len(executionIssues) == 0
	detail := fmt.Sprintf("executed %d authored graph cases through the injected graph store", len(artifacts.Suite.Cases))
	if !passed {
		detail = "graph execution failed: " + joinIssues(executionIssues)
	}
	result.Receipts = append(result.Receipts, ProofReceipt{Gate: "graph_execution", Passed: passed, Execution: "graph_store", Detail: detail})
	if !passed {
		return result, errors.New("authored graph tests failed against injected graph store")
	}
	return result, nil
}

func writeProofArtifact(root string, rel string, content []byte) error {
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
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
