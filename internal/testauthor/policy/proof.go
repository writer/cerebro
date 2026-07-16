package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/writer/cerebro/internal/findingdsl"
)

type ProofReceipt struct {
	Gate   string `json:"gate"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

type ProofResult struct {
	PolicyID     string         `json:"policy_id"`
	PolicyPath   string         `json:"policy_path"`
	TestPath     string         `json:"test_path"`
	PolicyDigest string         `json:"policy_digest"`
	TestDigest   string         `json:"test_digest"`
	Receipts     []ProofReceipt `json:"receipts"`
}

func Prove(artifacts Artifacts) (ProofResult, error) {
	result := ProofResult{
		PolicyID: artifacts.Rule.Metadata.ID, PolicyPath: artifacts.PolicyPath, TestPath: artifacts.TestPath,
		PolicyDigest: digest(artifacts.PolicyYAML), TestDigest: digest(artifacts.TestYAML),
	}
	protectedPassed, protectedDetail := suitePasses(artifacts.Rule, artifacts.Suite)
	result.Receipts = append(result.Receipts, ProofReceipt{Gate: "protected_target", Passed: protectedPassed, Detail: protectedDetail})
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
	result.Receipts = append(result.Receipts, ProofReceipt{Gate: "unprotected_target", Passed: killed, Detail: "first policy condition removed: " + unprotectedDetail})
	if !killed {
		return result, errors.New("authored tests did not reject the weakened policy")
	}
	return result, nil
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
