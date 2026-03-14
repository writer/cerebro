package compliance

import (
	"sort"
	"strings"
)

type policyEvaluatorFunc func(*graphComplianceEvaluator, string) policyEvaluation

type registeredPolicyEvaluator struct {
	definition GraphQueryDefinition
	evaluate   policyEvaluatorFunc
}

var builtinPolicyEvaluators = buildPolicyEvaluatorRegistry()

func buildPolicyEvaluatorRegistry() map[string]registeredPolicyEvaluator {
	registry := make(map[string]registeredPolicyEvaluator)
	for _, evaluators := range []map[string]registeredPolicyEvaluator{
		awsPolicyEvaluators,
		gcpPolicyEvaluators,
		dataPolicyEvaluators,
	} {
		for policyID, evaluator := range evaluators {
			registry[policyID] = evaluator
		}
	}
	return registry
}

func lookupPolicyEvaluator(policyID string) (registeredPolicyEvaluator, bool) {
	evaluator, ok := builtinPolicyEvaluators[strings.TrimSpace(policyID)]
	return evaluator, ok
}

func graphQueryDefinitionsForPolicies(policyIDs []string) []GraphQueryDefinition {
	if len(policyIDs) == 0 {
		return nil
	}
	unique := make(map[string]GraphQueryDefinition)
	for _, policyID := range policyIDs {
		evaluator, ok := lookupPolicyEvaluator(policyID)
		if !ok {
			continue
		}
		unique[evaluator.definition.ID] = evaluator.definition
	}
	if len(unique) == 0 {
		return nil
	}
	definitions := make([]GraphQueryDefinition, 0, len(unique))
	for _, definition := range unique {
		definitions = append(definitions, definition)
	}
	sort.Slice(definitions, func(i, j int) bool {
		return definitions[i].ID < definitions[j].ID
	})
	return definitions
}
