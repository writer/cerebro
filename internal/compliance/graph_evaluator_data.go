package compliance

import "github.com/evalops/cerebro/internal/graph"

var dataPolicyEvaluators = map[string]registeredPolicyEvaluator{
	"dspm-restricted-data-unencrypted": {
		definition: GraphQueryDefinition{ID: "dspm-restricted-data-unencrypted", Provider: "multi", Description: "Evaluate whether restricted or sensitive data assets are encrypted"},
		evaluate: func(e *graphComplianceEvaluator, policyID string) policyEvaluation {
			return e.evaluateSensitiveDataEncryption(policyID)
		},
	},
	"dspm-confidential-data-public": {
		definition: GraphQueryDefinition{ID: "dspm-confidential-data-public", Provider: "multi", Description: "Evaluate whether restricted or sensitive data assets are publicly exposed"},
		evaluate: func(e *graphComplianceEvaluator, policyID string) policyEvaluation {
			return e.evaluateSensitiveDataExposure(policyID)
		},
	},
}

func (e *graphComplianceEvaluator) evaluateSensitiveDataEncryption(policyID string) policyEvaluation {
	records := e.entityRecords("", graph.NodeKindBucket, graph.NodeKindDatabase, graph.NodeKindSecret, graph.NodeKindService)
	result := newGraphPolicyEvaluation(policyID)
	if len(records) == 0 {
		result.Status = ControlStateNotApplicable
		return result
	}
	unknown := 0
	for _, record := range records {
		sensitive, sensitiveKnown := sensitiveDataState(record)
		if !sensitiveKnown || !sensitive {
			continue
		}
		encrypted, encryptionKnown, facetID := encryptionState(record)
		if !encryptionKnown {
			unknown++
			continue
		}
		result.Applicable++
		if encrypted {
			result.Passing++
			result.PassEntityIDs[record.ID] = struct{}{}
			result.Evidence = append(result.Evidence, controlEvidence(record, facetID, policyID, ControlStatePassing, "Sensitive data asset is encrypted"))
			continue
		}
		result.Failing++
		result.FailEntityIDs[record.ID] = struct{}{}
		result.Evidence = append(result.Evidence, controlEvidence(record, facetID, policyID, ControlStateFailing, "Sensitive data asset is not encrypted"))
	}
	result.Status = summarizePolicyStatus(result, unknown, len(records))
	return result
}

func (e *graphComplianceEvaluator) evaluateSensitiveDataExposure(policyID string) policyEvaluation {
	records := e.entityRecords("", graph.NodeKindBucket, graph.NodeKindDatabase, graph.NodeKindService, graph.NodeKindSecret, graph.NodeKindFunction)
	result := newGraphPolicyEvaluation(policyID)
	if len(records) == 0 {
		result.Status = ControlStateNotApplicable
		return result
	}
	unknown := 0
	for _, record := range records {
		sensitive, sensitiveKnown := sensitiveDataState(record)
		if !sensitiveKnown || !sensitive {
			continue
		}
		public, publicKnown, facetID := publicExposureState(record)
		if !publicKnown {
			unknown++
			continue
		}
		result.Applicable++
		if public {
			result.Failing++
			result.FailEntityIDs[record.ID] = struct{}{}
			result.Evidence = append(result.Evidence, controlEvidence(record, facetID, policyID, ControlStateFailing, "Sensitive data asset is publicly exposed"))
			continue
		}
		result.Passing++
		result.PassEntityIDs[record.ID] = struct{}{}
		result.Evidence = append(result.Evidence, controlEvidence(record, facetID, policyID, ControlStatePassing, "Sensitive data asset is not publicly exposed"))
	}
	result.Status = summarizePolicyStatus(result, unknown, len(records))
	return result
}
