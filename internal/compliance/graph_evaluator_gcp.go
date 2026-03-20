package compliance

import "github.com/writer/cerebro/internal/graph"

var gcpPolicyEvaluators = map[string]registeredPolicyEvaluator{
	"gcp-storage-bucket-no-public": {
		definition: GraphQueryDefinition{ID: "gcp-storage-bucket-no-public", Provider: "gcp", Description: "Evaluate whether GCS buckets are publicly accessible"},
		evaluate: func(e *graphComplianceEvaluator, policyID string) policyEvaluation {
			return e.evaluateFacetBoolPolicy(policyID, "gcp", []graph.NodeKind{graph.NodeKindBucket}, "bucket_public_access", "public_access", false, "Bucket is not publicly accessible", "Bucket is publicly accessible")
		},
	},
	"gcp-storage-no-public-allusers": {
		definition: GraphQueryDefinition{ID: "gcp-storage-no-public-allusers", Provider: "gcp", Description: "Evaluate whether GCS bucket policies expose public principals"},
		evaluate: func(e *graphComplianceEvaluator, policyID string) policyEvaluation {
			return e.evaluateBucketPublicPolicy(policyID, "gcp")
		},
	},
	"gcp-iam-sa-no-admin-privileges": {
		definition: GraphQueryDefinition{ID: "gcp-iam-sa-no-admin-privileges", Provider: "gcp", Description: "Evaluate whether service accounts avoid admin or high-privilege roles"},
		evaluate: func(e *graphComplianceEvaluator, policyID string) policyEvaluation {
			return e.evaluateServiceAccountAdminPrivileges(policyID)
		},
	},
	"gcp-sa-admin-privileges": {
		definition: GraphQueryDefinition{ID: "gcp-sa-admin-privileges", Provider: "gcp", Description: "Evaluate whether service accounts avoid admin or high-privilege roles"},
		evaluate: func(e *graphComplianceEvaluator, policyID string) policyEvaluation {
			return e.evaluateServiceAccountAdminPrivileges(policyID)
		},
	},
	"gcp-service-account-key-rotation": {
		definition: GraphQueryDefinition{ID: "gcp-service-account-key-rotation", Provider: "gcp", Description: "Evaluate whether service account user-managed keys rotate within 90 days"},
		evaluate: func(e *graphComplianceEvaluator, policyID string) policyEvaluation {
			return e.evaluateServiceAccountKeyRotation(policyID)
		},
	},
	"gcp-iam-minimize-user-managed-keys": {
		definition: GraphQueryDefinition{ID: "gcp-iam-minimize-user-managed-keys", Provider: "gcp", Description: "Evaluate whether service accounts minimize user-managed keys"},
		evaluate: func(e *graphComplianceEvaluator, policyID string) policyEvaluation {
			return e.evaluateServiceAccountMinimizeKeys(policyID)
		},
	},
}

func (e *graphComplianceEvaluator) evaluateServiceAccountAdminPrivileges(policyID string) policyEvaluation {
	records := e.entityRecords("gcp", graph.NodeKindServiceAccount)
	result := newGraphPolicyEvaluation(policyID)
	if len(records) == 0 {
		result.Status = ControlStateNotApplicable
		return result
	}
	unknown := 0
	for _, record := range records {
		hasAdmin, okAdmin := firstBool(record.Properties, "has_admin_role")
		hasHighPriv, okHigh := firstBool(record.Properties, "has_high_privilege")
		if !okAdmin && !okHigh {
			unknown++
			continue
		}
		result.Applicable++
		if hasAdmin || hasHighPriv {
			result.Failing++
			result.FailEntityIDs[record.ID] = struct{}{}
			result.Evidence = append(result.Evidence, controlEvidence(record, "", policyID, ControlStateFailing, "Service account has admin or high-privilege roles"))
			continue
		}
		result.Passing++
		result.PassEntityIDs[record.ID] = struct{}{}
		result.Evidence = append(result.Evidence, controlEvidence(record, "", policyID, ControlStatePassing, "Service account does not have admin or high-privilege roles"))
	}
	result.Status = summarizePolicyStatus(result, unknown, len(records))
	return result
}

func (e *graphComplianceEvaluator) evaluateServiceAccountKeyRotation(policyID string) policyEvaluation {
	records := e.entityRecords("gcp", graph.NodeKindServiceAccount)
	result := newGraphPolicyEvaluation(policyID)
	if len(records) == 0 {
		result.Status = ControlStateNotApplicable
		return result
	}
	unknown := 0
	for _, record := range records {
		hasKeys, okKeys := firstBool(record.Properties, "has_access_keys")
		if !okKeys {
			unknown++
			continue
		}
		if !hasKeys {
			result.Applicable++
			result.Passing++
			result.PassEntityIDs[record.ID] = struct{}{}
			result.Evidence = append(result.Evidence, controlEvidence(record, "", policyID, ControlStatePassing, "Service account has no user-managed keys"))
			continue
		}
		oldestKeyAge, okAge := firstInt(record.Properties, "oldest_key_age_days")
		if !okAge {
			unknown++
			continue
		}
		result.Applicable++
		if oldestKeyAge <= 90 {
			result.Passing++
			result.PassEntityIDs[record.ID] = struct{}{}
			result.Evidence = append(result.Evidence, controlEvidence(record, "", policyID, ControlStatePassing, "Service account keys are rotated within 90 days"))
			continue
		}
		result.Failing++
		result.FailEntityIDs[record.ID] = struct{}{}
		result.Evidence = append(result.Evidence, controlEvidence(record, "", policyID, ControlStateFailing, "Service account keys are older than 90 days"))
	}
	result.Status = summarizePolicyStatus(result, unknown, len(records))
	return result
}

func (e *graphComplianceEvaluator) evaluateServiceAccountMinimizeKeys(policyID string) policyEvaluation {
	records := e.entityRecords("gcp", graph.NodeKindServiceAccount)
	result := newGraphPolicyEvaluation(policyID)
	if len(records) == 0 {
		result.Status = ControlStateNotApplicable
		return result
	}
	unknown := 0
	for _, record := range records {
		hasKeys, ok := firstBool(record.Properties, "has_access_keys")
		if !ok {
			unknown++
			continue
		}
		result.Applicable++
		if hasKeys {
			result.Failing++
			result.FailEntityIDs[record.ID] = struct{}{}
			result.Evidence = append(result.Evidence, controlEvidence(record, "", policyID, ControlStateFailing, "Service account uses user-managed keys"))
			continue
		}
		result.Passing++
		result.PassEntityIDs[record.ID] = struct{}{}
		result.Evidence = append(result.Evidence, controlEvidence(record, "", policyID, ControlStatePassing, "Service account has no user-managed keys"))
	}
	result.Status = summarizePolicyStatus(result, unknown, len(records))
	return result
}
