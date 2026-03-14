package compliance

import (
	"strings"

	"github.com/evalops/cerebro/internal/graph"
)

var awsPolicyEvaluators = map[string]registeredPolicyEvaluator{
	"aws-s3-bucket-encryption-enabled": {
		definition: GraphQueryDefinition{ID: "aws-s3-bucket-encryption-enabled", Provider: "aws", Description: "Evaluate default S3 bucket encryption state"},
		evaluate: func(e *graphComplianceEvaluator, policyID string) policyEvaluation {
			return e.evaluateFacetBoolPolicy(policyID, "aws", []graph.NodeKind{graph.NodeKindBucket}, "bucket_encryption", "encrypted", true, "Bucket encryption is enabled", "Bucket encryption is disabled or incomplete")
		},
	},
	"aws-s3-bucket-no-public-access": {
		definition: GraphQueryDefinition{ID: "aws-s3-bucket-no-public-access", Provider: "aws", Description: "Evaluate whether S3 buckets are publicly accessible"},
		evaluate: func(e *graphComplianceEvaluator, policyID string) policyEvaluation {
			return e.evaluateFacetBoolPolicy(policyID, "aws", []graph.NodeKind{graph.NodeKindBucket}, "bucket_public_access", "public_access", false, "Bucket is not publicly accessible", "Bucket is publicly accessible")
		},
	},
	"aws-s3-bucket-policy-public": {
		definition: GraphQueryDefinition{ID: "aws-s3-bucket-policy-public", Provider: "aws", Description: "Evaluate whether S3 bucket policies expose public principals"},
		evaluate: func(e *graphComplianceEvaluator, policyID string) policyEvaluation {
			return e.evaluateBucketPublicPolicy(policyID, "aws")
		},
	},
	"aws-s3-bucket-logging-enabled": {
		definition: GraphQueryDefinition{ID: "aws-s3-bucket-logging-enabled", Provider: "aws", Description: "Evaluate whether S3 bucket access logging is enabled"},
		evaluate: func(e *graphComplianceEvaluator, policyID string) policyEvaluation {
			return e.evaluateFacetBoolPolicy(policyID, "aws", []graph.NodeKind{graph.NodeKindBucket}, "bucket_logging", "logging_enabled", true, "Bucket access logging is enabled", "Bucket access logging is disabled")
		},
	},
	"aws-s3-bucket-versioning-enabled": {
		definition: GraphQueryDefinition{ID: "aws-s3-bucket-versioning-enabled", Provider: "aws", Description: "Evaluate whether S3 bucket versioning is enabled"},
		evaluate: func(e *graphComplianceEvaluator, policyID string) policyEvaluation {
			return e.evaluateBucketVersioning(policyID, "aws")
		},
	},
	"aws-rds-encryption-enabled": {
		definition: GraphQueryDefinition{ID: "aws-rds-encryption-enabled", Provider: "aws", Description: "Evaluate whether RDS instances are encrypted at rest"},
		evaluate: func(e *graphComplianceEvaluator, policyID string) policyEvaluation {
			return e.evaluatePropertyBoolPolicy(policyID, "aws", []graph.NodeKind{graph.NodeKindDatabase}, []string{"encrypted", "storage_encrypted", "kms_encrypted"}, true, "", "Database encryption is enabled", "Database encryption is disabled")
		},
	},
	"aws-rds-no-public-access": {
		definition: GraphQueryDefinition{ID: "aws-rds-no-public-access", Provider: "aws", Description: "Evaluate whether RDS instances avoid public network exposure"},
		evaluate: func(e *graphComplianceEvaluator, policyID string) policyEvaluation {
			return e.evaluatePropertyBoolPolicy(policyID, "aws", []graph.NodeKind{graph.NodeKindDatabase}, []string{"public", "public_access", "publicly_accessible"}, false, "", "Database is not publicly accessible", "Database is publicly accessible")
		},
	},
}

func (e *graphComplianceEvaluator) evaluateFacetBoolPolicy(policyID, provider string, kinds []graph.NodeKind, facetID, field string, expected bool, passReason, failReason string) policyEvaluation {
	records := e.entityRecords(provider, kinds...)
	result := newGraphPolicyEvaluation(policyID)
	if len(records) == 0 {
		result.Status = ControlStateNotApplicable
		return result
	}
	unknown := 0
	for _, record := range records {
		facet, ok := entityFacet(record, facetID)
		if !ok {
			unknown++
			continue
		}
		value, ok := boolField(facet.Fields, field)
		if !ok {
			unknown++
			continue
		}
		result.Applicable++
		if value == expected {
			result.Passing++
			result.PassEntityIDs[record.ID] = struct{}{}
			result.Evidence = append(result.Evidence, controlEvidence(record, facetID, policyID, ControlStatePassing, passReason))
			continue
		}
		result.Failing++
		result.FailEntityIDs[record.ID] = struct{}{}
		result.Evidence = append(result.Evidence, controlEvidence(record, facetID, policyID, ControlStateFailing, failReason))
	}
	result.Status = summarizePolicyStatus(result, unknown, len(records))
	return result
}

func (e *graphComplianceEvaluator) evaluateBucketPublicPolicy(policyID, provider string) policyEvaluation {
	records := e.entityRecords(provider, graph.NodeKindBucket)
	result := newGraphPolicyEvaluation(policyID)
	if len(records) == 0 {
		result.Status = ControlStateNotApplicable
		return result
	}
	unknown := 0
	for _, record := range records {
		facet, ok := entityFacet(record, "bucket_public_access")
		if !ok {
			unknown++
			continue
		}
		publicAccess, publicKnown := boolField(facet.Fields, "public_access")
		allUsers, allUsersKnown := boolField(facet.Fields, "all_users_access")
		allAuthenticated, authKnown := boolField(facet.Fields, "all_authenticated_users_access")
		if !publicKnown && !allUsersKnown && !authKnown {
			unknown++
			continue
		}
		result.Applicable++
		public := (publicKnown && publicAccess) || (allUsersKnown && allUsers) || (authKnown && allAuthenticated)
		if public {
			result.Failing++
			result.FailEntityIDs[record.ID] = struct{}{}
			result.Evidence = append(result.Evidence, controlEvidence(record, "bucket_public_access", policyID, ControlStateFailing, "Bucket policy or access posture allows public principals"))
			continue
		}
		result.Passing++
		result.PassEntityIDs[record.ID] = struct{}{}
		result.Evidence = append(result.Evidence, controlEvidence(record, "bucket_public_access", policyID, ControlStatePassing, "Bucket policy does not expose public principals"))
	}
	result.Status = summarizePolicyStatus(result, unknown, len(records))
	return result
}

func (e *graphComplianceEvaluator) evaluateBucketVersioning(policyID, provider string) policyEvaluation {
	records := e.entityRecords(provider, graph.NodeKindBucket)
	result := newGraphPolicyEvaluation(policyID)
	if len(records) == 0 {
		result.Status = ControlStateNotApplicable
		return result
	}
	unknown := 0
	for _, record := range records {
		facet, ok := entityFacet(record, "bucket_versioning")
		if !ok {
			unknown++
			continue
		}
		status := strings.TrimSpace(strings.ToLower(stringField(facet.Fields, "versioning_status")))
		if status == "" {
			unknown++
			continue
		}
		result.Applicable++
		if status == "enabled" || status == "on" {
			result.Passing++
			result.PassEntityIDs[record.ID] = struct{}{}
			result.Evidence = append(result.Evidence, controlEvidence(record, "bucket_versioning", policyID, ControlStatePassing, "Bucket versioning is enabled"))
			continue
		}
		result.Failing++
		result.FailEntityIDs[record.ID] = struct{}{}
		result.Evidence = append(result.Evidence, controlEvidence(record, "bucket_versioning", policyID, ControlStateFailing, "Bucket versioning is not enabled"))
	}
	result.Status = summarizePolicyStatus(result, unknown, len(records))
	return result
}

func (e *graphComplianceEvaluator) evaluatePropertyBoolPolicy(policyID, provider string, kinds []graph.NodeKind, keys []string, expected bool, facetID, passReason, failReason string) policyEvaluation {
	records := e.entityRecords(provider, kinds...)
	result := newGraphPolicyEvaluation(policyID)
	if len(records) == 0 {
		result.Status = ControlStateNotApplicable
		return result
	}
	unknown := 0
	for _, record := range records {
		value, ok := firstBool(record.Properties, keys...)
		if !ok {
			unknown++
			continue
		}
		result.Applicable++
		if value == expected {
			result.Passing++
			result.PassEntityIDs[record.ID] = struct{}{}
			result.Evidence = append(result.Evidence, controlEvidence(record, facetID, policyID, ControlStatePassing, passReason))
			continue
		}
		result.Failing++
		result.FailEntityIDs[record.ID] = struct{}{}
		result.Evidence = append(result.Evidence, controlEvidence(record, facetID, policyID, ControlStateFailing, failReason))
	}
	result.Status = summarizePolicyStatus(result, unknown, len(records))
	return result
}
