package postgres

import (
	"strings"
	"testing"
)

func TestGRCVendorDiscoveryDecisionSchemaSerializesEvents(t *testing.T) {
	joined := strings.Join(ensureGRCVendorDiscoveryDecisionStatements, "\n")
	for _, fragment := range []string{
		"grc_vendor_discovery_decision_events_tenant_discovery_version_uidx",
		"(tenant_id, discovery_urn, version)",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("vendor discovery decision schema missing %q:\n%s", fragment, joined)
		}
	}
}

func TestGRCVendorDiscoveryDecisionAdvisoryLockSerializesUpserts(t *testing.T) {
	query := grcVendorDiscoveryDecisionAdvisoryLockSQL()
	for _, fragment := range []string{
		"pg_advisory_xact_lock",
		"hashtext('grc_vendor_discovery_decision')",
		"hashtext($1)",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("vendor discovery decision advisory lock query missing %q:\n%s", fragment, query)
		}
	}
}

func TestGRCVendorQuestionnaireReviewSchemaSerializesEvents(t *testing.T) {
	joined := strings.Join(ensureGRCVendorQuestionnaireStatements, "\n")
	for _, fragment := range []string{
		"grc_vendor_questionnaire_reviews",
		"grc_vendor_questionnaire_review_events",
		"assignments_json JSONB",
		"evidence_matches_json JSONB",
		"missing_questions_json JSONB",
		"answer_suggestions_json JSONB",
		"timeline_json JSONB",
		"grc_vendor_questionnaire_review_events_review_version_uidx",
		"(tenant_id, review_id, version)",
		"grc_vendor_questionnaire_reviews_tenant_status_idx",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("vendor questionnaire review schema missing %q:\n%s", fragment, joined)
		}
	}
}

func TestGRCVendorQuestionnaireReviewAdvisoryLockSerializesUpserts(t *testing.T) {
	query := grcVendorQuestionnaireReviewAdvisoryLockSQL()
	for _, fragment := range []string{
		"pg_advisory_xact_lock",
		"hashtext('grc_vendor_questionnaire_review')",
		"hashtext($1)",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("vendor questionnaire review advisory lock query missing %q:\n%s", fragment, query)
		}
	}
}
