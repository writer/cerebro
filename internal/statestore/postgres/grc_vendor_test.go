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

func TestQuestionnaireRunSchemaSerializesEvents(t *testing.T) {
	joined := strings.Join(ensureQuestionnaireRunStatements, "\n")
	for _, fragment := range []string{
		"grc_questionnaire_runs",
		"grc_questionnaire_run_events",
		"questions_json JSONB",
		"answers_json JSONB",
		"assignments_json JSONB",
		"decisions_json JSONB",
		"timeline_json JSONB",
		"grc_questionnaire_run_events_run_version_uidx",
		"(tenant_id, run_id, version)",
		"grc_questionnaire_runs_tenant_status_idx",
		"grc_questionnaire_runs_tenant_direction_idx",
		"grc_questionnaire_runs_tenant_vendor_idx",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("questionnaire run schema missing %q:\n%s", fragment, joined)
		}
	}
}

func TestQuestionnaireRunAdvisoryLockSerializesUpserts(t *testing.T) {
	query := questionnaireRunAdvisoryLockSQL()
	for _, fragment := range []string{
		"pg_advisory_xact_lock",
		"hashtext('grc_questionnaire_run')",
		"hashtext($1)",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("questionnaire run advisory lock query missing %q:\n%s", fragment, query)
		}
	}
}
