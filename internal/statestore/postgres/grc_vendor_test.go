package postgres

import (
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
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

func TestQuestionnaireVendorRollupQueryBatchesVendors(t *testing.T) {
	now := time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC)
	query, args := questionnaireVendorRollupQuery(ports.QuestionnaireVendorRollupFilter{
		TenantID:   "writer",
		VendorURNs: []string{"urn:cerebro:writer:vendor:one", "urn:cerebro:writer:vendor:two"},
		Now:        now,
	})
	for _, fragment := range []string{
		"WITH filtered AS",
		"ROW_NUMBER() OVER",
		"PARTITION BY vendor_urn, COALESCE(NULLIF(attributes_json->>'questionnaire_urn', ''), run_id)",
		"current_questionnaires AS",
		"WHERE questionnaire_rank = 1",
		"vendor_urn IN ($2, $3)",
		"due_at <= $4",
		"CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(assignments_json) = 'array' THEN assignments_json ELSE '[]'::jsonb END)",
		"status NOT IN ('approved', 'rejected')",
		"LEFT JOIN open_assignments USING (tenant_id, run_id)",
		"COALESCE(open_assignments.open_assignment_count, 0)",
		"GROUP BY vendor_urn",
		"ORDER BY vendor_urn ASC",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("questionnaire vendor rollup query missing %q:\n%s", fragment, query)
		}
	}
	if len(args) != 4 || args[0] != "writer" || args[3] != now {
		t.Fatalf("args = %#v, want tenant, two vendors, and cutoff", args)
	}
}

func TestQuestionnaireRunOwnerFilterGuardsAssignmentJSONType(t *testing.T) {
	clauses, args := questionnaireRunWhere(ports.QuestionnaireRunFilter{OwnerID: "security"})
	query := strings.Join(clauses, "\n")
	for _, fragment := range []string{
		"jsonb_array_elements(CASE WHEN jsonb_typeof(assignments_json) = 'array' THEN assignments_json ELSE '[]'::jsonb END)",
		"lower(assignment->>'owner_id') LIKE $1",
		"lower(assignment->>'team') LIKE $1",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("questionnaire owner filter missing %q:\n%s", fragment, query)
		}
	}
	if len(args) != 1 || args[0] != "%security%" {
		t.Fatalf("args = %#v, want owner search arg", args)
	}
}

func TestMarshalQuestionnaireRunJSONUsesArraysForNilSlices(t *testing.T) {
	fields, err := marshalQuestionnaireRunJSON(ports.QuestionnaireRunRecord{})
	if err != nil {
		t.Fatalf("marshalQuestionnaireRunJSON() error = %v", err)
	}
	for label, value := range map[string]string{
		"questions":   fields.questions,
		"answers":     fields.answers,
		"assignments": fields.assignments,
		"decisions":   fields.decisions,
		"comments":    fields.comments,
		"timeline":    fields.timeline,
	} {
		if value != "[]" {
			t.Fatalf("%s JSON = %q, want []", label, value)
		}
	}
	if fields.attributes != "{}" {
		t.Fatalf("attributes JSON = %q, want {}", fields.attributes)
	}
}
