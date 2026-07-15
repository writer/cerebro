package apicontract

import (
	"os"
	"strings"
	"testing"
)

func TestComplianceReadRoutesRemainContractOnlyAndUseDistinctScopes(t *testing.T) {
	payload, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(payload)
	tests := []struct {
		path  string
		scope string
	}{
		{path: "/grc/programs", scope: "cerebro.compliance.programs.read"},
		{path: "/grc/programs/{programID}", scope: "cerebro.compliance.programs.read"},
		{path: "/grc/programs/{programID}/control-implementations", scope: "cerebro.compliance.programs.read"},
		{path: "/grc/control-implementations/{implementationID}", scope: "cerebro.compliance.programs.read"},
		{path: "/grc/evidence-artifacts", scope: "cerebro.compliance.evidence.read"},
		{path: "/grc/evidence-artifacts/{evidenceArtifactID}", scope: "cerebro.compliance.evidence.read"},
		{path: "/grc/assessment-plans", scope: "cerebro.compliance.assessments.read"},
		{path: "/grc/assessment-plans/{planID}", scope: "cerebro.compliance.assessments.read"},
		{path: "/grc/compliance-assessments", scope: "cerebro.compliance.assessments.read"},
		{path: "/grc/compliance-assessments/{runID}", scope: "cerebro.compliance.assessments.read"},
		{path: "/grc/compliance-assessments/{runID}/objectives", scope: "cerebro.compliance.assessments.read"},
		{path: "/grc/compliance-results/{resultID}", scope: "cerebro.compliance.assessments.read"},
		{path: "/grc/compliance-assessments/{runID}/reviews", scope: "cerebro.compliance.assessments.read"},
		{path: "/grc/compliance-reviews/{reviewID}", scope: "cerebro.compliance.assessments.read"},
		{path: "/grc/compliance-work-items", scope: "cerebro.compliance.work.read"},
		{path: "/grc/compliance-work-items/{workItemID}", scope: "cerebro.compliance.work.read"},
	}
	for _, test := range tests {
		section := openAPIPathSection(t, doc, test.path)
		for _, want := range []string{
			"x-cerebro-route-state: contract_only",
			"x-required-scope: " + test.scope,
		} {
			if !strings.Contains(section, want) {
				t.Fatalf("OpenAPI path %s missing %q:\n%s", test.path, want, section)
			}
		}
	}
}

func TestComplianceReadSchemasExposeRevisionAndPagingContracts(t *testing.T) {
	payload, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(payload)
	for _, want := range []string{
		"ComplianceRevisionMetadata:",
		"required: [id, revision_id, version, content_digest, last_modified, etag]",
		"description: Opaque cursor present only when another page is available.",
		"EvidenceArtifactMetadata:",
		"Raw evidence content is intentionally excluded.",
		"ComplianceWorkItem:",
		"aggregate_version:",
		"ComplianceNotFound:",
		"Foreign-tenant records use this same response.",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("OpenAPI compliance contract missing %q", want)
		}
	}
}
