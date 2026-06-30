package apicontract

import (
	"os"
	"strings"
	"testing"
)

func TestQuestionnaireRunRoutesDocumentUnifiedQueueContract(t *testing.T) {
	docBytes, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	doc := string(docBytes)
	for _, path := range []string{
		"/grc/questionnaire-runs",
		"/grc/questionnaire-runs/{runID}",
		"/grc/questionnaire-runs/{runID}/process",
		"/grc/questionnaire-runs/{runID}/assignments",
		"/grc/questionnaire-runs/{runID}/decisions",
	} {
		if !strings.Contains(doc, "  "+path+":") {
			t.Fatalf("OpenAPI missing path %s", path)
		}
	}
	section := openAPIPathSection(t, doc, "/grc/questionnaire-runs")
	for _, want := range []string{
		"GRCQuestionnaireRunsResponse",
		"GRCQuestionnaireCreateRunRequest",
		"GRCQuestionnaireRunResponse",
	} {
		if !strings.Contains(section, want) {
			t.Fatalf("questionnaire runs OpenAPI section missing %q:\n%s", want, section)
		}
	}
	for _, want := range []string{
		"GRCQuestionnaireRun:",
		"GRCQuestionnaireRunAnswer:",
		"GRCQuestionnaireEvidenceSlot:",
		"GRCQuestionnaireCitation:",
		"GRCQuestionnaireRunEvidenceGap:",
		"GRCQuestionnaireDecisionRequest:",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("OpenAPI missing schema %q", want)
		}
	}
}
