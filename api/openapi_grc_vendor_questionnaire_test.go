package apicontract

import (
	"os"
	"strings"
	"testing"
)

func TestGRCVendorQuestionnaireRoutesDocumentWorkflowContract(t *testing.T) {
	docBytes, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	doc := string(docBytes)
	for _, path := range []string{
		"/grc/vendors/{vendorID}/questionnaire-reviews",
		"/grc/vendor-questionnaire-reviews/{reviewID}",
		"/grc/vendor-questionnaire-reviews/{reviewID}/process",
		"/grc/vendor-questionnaire-reviews/{reviewID}/assignments",
		"/grc/vendor-questionnaire-reviews/{reviewID}/comments",
		"/grc/vendor-questionnaire-reviews/{reviewID}/approvals",
	} {
		if !strings.Contains(doc, "  "+path+":") {
			t.Fatalf("OpenAPI missing path %s", path)
		}
	}
	section := openAPIPathSection(t, doc, "/grc/vendors/{vendorID}/questionnaire-reviews")
	for _, want := range []string{
		"GRCVendorQuestionnaireReviewsResponse",
		"GRCVendorQuestionnaireCreateRequest",
		"GRCVendorQuestionnaireReviewResponse",
	} {
		if !strings.Contains(section, want) {
			t.Fatalf("vendor questionnaire OpenAPI section missing %q:\n%s", want, section)
		}
	}
	for _, want := range []string{
		"GRCVendorQuestionnaireEvidenceMatch:",
		"GRCVendorQuestionnaireAssignmentRequest:",
		"GRCVendorQuestionnaireApprovalRequest:",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("OpenAPI missing schema %q", want)
		}
	}
}
