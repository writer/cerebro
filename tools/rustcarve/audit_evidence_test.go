package main

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestPolicyEventAuditEvidenceBatchFailsClosedWithCanonicalReasons(t *testing.T) {
	request, err := loadCarveRequest("testdata/policy-event-audit-evidence.request.json")
	if err != nil {
		t.Fatal(err)
	}
	if request.Subject.AuthorityState != "go_evaluator_active" {
		t.Fatalf("authority state = %q, want active Go evaluator", request.Subject.AuthorityState)
	}
	result, err := distill(repositoryRoot(t), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Unsupported == nil {
		t.Fatal("audit-evidence batch produced migration artifacts")
	}
	wantReasons := []reasonCode{reasonUnsupportedGraphAnchor, reasonUnsupportedLifecycle}
	if !reflect.DeepEqual(result.Unsupported.ReasonCodes, wantReasons) {
		t.Fatalf("unsupported reasons = %v, want %v", result.Unsupported.ReasonCodes, wantReasons)
	}
	if len(result.Artifacts) != 0 || result.Manifest.Eligible {
		t.Fatalf("unsupported batch emitted artifacts or deletion eligibility: %#v", result)
	}

	payload, err := os.ReadFile("testdata/golden/policy-event-audit-evidence/unsupported.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden unsupportedReport
	if err := json.Unmarshal(payload, &golden); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*result.Unsupported, golden) {
		t.Fatalf("unsupported result differs from golden: got %#v want %#v", *result.Unsupported, golden)
	}
}
