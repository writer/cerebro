package main

import (
	"path/filepath"
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions/openapigen"
	"github.com/writer/cerebro/internal/providercontractlock"
)

func TestContractSelectionsPreserveGeneratedEndpointIdentity(t *testing.T) {
	selections := contractSelections([]openapigen.Endpoint{{
		FamilyID:    "audit_events",
		Method:      "GET",
		Path:        "/v1/audit/events",
		OperationID: "listAuditEvents",
	}})
	if len(selections) != 1 {
		t.Fatalf("selections = %#v", selections)
	}
	selection := selections[0]
	if selection.FamilyID != "audit_events" || selection.Method != "GET" || selection.Path != "/v1/audit/events" || selection.OperationID != "listAuditEvents" {
		t.Fatalf("selection = %#v", selection)
	}
}

func TestProviderContractOutputPath(t *testing.T) {
	if got := providerContractOutputPath("/workspace", "example", "", ""); got != filepath.Join("/workspace", "sources", "example", ".provider-contract-lock.json") {
		t.Fatalf("default output path = %q", got)
	}
	if got := providerContractOutputPath("/workspace", "example", "/reviewed.json", ""); got != "/reviewed.json" {
		t.Fatalf("input-backed output path = %q", got)
	}
	if got := providerContractOutputPath("/workspace", "example", "/reviewed.json", "/next.json"); got != "/next.json" {
		t.Fatalf("explicit output path = %q", got)
	}
}

func TestContractChangeNeedsReview(t *testing.T) {
	for _, status := range []string{providercontractlock.DriftBehavioralReview, providercontractlock.DriftBreaking} {
		if !contractChangeNeedsReview(providercontractlock.Drift{Status: status}) {
			t.Fatalf("status %q did not require review", status)
		}
	}
	for _, status := range []string{providercontractlock.DriftNew, providercontractlock.DriftUnchanged, providercontractlock.DriftAdditive} {
		if contractChangeNeedsReview(providercontractlock.Drift{Status: status}) {
			t.Fatalf("status %q unexpectedly required a blocking review", status)
		}
	}
}
