package findings

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/policy"
)

type fakePolicyCatalog struct {
	policies []*policy.Policy
	byID     map[string]*policy.Policy
}

func (f *fakePolicyCatalog) ListPolicies() []*policy.Policy {
	return append([]*policy.Policy(nil), f.policies...)
}

func (f *fakePolicyCatalog) GetPolicy(id string) (*policy.Policy, bool) {
	p, ok := f.byID[id]
	return p, ok
}

func TestComplianceReporterUsesPolicyCatalogInterface(t *testing.T) {
	store := NewStore()
	store.Upsert(context.Background(), policy.Finding{
		ID:         "finding-1",
		PolicyID:   "policy-1",
		ResourceID: "resource-1",
		Resource: map[string]interface{}{
			"_cq_id": "resource-1",
		},
	})

	p := &policy.Policy{
		ID: "policy-1",
		Frameworks: []policy.FrameworkMapping{{
			Name:     "NIST 800-53",
			Controls: []string{"AC-1"},
		}},
	}
	reporter := NewComplianceReporter(store, &fakePolicyCatalog{
		policies: []*policy.Policy{p},
		byID:     map[string]*policy.Policy{"policy-1": p},
	})

	report := reporter.GenerateFrameworkReport("NIST 800-53")
	if report.FailingControls != 1 {
		t.Fatalf("failing controls = %d, want 1", report.FailingControls)
	}
	status, ok := report.ControlStatus["AC-1"]
	if !ok {
		t.Fatal("expected control AC-1")
	}
	if status.Status != "FAIL" {
		t.Fatalf("status = %q, want FAIL", status.Status)
	}
}
