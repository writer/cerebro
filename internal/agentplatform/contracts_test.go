package agentplatform

import "testing"

func TestContractDomainsHaveRequiredFields(t *testing.T) {
	if ContractVersion == "" {
		t.Fatal("contract version must be set")
	}
	for _, domain := range Domains {
		if domain.ID == "" || domain.Name == "" || domain.Principle == "" {
			t.Fatalf("domain has empty required field: %+v", domain)
		}
		if len(domain.Owns) == 0 {
			t.Fatalf("domain %q must name owned surfaces", domain.ID)
		}
		if len(domain.MustExpose) == 0 {
			t.Fatalf("domain %q must name exposed diagnostics", domain.ID)
		}
	}
}

func TestInvariantsReferenceKnownDomains(t *testing.T) {
	ids := map[string]bool{}
	for _, invariant := range Invariants {
		if invariant.ID == "" || invariant.Statement == "" {
			t.Fatalf("invariant has empty required field: %+v", invariant)
		}
		if ids[invariant.ID] {
			t.Fatalf("duplicate invariant id %q", invariant.ID)
		}
		ids[invariant.ID] = true
		if _, ok := DomainByID(invariant.DomainID); !ok {
			t.Fatalf("invariant %q references unknown domain %q", invariant.ID, invariant.DomainID)
		}
	}
}
