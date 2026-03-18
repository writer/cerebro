package reports

import "testing"

func TestEntityFacetCoveragePercentExcludesMissingFacets(t *testing.T) {
	entity := EntityRecord{
		Kind: NodeKindService,
		Facets: []EntityFacetRecord{
			{ID: "ownership", Status: "present"},
			{ID: "exposure", Status: "missing"},
			{ID: "data_sensitivity", Status: "missing"},
		},
	}

	coverage := entityFacetCoveragePercent(entity)
	if coverage >= 100 {
		t.Fatalf("expected missing facets to reduce coverage, got %.2f", coverage)
	}
	if coverage != (100.0 / 3.0) {
		t.Fatalf("expected one of three applicable service facets to count, got %.2f", coverage)
	}
}
