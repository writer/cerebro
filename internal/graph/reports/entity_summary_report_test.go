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
	applicable := 0
	for _, def := range defaultEntityFacetDefinitions {
		if entityFacetAppliesToNode(def, entity.Kind) {
			applicable++
		}
	}
	expected := 100.0 / float64(applicable)
	if coverage != expected {
		t.Fatalf("expected one of %d applicable service facets to count, got %.2f", applicable, coverage)
	}
}
