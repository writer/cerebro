package main

import (
	"strings"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/graphingest"
)

func TestRenderMarkdownIncludesSections(t *testing.T) {
	catalog := graphingest.ContractCatalog{
		APIVersion:     "cerebro.graph.contracts/v1alpha1",
		Kind:           "CloudEventMappingContractCatalog",
		GeneratedAt:    time.Date(2026, 3, 9, 22, 0, 0, 0, time.UTC),
		EnvelopeFields: []graphingest.CloudEventFieldContract{{Name: "specversion", Type: "string", Required: true}},
		Mappings: []graphingest.MappingContract{{
			Name:             "m1",
			SourcePattern:    "ensemble.tap.incident.timeline.*",
			Domain:           "incident",
			WildcardPattern:  true,
			APIVersion:       "cerebro.graphingest/v1alpha1",
			ContractVersion:  "1.0.0",
			RequiredDataKeys: []string{"incident_id"},
		}},
		DistinctRequiredData: []string{"incident_id"},
	}
	output := renderMarkdown(catalog)
	for _, want := range []string{
		"# CloudEvents Auto-Generated Contract Catalog",
		"## CloudEvent Envelope",
		"## Mapping Contracts",
		"`m1`",
		"`ensemble.tap.incident.timeline.*`",
		"`cerebro.graphingest/v1alpha1`",
		"`1.0.0`",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected output to contain %q", want)
		}
	}
}
