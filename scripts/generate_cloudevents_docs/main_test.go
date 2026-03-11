package main

import (
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/platformevents"
)

func TestRenderMarkdownIncludesSections(t *testing.T) {
	catalog := graphingest.ContractCatalog{
		APIVersion:     "cerebro.graph.contracts/v1alpha1",
		Kind:           "CloudEventMappingContractCatalog",
		GeneratedAt:    time.Date(2026, 3, 9, 22, 0, 0, 0, time.UTC),
		EnvelopeFields: []graphingest.CloudEventFieldContract{{Name: "specversion", Type: "string", Required: true}},
		LifecycleEvents: []platformevents.LifecycleEventContract{{
			EventType:        "platform.claim.written",
			Summary:          "Claim recorded",
			SchemaURL:        "urn:cerebro:events/platform.claim.written/v1",
			RequiredDataKeys: []string{"claim_id"},
			OptionalDataKeys: []string{"tenant_id"},
		}},
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
		"## Platform Lifecycle Event Contracts",
		"`platform.claim.written`",
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
