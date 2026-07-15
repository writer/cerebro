package main

import (
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcecertification"
)

func TestBuildConnectorCatalogCLIResponsePreservesCatalogOnlyDiscovery(t *testing.T) {
	response := buildConnectorCatalogCLIResponse(
		time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC),
		sourcecertification.AvailabilityPolicy{MinimumTier: sourcecertification.TierContractTested},
		[]*cerebrov1.SourceSpec{{Id: "compiled", Name: "Compiled"}},
		connectorcatalog.Analysis{Entries: []connectorcatalog.Entry{{Definition: connectordefinitions.Definition{SourceID: "catalog-only", DisplayName: "Catalog only"}, Status: connectorcatalog.StatusGenerateable}}},
	)
	seenBelowMinimum := false
	for _, entry := range response.Connectors {
		if !entry.Availability.Discoverable {
			t.Fatalf("connector %q was hidden by availability gate", entry.SourceID)
		}
		if entry.Availability.State == sourcecertification.AvailabilityBelowMinimum {
			seenBelowMinimum = true
		}
	}
	if len(response.Connectors) != 2 {
		t.Fatalf("connector count = %d, want compiled and catalog-only entries", len(response.Connectors))
	}
	if !seenBelowMinimum {
		t.Fatal("expected at least one discoverable below-minimum connector")
	}
}
