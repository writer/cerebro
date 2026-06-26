package grcproductareas

import (
	"testing"

	"github.com/writer/cerebro/internal/sourcecoverage"
)

func coverageRecord(overrides sourcecoverage.Record) sourcecoverage.Record {
	record := sourcecoverage.Record{
		SourceID:      "grc",
		DimensionID:   "vendors",
		DimensionType: "entity_family",
		Title:         "Vendors",
		State:         sourcecoverage.StateUnconfigured,
		SupportLevel:  "supported",
		BlindSpot:     true,
	}
	if overrides.SourceID != "" {
		record.SourceID = overrides.SourceID
	}
	if overrides.DimensionID != "" {
		record.DimensionID = overrides.DimensionID
	}
	if overrides.DimensionType != "" {
		record.DimensionType = overrides.DimensionType
	}
	if overrides.Title != "" {
		record.Title = overrides.Title
	}
	if overrides.Family != "" {
		record.Family = overrides.Family
	}
	if overrides.EvidenceTypes != nil {
		record.EvidenceTypes = overrides.EvidenceTypes
	}
	if overrides.ControlDomains != nil {
		record.ControlDomains = overrides.ControlDomains
	}
	return record
}

func TestCatalogDefinesStableProductAreas(t *testing.T) {
	areas := Catalog()
	got := make([]string, 0, len(areas))
	seen := map[string]bool{}
	for _, area := range areas {
		if area.ID == "" || area.Title == "" || area.Href == "" || area.Description == "" {
			t.Fatalf("area has incomplete identity fields: %#v", area)
		}
		if len(area.Workflows) == 0 || len(area.SourceFamilies) == 0 || len(area.CoverageDimensions) == 0 {
			t.Fatalf("area %q is missing workflow, family, or dimension coverage", area.ID)
		}
		if seen[area.ID] {
			t.Fatalf("duplicate area id %q", area.ID)
		}
		seen[area.ID] = true
		got = append(got, area.ID)
	}
	want := []string{"compliance", "customer_trust", "risk", "vendors", "privacy", "assets", "personnel", "integrations"}
	if len(got) != len(want) {
		t.Fatalf("product area ids = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("product area ids = %v, want %v", got, want)
		}
	}
}

func TestMatchesCoverageByDimensionFamilyEvidenceAndDomain(t *testing.T) {
	var vendors Area
	for _, area := range Catalog() {
		if area.ID == "vendors" {
			vendors = area
		}
	}
	if vendors.ID == "" {
		t.Fatal("vendors area not found")
	}
	if !MatchesCoverage(vendors, coverageRecord(sourcecoverage.Record{DimensionID: "discovered_vendors"})) {
		t.Fatal("vendors should match discovered_vendors dimension")
	}
	if !MatchesCoverage(vendors, coverageRecord(sourcecoverage.Record{DimensionID: "other", Family: "vendor_risk_attribute"})) {
		t.Fatal("vendors should match vendor_risk_attribute family")
	}
	if MatchesCoverage(vendors, coverageRecord(sourcecoverage.Record{DimensionID: "vulnerability_remediations"})) {
		t.Fatal("vendors should not claim known asset dimensions")
	}
}

func TestUnknownCoverageFallbackRequiresSingleOwner(t *testing.T) {
	views := BuildViews(BuildInput{
		CoverageBlindSpots: []sourcecoverage.Record{
			coverageRecord(sourcecoverage.Record{
				DimensionID:   "new_generic_snapshot_gap",
				EvidenceTypes: []string{"source_snapshot"},
				Title:         "Generic source snapshot gap",
			}),
		},
		HasCoverageContext: true,
	})
	for _, view := range views {
		if len(view.BlindSpots) != 0 {
			t.Fatalf("%s claimed ambiguous generic snapshot gap: %+v", view.ID, view.BlindSpots)
		}
	}
}

func TestPersonnelOwnsUsersDimensionWithoutFamily(t *testing.T) {
	var personnel Area
	for _, area := range Catalog() {
		if area.ID == "personnel" {
			personnel = area
		}
	}
	if personnel.ID == "" {
		t.Fatal("personnel area not found")
	}
	if !MatchesCoverage(personnel, coverageRecord(sourcecoverage.Record{DimensionID: "users"})) {
		t.Fatal("personnel should match users dimension without requiring a family tag")
	}
}

func TestKnownDimensionsStayScopedToOwningArea(t *testing.T) {
	var customerTrust Area
	for _, area := range Catalog() {
		if area.ID == "customer_trust" {
			customerTrust = area
		}
	}
	if customerTrust.ID == "" {
		t.Fatal("customer trust area not found")
	}
	if MatchesCoverage(customerTrust, coverageRecord(sourcecoverage.Record{
		DimensionID:    "vendor_risk_attributes",
		EvidenceTypes:  []string{"third_party_risk"},
		ControlDomains: []string{"vendor_risk"},
	})) {
		t.Fatal("customer trust should not claim a known vendor dimension through shared evidence or domain tags")
	}
	if !MatchesCoverage(customerTrust, coverageRecord(sourcecoverage.Record{
		DimensionID: "security_questionnaires",
		Family:      "security_questionnaire",
	})) {
		t.Fatal("customer trust should claim security questionnaires")
	}
}

func TestBuildViewsAnnotatesBlindSpotsAndStatuses(t *testing.T) {
	views := BuildViews(BuildInput{
		CoverageBlindSpots: []sourcecoverage.Record{
			coverageRecord(sourcecoverage.Record{DimensionID: "vendor_risk_attributes", Title: "Vendor risk attributes"}),
			coverageRecord(sourcecoverage.Record{DimensionID: "vulnerability_remediations", Title: "Vulnerability remediations"}),
		},
		HasCoverageContext: true,
	})
	byID := map[string]View{}
	for _, view := range views {
		byID[view.ID] = view
	}
	if got := byID["vendors"].Status; got != StatusAttention {
		t.Fatalf("vendors status = %q, want %q", got, StatusAttention)
	}
	if got := len(byID["vendors"].BlindSpots); got != 1 {
		t.Fatalf("vendors blind spots = %d, want 1", got)
	}
	if got := byID["assets"].Status; got != StatusAttention {
		t.Fatalf("assets status = %q, want %q", got, StatusAttention)
	}
	if got := byID["compliance"].Status; got != StatusMapped {
		t.Fatalf("compliance status = %q, want %q", got, StatusMapped)
	}
}

func TestBuildViewsUsesQuietStateUntilCoverageContextExists(t *testing.T) {
	views := BuildViews(BuildInput{})
	for _, view := range views {
		if view.Status != StatusQuiet {
			t.Fatalf("%s status = %q, want %q", view.ID, view.Status, StatusQuiet)
		}
	}
}

func TestBuildCoverageViewsDistinguishesNoCoverageFromNoGaps(t *testing.T) {
	for _, view := range BuildCoverageViews(nil) {
		if view.Status != StatusQuiet {
			t.Fatalf("%s status = %q, want %q without evaluated coverage", view.ID, view.Status, StatusQuiet)
		}
	}
	views := BuildCoverageViews([]sourcecoverage.Record{{
		SourceID:      "grc",
		DimensionID:   "vendors",
		DimensionType: "entity_family",
		Title:         "Vendors",
		State:         sourcecoverage.StateHealthy,
		SupportLevel:  "supported",
	}})
	for _, view := range views {
		if view.ID == "vendors" && view.Status != StatusMapped {
			t.Fatalf("vendors status = %q, want %q when coverage is evaluated with no gaps", view.Status, StatusMapped)
		}
	}
}
