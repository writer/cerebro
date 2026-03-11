package graph

import (
	"testing"
	"time"
)

func TestReportSectionEnvelopeRegistry(t *testing.T) {
	envelopes := ListReportSectionEnvelopeDefinitions()
	if len(envelopes) < 8 {
		t.Fatalf("expected at least 8 envelope definitions, got %d", len(envelopes))
	}
	summary, ok := GetReportSectionEnvelopeDefinition("summary")
	if !ok {
		t.Fatal("expected summary envelope definition")
	}
	if summary.SchemaName != "PlatformSummaryEnvelope" {
		t.Fatalf("expected PlatformSummaryEnvelope schema, got %q", summary.SchemaName)
	}
	if summary.Version != "1.0.0" {
		t.Fatalf("expected summary envelope version 1.0.0, got %q", summary.Version)
	}
	if len(summary.CompatibleSectionKinds) == 0 {
		t.Fatalf("expected compatible section kinds, got %+v", summary)
	}
	catalog := ReportSectionEnvelopeCatalogSnapshot(time.Date(2026, 3, 10, 6, 0, 0, 0, time.UTC))
	if catalog.Count != len(envelopes) {
		t.Fatalf("expected catalog count %d, got %d", len(envelopes), catalog.Count)
	}
}

func TestBenchmarkPackRegistry(t *testing.T) {
	packs := ListBenchmarkPacks()
	if len(packs) < 6 {
		t.Fatalf("expected at least 6 benchmark packs, got %d", len(packs))
	}
	pack, ok := GetBenchmarkPack("graph-quality.default")
	if !ok {
		t.Fatal("expected graph-quality.default pack")
	}
	if pack.SchemaName != "PlatformGraphQualityBenchmarkPack" {
		t.Fatalf("expected PlatformGraphQualityBenchmarkPack schema, got %q", pack.SchemaName)
	}
	if len(pack.MeasureBindings) == 0 {
		t.Fatalf("expected measure bindings, got %+v", pack)
	}
	if len(pack.MeasureBindings[0].Bands) == 0 {
		t.Fatalf("expected benchmark bands, got %+v", pack.MeasureBindings[0])
	}
	catalog := BenchmarkPackCatalogSnapshot(time.Date(2026, 3, 10, 6, 5, 0, 0, time.UTC))
	if catalog.Count != len(packs) {
		t.Fatalf("expected catalog count %d, got %d", len(packs), catalog.Count)
	}
}
