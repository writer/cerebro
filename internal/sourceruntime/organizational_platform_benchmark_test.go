package sourceruntime

import (
	"fmt"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourceprojection"
)

var (
	organizationalRawBenchmarkEntityCount int
	organizationalRawBenchmarkLinkCount   int
)

func TestOrganizationalPlatformRawBenchmarkCorpus(t *testing.T) {
	definition, family := organizationalBenchmarkContentAssetDefinition(t)
	runtime := organizationalBenchmarkRuntime()
	for _, recordCount := range []int{100, 1_000, 5_000} {
		records := organizationalBenchmarkRawAssets(recordCount)
		entityCount, linkCount := projectOrganizationalRawBenchmarkRecords(
			t,
			runtime,
			definition,
			family,
			records,
		)
		if entityCount != recordCount || linkCount != 0 {
			t.Fatalf(
				"projected entities/links = %d/%d, want %d/0",
				entityCount,
				linkCount,
				recordCount,
			)
		}
	}
}

func BenchmarkOrganizationalPlatformGoRawProjection(b *testing.B) {
	definition, family := organizationalBenchmarkContentAssetDefinition(b)
	runtime := organizationalBenchmarkRuntime()
	for _, recordCount := range []int{100, 1_000, 5_000} {
		records := organizationalBenchmarkRawAssets(recordCount)
		entityCount, linkCount := projectOrganizationalRawBenchmarkRecords(
			b,
			runtime,
			definition,
			family,
			records,
		)
		if entityCount != recordCount || linkCount != 0 {
			b.Fatalf(
				"projected entities/links = %d/%d, want %d/0",
				entityCount,
				linkCount,
				recordCount,
			)
		}
		b.Run(fmt.Sprintf("projection/content_assets/records_%d", recordCount), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				entityCount, linkCount := projectOrganizationalRawBenchmarkRecords(
					b,
					runtime,
					definition,
					family,
					records,
				)
				organizationalRawBenchmarkEntityCount = entityCount
				organizationalRawBenchmarkLinkCount = linkCount
			}
			b.StopTimer()
			b.ReportMetric(
				float64(b.Elapsed().Nanoseconds())/float64(b.N*recordCount),
				"ns/record",
			)
		})
	}
}

func projectOrganizationalRawBenchmarkRecords(
	tb testing.TB,
	runtime *cerebrov1.SourceRuntime,
	definition connectordefinitions.Definition,
	family connectordefinitions.ResourceFamily,
	records []any,
) (int, int) {
	tb.Helper()
	entityCount := 0
	linkCount := 0
	for index, record := range records {
		attributes := depositRecordAttributes(runtime, definition, family, record)
		event := &cerebrov1.EventEnvelope{
			Id:         fmt.Sprintf("observation-%05d", index),
			TenantId:   runtime.GetTenantId(),
			SourceId:   runtime.GetSourceId(),
			Kind:       "dropbox_business.content_assets",
			Attributes: attributes,
		}
		entities, links, err := sourceprojection.ProjectEvent(event)
		if err != nil {
			tb.Fatal(err)
		}
		entityCount += len(entities)
		linkCount += len(links)
	}
	return entityCount, linkCount
}

func organizationalBenchmarkContentAssetDefinition(
	tb testing.TB,
) (connectordefinitions.Definition, connectordefinitions.ResourceFamily) {
	tb.Helper()
	entry, ok, err := connectorcatalog.BuiltinEntry("dropbox_business")
	if err != nil {
		tb.Fatal(err)
	}
	if !ok {
		tb.Fatal("Dropbox Business connector definition is missing")
	}
	for _, family := range entry.Definition.ResourceFamilies {
		if family.ID == "content_assets" {
			return entry.Definition, family
		}
	}
	tb.Fatal("Dropbox Business content_assets family is missing")
	return connectordefinitions.Definition{}, connectordefinitions.ResourceFamily{}
}

func organizationalBenchmarkRuntime() *cerebrov1.SourceRuntime {
	return &cerebrov1.SourceRuntime{
		Id:       "dropbox-business-benchmark",
		TenantId: "benchmark-tenant",
		SourceId: "dropbox_business",
	}
}

func organizationalBenchmarkRawAssets(recordCount int) []any {
	records := make([]any, 0, recordCount)
	for index := range recordCount {
		id := fmt.Sprintf("asset-%05d", index)
		records = append(records, map[string]any{
			"id":   id,
			"name": fmt.Sprintf("Asset %05d", index),
			"type": "file",
			"resource_urn": fmt.Sprintf(
				"urn:cerebro:benchmark-tenant:runtime_file:%s",
				id,
			),
		})
	}
	return records
}
