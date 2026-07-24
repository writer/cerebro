package graphrebuild

import (
	"context"
	"fmt"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourceprojection"
)

var (
	organizationalBenchmarkEntityCount int
	organizationalBenchmarkLinkCount   int
)

func TestOrganizationalPlatformBenchmarkCorpus(t *testing.T) {
	for _, recordCount := range []int{100, 1_000, 5_000} {
		events := organizationalBenchmarkAssetEvents(recordCount)
		verifyOrganizationalBenchmarkProjection(t, events)
	}
}

func BenchmarkOrganizationalPlatformGo(b *testing.B) {
	for _, recordCount := range []int{100, 1_000, 5_000} {
		events := organizationalBenchmarkAssetEvents(recordCount)
		verifyOrganizationalBenchmarkProjection(b, events)
		b.Run(fmt.Sprintf("projection/box_assets/records_%d", recordCount), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				entityCount, linkCount := projectOrganizationalBenchmarkEvents(b, events)
				organizationalBenchmarkEntityCount = entityCount
				organizationalBenchmarkLinkCount = linkCount
			}
			b.StopTimer()
			b.ReportMetric(
				float64(b.Elapsed().Nanoseconds())/float64(b.N*recordCount),
				"ns/record",
			)
		})
		b.Run(fmt.Sprintf("admission/box_assets/records_%d", recordCount), func(b *testing.B) {
			ctx := context.Background()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				store, err := newMemoryGraphStore()
				if err != nil {
					b.Fatal(err)
				}
				entityCount := 0
				linkCount := 0
				for _, event := range events {
					entities, links, err := sourceprojection.ProjectEvent(event)
					if err != nil {
						b.Fatal(err)
					}
					entityCount += len(entities)
					linkCount += len(links)
					for _, entity := range entities {
						if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
							b.Fatal(err)
						}
					}
					for _, link := range links {
						if err := store.UpsertProjectedLink(ctx, link); err != nil {
							b.Fatal(err)
						}
					}
				}
				organizationalBenchmarkEntityCount = entityCount
				organizationalBenchmarkLinkCount = linkCount
			}
			b.StopTimer()
			b.ReportMetric(
				float64(b.Elapsed().Nanoseconds())/float64(b.N*recordCount),
				"ns/record",
			)
		})
	}
}

type organizationalBenchmarkTB interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

func verifyOrganizationalBenchmarkProjection(
	tb organizationalBenchmarkTB,
	events []*cerebrov1.EventEnvelope,
) {
	tb.Helper()
	entityCount, linkCount := projectOrganizationalBenchmarkEvents(tb, events)
	if entityCount != len(events) || linkCount != 0 {
		tb.Fatalf(
			"projected entities/links = %d/%d, want %d/0",
			entityCount,
			linkCount,
			len(events),
		)
	}
	firstEntities, _, err := sourceprojection.ProjectEvent(events[0])
	if err != nil {
		tb.Fatal(err)
	}
	lastEntities, _, err := sourceprojection.ProjectEvent(events[len(events)-1])
	if err != nil {
		tb.Fatal(err)
	}
	if got := firstEntities[0].Attributes["resource_id"]; got != "asset-00000" {
		tb.Fatalf("first resource_id = %q, want asset-00000", got)
	}
	lastID := fmt.Sprintf("asset-%05d", len(events)-1)
	if got := lastEntities[0].Attributes["resource_id"]; got != lastID {
		tb.Fatalf("last resource_id = %q, want %s", got, lastID)
	}
}

func projectOrganizationalBenchmarkEvents(
	tb organizationalBenchmarkTB,
	events []*cerebrov1.EventEnvelope,
) (int, int) {
	tb.Helper()
	entityCount := 0
	linkCount := 0
	for _, event := range events {
		entities, links, err := sourceprojection.ProjectEvent(event)
		if err != nil {
			tb.Fatal(err)
		}
		entityCount += len(entities)
		linkCount += len(links)
	}
	return entityCount, linkCount
}

func organizationalBenchmarkAssetEvents(recordCount int) []*cerebrov1.EventEnvelope {
	events := make([]*cerebrov1.EventEnvelope, 0, recordCount)
	for index := range recordCount {
		id := fmt.Sprintf("asset-%05d", index)
		events = append(events, &cerebrov1.EventEnvelope{
			Id:       fmt.Sprintf("observation-%05d", index),
			TenantId: "benchmark-tenant",
			SourceId: "box",
			Kind:     "box.content_assets",
			Attributes: map[string]string{
				"resource_id":   id,
				"resource_name": fmt.Sprintf("Asset %05d", index),
				"resource_type": "file",
				"resource_urn": fmt.Sprintf(
					"urn:cerebro:benchmark-tenant:runtime_file:%s",
					id,
				),
			},
		})
	}
	return events
}
