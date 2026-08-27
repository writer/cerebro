package sourceprojection

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestBotifyGoProjectionFailsClosedForRustAuthoritativeFamilies(t *testing.T) {
	for _, kind := range []string{
		"botify.analyses",
		"botify.datamodel",
		"botify.domain",
		"botify.export",
		"botify.filter",
		"botify.orphan_url",
		"botify.out_of_config",
		"botify.percentile",
		"botify.project",
		"botify.report",
		"botify.sitemap_only",
		"botify.url",
	} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := ProjectEvent(&cerebrov1.EventEnvelope{
				Id:       "event-1",
				TenantId: "tenant",
				SourceId: "botify",
				Kind:     kind,
			})
			if !errors.Is(err, errBotifyRustProjectionRequired) {
				t.Fatalf("ProjectEvent() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Go projection produced entities=%d links=%d", len(entities), len(links))
			}
		})
	}
}
