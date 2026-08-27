package sourceprojection

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestAkeneoGoProjectionFailsClosedForRustAuthoritativeFamilies(t *testing.T) {
	for _, kind := range []string{
		"akeneo.asset",
		"akeneo.asset_families_attribute",
		"akeneo.asset_family",
		"akeneo.attribute",
		"akeneo.attribute_group",
		"akeneo.attributes_option",
		"akeneo.draft",
		"akeneo.option",
		"akeneo.products_draft",
		"akeneo.products_uuid_draft",
		"akeneo.reference_entities_attribute",
		"akeneo.v1_attribute",
	} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := ProjectEvent(&cerebrov1.EventEnvelope{
				Id:       "event-1",
				TenantId: "tenant",
				SourceId: "akeneo",
				Kind:     kind,
			})
			if !errors.Is(err, errAkeneoRustProjectionRequired) {
				t.Fatalf("ProjectEvent() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Go projection produced entities=%d links=%d", len(entities), len(links))
			}
		})
	}
}
