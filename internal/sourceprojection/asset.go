package sourceprojection

import (
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func assetDataSensitivityProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return assetClassificationProjections(event, false)
}

func assetCrownJewelProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return assetClassificationProjections(event, true)
}

func assetClassificationProjections(event *cerebrov1.EventEnvelope, crownJewelEvent bool) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	attributes := event.GetAttributes()
	provider := firstNonEmpty(attributes["source_provider"], attributes["resource_provider"], "asset")
	return cloudResourceMetadataProjections(event, identityProjectionProfile{Provider: provider}, cloudResourceProjectionOptions{
		CrownJewelEvent:              crownJewelEvent,
		DefaultUnknownClassification: true,
		Provider:                     provider,
	})
}
