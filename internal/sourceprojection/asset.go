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

func assetCloudAccountID(provider string, resourceID string, resourceURN string, attributes map[string]string) string {
	provider = normalizeIdentifier(provider)
	switch provider {
	case "aws":
		return firstNonEmpty(
			awsAccountID(attributes["aws_account_id"]),
			awsAccountIDFromARN(resourceID),
			awsAccountIDFromARN(resourceURN),
		)
	case "azure":
		return firstNonEmpty(
			attributes["subscription_id"],
			azureSubscriptionIDFromScope(resourceID),
			azureSubscriptionIDFromScope(resourceURN),
		)
	case "gcp":
		return firstNonEmpty(
			attributes["gcp_project_id"],
			attributes["project_id"],
			gcpProjectIDFromResource(resourceID),
			gcpProjectIDFromResource(resourceURN),
		)
	default:
		return ""
	}
}
