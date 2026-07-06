package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func apolloUsersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityUserProjections(event, identityProjectionProfile{Provider: "apollo"})
}

func apolloContactsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityUserProjections(event, identityProjectionProfile{Provider: "apollo"})
}

func apolloAccountsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	resourceID := firstNonEmpty(attributes["resource_id"], attributes["organization_id"], event.GetId())
	resourceType := firstNonEmpty(attributes["resource_type"], "apollo_account")
	resourceURN := firstNonEmpty(attributes["resource_urn"], projectionURN(tenantID, "runtime_"+normalizeCloudType(resourceType), resourceID))
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        resourceURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "runtime." + strings.ReplaceAll(normalizeCloudType(resourceType), "_", "."),
		Label:      firstNonEmpty(attributes["resource_name"], attributes["domain"], resourceID),
		Attributes: map[string]string{
			"account_stage_id":  strings.TrimSpace(attributes["account_stage_id"]),
			"domain":            strings.TrimSpace(attributes["domain"]),
			"organization_id":   strings.TrimSpace(attributes["organization_id"]),
			"owner_id":          strings.TrimSpace(attributes["owner_id"]),
			"resource_id":       resourceID,
			"resource_type":     resourceType,
			"source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID]),
		},
	})
	return identityProjectionResult(entities, links)
}
