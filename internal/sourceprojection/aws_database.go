package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func awsDatabaseInstanceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := awsCloudResourceProjections(event)
	if err != nil {
		return nil, nil, err
	}
	entityMap := projectedEntitiesMap(entities)
	linkMap := projectedLinksMap(links)
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	resourceType := normalizeCloudType(firstNonEmpty(attributes["resource_type"], "database_instance"))
	instanceID := firstNonEmpty(attributes["resource_id"], attributes["arn"], attributes["db_instance_identifier"], attributes["resource_name"])
	instanceURN := projectionURN(tenantID, "aws_"+resourceType, instanceID)
	clusterType := awsDatabaseClusterResourceType(resourceType)
	clusterID := firstNonEmpty(attributes["cluster_arn"], attributes["cluster_id"], attributes["db_cluster_identifier"], attributes["cluster_name"])
	clusterURN := projectionURN(tenantID, "aws_"+clusterType, clusterID)
	if instanceURN == "" || clusterURN == "" {
		return identityProjectionResult(entityMap, linkMap)
	}
	addEntity(entityMap, &ports.ProjectedEntity{
		URN:        clusterURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "aws." + strings.ReplaceAll(clusterType, "_", "."),
		Label:      firstNonEmpty(attributes["cluster_name"], attributes["db_cluster_identifier"], clusterID),
		Attributes: compactAttributes(map[string]string{
			"cluster_arn":           strings.TrimSpace(attributes["cluster_arn"]),
			"cluster_name":          strings.TrimSpace(firstNonEmpty(attributes["cluster_name"], attributes["db_cluster_identifier"])),
			"db_cluster_identifier": strings.TrimSpace(attributes["db_cluster_identifier"]),
			"domain":                strings.TrimSpace(attributes["domain"]),
			"region":                strings.TrimSpace(attributes["region"]),
			"resource_id":           clusterID,
			"resource_provider":     "aws",
			"resource_type":         clusterType,
		}),
	})
	addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), instanceURN, clusterURN, relationBelongsTo, map[string]string{
		"cluster_name": strings.TrimSpace(firstNonEmpty(attributes["cluster_name"], attributes["db_cluster_identifier"])),
		"event_id":     event.GetId(),
		"match_type":   "aws_database_instance_cluster",
	}))
	addCloudAccountLink(entityMap, linkMap, tenantID, event.GetSourceId(), event, clusterURN, attributes["domain"], "aws")
	return identityProjectionResult(entityMap, linkMap)
}

func awsDatabaseClusterResourceType(instanceType string) string {
	switch normalizeCloudType(instanceType) {
	case "docdb_instance":
		return "docdb_cluster"
	case "neptune_instance":
		return "neptune_cluster"
	default:
		return strings.TrimSuffix(normalizeCloudType(instanceType), "_instance") + "_cluster"
	}
}
