package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func awsDataResourceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
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
	resourceType := cloudResourceProjectionType(event, "aws", attributes)
	resourceID := cloudResourceProjectionID(attributes)
	resourceURN := firstNonEmpty(attributes["resource_urn"], projectionURN(tenantID, "aws_"+resourceType, resourceID))
	addAWSNetworkContextLinks(entityMap, linkMap, tenantID, event.GetSourceId(), event, resourceURN, attributes)
	addElastiCacheContextLinks(entityMap, linkMap, tenantID, event, resourceURN, attributes)
	return identityProjectionResult(entityMap, linkMap)
}

func addElastiCacheContextLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, resourceURN string, attributes map[string]string) {
	resourceType := strings.TrimSpace(attributes["resource_type"])
	if resourceURN == "" || resourceType == "" {
		return
	}
	accountID := strings.TrimSpace(attributes["domain"])
	if replicationGroupID := strings.TrimSpace(attributes["replication_group_id"]); replicationGroupID != "" && resourceType != "elasticache_replication_group" {
		replicationGroupURN := projectionURN(tenantID, "aws_elasticache_replication_group", replicationGroupID)
		if replicationGroupURN != "" {
			addEntity(entities, &ports.ProjectedEntity{
				URN:        replicationGroupURN,
				TenantID:   tenantID,
				SourceID:   event.GetSourceId(),
				EntityType: "aws.elasticache.replication.group",
				Label:      replicationGroupID,
				Attributes: map[string]string{
					"domain":               accountID,
					"replication_group_id": replicationGroupID,
					"resource_id":          replicationGroupID,
					"resource_provider":    "aws",
					"resource_type":        "elasticache_replication_group",
				},
			})
			addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, replicationGroupURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "elasticache_cluster_replication_group"}))
			addCloudAccountLink(entities, links, tenantID, event.GetSourceId(), event, replicationGroupURN, accountID, "aws")
		}
	}
	if subnetGroupName := strings.TrimSpace(attributes["cache_subnet_group_name"]); subnetGroupName != "" && resourceType != "elasticache_subnet_group" {
		subnetGroupURN := projectionURN(tenantID, "aws_elasticache_subnet_group", subnetGroupName)
		if subnetGroupURN != "" {
			addEntity(entities, &ports.ProjectedEntity{
				URN:        subnetGroupURN,
				TenantID:   tenantID,
				SourceID:   event.GetSourceId(),
				EntityType: "aws.elasticache.subnet.group",
				Label:      subnetGroupName,
				Attributes: map[string]string{
					"cache_subnet_group_name": subnetGroupName,
					"domain":                  accountID,
					"resource_id":             subnetGroupName,
					"resource_provider":       "aws",
					"resource_type":           "elasticache_subnet_group",
				},
			})
			addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, subnetGroupURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "elasticache_cluster_subnet_group"}))
			addCloudAccountLink(entities, links, tenantID, event.GetSourceId(), event, subnetGroupURN, accountID, "aws")
		}
	}
	for _, memberClusterID := range splitCloudAttributeList(attributes["member_cluster_ids"]) {
		clusterURN := projectionURN(tenantID, "aws_elasticache_cluster", memberClusterID)
		if clusterURN == "" {
			continue
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        clusterURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "aws.elasticache.cluster",
			Label:      memberClusterID,
			Attributes: map[string]string{
				"cache_cluster_id":  memberClusterID,
				"domain":            accountID,
				"resource_id":       memberClusterID,
				"resource_provider": "aws",
				"resource_type":     "elasticache_cluster",
			},
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), clusterURN, resourceURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "elasticache_member_cluster"}))
		addCloudAccountLink(entities, links, tenantID, event.GetSourceId(), event, clusterURN, accountID, "aws")
	}
}
