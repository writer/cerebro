package stream

import (
	"strings"

	"github.com/writer/cerebro/internal/graph"
)

func firstNonEmpty(values ...string) string {
	return CoalesceString(values...)
}

func shouldRefreshEventCorrelations(securityGraph *graph.Graph, nodeIDs []string) bool {
	if securityGraph == nil || len(nodeIDs) == 0 {
		return false
	}
	for _, nodeID := range nodeIDs {
		nodeID = strings.TrimSpace(nodeID)
		if nodeID == "" {
			continue
		}
		node, ok := securityGraph.GetNode(nodeID)
		if !ok || node == nil {
			continue
		}
		if graph.IsEventCorrelationNodeKind(node.Kind) {
			return true
		}
	}
	return false
}

func isAuditMutationEventType(eventType string) bool {
	eventType = strings.ToLower(strings.TrimSpace(eventType))
	switch {
	case strings.HasPrefix(eventType, "aws.cloudtrail.asset."):
		return true
	case strings.HasPrefix(eventType, "gcp.auditlog.asset."),
		strings.HasPrefix(eventType, "gcp.auditlogs.asset."):
		return true
	case strings.HasPrefix(eventType, "azure.activitylog.asset."),
		strings.HasPrefix(eventType, "azure.activitylogs.asset."):
		return true
	default:
		return false
	}
}
