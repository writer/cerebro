package sync

import (
	"context"
	"errors"
	"fmt"
	"strings"

	ids "cloud.google.com/go/ids/apiv1"
	"cloud.google.com/go/ids/apiv1/idspb"
	"google.golang.org/api/iterator"
)

func (e *GCPSyncEngine) gcpIdsEndpointTable() GCPTableSpec {
	return GCPTableSpec{
		Name:    "gcp_ids_endpoints",
		Columns: []string{"project_id", "name", "endpoint_id", "network", "severity", "state", "endpoint_forwarding_rule", "endpoint_ip", "traffic_logs", "description", "labels", "create_time", "update_time", "has_notification_configuration"},
		Fetch:   e.fetchGCPIdsEndpoints,
	}
}

func (e *GCPSyncEngine) fetchGCPIdsEndpoints(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	client, err := ids.NewClient(ctx, gcpClientOptionsFromContext(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("create ids client: %w", err)
	}
	defer func() { _ = client.Close() }()

	req := &idspb.ListEndpointsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectID),
	}

	it := client.ListEndpoints(ctx, req)
	rows := make([]map[string]interface{}, 0, 50)
	for {
		endpoint, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list endpoints: %w", err)
		}

		row := map[string]interface{}{
			"_cq_id":                         endpoint.Name,
			"project_id":                     projectID,
			"name":                           endpoint.Name,
			"endpoint_id":                    extractEndpointID(endpoint.Name),
			"network":                        endpoint.Network,
			"severity":                       endpoint.Severity.String(),
			"state":                          endpoint.State.String(),
			"endpoint_forwarding_rule":       endpoint.EndpointForwardingRule,
			"endpoint_ip":                    endpoint.EndpointIp,
			"traffic_logs":                   endpoint.TrafficLogs,
			"description":                    endpoint.Description,
			"labels":                         endpoint.Labels,
			"has_notification_configuration": endpoint.TrafficLogs,
		}

		if endpoint.CreateTime != nil {
			row["create_time"] = endpoint.CreateTime.AsTime()
		}
		if endpoint.UpdateTime != nil {
			row["update_time"] = endpoint.UpdateTime.AsTime()
		}

		rows = append(rows, row)
	}

	return rows, nil
}

func extractEndpointID(name string) string {
	if name == "" {
		return ""
	}
	parts := strings.Split(name, "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}
