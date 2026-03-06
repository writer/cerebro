package jobs

import (
	"context"
	"encoding/json"

	"github.com/evalops/cerebro/internal/agents"
)

// NewInspectResourceHandler creates a handler for InspectResource jobs.
func NewInspectResourceHandler(tools *agents.SecurityTools) JobHandler {
	return func(ctx context.Context, payload string) (string, error) {
		var data InspectResourcePayload
		if err := json.Unmarshal([]byte(payload), &data); err != nil {
			return "", err
		}

		params := agents.InspectCloudResourceParams{
			Resource:   data.Resource.Resource,
			Provider:   data.Resource.Provider,
			Service:    data.Resource.Service,
			Identifier: data.Resource.Identifier,
			Account:    data.Overrides.AWSAccount,
			Region:     data.Overrides.AWSRegion,
			Project:    data.Overrides.GCPProject,
			Zone:       data.Overrides.GCPZone,
			Cluster:    data.Overrides.Cluster,
		}
		if params.Resource == "" {
			params.Resource = data.Resource.Identifier
		}

		return tools.InspectCloudResource(ctx, params)
	}
}
