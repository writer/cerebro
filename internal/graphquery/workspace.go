package graphquery

import (
	"context"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

type WorkspaceResourceRequest struct {
	TenantID               string
	ResourceTenantID       string
	ApplicationWorkspaceID string
	URNs                   []string
}

func (s *Service) QualifyWorkspaceResources(ctx context.Context, request WorkspaceResourceRequest) (*ports.EntityNeighborhood, error) {
	if s == nil {
		return nil, ErrRuntimeUnavailable
	}
	tenantID := strings.TrimSpace(request.TenantID)
	resourceTenantID := strings.TrimSpace(request.ResourceTenantID)
	if tenantID != "" && resourceTenantID != "" && tenantID != resourceTenantID {
		return nil, ports.ErrGraphEntityNotFound
	}
	if resourceTenantID != "" {
		tenantID = resourceTenantID
	}
	workspaceID := strings.TrimSpace(request.ApplicationWorkspaceID)
	if tenantID != "" && workspaceID == "" {
		return nil, nil
	}
	if s.catalog == nil {
		return nil, ErrRuntimeUnavailable
	}
	urns := uniqueWorkspaceURNs(request.URNs)
	if tenantID == "" || workspaceID == "" || len(urns) == 0 {
		return nil, fmt.Errorf("%w: tenant_id, workspace_id, and resource urns are required", ErrInvalidRequest)
	}
	var root *ports.NeighborhoodNode
	for _, urn := range urns {
		page, err := s.catalog.ListEntities(ctx, ports.EntityCatalogPageRequest{Filter: ports.EntityCatalogFilter{
			TenantID: tenantID, ApplicationWorkspaceID: workspaceID, ExactAgentKey: urn,
		}, Limit: 1})
		if err != nil {
			return nil, err
		}
		if page == nil || page.TenantID != tenantID || page.Truncated {
			return nil, ErrRuntimeUnavailable
		}
		if len(page.Entities) != 1 || page.Entities[0].URN != urn || page.Entities[0].TenantID != tenantID {
			return nil, ports.ErrGraphEntityNotFound
		}
		if root == nil {
			entity := page.Entities[0]
			root = &ports.NeighborhoodNode{URN: entity.URN, EntityType: entity.EntityType, Label: entity.Label}
		}
	}
	return &ports.EntityNeighborhood{Root: root, Neighbors: []*ports.NeighborhoodNode{}, Relations: []*ports.NeighborhoodRelation{}}, nil
}

func uniqueWorkspaceURNs(values []string) []string {
	unique := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	return unique
}
