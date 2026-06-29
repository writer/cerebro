package graphquery

import (
	"context"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/attackpath"
)

type AttackPathRequest = attackpath.Request
type AttackPathResult = attackpath.Result
type AttackPathFilters = attackpath.Filters
type AttackPathCounts = attackpath.Counts
type AttackPath = attackpath.Path
type AttackPathEdge = attackpath.Edge

func (s *Service) GetAttackPaths(ctx context.Context, request AttackPathRequest) (*AttackPathResult, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	request.TenantID = tenantID
	return attackpath.New(s.store).Traverse(ctx, request)
}
