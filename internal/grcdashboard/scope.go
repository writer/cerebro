package grcdashboard

import (
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

// AggregateFindingRequest keeps finding predicates while replacing list-only
// pagination and ordering with one exact runtime scope for dashboard totals.
func AggregateFindingRequest(tenantID string, runtimeIDs []string, filter ports.ListFindingsRequest) ports.ListFindingsRequest {
	request := filter
	request.TenantID = strings.TrimSpace(tenantID)
	request.RuntimeID = ""
	request.RuntimeIDs = append([]string(nil), runtimeIDs...)
	request.ProfilePredicate = ports.FindingProfilePredicate{}
	request.LastObservedBefore = time.Time{}
	request.Limit = 0
	request.PriorityOrder = false
	request.Order = ""
	return request
}
