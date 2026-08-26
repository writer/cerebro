package grcdashboard

import (
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

func TestAggregateFindingRequestReplacesRuntimeScopeAndListControls(t *testing.T) {
	filter := ports.ListFindingsRequest{
		RuntimeID:          "old-runtime",
		RuntimeIDs:         []string{"old-runtime"},
		Status:             "open",
		Severity:           "critical",
		ProfilePredicate:   ports.FindingProfilePredicate{RuleIDs: []string{"rule-a"}},
		LastObservedBefore: time.Now().UTC(),
		Limit:              25,
		PriorityOrder:      true,
		Order:              ports.FindingOrderRiskScore,
	}
	request := AggregateFindingRequest(" tenant-a ", []string{"runtime-a", "runtime-b"}, filter)
	if request.TenantID != "tenant-a" || request.RuntimeID != "" || len(request.RuntimeIDs) != 2 {
		t.Fatalf("aggregate scope = tenant %q runtime %q runtimes %v", request.TenantID, request.RuntimeID, request.RuntimeIDs)
	}
	if request.Status != "open" || request.Severity != "critical" {
		t.Fatalf("aggregate predicates = status %q severity %q", request.Status, request.Severity)
	}
	if len(request.ProfilePredicate.RuleIDs) != 0 || !request.LastObservedBefore.IsZero() || request.Limit != 0 || request.PriorityOrder || request.Order != "" {
		t.Fatalf("aggregate request retained list-only controls: %+v", request)
	}
}
