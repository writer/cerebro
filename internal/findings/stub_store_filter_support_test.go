package findings

import (
	"reflect"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

// TestFindingFilterSupportCoversRequest fails when a field is added to
// ports.ListFindingsRequest without deciding whether the stub finding store
// applies it.
//
// Without this, a new filter defaults to being silently dropped by the stub:
// fast tests keep passing while the Postgres store filters on something they
// never exercise. That is the failure mode that hid the application workspace
// scoping regression until the nightly Integration job caught it.
func TestFindingFilterSupportCoversRequest(t *testing.T) {
	structType := reflect.TypeOf(ports.ListFindingsRequest{})
	seen := map[string]struct{}{}

	var walk func(reflect.Type)
	walk = func(current reflect.Type) {
		for i := range current.NumField() {
			field := current.Field(i)
			if field.Anonymous && field.Type.Kind() == reflect.Struct {
				walk(field.Type)
				continue
			}
			seen[field.Name] = struct{}{}
			if _, ok := findingFilterSupport[field.Name]; !ok {
				t.Errorf(
					"ports.ListFindingsRequest.%s is unclassified: add it to findingFilterSupport, "+
						"either implemented in findingMatches or explicitly unsupported",
					field.Name,
				)
			}
		}
	}
	walk(structType)

	for name := range findingFilterSupport {
		if _, ok := seen[name]; !ok {
			t.Errorf("findingFilterSupport lists %q, which is no longer a ListFindingsRequest field", name)
		}
	}
}

// TestUnsupportedFindingFilterIsRejected pins the fail-closed behaviour: a
// filter the stub cannot apply must surface as an error, never as a silently
// unfiltered result set.
//
// Every current field is classified as supported, so the test withdraws
// support for one field for its own duration to prove the rejection path still
// works, rather than relying on an unsupported field continuing to exist.
func TestUnsupportedFindingFilterIsRejected(t *testing.T) {
	for name, request := range map[string]ports.ListFindingsRequest{
		"status":     {TenantID: "writer", RuleID: "rule-a", Status: "open"},
		"SLAStatus":  {TenantID: "writer", RuleID: "rule-a", SLAStatus: "overdue"},
		"MinAgeDays": {TenantID: "writer", RuleID: "rule-a", FindingAgeRange: ports.FindingAgeRange{MinAgeDays: 7}},
		"MaxAgeDays": {TenantID: "writer", RuleID: "rule-a", FindingAgeRange: ports.FindingAgeRange{MaxAgeDays: 30}},
		"ProfilePredicate": {
			TenantID:         "writer",
			RuleID:           "rule-a",
			ProfilePredicate: ports.FindingProfilePredicate{RuleIDs: []string{"rule-b"}},
		},
	} {
		if field := unsupportedFindingFilter(request); field != "" {
			t.Errorf("unsupportedFindingFilter(%s) = %q, want \"\"", name, field)
		}
	}

	const withdrawn = "SLAStatus"
	previous, ok := findingFilterSupport[withdrawn]
	if !ok {
		t.Fatalf("findingFilterSupport has no %q entry", withdrawn)
	}
	findingFilterSupport[withdrawn] = ""
	t.Cleanup(func() { findingFilterSupport[withdrawn] = previous })

	request := ports.ListFindingsRequest{TenantID: "writer", RuleID: "rule-a", SLAStatus: "overdue"}
	if field := unsupportedFindingFilter(request); field != withdrawn {
		t.Fatalf("unsupportedFindingFilter(withdrawn) = %q, want %q", field, withdrawn)
	}
	store := &stubFindingStore{findings: map[string]*ports.FindingRecord{}}
	if _, err := store.ListFindings(t.Context(), request); err == nil {
		t.Fatal("ListFindings() with an unsupported filter returned no error, want a rejection")
	}
}

// TestStubFindingStoreKeepsWorkspaceScope pins that a finding written through
// the stub keeps its ApplicationWorkspaceID, so the workspace filter can
// actually exclude it. The stub stores and returns clones, and a clone that
// dropped the workspace made the filter vacuous for every stub-written finding.
func TestStubFindingStoreKeepsWorkspaceScope(t *testing.T) {
	store := &stubFindingStore{findings: map[string]*ports.FindingRecord{}}
	scoped := &ports.FindingRecord{
		ID:              "finding-scoped",
		Fingerprint:     "fp-scoped",
		TenantID:        "writer",
		RuntimeID:       "runtime-a",
		RuleID:          "rule-a",
		Severity:        "HIGH",
		Status:          "open",
		FirstObservedAt: time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC),
		LastObservedAt:  time.Date(2026, time.September, 1, 13, 0, 0, 0, time.UTC),
	}
	scoped.ApplicationWorkspaceID = "tenant-only:writer"
	if _, err := store.UpsertFinding(t.Context(), scoped); err != nil {
		t.Fatalf("UpsertFinding(): %v", err)
	}

	stored, err := store.GetFinding(t.Context(), scoped.ID)
	if err != nil {
		t.Fatalf("GetFinding(): %v", err)
	}
	if got := stored.ApplicationWorkspaceID; got != scoped.ApplicationWorkspaceID {
		t.Fatalf("stored ApplicationWorkspaceID = %q, want %q", got, scoped.ApplicationWorkspaceID)
	}

	otherWorkspace, err := store.ListFindings(t.Context(), ports.ListFindingsRequest{
		TenantID:               "writer",
		RuleID:                 "rule-a",
		ApplicationWorkspaceID: "other-workspace",
	})
	if err != nil {
		t.Fatalf("ListFindings(other workspace): %v", err)
	}
	if len(otherWorkspace) != 0 {
		t.Fatalf("ListFindings(other workspace) returned %d findings, want 0", len(otherWorkspace))
	}
}

// TestStubFindingStoreSQLMirroredFilters pins the stub's reading of the
// filters that the Postgres store evaluates in SQL. The Postgres-backed
// TestStubFindingStoreFilterParity is the authority; this keeps the fast suite
// honest when that job is not running.
func TestStubFindingStoreSQLMirroredFilters(t *testing.T) {
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	const day = 24 * time.Hour
	finding := func(id, ruleID, severity, status string, age time.Duration) *ports.FindingRecord {
		return &ports.FindingRecord{
			ID:              id,
			TenantID:        "writer",
			RuntimeID:       "runtime-a",
			RuleID:          ruleID,
			Severity:        severity,
			Status:          status,
			FirstObservedAt: now.Add(-age),
			LastObservedAt:  now.Add(-age).Add(time.Hour),
		}
	}
	overdue := finding("overdue", "rule-a", "HIGH", "open", 30*day+12*time.Hour)
	overdue.DueAt = now.Add(-day)
	overdue.ControlRefs = []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.6"}}
	overdue.RiskScore = 50
	dueSoon := finding("due-soon", "rule-a", "MEDIUM", "open", 29*day+12*time.Hour)
	dueSoon.DueAt = now.Add(day)
	dueSoon.Attributes = map[string]string{FindingEffectiveSeverityAttribute: "CRITICAL"}
	resolved := finding("resolved", "rule-a", "LOW", "Resolved", 28*day+12*time.Hour)
	resolved.RiskScore = 90
	onTrack := finding("on-track", "rule-a", "HIGH", "open", 27*day+12*time.Hour)
	onTrack.DueAt = now.Add(10 * day)
	noDue := finding("no-due", "rule-b", "HIGH", "open", 26*day+12*time.Hour)
	records := []*ports.FindingRecord{overdue, dueSoon, resolved, onTrack, noDue}

	ids := func(request ports.ListFindingsRequest) []string {
		t.Helper()
		matched := []string{}
		for _, record := range records {
			if findingMatchesAt(request, record, now) {
				matched = append(matched, record.ID)
			}
		}
		return matched
	}
	base := ports.ListFindingsRequest{TenantID: "writer", RuntimeID: "runtime-a"}
	with := func(mutate func(*ports.ListFindingsRequest)) ports.ListFindingsRequest {
		request := base
		mutate(&request)
		return request
	}

	for _, tt := range []struct {
		name    string
		request ports.ListFindingsRequest
		want    []string
	}{
		{"profile rule ids", with(func(r *ports.ListFindingsRequest) { r.ProfilePredicate.RuleIDs = []string{" rule-b "} }), []string{"no-due"}},
		{"profile control refs are case-insensitive", with(func(r *ports.ListFindingsRequest) {
			r.ProfilePredicate.ControlRefs = []ports.FindingControlRef{{FrameworkName: "soc 2", ControlID: "cc6.6"}}
		}), []string{"overdue"}},
		{"profile predicate is a union", with(func(r *ports.ListFindingsRequest) {
			r.ProfilePredicate = ports.FindingProfilePredicate{
				RuleIDs:     []string{"rule-b"},
				ControlRefs: []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.6"}},
			}
		}), []string{"overdue", "no-due"}},
		{"profile predicate drops half-empty control refs", with(func(r *ports.ListFindingsRequest) {
			r.ProfilePredicate.ControlRefs = []ports.FindingControlRef{{FrameworkName: "SOC 2"}}
		}), []string{"overdue", "due-soon", "resolved", "on-track", "no-due"}},
		{"min age days", with(func(r *ports.ListFindingsRequest) { r.MinAgeDays = 28 }), []string{"overdue", "due-soon", "resolved"}},
		{"max age days", with(func(r *ports.ListFindingsRequest) { r.MaxAgeDays = 28 }), []string{"resolved", "on-track", "no-due"}},
		{"age window", with(func(r *ports.ListFindingsRequest) { r.MinAgeDays = 28; r.MaxAgeDays = 28 }), []string{"resolved"}},
		{"sla overdue", with(func(r *ports.ListFindingsRequest) { r.SLAStatus = "overdue" }), []string{"overdue"}},
		{"sla due soon", with(func(r *ports.ListFindingsRequest) { r.SLAStatus = "due_soon" }), []string{"due-soon"}},
		{"sla on track", with(func(r *ports.ListFindingsRequest) { r.SLAStatus = "on_track" }), []string{"on-track"}},
		{"sla no due date", with(func(r *ports.ListFindingsRequest) { r.SLAStatus = "no_due_date" }), []string{"no-due"}},
		{"sla closed", with(func(r *ports.ListFindingsRequest) { r.SLAStatus = "closed" }), []string{"resolved"}},
		{"sla explicit status is lower-cased", with(func(r *ports.ListFindingsRequest) { r.SLAStatus = " RESOLVED " }), []string{"resolved"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := ids(tt.request); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("findingMatchesAt() = %v, want %v", got, tt.want)
			}
		})
	}

	list := func(request ports.ListFindingsRequest) []string {
		t.Helper()
		listed, err := ListFindingsForParity(request, records)
		if err != nil {
			t.Fatalf("ListFindings(): %v", err)
		}
		ordered := make([]string, 0, len(listed))
		for _, record := range listed {
			ordered = append(ordered, record.ID)
		}
		return ordered
	}
	for _, tt := range []struct {
		name    string
		request ports.ListFindingsRequest
		want    []string
	}{
		{"default order is last observed desc", base, []string{"no-due", "on-track", "resolved", "due-soon", "overdue"}},
		{"limit truncates in order", with(func(r *ports.ListFindingsRequest) { r.Limit = 2 }), []string{"no-due", "on-track"}},
		{"limit is capped like the store", with(func(r *ports.ListFindingsRequest) { r.Limit = maxStubFindingListLimit + 100 }), []string{"no-due", "on-track", "resolved", "due-soon", "overdue"}},
		{"priority order ranks effective severity first", with(func(r *ports.ListFindingsRequest) { r.PriorityOrder = true }), []string{"due-soon", "no-due", "on-track", "overdue", "resolved"}},
		{"order priority matches the legacy flag", with(func(r *ports.ListFindingsRequest) { r.Order = ports.FindingOrderPriority }), []string{"due-soon", "no-due", "on-track", "overdue", "resolved"}},
		{"order risk score then severity", with(func(r *ports.ListFindingsRequest) { r.Order = ports.FindingOrderRiskScore }), []string{"resolved", "overdue", "due-soon", "no-due", "on-track"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := list(tt.request); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ListFindings() order = %v, want %v", got, tt.want)
			}
		})
	}
}
