package sourcecoverage

import (
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestEvaluateDistinguishesCoverageStates(t *testing.T) {
	contracts := []sourcecdk.CoverageContract{{
		SourceID:        "okta",
		OwnerDomain:     "identity",
		AuthorityDomain: "okta",
		Dimensions: []sourcecdk.CoverageDimension{
			{ID: "users", Type: "entity_family", Title: "Users", Families: []string{"user"}, Support: sourcecdk.CoverageSupportSupported, HighValue: true},
			{ID: "apps", Type: "entity_family", Title: "Applications", Families: []string{"application"}, Support: sourcecdk.CoverageSupportSupported, HighValue: true},
			{ID: "audit", Type: "audit_event", Title: "Audit events", Families: []string{"audit"}, Support: sourcecdk.CoverageSupportSupported, HighValue: true},
			{ID: "remediation", Type: "remediation_state", Title: "Remediation lifecycle", Support: sourcecdk.CoverageSupportUnsupported, HighValue: true},
			{ID: "entitlements", Type: "app_entitlement", Title: "App entitlements", Families: []string{"app_assignment"}, Support: sourcecdk.CoverageSupportPartial, HighValue: true},
		},
	}}
	records := Evaluate(contracts, []RuntimeObservation{
		{RuntimeID: "okta-user", SourceID: "okta", TenantID: "writer", Family: "user", Status: "healthy"},
		{RuntimeID: "okta-audit", SourceID: "okta", TenantID: "writer", Family: "audit", Status: "failing"},
		{RuntimeID: "okta-app-assignment", SourceID: "okta", TenantID: "writer", Family: "app_assignment", Status: "healthy"},
	}, Options{TenantID: "writer"})

	byDimension := map[string]Record{}
	for _, record := range records {
		byDimension[record.DimensionID] = record
	}
	for dimension, want := range map[string]string{
		"users":        StateHealthy,
		"apps":         StateUnconfigured,
		"audit":        StateFailed,
		"remediation":  StateUnsupported,
		"entitlements": StatePartial,
	} {
		if got := byDimension[dimension].State; got != want {
			t.Fatalf("%s state = %q, want %q; records=%#v", dimension, got, want, records)
		}
	}
	blindSpots := BlindSpots(records)
	if len(blindSpots) != 4 {
		t.Fatalf("len(BlindSpots()) = %d, want 4: %#v", len(blindSpots), blindSpots)
	}
	summaries := Summaries(records)
	if len(summaries) != 1 || summaries[0].BlindSpots != 4 || summaries[0].Unconfigured != 1 || summaries[0].Failed != 1 {
		t.Fatalf("Summaries() = %#v", summaries)
	}
}

func TestObservationsFromRuntimesPreservesFamilyStatusAndLastSync(t *testing.T) {
	lastSync := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	runtimes := []*cerebrov1.SourceRuntime{{
		Id:           "runtime-1",
		SourceId:     "okta",
		TenantId:     "writer",
		LastSyncedAt: timestamppb.New(lastSync),
		Config: map[string]string{
			"family": "audit",
			"__cerebro_runtime_last_failure_category": "auth_error",
		},
	}}

	observations := ObservationsFromRuntimes(runtimes, func(*cerebrov1.SourceRuntime) string { return "healthy" })

	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}
	got := observations[0]
	if got.RuntimeID != "runtime-1" || got.Family != "audit" || got.LastFailureCategory != "auth_error" {
		t.Fatalf("observation = %#v", got)
	}
	if got.LastSyncedAt != lastSync.Format(time.RFC3339Nano) {
		t.Fatalf("LastSyncedAt = %q, want %q", got.LastSyncedAt, lastSync.Format(time.RFC3339Nano))
	}
}
