package graph

import (
	"testing"
	"time"
)

func TestBuildVendorRiskReportFiltersAndAlerts(t *testing.T) {
	now := time.Date(2026, 3, 20, 0, 0, 0, 0, time.UTC)
	origNow := temporalNowUTC
	defer func() { temporalNowUTC = origNow }()
	temporalNowUTC = func() time.Time { return now }
	earlier := now.Add(-14 * 24 * time.Hour)
	later := now.Add(-24 * time.Hour)

	g := New()

	g.AddNode(&Node{
		ID:   "vendor:slack",
		Kind: NodeKindVendor,
		Name: "Slack",
		Risk: RiskHigh,
		Properties: map[string]any{
			"vendor_risk_score":               86,
			"verification_status":             "verified",
			"vendor_category":                 "saas_integration",
			"permission_level":                "admin",
			"source_providers":                []string{"azure", "okta"},
			"integration_types":               []string{"entra_service_principal", "okta_application"},
			"accessible_resource_kinds":       []string{"bucket", "secret"},
			"accessible_resource_count":       2,
			"sensitive_resource_count":        1,
			"read_access_count":               1,
			"admin_access_count":              1,
			"dependent_principal_count":       4,
			"dependent_user_count":            2,
			"dependent_group_count":           1,
			"dependent_service_account_count": 1,
			"delegated_admin_consent_count":   1,
			"verified_publisher_count":        1,
			"unverified_integration_count":    0,
			"last_grant_updated_at":           later.Add(-time.Hour).Format(time.RFC3339),
			"last_oauth_activity_at":          later.Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{
		ID:   "vendor:zoom",
		Kind: NodeKindVendor,
		Name: "Zoom",
		Risk: RiskLow,
		Properties: map[string]any{
			"vendor_risk_score":            33,
			"verification_status":          "verified",
			"vendor_category":              "saas_integration",
			"permission_level":             "read",
			"accessible_resource_count":    1,
			"sensitive_resource_count":     0,
			"dependent_principal_count":    1,
			"unverified_integration_count": 0,
		},
	})

	slack, ok := g.GetNode("vendor:slack")
	if !ok {
		t.Fatal("expected slack vendor node")
	}
	slack.PropertyHistory = map[string][]PropertySnapshot{
		"vendor_risk_score": {
			{Timestamp: earlier, Value: 44},
			{Timestamp: later, Value: 86},
		},
		"admin_access_count": {
			{Timestamp: earlier, Value: 0},
			{Timestamp: later, Value: 1},
		},
		"sensitive_resource_count": {
			{Timestamp: earlier, Value: 0},
			{Timestamp: later, Value: 1},
		},
	}

	report := BuildVendorRiskReport(g, VendorRiskReportOptions{
		MinRiskScore:     40,
		RiskLevels:       []RiskLevel{RiskHigh, RiskMedium},
		IncludeAlerts:    true,
		MonitoringWindow: 30 * 24 * time.Hour,
	})

	if report.Summary.VendorCount != 2 {
		t.Fatalf("summary vendor_count = %d, want 2", report.Summary.VendorCount)
	}
	if report.TotalCount != 1 || report.Count != 1 {
		t.Fatalf("report counts = total:%d count:%d, want 1/1", report.TotalCount, report.Count)
	}
	if len(report.Vendors) != 1 || report.Vendors[0].VendorID != "vendor:slack" {
		t.Fatalf("expected filtered report to keep slack only, got %#v", report.Vendors)
	}
	if report.Summary.MaxRiskScore != 86 {
		t.Fatalf("max_risk_score = %d, want 86", report.Summary.MaxRiskScore)
	}
	if report.Summary.TotalSensitiveResources != 1 {
		t.Fatalf("total_sensitive_resources = %d, want 1", report.Summary.TotalSensitiveResources)
	}
	if got := report.Summary.RiskCounts[string(RiskHigh)]; got != 1 {
		t.Fatalf("high risk count = %d, want 1", got)
	}
	if len(report.Vendors[0].RiskDrivers) == 0 {
		t.Fatal("expected risk drivers for slack vendor")
	}
	if report.Vendors[0].RiskDrivers[0].Type != "admin_access" {
		t.Fatalf("expected admin_access to sort first, got %#v", report.Vendors[0].RiskDrivers[0])
	}
	if len(report.Alerts) == 0 {
		t.Fatal("expected monitoring alerts for slack vendor")
	}
	foundRiskScoreIncrease := false
	foundAdminExpansion := false
	for _, alert := range report.Alerts {
		switch alert.Type {
		case "risk_score_increase":
			foundRiskScoreIncrease = true
			if alert.Delta <= 0 {
				t.Fatalf("expected positive risk-score delta, got %#v", alert)
			}
		case "admin_access_expansion":
			foundAdminExpansion = true
		}
	}
	if !foundRiskScoreIncrease || !foundAdminExpansion {
		t.Fatalf("expected risk score and admin expansion alerts, got %#v", report.Alerts)
	}
}
