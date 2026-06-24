package postgres

import (
	"database/sql"
	"strings"
	"testing"
	"time"
)

func TestScanCustomDashboard(t *testing.T) {
	created := time.Date(2026, 6, 23, 8, 0, 0, 0, time.UTC)
	updated := time.Date(2026, 6, 23, 9, 0, 0, 0, time.UTC)
	scanner := &fakeScanner{values: []any{
		"dashboard-1", "local", "org-1", "workspace-1", "user-1",
		"GRC trends", "Custom trend view", "workspace", 1,
		`{"columns":12}`, `[{"id":"trend","type":"trend_chart"}]`, `{"severity":"HIGH"}`,
		"user-1", "user-2", created, updated, sql.NullTime{},
	}}
	dashboard, err := scanCustomDashboard(scanner)
	if err != nil {
		t.Fatalf("scanCustomDashboard() error = %v", err)
	}
	if dashboard.ID != "dashboard-1" || dashboard.TenantID != "local" || dashboard.WorkspaceID != "workspace-1" {
		t.Fatalf("unexpected identity fields: %+v", dashboard)
	}
	if dashboard.Name != "GRC trends" || dashboard.Visibility != "workspace" || dashboard.SchemaVersion != 1 {
		t.Fatalf("unexpected content fields: %+v", dashboard)
	}
	if dashboard.WidgetsJSON == "" || dashboard.FiltersJSON == "" || !dashboard.CreatedAt.Equal(created) || !dashboard.UpdatedAt.Equal(updated) {
		t.Fatalf("unexpected JSON/timestamps: %+v", dashboard)
	}
}

func TestCustomDashboardSchemaCreatesTableAndIndexes(t *testing.T) {
	joined := strings.Join(ensureCustomDashboardStatements, "\n")
	for _, fragment := range []string{
		"CREATE TABLE IF NOT EXISTS custom_dashboards",
		"custom_dashboards_tenant_updated_idx",
		"custom_dashboards_workspace_updated_idx",
		"custom_dashboards_owner_updated_idx",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("custom dashboard schema missing %q:\n%s", fragment, joined)
		}
	}
	for _, removed := range []string{"dashboard_users", "dashboard_organizations", "dashboard_workspaces"} {
		if strings.Contains(joined, removed) {
			t.Fatalf("custom dashboard schema should not reference unused identity table %q:\n%s", removed, joined)
		}
	}
}

func TestCustomDashboardListLimit(t *testing.T) {
	cases := []struct {
		in   uint32
		want uint32
	}{
		{in: 0, want: 100},
		{in: 50, want: 50},
		{in: 1000, want: 500},
	}
	for _, tc := range cases {
		if got := customDashboardListLimit(tc.in); got != tc.want {
			t.Fatalf("customDashboardListLimit(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
