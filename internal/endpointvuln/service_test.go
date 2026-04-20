package endpointvuln

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/threatintel"
	"github.com/writer/cerebro/internal/warehouse"
)

type fakeThreatIntel struct {
	indicators map[string]*threatintel.Indicator
}

func (f fakeThreatIntel) LookupCVE(cve string) (*threatintel.Indicator, bool) {
	indicator, ok := f.indicators[normalizeCVE(cve)]
	return indicator, ok
}

func (f fakeThreatIntel) IsKEV(cve string) bool {
	indicator, ok := f.LookupCVE(cve)
	return ok && indicator != nil && indicator.Source == "cisa-kev"
}

type fakeAdvisories struct {
	entries map[string]*scanner.CVEInfo
}

func (f fakeAdvisories) LookupCVE(cve string) (*scanner.CVEInfo, bool) {
	info, ok := f.entries[normalizeCVE(cve)]
	return info, ok
}

func (f fakeAdvisories) IsKEV(cve string) bool {
	info, ok := f.LookupCVE(cve)
	return ok && info != nil && info.InKEV
}

func TestRefresherBuildsCorrelatedEndpointVulnerabilityTables(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newTestWarehouse(t)
	seedEndpointVulnSourceTables(t, ctx, store)

	now := time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)
	refresher := Refresher{
		Warehouse: store,
		ThreatIntel: fakeThreatIntel{
			indicators: map[string]*threatintel.Indicator{
				"CVE-2026-0001": {
					ID:     "CVE-2026-0001",
					Type:   threatintel.IndicatorTypeCVE,
					Value:  "CVE-2026-0001",
					Source: "cisa-kev",
					Metadata: map[string]string{
						"due_date": "2026-04-20",
					},
				},
			},
		},
		Advisories: fakeAdvisories{
			entries: map[string]*scanner.CVEInfo{
				"CVE-2026-0001": {
					ID:             "CVE-2026-0001",
					Severity:       "critical",
					Description:    "Actively exploited browser issue",
					CVSS:           9.8,
					EPSSScore:      0.97,
					EPSSPercentile: 0.99,
					Exploitable:    true,
					InKEV:          true,
					References:     []string{"https://example.com/CVE-2026-0001"},
				},
			},
		},
		Now: func() time.Time { return now },
	}

	if err := refresher.Refresh(ctx); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	tables, err := store.ListAvailableTables(ctx)
	if err != nil {
		t.Fatalf("list tables failed: %v", err)
	}
	for _, table := range []string{endpointsTableName, endpointSoftwareTableName, vulnerabilitiesTableName} {
		if !containsString(tables, table) {
			t.Fatalf("expected table %q in %#v", table, tables)
		}
	}

	endpointsResult, err := store.Query(ctx, "SELECT * FROM endpoints")
	if err != nil {
		t.Fatalf("query endpoints failed: %v", err)
	}
	if endpointsResult.Count != 1 {
		t.Fatalf("expected 1 endpoint row, got %#v", endpointsResult.Rows)
	}
	endpoint := endpointsResult.Rows[0]
	if got := rowInt(endpoint, "provider_count"); got != 3 {
		t.Fatalf("endpoint provider_count = %d, want 3", got)
	}
	if got := rowString(endpoint, "providers"); got != "crowdstrike,kandji,sentinelone" {
		t.Fatalf("endpoint providers = %q, want crowdstrike,kandji,sentinelone", got)
	}
	if !rowBool(endpoint, "mdm_enrolled") || !rowBool(endpoint, "edr_installed") || !rowBool(endpoint, "malware_protection_enabled") {
		t.Fatalf("expected merged endpoint protections, got %#v", endpoint)
	}
	if got := rowString(endpoint, "correlation_confidence"); got != "high" {
		t.Fatalf("endpoint correlation_confidence = %q, want high", got)
	}

	softwareResult, err := store.Query(ctx, "SELECT * FROM endpoint_software_inventory")
	if err != nil {
		t.Fatalf("query endpoint software failed: %v", err)
	}
	if softwareResult.Count != 1 {
		t.Fatalf("expected 1 software row, got %#v", softwareResult.Rows)
	}
	software := softwareResult.Rows[0]
	if got := rowInt(software, "provider_count"); got != 2 {
		t.Fatalf("software provider_count = %d, want 2", got)
	}
	if got := rowString(software, "software_name"); got != "Chrome" {
		t.Fatalf("software_name = %q, want Chrome", got)
	}

	vulnResult, err := store.Query(ctx, "SELECT * FROM vulnerabilities")
	if err != nil {
		t.Fatalf("query vulnerabilities failed: %v", err)
	}
	if vulnResult.Count != 1 {
		t.Fatalf("expected 1 vulnerability row, got %#v", vulnResult.Rows)
	}
	vulnerability := vulnResult.Rows[0]
	if got := rowString(vulnerability, "cve_id"); got != "CVE-2026-0001" {
		t.Fatalf("cve_id = %q, want CVE-2026-0001", got)
	}
	if got := rowString(vulnerability, "severity"); got != "CRITICAL" {
		t.Fatalf("severity = %q, want CRITICAL", got)
	}
	if got := rowString(vulnerability, "priority"); got != "critical" {
		t.Fatalf("priority = %q, want critical", got)
	}
	if !rowBool(vulnerability, "is_kev") || !rowBool(vulnerability, "exploited_in_wild") {
		t.Fatalf("expected KEV/exploit enrichment, got %#v", vulnerability)
	}
	if got := rowString(vulnerability, "kev_due_date"); got != "2026-04-20" {
		t.Fatalf("kev_due_date = %q, want 2026-04-20", got)
	}
	if got := rowInt(vulnerability, "provider_count"); got != 3 {
		t.Fatalf("vulnerability provider_count = %d, want 3", got)
	}
	if got := rowInt(vulnerability, "days_open"); got != 9 {
		t.Fatalf("days_open = %d, want 9", got)
	}
	if got := rowString(vulnerability, "providers"); got != "crowdstrike,kandji,sentinelone" {
		t.Fatalf("vulnerability providers = %q, want crowdstrike,kandji,sentinelone", got)
	}
	if got := rowString(vulnerability, "references_json"); !strings.Contains(got, "CVE-2026-0001") {
		t.Fatalf("expected references_json to contain advisory reference, got %q", got)
	}
}

func TestRefresherCreatesEmptyNormalizedTablesWithoutSourceTables(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newTestWarehouse(t)

	refresher := Refresher{
		Warehouse: store,
		Now:       func() time.Time { return time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC) },
	}
	if err := refresher.Refresh(ctx); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	for _, table := range []string{endpointsTableName, endpointSoftwareTableName, vulnerabilitiesTableName} {
		result, err := store.Query(ctx, "SELECT * FROM "+table)
		if err != nil {
			t.Fatalf("query %s failed: %v", table, err)
		}
		if result.Count != 0 {
			t.Fatalf("expected %s to be empty, got %#v", table, result.Rows)
		}
	}
}

func TestRefresherRefreshKeepsNormalizedTablesAtomicOnInsertFailure(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newTestWarehouse(t)
	seedEndpointVulnSourceTables(t, ctx, store)

	refresher := Refresher{
		Warehouse: store,
		Now:       func() time.Time { return time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC) },
	}
	if err := refresher.Refresh(ctx); err != nil {
		t.Fatalf("initial refresh failed: %v", err)
	}

	if _, err := store.Exec(ctx, `INSERT INTO kandji_devices (
		device_id, device_name, serial_number, platform, os_version, last_check_in, user_name, user_email, agent_installed, firewall_enabled, filevault_enabled
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"device-2", "macbook-02", "SERIAL-2", "macOS", "14.4", "2026-04-14T12:00:00Z", "analyst", "analyst@example.com", true, true, true,
	); err != nil {
		t.Fatalf("seed second device: %v", err)
	}
	if _, err := store.Exec(ctx, `INSERT INTO kandji_device_apps (device_id, app_name, version, bundle_id) VALUES (?, ?, ?, ?)`,
		"device-2", "Firefox", "125.0", "org.mozilla.firefox",
	); err != nil {
		t.Fatalf("seed second app: %v", err)
	}
	if _, err := store.Exec(ctx, `INSERT INTO kandji_vulnerabilities (
		device_id, cve_id, software_name, software_version, cvss_score, cvss_severity, first_detection_date, latest_detection_date, cve_link
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"device-2", "CVE-2026-9999", "Firefox", "125.0", 7.8, "high", "2026-04-13T00:00:00Z", "2026-04-14T00:00:00Z", "https://example.com/CVE-2026-9999",
	); err != nil {
		t.Fatalf("seed second vulnerability: %v", err)
	}
	if _, err := store.Exec(ctx, `
		CREATE TRIGGER fail_vulnerabilities_insert
		BEFORE INSERT ON vulnerabilities
		BEGIN
			SELECT RAISE(FAIL, 'vulnerability refresh blocked');
		END;
	`); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}

	err := refresher.Refresh(ctx)
	if err == nil || !strings.Contains(err.Error(), "insert into vulnerabilities") {
		t.Fatalf("expected vulnerability insert failure, got %v", err)
	}

	for _, tc := range []struct {
		name string
		want int
	}{
		{name: endpointsTableName, want: 1},
		{name: endpointSoftwareTableName, want: 1},
		{name: vulnerabilitiesTableName, want: 1},
	} {
		result, queryErr := store.Query(ctx, "SELECT * FROM "+tc.name)
		if queryErr != nil {
			t.Fatalf("query %s failed: %v", tc.name, queryErr)
		}
		if result.Count != tc.want {
			t.Fatalf("%s count = %d, want %d", tc.name, result.Count, tc.want)
		}
	}
}

func newTestWarehouse(t *testing.T) *warehouse.SQLiteWarehouse {
	t.Helper()

	store, err := warehouse.NewSQLiteWarehouse(warehouse.SQLiteWarehouseConfig{
		Path:      filepath.Join(t.TempDir(), "warehouse.db"),
		Database:  "sqlite",
		Schema:    "RAW",
		AppSchema: "CEREBRO",
	})
	if err != nil {
		t.Fatalf("new sqlite warehouse: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func seedEndpointVulnSourceTables(t *testing.T, ctx context.Context, store *warehouse.SQLiteWarehouse) {
	t.Helper()

	statements := []string{
		`CREATE TABLE kandji_devices (
			device_id TEXT,
			device_name TEXT,
			serial_number TEXT,
			platform TEXT,
			os_version TEXT,
			last_check_in TEXT,
			user_name TEXT,
			user_email TEXT,
			agent_installed BOOLEAN,
			firewall_enabled BOOLEAN,
			filevault_enabled BOOLEAN
		)`,
		`CREATE TABLE kandji_device_apps (
			device_id TEXT,
			app_name TEXT,
			version TEXT,
			bundle_id TEXT
		)`,
		`CREATE TABLE kandji_vulnerabilities (
			device_id TEXT,
			cve_id TEXT,
			software_name TEXT,
			software_version TEXT,
			cvss_score FLOAT,
			cvss_severity TEXT,
			first_detection_date TEXT,
			latest_detection_date TEXT,
			cve_link TEXT
		)`,
		`CREATE TABLE sentinelone_agents (
			id TEXT,
			computer_name TEXT,
			os_type TEXT,
			os_version TEXT,
			is_active BOOLEAN,
			last_active_date TEXT,
			firewall_enabled BOOLEAN
		)`,
		`CREATE TABLE sentinelone_applications (
			agent_id TEXT,
			name TEXT,
			version TEXT,
			publisher TEXT,
			installed_date TEXT
		)`,
		`CREATE TABLE sentinelone_vulnerabilities (
			agent_id TEXT,
			cve_id TEXT,
			application_name TEXT,
			application_version TEXT,
			severity TEXT,
			cvss_score FLOAT,
			exploited_in_wild BOOLEAN,
			days_since_detection INTEGER,
			remediation_action TEXT,
			detected_at TEXT
		)`,
		`CREATE TABLE crowdstrike_hosts (
			device_id TEXT,
			hostname TEXT,
			platform_name TEXT,
			os_version TEXT,
			last_seen TEXT
		)`,
		`CREATE TABLE crowdstrike_vulnerabilities (
			id TEXT,
			cve_id TEXT,
			host_id TEXT,
			severity TEXT,
			status TEXT,
			app_name TEXT,
			app_version TEXT,
			exploit_available BOOLEAN,
			created_at TEXT,
			updated_at TEXT,
			remediation_action TEXT
		)`,
	}

	for _, statement := range statements {
		if _, err := store.Exec(ctx, statement); err != nil {
			t.Fatalf("exec %q: %v", statement, err)
		}
	}

	inserts := []struct {
		query string
		args  []any
	}{
		{
			query: `INSERT INTO kandji_devices (device_id, device_name, serial_number, platform, os_version, last_check_in, user_name, user_email, agent_installed, firewall_enabled, filevault_enabled)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			args: []any{"device-1", "host-1.corp.example", "SERIAL-1", "macOS", "14.4", "2026-04-14T08:00:00Z", "Jane Doe", "jane@example.com", true, true, true},
		},
		{
			query: `INSERT INTO kandji_device_apps (device_id, app_name, version, bundle_id) VALUES (?, ?, ?, ?)`,
			args:  []any{"device-1", "Chrome", "1.2.3", "com.google.Chrome"},
		},
		{
			query: `INSERT INTO kandji_vulnerabilities (device_id, cve_id, software_name, software_version, cvss_score, cvss_severity, first_detection_date, latest_detection_date, cve_link)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			args: []any{"device-1", "CVE-2026-0001", "Chrome", "1.2.3", 7.2, "high", "2026-04-05T00:00:00Z", "2026-04-14T00:00:00Z", "https://kandji.example/CVE-2026-0001"},
		},
		{
			query: `INSERT INTO sentinelone_agents (id, computer_name, os_type, os_version, is_active, last_active_date, firewall_enabled)
				VALUES (?, ?, ?, ?, ?, ?, ?)`,
			args: []any{"agent-1", "host-1", "macos", "14.4", true, "2026-04-14T09:30:00Z", true},
		},
		{
			query: `INSERT INTO sentinelone_applications (agent_id, name, version, publisher, installed_date) VALUES (?, ?, ?, ?, ?)`,
			args:  []any{"agent-1", "Chrome", "1.2.3", "Google", "2026-04-01T00:00:00Z"},
		},
		{
			query: `INSERT INTO sentinelone_vulnerabilities (agent_id, cve_id, application_name, application_version, severity, cvss_score, exploited_in_wild, days_since_detection, remediation_action, detected_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			args: []any{"agent-1", "CVE-2026-0001", "Chrome", "1.2.3", "high", 8.4, true, 9, "Update Chrome to a patched release", "2026-04-05T00:00:00Z"},
		},
		{
			query: `INSERT INTO crowdstrike_hosts (device_id, hostname, platform_name, os_version, last_seen) VALUES (?, ?, ?, ?, ?)`,
			args:  []any{"device-cs-1", "host-1", "Mac", "14.4", "2026-04-14T10:00:00Z"},
		},
		{
			query: `INSERT INTO crowdstrike_vulnerabilities (id, cve_id, host_id, severity, status, app_name, app_version, exploit_available, created_at, updated_at, remediation_action)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			args: []any{"device-cs-1|CVE-2026-0001|Chrome|1.2.3", "CVE-2026-0001", "device-cs-1", "critical", "open", "Chrome", "1.2.3", true, "2026-04-06T00:00:00Z", "2026-04-14T00:00:00Z", "Upgrade Chrome"},
		},
	}

	for _, insert := range inserts {
		if _, err := store.Exec(ctx, insert.query, insert.args...); err != nil {
			t.Fatalf("insert source row failed: %v", err)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
