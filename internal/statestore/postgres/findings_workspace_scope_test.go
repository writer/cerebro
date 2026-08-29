package postgres

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

// TestListFindingsWorkspaceScopeKeepsLegacyTenantRows pins the scoping rule for
// application_workspace_id.
//
// The durable emit path never populates the column, so every finding written by
// a Go event rule stores the ” default. Filtering a workspace-scoped list on
// plain equality hid all of those rows, which silently emptied the ListFindings
// API and stopped counter-event remediation from closing them. Legacy rows are
// tenant-scoped and must stay visible; a row belonging to a different workspace
// in the same tenant must not.
//
// Run with: CEREBRO_POSTGRES_DSN=... go test ./internal/statestore/postgres -run TestListFindingsWorkspaceScopeKeepsLegacyTenantRows -count=1
func TestListFindingsWorkspaceScopeKeepsLegacyTenantRows(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run the finding workspace scope integration test")
	}
	store, err := Open(config.StateStoreConfig{Driver: config.StateStoreDriverPostgres, PostgresDSN: dsn})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	ctx := context.Background()

	nonce := time.Now().UTC().UnixNano()
	tenantID := fmt.Sprintf("tenant-workspace-scope-%d", nonce)
	ruleID := fmt.Sprintf("rule-workspace-scope-%d", nonce)
	observed := time.Now().UTC().Truncate(time.Microsecond)

	t.Cleanup(func() {
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM findings WHERE tenant_id = $1`, tenantID)
		_ = store.Close()
	})

	seed := []struct {
		id        string
		workspace string
	}{
		{id: "legacy-unscoped", workspace: ""},
		{id: "workspace-a", workspace: "tenant-only:" + tenantID},
		{id: "workspace-b", workspace: "other-workspace"},
	}
	for _, entry := range seed {
		record := &ports.FindingRecord{
			ID:              fmt.Sprintf("finding-%s-%d", entry.id, nonce),
			Fingerprint:     fmt.Sprintf("fp-%s-%d", entry.id, nonce),
			TenantID:        tenantID,
			RuntimeID:       fmt.Sprintf("runtime-workspace-scope-%d", nonce),
			RuleID:          ruleID,
			Title:           "Workspace scope finding",
			Severity:        "HIGH",
			Status:          "open",
			Summary:         "summary",
			FirstObservedAt: observed,
			LastObservedAt:  observed,
		}
		record.ApplicationWorkspaceID = entry.workspace
		if _, err := store.UpsertFinding(ctx, record); err != nil {
			t.Fatalf("seed %q: %v", entry.id, err)
		}
	}

	listed, err := store.ListFindings(ctx, ports.ListFindingsRequest{
		TenantID:               tenantID,
		ApplicationWorkspaceID: "tenant-only:" + tenantID,
		RuleID:                 ruleID,
		Status:                 "open",
	})
	if err != nil {
		t.Fatalf("ListFindings() error = %v", err)
	}

	got := make([]string, 0, len(listed))
	for _, finding := range listed {
		got = append(got, strings.TrimSpace(finding.ApplicationWorkspaceID))
	}
	sort.Strings(got)
	want := []string{"", "tenant-only:" + tenantID}
	if len(got) != len(want) {
		t.Fatalf("ListFindings() workspaces = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ListFindings() workspaces = %q, want %q", got, want)
		}
	}
}
