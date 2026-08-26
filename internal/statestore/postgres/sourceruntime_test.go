package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

func TestPutSourceRuntimeRejectsNilRuntime(t *testing.T) {
	store := &Store{}
	if err := store.PutSourceRuntime(context.Background(), nil); err == nil {
		t.Fatal("PutSourceRuntime() error = nil, want non-nil")
	}
}

func TestGetSourceRuntimeRejectsMissingID(t *testing.T) {
	store := &Store{}
	if _, err := store.GetSourceRuntime(context.Background(), ""); err == nil {
		t.Fatal("GetSourceRuntime() error = nil, want non-nil")
	}
}

func TestAcquireSourceRuntimeLeaseRejectsMissingID(t *testing.T) {
	store := &Store{}
	if _, err := store.AcquireSourceRuntimeLease(context.Background(), " ", "owner", time.Minute); err == nil {
		t.Fatal("AcquireSourceRuntimeLease() error = nil, want non-nil")
	}
}

func TestAcquireSourceRuntimeLeaseRejectsMissingOwner(t *testing.T) {
	store := &Store{}
	if _, err := store.AcquireSourceRuntimeLease(context.Background(), "runtime", " ", time.Minute); err == nil {
		t.Fatal("AcquireSourceRuntimeLease() error = nil, want non-nil")
	}
}

func TestAcquireSourceRuntimeLeaseRejectsNonPositiveTTL(t *testing.T) {
	store := &Store{}
	if _, err := store.AcquireSourceRuntimeLease(context.Background(), "runtime", "owner", 0); err == nil {
		t.Fatal("AcquireSourceRuntimeLease() error = nil, want non-nil")
	}
}

func TestRenewSourceRuntimeLeaseRejectsMissingOwner(t *testing.T) {
	store := &Store{}
	if _, err := store.RenewSourceRuntimeLease(context.Background(), "runtime", " ", time.Minute); err == nil {
		t.Fatal("RenewSourceRuntimeLease() error = nil, want non-nil")
	}
}

func TestPutSourceRuntimeRejectsMissingSourceID(t *testing.T) {
	store := &Store{}
	err := store.PutSourceRuntime(context.Background(), &cerebrov1.SourceRuntime{Id: "runtime"})
	if err == nil {
		t.Fatal("PutSourceRuntime() error = nil, want non-nil")
	}
}

func TestSourceRuntimeListOrderRotatesRecentlyUpdatedRows(t *testing.T) {
	if got := sourceRuntimeListOrderClause(); got != "updated_at ASC, id ASC" {
		t.Fatalf("sourceRuntimeListOrderClause() = %q, want least recently updated first", got)
	}
}

func TestSourceRuntimeSchemaIndexesDashboardFilters(t *testing.T) {
	joined := strings.Join(ensureSourceRuntimeStatements, "\n")
	for _, fragment := range []string{
		"lease_generation BIGINT NOT NULL DEFAULT 0",
		"tenant_id TEXT GENERATED ALWAYS AS",
		"source_id TEXT GENERATED ALWAYS AS",
		"application_workspace_id TEXT GENERATED ALWAYS AS",
		"source_runtimes_scope_updated_idx",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS source_runtimes_scope_updated_idx",
		"tenant_id, updated_at ASC, id ASC",
		"source_runtimes_scope_source_updated_idx",
		"tenant_id, source_id, updated_at ASC, id ASC",
		"source_runtimes_scope_workspace_updated_idx",
		"tenant_id, application_workspace_id, updated_at ASC, id ASC",
		"DROP INDEX CONCURRENTLY IF EXISTS source_runtimes_tenant_updated_idx",
		"DROP INDEX CONCURRENTLY IF EXISTS source_runtimes_tenant_source_updated_idx",
		"DROP INDEX CONCURRENTLY IF EXISTS source_runtimes_tenant_workspace_updated_idx",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("source runtime schema missing %q:\n%s", fragment, joined)
		}
	}
	if strings.Contains(joined, "source_runtimes_lease_expiry_idx") {
		t.Fatalf("source runtime schema includes unused lease expiry index:\n%s", joined)
	}
}

func TestSourceRuntimeListQueryScopesTenantAndApplicationWorkspace(t *testing.T) {
	query, args, err := sourceRuntimeListQuery(ports.SourceRuntimeFilter{
		TenantID:               "tenant-a",
		ApplicationWorkspaceID: "workspace-a",
		SourceID:               "okta",
		Limit:                  13,
	})
	if err != nil {
		t.Fatalf("sourceRuntimeListQuery() error = %v", err)
	}
	for _, fragment := range []string{
		"tenant_id = $1",
		"application_workspace_id = $2",
		"source_id = $3",
		"LIMIT $4",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("source runtime query missing %q:\n%s", fragment, query)
		}
	}
	if strings.Contains(query, "runtime_json->") {
		t.Fatalf("source runtime query re-parses JSON scope fields:\n%s", query)
	}
	if len(args) != 4 || args[0] != "tenant-a" || args[1] != "workspace-a" || args[2] != "okta" || args[3] != uint32(13) {
		t.Fatalf("source runtime query args = %#v, want tenant/workspace/source/limit", args)
	}
}

func TestSourceRuntimeGeneratedScopeColumnsStayTenantWorkspaceIsolatedPostgresIntegration(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run source runtime scope integration test")
	}
	store, err := Open(config.StateStoreConfig{Driver: config.StateStoreDriverPostgres, PostgresDSN: dsn})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	unique := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")) + "-" + time.Now().UTC().Format("20060102150405.000000000")
	tenantA := unique + "-tenant-a"
	tenantB := unique + "-tenant-b"
	workspaceA := unique + "-workspace-a"
	workspaceB := unique + "-workspace-b"
	runtimeA := &cerebrov1.SourceRuntime{
		Id:       unique + "-runtime-a",
		TenantId: tenantA,
		SourceId: "okta",
		Config:   map[string]string{ports.SourceRuntimeApplicationWorkspaceIDConfigKey: workspaceA},
	}
	runtimeOtherTenant := &cerebrov1.SourceRuntime{
		Id:       unique + "-runtime-other-tenant",
		TenantId: tenantB,
		SourceId: "okta",
		Config:   map[string]string{ports.SourceRuntimeApplicationWorkspaceIDConfigKey: workspaceA},
	}
	runtimeOtherWorkspace := &cerebrov1.SourceRuntime{
		Id:       unique + "-runtime-other-workspace",
		TenantId: tenantA,
		SourceId: "okta",
		Config:   map[string]string{ports.SourceRuntimeApplicationWorkspaceIDConfigKey: workspaceB},
	}
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(ctx, `DELETE FROM source_runtimes WHERE id = ANY($1::text[])`, []string{runtimeA.GetId(), runtimeOtherTenant.GetId(), runtimeOtherWorkspace.GetId()})
	})
	if err := store.PutSourceRuntimes(ctx, []*cerebrov1.SourceRuntime{runtimeA, runtimeOtherTenant, runtimeOtherWorkspace}); err != nil {
		t.Fatalf("PutSourceRuntimes() error = %v", err)
	}

	assertScopeColumns := func(wantTenant, wantSource, wantWorkspace string) {
		t.Helper()
		var tenantID, sourceID, workspaceID string
		if err := store.db.QueryRowContext(ctx, `
SELECT tenant_id, source_id, application_workspace_id
FROM source_runtimes
WHERE id = $1`, runtimeA.GetId()).Scan(&tenantID, &sourceID, &workspaceID); err != nil {
			t.Fatalf("read generated source runtime scope: %v", err)
		}
		if tenantID != wantTenant || sourceID != wantSource || workspaceID != wantWorkspace {
			t.Fatalf("generated scope = tenant %q source %q workspace %q, want %q/%q/%q", tenantID, sourceID, workspaceID, wantTenant, wantSource, wantWorkspace)
		}
	}
	assertScopeColumns(tenantA, "okta", workspaceA)

	runtimes, err := store.ListSourceRuntimes(ctx, ports.SourceRuntimeFilter{TenantID: tenantA, ApplicationWorkspaceID: workspaceA})
	if err != nil {
		t.Fatalf("ListSourceRuntimes() error = %v", err)
	}
	if len(runtimes) != 1 || runtimes[0].GetId() != runtimeA.GetId() {
		t.Fatalf("tenant/workspace scoped runtimes = %v, want only %q", sourceRuntimeIDs(runtimes), runtimeA.GetId())
	}

	runtimeA.TenantId = tenantB
	runtimeA.SourceId = "github"
	runtimeA.Config[ports.SourceRuntimeApplicationWorkspaceIDConfigKey] = workspaceB
	if err := store.PutSourceRuntime(ctx, runtimeA); err != nil {
		t.Fatalf("PutSourceRuntime(update) error = %v", err)
	}
	assertScopeColumns(tenantB, "github", workspaceB)
	runtimes, err = store.ListSourceRuntimes(ctx, ports.SourceRuntimeFilter{TenantID: tenantA, ApplicationWorkspaceID: workspaceA})
	if err != nil {
		t.Fatalf("ListSourceRuntimes(old scope) error = %v", err)
	}
	if len(runtimes) != 0 {
		t.Fatalf("old tenant/workspace scope leaked updated runtime ids %v", sourceRuntimeIDs(runtimes))
	}
}

func sourceRuntimeIDs(runtimes []*cerebrov1.SourceRuntime) []string {
	ids := make([]string, 0, len(runtimes))
	for _, runtime := range runtimes {
		ids = append(ids, runtime.GetId())
	}
	return ids
}
