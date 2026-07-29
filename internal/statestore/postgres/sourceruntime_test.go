package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
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
		"source_runtimes_tenant_updated_idx",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS source_runtimes_tenant_updated_idx",
		"(runtime_json->>'tenant_id'), updated_at ASC, id ASC",
		"source_runtimes_tenant_source_updated_idx",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS source_runtimes_tenant_source_updated_idx",
		"(runtime_json->>'tenant_id'), (runtime_json->>'source_id'), updated_at ASC, id ASC",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("source runtime schema missing %q:\n%s", fragment, joined)
		}
	}
	if strings.Contains(joined, "source_runtimes_lease_expiry_idx") {
		t.Fatalf("source runtime schema includes unused lease expiry index:\n%s", joined)
	}
}
