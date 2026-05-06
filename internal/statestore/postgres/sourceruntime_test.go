package postgres

import (
	"context"
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
