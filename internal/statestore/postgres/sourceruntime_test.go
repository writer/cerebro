package postgres

import (
	"context"
	"testing"

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

func TestTouchSourceRuntimeRejectsMissingID(t *testing.T) {
	store := &Store{}
	if err := store.TouchSourceRuntime(context.Background(), " "); err == nil {
		t.Fatal("TouchSourceRuntime() error = nil, want non-nil")
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
