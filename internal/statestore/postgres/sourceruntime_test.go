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

func TestPutSourceRuntimeRejectsMissingSourceID(t *testing.T) {
	store := &Store{}
	err := store.PutSourceRuntime(context.Background(), &cerebrov1.SourceRuntime{Id: "runtime"})
	if err == nil {
		t.Fatal("PutSourceRuntime() error = nil, want non-nil")
	}
}

func TestDecodeSourceRuntimeDiscardsUnknownFields(t *testing.T) {
	runtime, err := decodeSourceRuntime("runtime", `{"id":"runtime","source_id":"okta","future_field":"ignored"}`)
	if err != nil {
		t.Fatalf("decodeSourceRuntime() error = %v", err)
	}
	if runtime.GetId() != "runtime" {
		t.Fatalf("decodeSourceRuntime().Id = %q, want runtime", runtime.GetId())
	}
	if runtime.GetSourceId() != "okta" {
		t.Fatalf("decodeSourceRuntime().SourceId = %q, want okta", runtime.GetSourceId())
	}
}

func TestPutSourceRuntimeEnsuresTableOnce(t *testing.T) {
	recorder := &projectionSQLRecorder{}
	store := newProjectionTestStore(t, recorder)
	runtime := &cerebrov1.SourceRuntime{
		Id:       "runtime",
		SourceId: "okta",
	}

	if err := store.PutSourceRuntime(context.Background(), runtime); err != nil {
		t.Fatalf("PutSourceRuntime(first) error = %v", err)
	}
	if err := store.PutSourceRuntime(context.Background(), runtime); err != nil {
		t.Fatalf("PutSourceRuntime(second) error = %v", err)
	}

	ddlExecs, upserts := recorder.counts()
	if ddlExecs != 1 {
		t.Fatalf("source runtime DDL executions = %d, want 1", ddlExecs)
	}
	if upserts != 2 {
		t.Fatalf("source runtime upserts = %d, want 2", upserts)
	}
}

func TestPutSourceRuntimeRetriesEnsureAfterFailure(t *testing.T) {
	recorder := &projectionSQLRecorder{failNextDDL: true}
	store := newProjectionTestStore(t, recorder)
	runtime := &cerebrov1.SourceRuntime{
		Id:       "runtime",
		SourceId: "okta",
	}

	if err := store.PutSourceRuntime(context.Background(), runtime); err == nil {
		t.Fatal("PutSourceRuntime(first) error = nil, want non-nil")
	}
	if err := store.PutSourceRuntime(context.Background(), runtime); err != nil {
		t.Fatalf("PutSourceRuntime(second) error = %v", err)
	}

	ddlExecs, upserts := recorder.counts()
	if ddlExecs != 2 {
		t.Fatalf("source runtime DDL executions = %d, want 2", ddlExecs)
	}
	if upserts != 1 {
		t.Fatalf("source runtime upserts = %d, want 1", upserts)
	}
}
