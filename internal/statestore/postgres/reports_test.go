package postgres

import (
	"context"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestPutReportRunRejectsNilRun(t *testing.T) {
	store := &Store{}
	if err := store.PutReportRun(context.Background(), nil); err == nil {
		t.Fatal("PutReportRun() error = nil, want non-nil")
	}
}

func TestPutReportRunRejectsMissingReportID(t *testing.T) {
	store := &Store{}
	err := store.PutReportRun(context.Background(), &cerebrov1.ReportRun{
		Id:     "report-run-1",
		Status: "completed",
	})
	if err == nil {
		t.Fatal("PutReportRun() error = nil, want non-nil")
	}
}

func TestGetReportRunRejectsUnconfiguredStore(t *testing.T) {
	store := &Store{}
	if _, err := store.GetReportRun(context.Background(), "report-run-1"); err == nil {
		t.Fatal("GetReportRun() error = nil, want non-nil")
	}
}

func TestGetReportRunRejectsMissingID(t *testing.T) {
	store := &Store{}
	if _, err := store.GetReportRun(context.Background(), ""); err == nil {
		t.Fatal("GetReportRun() error = nil, want non-nil")
	}
}

func TestPutReportRunRejectsUnconfiguredStore(t *testing.T) {
	store := &Store{}
	result, err := structpb.NewStruct(map[string]any{"total_findings": 1})
	if err != nil {
		t.Fatalf("NewStruct() error = %v", err)
	}
	err = store.PutReportRun(context.Background(), &cerebrov1.ReportRun{
		Id:       "report-run-1",
		ReportId: "finding-summary",
		Status:   "completed",
		Result:   result,
	})
	if err == nil {
		t.Fatal("PutReportRun() error = nil, want non-nil")
	}
}
