package warehouse

import (
	"context"
	"testing"

	"github.com/evalops/cerebro/internal/snowflake"
)

func TestMemoryWarehouseRecordsCalls(t *testing.T) {
	store := &MemoryWarehouse{SchemaValue: "RAW"}
	_, err := store.Query(context.Background(), "SELECT 1", "arg")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(store.Queries) != 1 {
		t.Fatalf("expected 1 recorded query, got %d", len(store.Queries))
	}
	if store.Queries[0].Statement != "SELECT 1" {
		t.Fatalf("unexpected statement %q", store.Queries[0].Statement)
	}
	if store.Schema() != "RAW" {
		t.Fatalf("expected schema RAW, got %q", store.Schema())
	}
}

func TestMemoryWarehouseTracksCDCEvents(t *testing.T) {
	store := &MemoryWarehouse{}
	events := []snowflake.CDCEvent{{TableName: "AWS_IAM_USERS", ResourceID: "user-1"}}
	if err := store.InsertCDCEvents(context.Background(), events); err != nil {
		t.Fatalf("insert cdc events: %v", err)
	}
	if len(store.CDCBatches) != 1 {
		t.Fatalf("expected one cdc batch, got %d", len(store.CDCBatches))
	}
	if len(store.CDCBatches[0]) != 1 || store.CDCBatches[0][0].ResourceID != "user-1" {
		t.Fatalf("unexpected cdc batch contents %#v", store.CDCBatches)
	}
}
