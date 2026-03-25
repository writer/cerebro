package agents

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/writer/cerebro/internal/warehouse"
)

func TestQueryAssetsRejectsUnsafeQuery(t *testing.T) {
	st := &SecurityTools{}
	args := json.RawMessage(`{"query":"DROP TABLE users"}`)

	_, err := st.queryAssets(context.Background(), args)
	if !errors.Is(err, warehouse.ErrNonSelectQuery) {
		t.Fatalf("expected ErrNonSelectQuery, got %v", err)
	}
}

func TestQueryAssetsRequiresWarehouseForValidQuery(t *testing.T) {
	st := &SecurityTools{}
	args := json.RawMessage(`{"query":"SELECT * FROM users"}`)

	_, err := st.queryAssets(context.Background(), args)
	if err == nil || err.Error() != "warehouse not configured" {
		t.Fatalf("expected warehouse not configured error, got %v", err)
	}
}
