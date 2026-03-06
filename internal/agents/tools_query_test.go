package agents

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/evalops/cerebro/internal/snowflake"
)

func TestQueryAssetsRejectsUnsafeQuery(t *testing.T) {
	st := &SecurityTools{}
	args := json.RawMessage(`{"query":"DROP TABLE users"}`)

	_, err := st.queryAssets(context.Background(), args)
	if !errors.Is(err, snowflake.ErrNonSelectQuery) {
		t.Fatalf("expected ErrNonSelectQuery, got %v", err)
	}
}

func TestQueryAssetsRequiresSnowflakeForValidQuery(t *testing.T) {
	st := &SecurityTools{}
	args := json.RawMessage(`{"query":"SELECT * FROM users"}`)

	_, err := st.queryAssets(context.Background(), args)
	if err == nil || err.Error() != "snowflake not configured" {
		t.Fatalf("expected snowflake not configured error, got %v", err)
	}
}
