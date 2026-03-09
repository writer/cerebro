package snowflake

import (
	"context"
	"testing"
)

func TestRiskEngineStateRepository_Validation(t *testing.T) {
	repo := &RiskEngineStateRepository{}
	if err := repo.SaveSnapshot(context.Background(), "graph-id", []byte("{}")); err == nil {
		t.Fatal("expected save to fail when repository is uninitialized")
	}
	if _, err := repo.LoadSnapshot(context.Background(), "graph-id"); err == nil {
		t.Fatal("expected load to fail when repository is uninitialized")
	}

	repo = &RiskEngineStateRepository{
		client: &Client{},
		schema: "CEREBRO.CEREBRO",
	}
	if err := repo.SaveSnapshot(context.Background(), "", []byte("{}")); err == nil {
		t.Fatal("expected save validation error for missing graph id")
	}
	if _, err := repo.LoadSnapshot(context.Background(), ""); err == nil {
		t.Fatal("expected load validation error for missing graph id")
	}
}
