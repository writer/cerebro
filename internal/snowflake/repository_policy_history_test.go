package snowflake

import (
	"context"
	"testing"
)

func TestPolicyHistoryRepository_Validation(t *testing.T) {
	repo := &PolicyHistoryRepository{}

	if err := repo.Upsert(context.Background(), nil); err == nil {
		t.Fatal("expected nil record validation error")
		return
	}
	if err := repo.Upsert(context.Background(), &PolicyHistoryRecord{Version: 1}); err == nil {
		t.Fatal("expected missing policy id validation error")
		return
	}
	if err := repo.Upsert(context.Background(), &PolicyHistoryRecord{PolicyID: "p"}); err == nil {
		t.Fatal("expected invalid version validation error")
		return
	}

	if _, err := repo.List(context.Background(), "", 10); err == nil {
		t.Fatal("expected list validation error for missing policy id")
		return
	}
}
