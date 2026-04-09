package snowflake

import (
	"context"
	"testing"
	"time"
)

func TestRetentionRepository_RequiresInitialization(t *testing.T) {
	repo := &RetentionRepository{}
	cutoff := time.Now().UTC().Add(-24 * time.Hour)

	if _, err := repo.CleanupAuditLogs(context.Background(), cutoff); err == nil {
		t.Fatal("expected cleanup audit logs to fail when repository is uninitialized")
		return
	}

	if _, _, err := repo.CleanupAgentData(context.Background(), cutoff); err == nil {
		t.Fatal("expected cleanup agent data to fail when repository is uninitialized")
		return
	}

	if _, _, _, err := repo.CleanupGraphData(context.Background(), cutoff); err == nil {
		t.Fatal("expected cleanup graph data to fail when repository is uninitialized")
		return
	}

	if _, _, err := repo.CleanupAccessReviewData(context.Background(), cutoff); err == nil {
		t.Fatal("expected cleanup access review data to fail when repository is uninitialized")
		return
	}
}
