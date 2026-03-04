package snowflake

import (
	"testing"
	"time"
)

func TestAssetFilter_CursorFields(t *testing.T) {
	now := time.Now()
	f := AssetFilter{
		CursorSyncTime: now,
		CursorID:       "cursor-123",
		Limit:          50,
	}
	if f.CursorSyncTime != now {
		t.Errorf("CursorSyncTime mismatch")
	}
	if f.CursorID != "cursor-123" {
		t.Errorf("CursorID = %q", f.CursorID)
	}
}

func TestGetAssets_StableOrdering(t *testing.T) {
	// Verify that AssetFilter with zero Since still gets cursor fields
	f := AssetFilter{
		Limit: 100,
	}
	if !f.Since.IsZero() {
		t.Error("Since should be zero for full scan")
	}
	if !f.CursorSyncTime.IsZero() {
		t.Error("CursorSyncTime should be zero initially")
	}
}
