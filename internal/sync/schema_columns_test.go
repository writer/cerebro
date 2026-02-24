package sync

import (
	"reflect"
	"testing"
)

func TestColumnsMissingFromSchema_ConsecutiveRunNoOps(t *testing.T) {
	existing := []string{"_cq_id", "_cq_sync_time", "_cq_hash", "region", "account_id"}
	desired := []string{"_CQ_HASH", "REGION", "account_id"}

	missing := columnsMissingFromSchema(existing, desired)
	if len(missing) != 0 {
		t.Fatalf("expected no missing columns on consecutive sync, got %v", missing)
	}
}

func TestColumnsMissingFromSchema_ReturnsNormalizedUniqueMissing(t *testing.T) {
	existing := []string{"REGION", "ACCOUNT_ID"}
	desired := []string{"region", "account_id", "name", " NAME ", "", "\t"}

	missing := columnsMissingFromSchema(existing, desired)
	want := []string{"NAME"}
	if !reflect.DeepEqual(missing, want) {
		t.Fatalf("unexpected missing columns: got %v, want %v", missing, want)
	}
}
