package sync

import (
	"testing"
)

func TestGCPHashRowContent(t *testing.T) {
	e := &GCPSyncEngine{}

	// Same content should produce same hash
	row1 := map[string]interface{}{
		"name":    "test-bucket",
		"project": "my-project",
	}
	row2 := map[string]interface{}{
		"project": "my-project",
		"name":    "test-bucket",
	}

	hash1 := e.hashRowContent(row1)
	hash2 := e.hashRowContent(row2)

	if hash1 != hash2 {
		t.Errorf("Same content should produce same hash, got %q and %q", hash1, hash2)
	}

	// Different content should produce different hash
	row3 := map[string]interface{}{
		"name":    "different-bucket",
		"project": "my-project",
	}
	hash3 := e.hashRowContent(row3)

	if hash1 == hash3 {
		t.Error("Different content should produce different hash")
	}

	// _cq_id should be excluded from hash
	row4 := map[string]interface{}{
		"_cq_id":  "should-be-ignored",
		"name":    "test-bucket",
		"project": "my-project",
	}
	hash4 := e.hashRowContent(row4)

	if hash1 != hash4 {
		t.Errorf("_cq_id should be excluded from hash, got %q and %q", hash1, hash4)
	}
}

func TestGCPTables(t *testing.T) {
	e := &GCPSyncEngine{}
	tables := e.getGCPTables()

	if len(tables) == 0 {
		t.Error("getGCPTables should return at least one table")
	}

	// Check expected tables exist
	expectedTables := []string{
		"gcp_compute_instances",
		"gcp_storage_buckets",
		"gcp_iam_service_accounts",
		"gcp_compute_firewalls",
		"gcp_sql_instances",
		"gcp_container_clusters",
	}

	tableNames := make(map[string]bool)
	for _, t := range tables {
		tableNames[t.Name] = true
	}

	for _, expected := range expectedTables {
		if !tableNames[expected] {
			t.Errorf("Expected table %q not found in GCP tables", expected)
		}
	}
}

func TestWithGCPProject(t *testing.T) {
	e := &GCPSyncEngine{}
	opt := WithGCPProject("test-project-123")
	opt(e)

	if e.projectID != "test-project-123" {
		t.Errorf("WithGCPProject did not set projectID, got %q", e.projectID)
	}
}

func TestWithGCPConcurrency(t *testing.T) {
	e := &GCPSyncEngine{}
	opt := WithGCPConcurrency(20)
	opt(e)

	if e.concurrency != 20 {
		t.Errorf("WithGCPConcurrency did not set concurrency, got %d", e.concurrency)
	}
}
