package findings

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/policy"
)

func TestFileStore(t *testing.T) {
	// Create temp file
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "findings.json")

	store, err := NewFileStore(filePath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	// Add a finding
	pf := policy.Finding{
		ID:         "test-finding-1",
		PolicyID:   "test-policy",
		PolicyName: "Test Policy",
		Severity:   "high",
		Resource:   map[string]interface{}{"arn": "arn:aws:s3:::my-bucket"},
	}

	f := store.Upsert(context.Background(), pf)
	if f.ID != "test-finding-1" {
		t.Errorf("expected ID test-finding-1, got %s", f.ID)
	}

	// Verify stats
	stats := store.Stats()
	if stats.Total != 1 {
		t.Errorf("expected 1 finding, got %d", stats.Total)
	}

	// Force save
	if syncErr := store.Sync(context.Background()); syncErr != nil {
		t.Errorf("sync failed: %v", syncErr)
	}

	// Verify file exists
	if _, statErr := os.Stat(filePath); os.IsNotExist(statErr) {
		t.Error("file should exist after sync")
	}

	// Create new store from same file
	store2, err := NewFileStore(filePath)
	if err != nil {
		t.Fatalf("failed to create store2: %v", err)
	}
	defer store2.Close()

	// Should have loaded the finding
	stats2 := store2.Stats()
	if stats2.Total != 1 {
		t.Errorf("expected 1 finding after reload, got %d", stats2.Total)
	}

	// Get the finding
	f2, ok := store2.Get("test-finding-1")
	if !ok {
		t.Error("expected to find test-finding-1")
	}
	if f2.PolicyID != "test-policy" {
		t.Errorf("expected policy_id test-policy, got %s", f2.PolicyID)
	}
}

func TestFileStoreResolve(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "findings.json")

	store, err := NewFileStore(filePath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	// Add a finding
	pf := policy.Finding{
		ID:       "test-finding-2",
		PolicyID: "test-policy",
		Severity: "medium",
	}
	store.Upsert(context.Background(), pf)

	// Resolve it
	if !store.Resolve("test-finding-2") {
		t.Error("resolve should return true")
	}

	// Verify status changed
	f, _ := store.Get("test-finding-2")
	if f.Status != "RESOLVED" {
		t.Errorf("expected status RESOLVED, got %s", f.Status)
	}
}

func TestFileStoreCleanup(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "findings.json")

	store, err := NewFileStore(filePath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	// Add old resolved finding directly
	store.store.mu.Lock()
	store.store.findings["old-finding"] = &Finding{
		ID:       "old-finding",
		PolicyID: "test",
		Status:   "RESOLVED",
		LastSeen: time.Now().Add(-30 * 24 * time.Hour), // 30 days old
	}
	store.store.mu.Unlock()

	// Add new finding
	store.Upsert(context.Background(), policy.Finding{
		ID:       "new-finding",
		PolicyID: "test",
		Severity: "low",
	})

	// Cleanup old resolved findings
	removed := store.Cleanup(7 * 24 * time.Hour)
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}

	// Verify old finding gone, new remains
	_, ok := store.Get("old-finding")
	if ok {
		t.Error("old finding should be removed")
	}

	_, ok = store.Get("new-finding")
	if !ok {
		t.Error("new finding should remain")
	}
}

func TestDefaultFilePath(t *testing.T) {
	path := DefaultFilePath()
	if path == "" {
		t.Error("path should not be empty")
	}
	if !filepath.IsAbs(path) {
		t.Error("path should be absolute")
	}
}
