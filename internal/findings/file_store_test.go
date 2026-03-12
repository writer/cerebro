package findings

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/writer/cerebro/internal/metrics"
	"github.com/writer/cerebro/internal/policy"
)

func TestFileStore(t *testing.T) {
	// Create temp file
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "findings.json")

	store, err := NewFileStore(filePath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer func() {
		_ = store.Close()
	}()

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
	defer func() {
		_ = store2.Close()
	}()

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
	defer func() {
		_ = store.Close()
	}()

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
	defer func() {
		_ = store.Close()
	}()
	store.store.resolvedRetention = 0

	// Add old resolved finding directly
	store.store.mu.Lock()
	store.store.findings["old-finding"] = &Finding{
		ID:       "old-finding",
		PolicyID: "test",
		Status:   "RESOLVED",
		LastSeen: time.Now().Add(-30 * 24 * time.Hour), // 30 days old
	}
	store.store.resolvedCount = 1
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
	if store.store.resolvedCount != 0 {
		t.Fatalf("expected resolvedCount to be decremented, got %d", store.store.resolvedCount)
	}
}

func TestFileStoreClearResetsResolvedTracking(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "findings.json")

	store, err := NewFileStore(filePath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer func() {
		_ = store.Close()
	}()

	store.store.mu.Lock()
	store.store.findings["resolved"] = &Finding{
		ID:       "resolved",
		PolicyID: "test",
		Status:   "RESOLVED",
		LastSeen: time.Now().Add(-24 * time.Hour),
	}
	store.store.resolvedCount = 1
	store.store.lastResolvedSweep = time.Now()
	store.store.mu.Unlock()

	if err := store.Clear(); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if got := store.store.resolvedCount; got != 0 {
		t.Fatalf("resolvedCount = %d, want 0", got)
	}
	if !store.store.lastResolvedSweep.IsZero() {
		t.Fatalf("expected lastResolvedSweep to reset, got %s", store.store.lastResolvedSweep)
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

func TestFileStoreLoadEnforcesCapacityAndMetrics(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "findings.json")
	now := time.Now().UTC()
	findings := []*Finding{
		{ID: "resolved-old", PolicyID: "policy", Severity: "low", Status: "RESOLVED", LastSeen: now.Add(-3 * time.Hour)},
		{ID: "suppressed-mid", PolicyID: "policy", Severity: "medium", Status: "SUPPRESSED", LastSeen: now.Add(-2 * time.Hour)},
		{ID: "open-new", PolicyID: "policy", Severity: "high", Status: "OPEN", LastSeen: now.Add(-1 * time.Hour)},
	}
	data, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("marshal findings: %v", err)
	}
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		t.Fatalf("write findings file: %v", err)
	}

	fs := &FileStore{
		store:    NewStoreWithConfig(StoreConfig{MaxFindings: 2}),
		filePath: filePath,
		done:     make(chan struct{}),
	}
	if err := fs.load(); err != nil {
		t.Fatalf("load findings: %v", err)
	}
	if got := fs.store.Len(); got != 2 {
		t.Fatalf("loaded findings = %d, want 2", got)
	}
	if _, ok := fs.Get("resolved-old"); ok {
		t.Fatal("expected resolved finding to be evicted at load-time capacity enforcement")
	}
	if got := findingsStoreSizeMetricValue(t); got != 2 {
		t.Fatalf("findings store size metric = %.0f, want 2", got)
	}
}

func TestFileStoreLoadAppliesResolvedRetention(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "findings.json")
	now := time.Now().UTC()
	findings := []*Finding{
		{ID: "resolved-expired", PolicyID: "policy", Severity: "low", Status: "RESOLVED", LastSeen: now.Add(-72 * time.Hour)},
		{ID: "open-current", PolicyID: "policy", Severity: "high", Status: "OPEN", LastSeen: now.Add(-1 * time.Hour)},
	}
	data, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("marshal findings: %v", err)
	}
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		t.Fatalf("write findings file: %v", err)
	}

	fs := &FileStore{
		store: NewStoreWithConfig(StoreConfig{
			MaxFindings:       10,
			ResolvedRetention: 24 * time.Hour,
		}),
		filePath: filePath,
		done:     make(chan struct{}),
	}
	if err := fs.load(); err != nil {
		t.Fatalf("load findings: %v", err)
	}
	if _, ok := fs.Get("resolved-expired"); ok {
		t.Fatal("expected resolved finding older than retention to be removed during load")
	}
	if _, ok := fs.Get("open-current"); !ok {
		t.Fatal("expected current open finding to remain after load")
	}
	if got := findingsStoreSizeMetricValue(t); got != 1 {
		t.Fatalf("findings store size metric = %.0f, want 1", got)
	}
}

func findingsStoreSizeMetricValue(t *testing.T) float64 {
	t.Helper()
	metric := &dto.Metric{}
	if err := metrics.FindingsStoreSize.Write(metric); err != nil {
		t.Fatalf("read findings store size metric: %v", err)
	}
	if metric.Gauge == nil {
		t.Fatal("expected findings store size gauge metric")
	}
	return metric.GetGauge().GetValue()
}
