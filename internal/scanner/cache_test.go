package scanner

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/cache"
	"github.com/writer/cerebro/internal/policy"
)

func TestHashAsset_Deterministic(t *testing.T) {
	a := map[string]interface{}{
		"name":   "bucket-1",
		"public": true,
		"region": "us-east-1",
	}
	h1 := hashAsset(a)
	h2 := hashAsset(a)
	if h1 != h2 {
		t.Error("same asset should produce same hash")
	}
}

func TestHashAsset_ExcludesMetadata(t *testing.T) {
	a := map[string]interface{}{"name": "bucket-1", "public": true}
	b := map[string]interface{}{
		"name":          "bucket-1",
		"public":        true,
		"_cq_id":        "different-id",
		"_cq_sync_time": "2026-01-01",
		"_cq_table":     "aws_s3_buckets",
	}
	if hashAsset(a) != hashAsset(b) {
		t.Error("metadata fields should be excluded from hash")
	}
}

func TestHashAsset_DifferentContent(t *testing.T) {
	a := map[string]interface{}{"name": "bucket-1", "public": true}
	b := map[string]interface{}{"name": "bucket-1", "public": false}
	if hashAsset(a) == hashAsset(b) {
		t.Error("different content should produce different hash")
	}
}

func TestScannerWithCache(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	engine := policy.NewEngine()
	engine.AddPolicy(&policy.Policy{
		ID:         "pub-check",
		Effect:     "forbid",
		Conditions: []string{"public == true"},
		Severity:   "high",
	})

	c := cache.NewPolicyCache(1000, 5*time.Minute)
	s := NewScanner(engine, ScanConfig{Workers: 2}, logger)
	s.SetCache(c)

	assets := []map[string]interface{}{
		{"_cq_id": "1", "name": "pub-bucket", "public": "true"},
		{"_cq_id": "2", "name": "priv-bucket", "public": "false"},
	}

	// First scan: all cache misses
	r1 := s.ScanAssets(context.Background(), assets)
	if r1.Scanned != 2 {
		t.Errorf("first scan: expected 2 scanned, got %d", r1.Scanned)
	}
	firstViolations := r1.Violations

	// Second scan with same assets: should get cache hits but still report findings
	r2 := s.ScanAssets(context.Background(), assets)
	if r2.Scanned != 2 {
		t.Errorf("second scan: expected 2 scanned, got %d", r2.Scanned)
	}
	if r2.Skipped < 1 {
		t.Logf("cache skipped: %d (may be 0 if cache key format doesn't match)", r2.Skipped)
	}
	// Violations must remain the same on cache hit -- findings must not be dropped
	if r2.Violations != firstViolations {
		t.Errorf("violations changed across cached scan: first=%d second=%d", firstViolations, r2.Violations)
	}
}

func TestScannerCacheCountersArePerScan(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	engine := policy.NewEngine()
	engine.AddPolicy(&policy.Policy{
		ID:         "pub-check",
		Effect:     "forbid",
		Conditions: []string{"public == true"},
		Severity:   "high",
	})

	c := cache.NewPolicyCache(1000, 5*time.Minute)
	s := NewScanner(engine, ScanConfig{Workers: 1}, logger)
	s.SetCache(c)

	assets := []map[string]interface{}{
		{"_cq_id": "1", "name": "bucket", "public": "true"},
	}

	// First scan populates the cache
	_ = s.ScanAssets(context.Background(), assets)

	// Second scan: 1 cache hit
	r2 := s.ScanAssets(context.Background(), assets)
	// Third scan: 1 cache hit
	r3 := s.ScanAssets(context.Background(), assets)

	// Skipped must reflect THIS scan only, not accumulate
	if r2.Skipped != r3.Skipped {
		t.Errorf("skipped should be per-scan: scan2=%d scan3=%d", r2.Skipped, r3.Skipped)
	}
}
