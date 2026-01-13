package scanner

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/writerinternal/cerebro/internal/policy"
)

func TestScanAssets(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	
	engine := policy.NewEngine()
	engine.AddPolicy(&policy.Policy{
		ID:          "test-public-check",
		Name:        "Public Check",
		Description: "Check for public resources",
		Effect:      "forbid",
		Conditions:  []string{"public == true"},
		Severity:    "high",
	})

	scanner := NewScanner(engine, ScanConfig{Workers: 4, BatchSize: 10}, logger)

	assets := []map[string]interface{}{
		{"_cq_id": "1", "name": "public-bucket", "public": "true"},
		{"_cq_id": "2", "name": "private-bucket", "public": "false"},
		{"_cq_id": "3", "name": "another-public", "public": "true"},
		{"_cq_id": "4", "name": "private-2", "public": "false"},
	}

	result := scanner.ScanAssets(context.Background(), assets)

	if result.Scanned != 4 {
		t.Errorf("expected 4 scanned, got %d", result.Scanned)
	}

	if result.Violations != 2 {
		t.Errorf("expected 2 violations, got %d", result.Violations)
	}

	if len(result.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(result.Findings))
	}
}

func TestScanAssetsEmpty(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	engine := policy.NewEngine()
	scanner := NewScanner(engine, ScanConfig{}, logger)

	result := scanner.ScanAssets(context.Background(), nil)

	if result.Scanned != 0 {
		t.Errorf("expected 0 scanned, got %d", result.Scanned)
	}
}

func TestScanAssetsContextCancellation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	engine := policy.NewEngine()
	scanner := NewScanner(engine, ScanConfig{Workers: 2}, logger)

	// Create a large set of assets
	assets := make([]map[string]interface{}, 1000)
	for i := range assets {
		assets[i] = map[string]interface{}{"_cq_id": i, "name": "asset"}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result := scanner.ScanAssets(ctx, assets)

	// Should complete without panic, may have partial results
	if result.Scanned > int64(len(assets)) {
		t.Errorf("scanned more than total assets")
	}
}

func BenchmarkScanAssets(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	
	engine := policy.NewEngine()
	engine.AddPolicy(&policy.Policy{
		ID:         "bench-policy",
		Conditions: []string{"public == true"},
		Severity:   "high",
	})

	scanner := NewScanner(engine, ScanConfig{Workers: 10, BatchSize: 100}, logger)

	assets := make([]map[string]interface{}, 1000)
	for i := range assets {
		public := "false"
		if i%10 == 0 {
			public = "true"
		}
		assets[i] = map[string]interface{}{"_cq_id": i, "name": "asset", "public": public}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.ScanAssets(context.Background(), assets)
	}
}
