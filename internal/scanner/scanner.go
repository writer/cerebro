package scanner

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/writerinternal/cerebro/internal/policy"
)

// Scanner performs parallel policy evaluation across assets
type Scanner struct {
	engine    *policy.Engine
	workers   int
	batchSize int
	logger    *slog.Logger
}

type ScanConfig struct {
	Workers   int
	BatchSize int
}

func NewScanner(engine *policy.Engine, cfg ScanConfig, logger *slog.Logger) *Scanner {
	if cfg.Workers == 0 {
		cfg.Workers = 10
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 100
	}
	return &Scanner{
		engine:    engine,
		workers:   cfg.Workers,
		batchSize: cfg.BatchSize,
		logger:    logger,
	}
}

type ScanResult struct {
	Findings   []policy.Finding
	Scanned    int64
	Violations int64
	Duration   time.Duration
	Errors     []string
}

// ScanAssets evaluates policies against assets using a worker pool
func (s *Scanner) ScanAssets(ctx context.Context, assets []map[string]interface{}) *ScanResult {
	start := time.Now()
	result := &ScanResult{
		Findings: make([]policy.Finding, 0),
	}

	if len(assets) == 0 {
		return result
	}

	// Channel for assets to scan
	assetCh := make(chan map[string]interface{}, s.batchSize)

	// Channel for results
	resultCh := make(chan []policy.Finding, s.workers)

	// Error channel
	errCh := make(chan string, s.workers)

	var scanned int64
	var violations int64

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for asset := range assetCh {
				findings, err := s.engine.EvaluateAsset(ctx, asset)
				atomic.AddInt64(&scanned, 1)

				if err != nil {
					select {
					case errCh <- err.Error():
					default:
					}
					continue
				}

				if len(findings) > 0 {
					atomic.AddInt64(&violations, int64(len(findings)))
					resultCh <- findings
				}
			}
		}()
	}

	// Feed assets to workers
	go func() {
		for _, asset := range assets {
			select {
			case assetCh <- asset:
			case <-ctx.Done():
				break
			}
		}
		close(assetCh)
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(resultCh)
		close(errCh)
	}()

	// Aggregate findings
	for findings := range resultCh {
		result.Findings = append(result.Findings, findings...)
	}

	// Collect errors
	for err := range errCh {
		result.Errors = append(result.Errors, err)
	}

	result.Scanned = atomic.LoadInt64(&scanned)
	result.Violations = atomic.LoadInt64(&violations)
	result.Duration = time.Since(start)

	s.logger.Info("scan complete",
		"scanned", result.Scanned,
		"violations", result.Violations,
		"duration_ms", result.Duration.Milliseconds(),
	)

	return result
}

// StreamScan scans assets as they're received (for large datasets)
func (s *Scanner) StreamScan(ctx context.Context, assetStream <-chan map[string]interface{}, resultStream chan<- policy.Finding) *ScanResult {
	start := time.Now()
	result := &ScanResult{}

	var scanned int64
	var violations int64

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.workers)

	for asset := range assetStream {
		select {
		case <-ctx.Done():
			break
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(a map[string]interface{}) {
			defer wg.Done()
			defer func() { <-sem }()

			findings, err := s.engine.EvaluateAsset(ctx, a)
			atomic.AddInt64(&scanned, 1)

			if err != nil {
				return
			}

			for _, f := range findings {
				atomic.AddInt64(&violations, 1)
				select {
				case resultStream <- f:
				case <-ctx.Done():
					return
				}
			}
		}(asset)
	}

	wg.Wait()

	result.Scanned = atomic.LoadInt64(&scanned)
	result.Violations = atomic.LoadInt64(&violations)
	result.Duration = time.Since(start)

	return result
}
