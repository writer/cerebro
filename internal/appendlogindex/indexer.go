// Package appendlogindex contains the domain logic that populates the
// per-runtime append-log replay index from the append log into the state store.
package appendlogindex

import (
	"context"

	"github.com/writer/cerebro/internal/ports"
)

// DefaultMaxBatches bounds how many scan windows a single population run
// advances before yielding, keeping each job invocation bounded.
const DefaultMaxBatches = 20

// Result summarizes one population run.
type Result struct {
	IndexedEntries int
	Batches        uint32
	Watermark      uint64
	CaughtUp       bool
}

// Populate advances the per-runtime append-log replay index from its persisted
// watermark, scanning up to maxBatches windows from source and persisting each
// window (entries plus the new watermark) idempotently via writer. Persisting
// the watermark even when a window yields no runtime-bearing entries keeps the
// indexer moving past canary/system events.
func Populate(ctx context.Context, source ports.RuntimeIndexSource, writer ports.RuntimeIndexWriter, batch uint32, maxBatches uint32) (Result, error) {
	if maxBatches == 0 {
		maxBatches = DefaultMaxBatches
	}
	watermark, err := writer.RuntimeIndexWatermark(ctx)
	if err != nil {
		return Result{}, err
	}
	result := Result{Watermark: watermark}
	for result.Batches < maxBatches {
		scan, err := source.ScanRuntimeIndex(ctx, watermark, batch)
		if err != nil {
			return Result{}, err
		}
		result.Batches++
		if len(scan.Entries) > 0 || scan.Watermark > watermark {
			if err := writer.PutRuntimeIndexEntries(ctx, scan.Entries, scan.Watermark); err != nil {
				return Result{}, err
			}
		}
		result.IndexedEntries += len(scan.Entries)
		if scan.Watermark <= watermark && len(scan.Entries) == 0 {
			result.CaughtUp = true
			break
		}
		watermark = scan.Watermark
		result.Watermark = watermark
		if scan.CaughtUp {
			result.CaughtUp = true
			break
		}
	}
	return result, nil
}
