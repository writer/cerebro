// Package appendlogindex contains the domain logic that populates the
// per-runtime append-log replay index from the append log into the state store.
package appendlogindex

import (
	"context"
	"errors"
	"fmt"

	"github.com/writer/cerebro/internal/ports"
)

// DefaultMaxBatches bounds how many scan windows a single population run
// advances before yielding, keeping each job invocation bounded.
const DefaultMaxBatches = 20

// ErrWarming indicates that a bounded index preparation advanced the index but
// did not catch up to the append-log tail in this invocation.
var ErrWarming = errors.New("append log runtime index is warming")

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

// PrepareReplay advances the runtime replay index before replay-backed
// evaluations. It stays bounded, so callers can retry instead of falling back to
// broad stream scans while the index is still catching up.
func PrepareReplay(ctx context.Context, source ports.RuntimeIndexSource, writer ports.RuntimeIndexWriter, batch uint32, maxBatches uint32) error {
	result, err := Populate(ctx, source, writer, batch, maxBatches)
	if err != nil {
		return err
	}
	if !result.CaughtUp {
		return fmt.Errorf("%w: watermark %d after %d batches", ErrWarming, result.Watermark, result.Batches)
	}
	return nil
}
