package appendlogindex

import (
	"context"
	"errors"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

type fakeIndexSource struct {
	scans   []ports.RuntimeIndexScan
	calls   []uint64
	batches []uint32
}

func (f *fakeIndexSource) ScanRuntimeIndex(_ context.Context, fromSeq uint64, batch uint32) (ports.RuntimeIndexScan, error) {
	f.calls = append(f.calls, fromSeq)
	f.batches = append(f.batches, batch)
	idx := len(f.calls) - 1
	if idx < len(f.scans) {
		return f.scans[idx], nil
	}
	return ports.RuntimeIndexScan{Watermark: fromSeq, CaughtUp: true}, nil
}

type fakeIndexWriter struct {
	watermark     uint64
	watermarkErr  error
	putErr        error
	putWatermarks []uint64
	putEntries    []int
}

func (f *fakeIndexWriter) RuntimeIndexWatermark(context.Context) (uint64, error) {
	return f.watermark, f.watermarkErr
}

func (f *fakeIndexWriter) PutRuntimeIndexEntries(_ context.Context, entries []ports.RuntimeIndexEntry, watermark uint64) error {
	if f.putErr != nil {
		return f.putErr
	}
	f.putWatermarks = append(f.putWatermarks, watermark)
	f.putEntries = append(f.putEntries, len(entries))
	return nil
}

func entry(seq uint64) ports.RuntimeIndexEntry {
	return ports.RuntimeIndexEntry{RuntimeID: "writer-github", Seq: seq, Kind: "github.audit"}
}

func TestPopulateAdvancesUntilCaughtUp(t *testing.T) {
	source := &fakeIndexSource{scans: []ports.RuntimeIndexScan{
		{Entries: []ports.RuntimeIndexEntry{entry(1), entry(2)}, Watermark: 1000},
		{Entries: []ports.RuntimeIndexEntry{entry(3)}, Watermark: 2000, CaughtUp: true},
	}}
	writer := &fakeIndexWriter{}

	result, err := Populate(context.Background(), source, writer, 0, 0)
	if err != nil {
		t.Fatalf("Populate() error = %v", err)
	}
	if result.IndexedEntries != 3 || result.Batches != 2 || result.Watermark != 2000 || !result.CaughtUp {
		t.Fatalf("result = %#v, want 3 entries / 2 batches / watermark 2000 / caughtUp", result)
	}
	if len(source.calls) != 2 || source.calls[0] != 0 || source.calls[1] != 1000 {
		t.Fatalf("scan offsets = %#v, want [0 1000]", source.calls)
	}
	if len(writer.putWatermarks) != 2 || writer.putWatermarks[0] != 1000 || writer.putWatermarks[1] != 2000 {
		t.Fatalf("put watermarks = %#v, want [1000 2000]", writer.putWatermarks)
	}
}

func TestPopulateStopsWhenNoProgress(t *testing.T) {
	source := &fakeIndexSource{scans: []ports.RuntimeIndexScan{
		{Watermark: 500},
	}}
	writer := &fakeIndexWriter{watermark: 500}

	result, err := Populate(context.Background(), source, writer, 0, 0)
	if err != nil {
		t.Fatalf("Populate() error = %v", err)
	}
	if result.Batches != 1 || result.IndexedEntries != 0 || result.Watermark != 500 || !result.CaughtUp {
		t.Fatalf("result = %#v, want 1 batch / 0 entries / watermark 500 / caughtUp", result)
	}
	if len(writer.putWatermarks) != 0 {
		t.Fatalf("put watermarks = %#v, want none for no-progress scan", writer.putWatermarks)
	}
}

func TestPopulateRespectsMaxBatches(t *testing.T) {
	source := &fakeIndexSource{scans: []ports.RuntimeIndexScan{
		{Entries: []ports.RuntimeIndexEntry{entry(1)}, Watermark: 100},
		{Entries: []ports.RuntimeIndexEntry{entry(2)}, Watermark: 200},
		{Entries: []ports.RuntimeIndexEntry{entry(3)}, Watermark: 300},
	}}
	writer := &fakeIndexWriter{}

	result, err := Populate(context.Background(), source, writer, 0, 3)
	if err != nil {
		t.Fatalf("Populate() error = %v", err)
	}
	if result.Batches != 3 || result.CaughtUp {
		t.Fatalf("result = %#v, want exactly 3 batches and not caughtUp", result)
	}
	if result.Watermark != 300 {
		t.Fatalf("result watermark = %d, want 300", result.Watermark)
	}
}

func TestPopulatePropagatesWatermarkReadError(t *testing.T) {
	boom := errors.New("watermark boom")
	writer := &fakeIndexWriter{watermarkErr: boom}
	if _, err := Populate(context.Background(), &fakeIndexSource{}, writer, 0, 0); !errors.Is(err, boom) {
		t.Fatalf("Populate() error = %v, want watermark boom", err)
	}
}

func TestPopulatePropagatesPutError(t *testing.T) {
	boom := errors.New("put boom")
	source := &fakeIndexSource{scans: []ports.RuntimeIndexScan{
		{Entries: []ports.RuntimeIndexEntry{entry(1)}, Watermark: 100},
	}}
	writer := &fakeIndexWriter{putErr: boom}
	if _, err := Populate(context.Background(), source, writer, 0, 0); !errors.Is(err, boom) {
		t.Fatalf("Populate() error = %v, want put boom", err)
	}
}

func TestPrepareReplaySucceedsWhenCaughtUp(t *testing.T) {
	source := &fakeIndexSource{scans: []ports.RuntimeIndexScan{
		{Entries: []ports.RuntimeIndexEntry{entry(1)}, Watermark: 100, CaughtUp: true},
	}}
	writer := &fakeIndexWriter{}

	if err := PrepareReplay(context.Background(), source, writer, 0, 0); err != nil {
		t.Fatalf("PrepareReplay() error = %v", err)
	}
	if got := source.batches; len(got) != 1 || got[0] != DefaultReplayPrepareBatch {
		t.Fatalf("scan batches = %#v, want default replay prepare batch %d", got, DefaultReplayPrepareBatch)
	}
}

func TestPrepareReplayReturnsWarmingWhenStillBehind(t *testing.T) {
	source := &fakeIndexSource{scans: []ports.RuntimeIndexScan{
		{Entries: []ports.RuntimeIndexEntry{entry(1)}, Watermark: 100},
	}}
	writer := &fakeIndexWriter{}

	if err := PrepareReplay(context.Background(), source, writer, 0, 1); !errors.Is(err, ErrWarming) {
		t.Fatalf("PrepareReplay() error = %v, want ErrWarming", err)
	}
	if got := writer.putWatermarks; len(got) != 1 || got[0] != 100 {
		t.Fatalf("put watermarks = %#v, want [100]", got)
	}
}
