package pipeline

import (
	"context"
	"time"
)

type BatchConfig[T any] struct {
	BatchSize     int
	FlushInterval time.Duration
	Flush         func(context.Context, []T)
}

type BatchSink struct {
	done chan struct{}
}

func StreamSlice[T any](ctx context.Context, items []T, buffer int, signal *BackpressureSignal) <-chan T {
	if buffer <= 0 {
		buffer = 1
	}
	out := make(chan T, buffer)
	go func() {
		defer close(out)
		draining := false
		for _, item := range items {
			if len(out) == cap(out) && signal != nil {
				signal.Mark()
			}
			if draining {
				out <- item
				continue
			}
			if !sendStageItem(ctx, out, item) {
				draining = true
			}
		}
	}()
	return out
}

func StartBatchSink[T any](ctx context.Context, in <-chan T, cfg BatchConfig[T]) *BatchSink {
	if ctx == nil {
		ctx = context.Background()
	}
	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 1
	}
	sink := &BatchSink{done: make(chan struct{})}
	go func() {
		defer close(sink.done)
		batch := make([]T, 0, batchSize)
		flushCtx := ctx
		if flushCtx.Err() != nil {
			flushCtx = context.WithoutCancel(flushCtx)
		}
		flush := func() {
			if len(batch) == 0 || cfg.Flush == nil {
				return
			}
			cfg.Flush(flushCtx, batch)
			batch = make([]T, 0, batchSize)
		}

		var ticker *time.Ticker
		if cfg.FlushInterval > 0 {
			ticker = time.NewTicker(cfg.FlushInterval)
			defer ticker.Stop()
		}

		ctxDone := ctx.Done()
		for {
			select {
			case <-ctxDone:
				ctxDone = nil
				flushCtx = context.WithoutCancel(ctx)
			case item, ok := <-in:
				if !ok {
					flush()
					return
				}
				batch = append(batch, item)
				if len(batch) >= batchSize {
					flush()
				}
			case <-batchSinkTick(ticker):
				flush()
			}
		}
	}()
	return sink
}

func (s *BatchSink) Wait() {
	if s == nil {
		return
	}
	<-s.done
}

func batchSinkTick(ticker *time.Ticker) <-chan time.Time {
	if ticker == nil {
		return nil
	}
	return ticker.C
}
