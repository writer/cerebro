package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
)

const wideEventQueueCapacity = 1024

type wideEventItem struct {
	encoded []byte
	writer  io.Writer
	flushed chan struct{}
}

type wideEventSink struct {
	queue   chan wideEventItem
	start   sync.Once
	dropped atomic.Uint64
	failed  atomic.Uint64
	output  func() io.Writer
}

var wideEvents = newWideEventSink(wideEventQueueCapacity, func() io.Writer { return os.Stderr })

func newWideEventSink(capacity int, output func() io.Writer) *wideEventSink {
	if capacity < 1 {
		capacity = 1
	}
	if output == nil {
		output = func() io.Writer { return io.Discard }
	}
	return &wideEventSink{
		queue:  make(chan wideEventItem, capacity),
		output: output,
	}
}

func (s *wideEventSink) enqueue(payload map[string]any) bool {
	encoded, err := json.Marshal(payload)
	if err != nil {
		s.failed.Add(1)
		return false
	}
	encoded = append(encoded, '\n')
	s.startWorker()
	item := wideEventItem{encoded: encoded, writer: s.output()}
	select {
	case s.queue <- item:
		return true
	default:
		s.dropped.Add(1)
		return false
	}
}

func (s *wideEventSink) flush(ctx context.Context) error {
	s.startWorker()
	flushed := make(chan struct{})
	select {
	case s.queue <- wideEventItem{writer: s.output(), flushed: flushed}:
	case <-ctx.Done():
		return fmt.Errorf("flush telemetry queue: %w", ctx.Err())
	}
	select {
	case <-flushed:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("flush telemetry writer: %w", ctx.Err())
	}
}

func (s *wideEventSink) startWorker() {
	s.start.Do(func() {
		go s.run()
	})
}

func (s *wideEventSink) run() {
	for item := range s.queue {
		if item.flushed != nil {
			s.writeDiagnostics(item.writer)
			close(item.flushed)
			continue
		}
		s.writeDiagnostics(item.writer)
		if _, err := item.writer.Write(item.encoded); err != nil {
			log.Printf("telemetry write: %v", err)
		}
	}
}

func (s *wideEventSink) writeDiagnostics(writer io.Writer) {
	dropped := s.dropped.Swap(0)
	failed := s.failed.Swap(0)
	if dropped == 0 && failed == 0 {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"kind":                               "telemetry_health",
		"telemetry.wide_event.dropped":       dropped,
		"telemetry.wide_event.encode_failed": failed,
	})
	if err != nil {
		return
	}
	payload = append(payload, '\n')
	if _, err := writer.Write(payload); err != nil {
		log.Printf("telemetry diagnostic write: %v", err)
	}
}

// FlushWideEvents waits for telemetry accepted by the bounded queue to reach
// the configured output. Request paths never call this function; shutdown and
// deterministic tests use it to preserve accepted wide events.
func FlushWideEvents(ctx context.Context) error {
	return wideEvents.flush(ctx)
}
