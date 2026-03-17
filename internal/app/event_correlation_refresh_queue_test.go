package app

import (
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/metrics"
	dto "github.com/prometheus/client_model/go"
)

func TestEventCorrelationRefreshQueueCoalescesScopesWithoutDrops(t *testing.T) {
	metrics.Register()
	beforeDropped := counterValueSingle(t, metrics.CorrelationRefreshDroppedTotal)

	processed := make(chan string, 1)
	queue := newEventCorrelationRefreshQueue(func(reason string) {
		processed <- reason
	})
	queue.debounce = 20 * time.Millisecond
	queue.start()
	defer queue.stop()

	for i := 0; i < 1000; i++ {
		reason := "tap_mapping"
		if i%2 == 1 {
			reason = "tap_business"
		}
		if level := queue.enqueue(reason); level != eventCorrelationBackpressureNormal {
			t.Fatalf("expected enqueue %d to remain normal before refresh starts, got %s", i, level)
		}
	}

	select {
	case reason := <-processed:
		if reason != "tap_business,tap_mapping" {
			t.Fatalf("expected coalesced reasons, got %q", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for coalesced refresh")
	}

	afterDropped := counterValueSingle(t, metrics.CorrelationRefreshDroppedTotal)
	if afterDropped != beforeDropped {
		t.Fatalf("expected zero dropped refresh requests, got before=%v after=%v", beforeDropped, afterDropped)
	}
}

func TestEventCorrelationRefreshQueueSignalsBackpressureWhileRefreshRunning(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})

	queue := newEventCorrelationRefreshQueue(func(string) {
		started <- struct{}{}
		<-release
	})
	queue.debounce = 5 * time.Millisecond
	queue.warnAfter = time.Millisecond
	queue.criticalAfter = 10 * time.Millisecond
	queue.start()
	defer queue.stop()

	if level := queue.enqueue("tap_mapping"); level != eventCorrelationBackpressureNormal {
		t.Fatalf("expected first enqueue to be normal, got %s", level)
	}

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for refresh processor to start")
	}

	if level := queue.enqueue("tap_business"); level != eventCorrelationBackpressureNormal {
		t.Fatalf("expected normal backpressure before pending work ages, got %s", level)
	}

	time.Sleep(2 * time.Millisecond)
	if level := queue.enqueue("tap_business"); level != eventCorrelationBackpressureWarning {
		t.Fatalf("expected warning backpressure after warn threshold, got %s", level)
	}

	time.Sleep(15 * time.Millisecond)
	if level := queue.enqueue("tap_business"); level != eventCorrelationBackpressureCritical {
		t.Fatalf("expected critical backpressure after pending work ages, got %s", level)
	}

	close(release)
}

func counterValueSingle(t *testing.T, counter interface{ Write(*dto.Metric) error }) float64 {
	t.Helper()
	var metric dto.Metric
	if err := counter.Write(&metric); err != nil {
		t.Fatalf("write counter metric: %v", err)
	}
	return metric.GetCounter().GetValue()
}
