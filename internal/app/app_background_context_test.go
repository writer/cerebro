package app

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

type backgroundContextKey string

type countingSecretsLoader struct {
	loads  int32
	config *Config
}

func (l *countingSecretsLoader) LoadConfig() *Config {
	if l == nil {
		return &Config{}
	}
	atomic.AddInt32(&l.loads, 1)
	if l.config != nil {
		return l.config
	}
	return &Config{}
}

func TestAppBackgroundContextPreservesValuesWithoutCancellation(t *testing.T) {
	base := context.WithValue(context.Background(), backgroundContextKey("trace"), "trace-123")
	cancelable, cancel := context.WithCancel(base)
	application := &App{rootCtx: cancelable}

	cancel()

	ctx := application.backgroundContext()
	if got := ctx.Value(backgroundContextKey("trace")); got != "trace-123" {
		t.Fatalf("backgroundContext() value = %v, want trace-123", got)
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("backgroundContext() should ignore parent cancellation, got %v", err)
	}
}

func TestStartSecretsReloaderIgnoresParentCancellation(t *testing.T) {
	loader := &countingSecretsLoader{config: &Config{}}
	application := &App{
		Config:        &Config{SecretsReloadInterval: 10 * time.Millisecond},
		secretsLoader: loader,
	}
	parent, cancel := context.WithCancel(context.Background())
	application.startSecretsReloader(parent)
	defer application.stopSecretsReloader()

	cancel()

	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&loader.loads) > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}

	t.Fatal("expected secrets reloader to continue after parent cancellation")
}

func TestInitEventCorrelationRefreshLoopIgnoresParentCancellation(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	application := &App{Config: &Config{}}

	application.initEventCorrelationRefreshLoop(parent)
	if application.eventCorrelationRefreshQueue == nil {
		t.Fatal("expected event correlation refresh queue to initialize")
	}
	application.eventCorrelationRefreshQueue.debounce = 10 * time.Millisecond
	processed := make(chan string, 1)
	application.eventCorrelationRefreshQueue.process = func(reason string) {
		processed <- reason
	}
	defer application.stopEventCorrelationRefreshLoop()

	cancel()
	application.queueEventCorrelationRefresh("tap_mapping")

	select {
	case got := <-processed:
		if got != "tap_mapping" {
			t.Fatalf("unexpected refresh reason %q", got)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected refresh loop to continue after parent cancellation")
	}
}
