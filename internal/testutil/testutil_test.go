package testutil

import (
	"testing"
	"time"
)

func TestLoggerReturnsNonNil(t *testing.T) {
	if Logger() == nil {
		t.Fatal("expected Logger to return a non-nil logger")
	}
}

func TestContextCancelsOnCleanup(t *testing.T) {
	done := make(chan struct{})

	t.Run("subtest", func(t *testing.T) {
		ctx := Context(t)
		go func() {
			<-ctx.Done()
			close(done)
		}()
	})

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected Context to be canceled when subtest cleanup runs")
	}
}

func TestNewMemoryWarehouseProvidesStableMetadataDefaults(t *testing.T) {
	warehouse := NewMemoryWarehouse()
	if warehouse == nil {
		t.Fatal("expected warehouse")
	}
	if warehouse.Database() != "TEST_DB" {
		t.Fatalf("database = %q, want TEST_DB", warehouse.Database())
	}
	if warehouse.Schema() != "PUBLIC" {
		t.Fatalf("schema = %q, want PUBLIC", warehouse.Schema())
	}
	if warehouse.AppSchema() != "CEREBRO_APP" {
		t.Fatalf("app schema = %q, want CEREBRO_APP", warehouse.AppSchema())
	}
}
