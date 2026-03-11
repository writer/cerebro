package telemetry

import (
	"context"
	"testing"
	"time"
)

func TestInitDisabled(t *testing.T) {
	shutdown, err := Init(context.Background(), Config{Enabled: false})
	if err != nil {
		t.Fatalf("expected disabled init to succeed, got %v", err)
	}
	if Enabled() {
		t.Fatal("expected telemetry to be disabled")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("expected noop shutdown, got %v", err)
	}
}

func TestInitEnabled(t *testing.T) {
	shutdown, err := Init(context.Background(), Config{
		Enabled:       true,
		ServiceName:   "cerebro-test",
		OTLPEndpoint:  "localhost:4318",
		OTLPInsecure:  true,
		SampleRatio:   0.5,
		ExportTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("expected enabled init to succeed, got %v", err)
	}
	if !Enabled() {
		t.Fatal("expected telemetry to be enabled")
	}
	_ = shutdown(context.Background())
}
