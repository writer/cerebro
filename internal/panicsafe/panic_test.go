package panicsafe

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/writer/cerebro/internal/telemetry"
)

func TestPayloadHoldsArbitraryValue(t *testing.T) {
	p := Payload{Value: "something went wrong"}
	if got, want := p.Value.(string), "something went wrong"; got != want {
		t.Fatalf("Payload.Value = %q, want %q", got, want)
	}
}

func TestPayloadHoldsNilValue(t *testing.T) {
	p := Payload{Value: nil}
	if p.Value != nil {
		t.Fatalf("Payload.Value = %v, want nil", p.Value)
	}
}

func TestRepanic(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("Repanic did not panic")
		}
		if got, want := r.(string), "test panic"; got != want {
			t.Fatalf("recovered value = %q, want %q", got, want)
		}
	}()
	Repanic(Payload{Value: "test panic"})
}

func TestRepanicPreservesErrorValue(t *testing.T) {
	type customError struct{ msg string }
	sentinel := &customError{msg: "fatal"}
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("Repanic did not panic")
		}
		got, ok := r.(*customError)
		if !ok {
			t.Fatalf("recovered value type = %T, want *customError", r)
		}
		if got != sentinel {
			t.Fatalf("recovered pointer = %p, want %p", got, sentinel)
		}
	}()
	Repanic(Payload{Value: sentinel})
}

func TestRepanicPreservesIntegerValue(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("Repanic did not panic")
		}
		if got, want := r.(int), 42; got != want {
			t.Fatalf("recovered value = %d, want %d", got, want)
		}
	}()
	Repanic(Payload{Value: 42})
}

func TestRepanicWithNilValuePanicsWithNil(t *testing.T) {
	panicked := make(chan bool, 1)
	go func() {
		defer func() {
			r := recover()
			panicked <- r != nil // Go 1.21+: panic(nil) wraps as *runtime.PanicNilError
		}()
		Repanic(Payload{Value: nil})
	}()
	if !<-panicked {
		t.Fatal("Repanic(Payload{Value: nil}) did not panic")
	}
}

func TestGoCompletesNormalTask(t *testing.T) {
	called := make(chan struct{})
	done := Go(context.Background(), "test.normal", func() { close(called) })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Go did not complete normal task")
	}
	select {
	case <-called:
	default:
		t.Fatal("Go did not call normal task")
	}
}

func TestGoRecoversAndCapturesPanic(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	oldProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		otel.SetTracerProvider(oldProvider)
		_ = provider.Shutdown(context.Background())
	})

	ctx, span := telemetry.Start(context.Background(), "test.operation", telemetry.Attrs())
	done := Go(ctx, "test.panicking_task", func() { panic("sensitive panic value") })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Go did not recover panicking task")
	}
	telemetry.End(span, "completed", telemetry.Attrs())

	ended := recorder.Ended()
	if len(ended) != 1 {
		t.Fatalf("ended spans = %d, want 1", len(ended))
	}
	events := ended[0].Events()
	if len(events) != 1 || events[0].Name != "background.task.panic" {
		t.Fatalf("span events = %#v, want one background.task.panic", events)
	}
	attributes := map[string]string{}
	for _, attribute := range events[0].Attributes {
		attributes[string(attribute.Key)] = attribute.Value.AsString()
	}
	if got, want := attributes["operation"], "test.panicking_task"; got != want {
		t.Fatalf("operation = %q, want %q", got, want)
	}
	if got, want := attributes["panic_type"], "string"; got != want {
		t.Fatalf("panic_type = %q, want %q", got, want)
	}
	if strings.Contains(fmt.Sprint(attributes), "sensitive panic value") {
		t.Fatalf("raw panic value leaked into telemetry: %#v", attributes)
	}
}
