package panicsafe

import (
	"testing"
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
