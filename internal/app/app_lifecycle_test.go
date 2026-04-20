package app

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
)

func TestRunSubsystemInitConcurrently_RunsAllSubsystems(t *testing.T) {
	var called atomic.Int32

	err := runSubsystemInitConcurrently(context.Background(),
		initOnlySubsystem("cache", func(context.Context) { called.Add(1) }),
		initOnlySubsystem("runtime", func(context.Context) { called.Add(1) }),
		initOnlySubsystem("events", func(context.Context) { called.Add(1) }),
	)
	if err != nil {
		t.Fatalf("runSubsystemInitConcurrently() error = %v", err)
	}
	if got, want := called.Load(), int32(3); got != want {
		t.Fatalf("subsystem init count = %d, want %d", got, want)
	}
}

func TestRunSubsystemInitConcurrently_PropagatesError(t *testing.T) {
	want := errors.New("boom")

	err := runSubsystemInitConcurrently(context.Background(),
		lifecycleSubsystem{
			name: "graph",
			init: func(context.Context) error {
				return want
			},
		},
	)
	if !errors.Is(err, want) {
		t.Fatalf("runSubsystemInitConcurrently() error = %v, want wrapped %v", err, want)
	}
}

func TestRunSubsystemInitSequentially_RunsInOrder(t *testing.T) {
	var order []string

	err := runSubsystemInitSequentially(context.Background(),
		lifecycleSubsystem{
			name: "remediation",
			init: func(context.Context) error {
				order = append(order, "remediation")
				return nil
			},
		},
		lifecycleSubsystem{
			name: "agents",
			init: func(context.Context) error {
				order = append(order, "agents")
				return nil
			},
		},
	)
	if err != nil {
		t.Fatalf("runSubsystemInitSequentially() error = %v", err)
	}
	if want := []string{"remediation", "agents"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("init order = %v, want %v", order, want)
	}
}

func TestRunSubsystemStartSequentially_RunsInOrder(t *testing.T) {
	var order []string

	err := runSubsystemStartSequentially(context.Background(),
		lifecycleSubsystem{
			name: "remediation",
			start: func(context.Context) error {
				order = append(order, "remediation")
				return nil
			},
		},
		lifecycleSubsystem{
			name: "events",
			start: func(context.Context) error {
				order = append(order, "events")
				return nil
			},
		},
	)
	if err != nil {
		t.Fatalf("runSubsystemStartSequentially() error = %v", err)
	}
	if want := []string{"remediation", "events"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("start order = %v, want %v", order, want)
	}
}

func TestRunSubsystemCloseSequentially_CollectsErrors(t *testing.T) {
	errs := runSubsystemCloseSequentially(context.Background(),
		lifecycleSubsystem{
			name: "agents",
			close: func(context.Context) error {
				return errors.New("close failed")
			},
		},
	)
	if len(errs) != 1 {
		t.Fatalf("close errors len = %d, want 1", len(errs))
	}
	if errs[0] == nil || errs[0].Error() == "" {
		t.Fatalf("expected non-empty close error, got %v", errs[0])
	}
}
