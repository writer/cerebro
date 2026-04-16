package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
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

func TestBuildSubsystemWaves_OrdersDependencies(t *testing.T) {
	subsystems := []lifecycleSubsystem{
		initOnlySubsystem("cache", nil),
		initOnlySubsystemWithDeps("scheduler", []string{"cache", "health"}, nil),
		initOnlySubsystem("health", nil),
		initOnlySubsystemWithDeps("agents", []string{"runtime"}, nil),
		initOnlySubsystem("runtime", nil),
	}

	waves, err := buildSubsystemWaves(subsystems)
	if err != nil {
		t.Fatalf("buildSubsystemWaves() error = %v", err)
	}

	got := subsystemWaveNames(waves)
	want := [][]string{
		{"cache", "health", "runtime"},
		{"scheduler", "agents"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildSubsystemWaves() = %v, want %v", got, want)
	}
}

func TestBuildSubsystemWaves_RejectsUnknownDependency(t *testing.T) {
	_, err := buildSubsystemWaves([]lifecycleSubsystem{
		initOnlySubsystemWithDeps("scheduler", []string{"missing"}, nil),
	})
	if err == nil || err.Error() == "" {
		t.Fatal("expected unknown dependency error")
	}
}

func TestBuildSubsystemWaves_RejectsCycle(t *testing.T) {
	_, err := buildSubsystemWaves([]lifecycleSubsystem{
		initOnlySubsystemWithDeps("cache", []string{"runtime"}, nil),
		initOnlySubsystemWithDeps("runtime", []string{"cache"}, nil),
	})
	if err == nil || err.Error() == "" {
		t.Fatal("expected dependency cycle error")
	}
}

func TestPhase2aSubsystemWaves(t *testing.T) {
	a := &App{
		Config: &Config{},
		Logger: slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}

	waves, err := buildSubsystemWaves(a.phase2aInitSubsystems(), "appstate", "graph")
	if err != nil {
		t.Fatalf("buildSubsystemWaves(phase2a) error = %v", err)
	}

	gotWaveBySubsystem := make(map[string]int)
	for waveIdx, wave := range subsystemWaveNames(waves) {
		for _, name := range wave {
			gotWaveBySubsystem[name] = waveIdx
		}
	}

	wantWaveBySubsystem := map[string]int{
		"cache":              0,
		"ticketing":          0,
		"identity":           0,
		"attackpath":         0,
		"webhooks":           0,
		"notifications":      0,
		"rbac":               0,
		"compliance":         0,
		"health":             0,
		"lineage":            0,
		"runtime":            0,
		"findings":           0,
		"providers":          0,
		"scan_watermarks":    0,
		"available_tables":   0,
		"snowflake_findings": 1,
		"threatintel":        1,
		"scheduler":          1,
	}
	if !reflect.DeepEqual(gotWaveBySubsystem, wantWaveBySubsystem) {
		t.Fatalf("phase2a wave plan = %v, want %v", gotWaveBySubsystem, wantWaveBySubsystem)
	}
}

func TestInitialize_partial_failure(t *testing.T) {
	report, err := executeLifecycleStages(context.Background(), nil, lifecycleStage{
		phase:  "initialize",
		action: lifecycleActionInit,
		subsystems: []lifecycleSubsystem{
			{
				name: "appstate",
				init: func(context.Context) error { return nil },
				close: func(context.Context) error {
					return nil
				},
			},
			{
				name:     "runtime",
				requires: []string{"appstate"},
				init:     func(context.Context) error { return nil },
				close: func(context.Context) error {
					return nil
				},
			},
			{
				name:     "agents",
				requires: []string{"runtime"},
				init: func(context.Context) error {
					return errors.New("boom")
				},
				close: func(context.Context) error {
					t.Fatal("failed subsystem should not be closed")
					return nil
				},
			},
		},
	})
	if err == nil {
		t.Fatal("expected initialize failure")
	}
	if got, want := report.Closed, []string{"runtime", "appstate"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("closed subsystems = %v, want %v", got, want)
	}
	if got, want := report.Stages[0].Succeeded, []string{"appstate", "runtime"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("successful subsystems = %v, want %v", got, want)
	}
}
