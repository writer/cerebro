package graph

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func TestToxicCombinationMonitorReactiveIgnoresIrrelevantChanges(t *testing.T) {
	g := New()
	monitor := NewToxicCombinationMonitor(g, 250*time.Millisecond, testMonitorLogger())
	var scans atomic.Int32
	monitor.scanHook = func() {
		scans.Add(1)
	}

	errCh := startMonitor(t, monitor.Start)
	waitForScanCount(t, &scans, 1, time.Second)

	g.AddNode(&Node{ID: "document:1", Kind: NodeKindDocument, Name: "runbook"})
	assertScanCountStays(t, &scans, 1, 100*time.Millisecond)

	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Name: "alice"})
	waitForScanCount(t, &scans, 2, time.Second)

	monitor.Stop()
	waitForMonitorStop(t, errCh)
}

func TestAttackPathMonitorReactiveCoalescesRapidChanges(t *testing.T) {
	g := New()
	monitor := NewAttackPathMonitor(g, 250*time.Millisecond, testMonitorLogger())
	var scans atomic.Int32
	monitor.scanHook = func() {
		scans.Add(1)
	}

	errCh := startMonitor(t, monitor.Start)
	waitForScanCount(t, &scans, 1, time.Second)

	g.AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Name: "internet"})
	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Name: "alice"})
	g.AddNode(&Node{ID: "db:prod", Kind: NodeKindDatabase, Name: "prod", Risk: RiskCritical})

	waitForScanCount(t, &scans, 2, time.Second)
	assertScanCountStays(t, &scans, 2, 100*time.Millisecond)

	monitor.Stop()
	waitForMonitorStop(t, errCh)
}

func TestAttackPathMonitorReactiveRescansOnBroadEdgeChanges(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Name: "internet"})
	g.AddNode(&Node{ID: "db:prod", Kind: NodeKindDatabase, Name: "prod", Risk: RiskCritical})

	monitor := NewAttackPathMonitor(g, 250*time.Millisecond, testMonitorLogger())
	var scans atomic.Int32
	monitor.scanHook = func() {
		scans.Add(1)
	}

	errCh := startMonitor(t, monitor.Start)
	waitForScanCount(t, &scans, 1, time.Second)

	g.AddEdge(&Edge{Source: "internet", Target: "db:prod", Kind: EdgeKindTriggeredBy})
	waitForScanCount(t, &scans, 2, time.Second)

	monitor.Stop()
	waitForMonitorStop(t, errCh)
}

func TestPrivilegeEscalationMonitorReactiveRescansOnRelevantPropertyChange(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Name: "alice"})

	monitor := NewPrivilegeEscalationMonitor(g, 250*time.Millisecond, testMonitorLogger())
	var scans atomic.Int32
	monitor.scanHook = func() {
		scans.Add(1)
	}

	errCh := startMonitor(t, monitor.Start)
	waitForScanCount(t, &scans, 1, time.Second)

	g.SetNodeProperty("user:alice", "actions", []any{"iam:PassRole"})
	waitForScanCount(t, &scans, 2, time.Second)

	monitor.Stop()
	waitForMonitorStop(t, errCh)
}

func TestReactiveMonitorLoopScansAtMaxStalenessUnderContinuousChanges(t *testing.T) {
	g := New()
	stopCh := make(chan struct{})
	var scans atomic.Int32

	errCh := make(chan error, 1)
	go func() {
		errCh <- runReactiveMonitorLoop(context.Background(), g, stopCh, 30*time.Millisecond, GraphChangeFilter{
			NodeKinds: []NodeKind{NodeKindUser},
		}, func() {
			scans.Add(1)
		})
	}()

	waitForScanCount(t, &scans, 1, time.Second)

	deadline := time.Now().Add(120 * time.Millisecond)
	for i := 0; time.Now().Before(deadline); i++ {
		g.AddNode(&Node{
			ID:   fmt.Sprintf("user:continuous:%d", i),
			Kind: NodeKindUser,
			Name: "continuous",
		})
		time.Sleep(5 * time.Millisecond)
	}

	waitForScanCount(t, &scans, 2, time.Second)

	close(stopCh)
	waitForMonitorStop(t, errCh)
}

func TestReactiveMonitorLoopDoesNotRescanWhenIdleAfterDebouncedChange(t *testing.T) {
	g := New()
	stopCh := make(chan struct{})
	var scans atomic.Int32

	errCh := make(chan error, 1)
	go func() {
		errCh <- runReactiveMonitorLoop(context.Background(), g, stopCh, 40*time.Millisecond, GraphChangeFilter{
			NodeKinds: []NodeKind{NodeKindUser},
		}, func() {
			scans.Add(1)
		})
	}()

	waitForScanCount(t, &scans, 1, time.Second)

	g.AddNode(&Node{ID: "user:idle", Kind: NodeKindUser, Name: "idle"})

	waitForScanCount(t, &scans, 2, time.Second)
	assertScanCountStays(t, &scans, 2, 70*time.Millisecond)

	close(stopCh)
	waitForMonitorStop(t, errCh)
}

func TestReactiveMonitorLoopCoalescesBurstIntoSingleFollowUpScan(t *testing.T) {
	g := New()
	stopCh := make(chan struct{})
	var scans atomic.Int32

	errCh := make(chan error, 1)
	go func() {
		errCh <- runReactiveMonitorLoop(context.Background(), g, stopCh, 40*time.Millisecond, GraphChangeFilter{
			NodeKinds: []NodeKind{NodeKindUser},
		}, func() {
			scans.Add(1)
		})
	}()

	waitForScanCount(t, &scans, 1, time.Second)

	g.AddNode(&Node{ID: "user:burst:1", Kind: NodeKindUser, Name: "burst"})
	time.Sleep(5 * time.Millisecond)
	g.AddNode(&Node{ID: "user:burst:2", Kind: NodeKindUser, Name: "burst"})
	time.Sleep(5 * time.Millisecond)
	g.AddNode(&Node{ID: "user:burst:3", Kind: NodeKindUser, Name: "burst"})

	waitForScanCount(t, &scans, 2, time.Second)
	assertScanCountStays(t, &scans, 2, 70*time.Millisecond)

	close(stopCh)
	waitForMonitorStop(t, errCh)
}

func startMonitor(t *testing.T, start func(context.Context) error) <-chan error {
	t.Helper()
	errCh := make(chan error, 1)
	go func() {
		errCh <- start(context.Background())
	}()
	return errCh
}

func waitForMonitorStop(t *testing.T, errCh <-chan error) {
	t.Helper()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("monitor exited with error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for monitor to stop")
	}
}

func waitForScanCount(t *testing.T, scans *atomic.Int32, want int32, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if scans.Load() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for scan count %d, got %d", want, scans.Load())
}

func assertScanCountStays(t *testing.T, scans *atomic.Int32, want int32, duration time.Duration) {
	t.Helper()
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		if scans.Load() != want {
			t.Fatalf("expected scan count to stay at %d, got %d", want, scans.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func testMonitorLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
