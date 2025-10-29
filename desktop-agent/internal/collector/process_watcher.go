package collector

import (
	"context"
	"time"

	"github.com/shirou/gopsutil/v3/host"

	"github.com/WriterInternal/cerebro/desktop-agent/internal/config"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/types"
)

// ProcessWatcher is an event collector that emits process start/exit deltas by
// diffing the current process list with the previous collection cycle. A simple
// in-memory baseline is retained across runs to keep state local.
type ProcessWatcher struct {
	previous map[int]types.ProcessSnapshot
}

// NewProcessWatcher constructs a delta tracker with an empty baseline ready to
// learn the host state on first execution.
func NewProcessWatcher() *ProcessWatcher {
	return &ProcessWatcher{previous: make(map[int]types.ProcessSnapshot)}
}

// Name returns the registry identifier for this event collector.
func (w *ProcessWatcher) Name() string {
	return "events.process.delta"
}

// Collect lists processes, compares them to the prior snapshot, and emits
// process_started/process_exited events for changes. It updates the retained
// baseline at the end of each run so future comparisons stay accurate.
func (w *ProcessWatcher) Collect(_ context.Context, cfg config.Config) ([]types.HostEvent, error) {
	now := time.Now().UTC()

	hostInfo, _ := host.Info()
	machineID := resolveMachineID(hostInfo)
	hostname := cfg.HostnameOverride
	if hostname == "" {
		if hostInfo != nil && hostInfo.Hostname != "" {
			hostname = hostInfo.Hostname
		}
	}

	snapshots, err := collectProcesses(0)
	if err != nil {
		return nil, err
	}

	current := make(map[int]types.ProcessSnapshot, len(snapshots))
	for _, snap := range snapshots {
		current[snap.PID] = snap
	}

	events := make([]types.HostEvent, 0)

	for pid, snap := range current {
		if _, ok := w.previous[pid]; ok {
			continue
		}
		events = append(events, types.HostEvent{
			HostID:      machineID,
			Hostname:    hostname,
			Category:    "process",
			EventType:   "process_started",
			Severity:    "info",
			Timestamp:   now,
			ProcessID:   pid,
			ParentPID:   snap.ParentPID,
			User:        snap.User,
			CommandLine: snap.Command,
			Source:      "process_watcher",
			Payload: map[string]any{
				"binary_hash": snap.BinaryHash,
				"name":        snap.Name,
			},
		})
	}

	for pid, snap := range w.previous {
		if _, ok := current[pid]; ok {
			continue
		}
		events = append(events, types.HostEvent{
			HostID:    machineID,
			Hostname:  hostname,
			Category:  "process",
			EventType: "process_exited",
			Severity:  "info",
			Timestamp: now,
			ProcessID: pid,
			ParentPID: snap.ParentPID,
			User:      snap.User,
			Source:    "process_watcher",
			Payload: map[string]any{
				"name": snap.Name,
			},
		})
	}

	w.previous = current

	return events, nil
}
