package collector

import (
	"context"
	"time"

	"github.com/shirou/gopsutil/v3/host"

	"github.com/WriterInternal/cerebro/desktop-agent/internal/config"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/types"
)

type ProcessWatcher struct {
	previous map[int]types.ProcessSnapshot
}

func NewProcessWatcher() *ProcessWatcher {
	return &ProcessWatcher{previous: make(map[int]types.ProcessSnapshot)}
}

func (w *ProcessWatcher) Name() string {
	return "events.process.delta"
}

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
