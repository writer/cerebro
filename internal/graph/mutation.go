package graph

import (
	"fmt"
	"time"
)

const (
	GraphMutationModeFullRebuild = "full_rebuild"
	GraphMutationModeIncremental = "incremental"
)

// GraphMutationSummary captures a single graph change operation.
type GraphMutationSummary struct {
	Mode            string
	Since           time.Time
	Until           time.Time
	Tables          []string
	EventsProcessed int
	NodesAdded      int
	NodesUpdated    int
	NodesRemoved    int
	NodeCount       int
	EdgeCount       int
	Duration        time.Duration
}

func (s GraphMutationSummary) HasChanges() bool {
	return s.EventsProcessed > 0 || s.NodesAdded > 0 || s.NodesUpdated > 0 || s.NodesRemoved > 0
}

func (s GraphMutationSummary) Payload(trigger string) map[string]any {
	tables := s.Tables
	if tables == nil {
		tables = []string{}
	}
	payload := map[string]any{
		"mode":             s.Mode,
		"since":            s.Since.UTC().Format(time.RFC3339Nano),
		"until":            s.Until.UTC().Format(time.RFC3339Nano),
		"tables":           tables,
		"events_processed": s.EventsProcessed,
		"nodes_added":      s.NodesAdded,
		"nodes_updated":    s.NodesUpdated,
		"nodes_removed":    s.NodesRemoved,
		"nodes":            s.NodeCount,
		"edges":            s.EdgeCount,
		"duration":         s.Duration.String(),
		"duration_ms":      s.Duration.Milliseconds(),
	}
	if trigger != "" {
		payload["trigger"] = trigger
	}
	return payload
}

func (s GraphMutationSummary) String() string {
	return fmt.Sprintf(
		"mode=%s events=%d nodes(+%d/~%d/-%d) totals(n=%d,e=%d)",
		s.Mode,
		s.EventsProcessed,
		s.NodesAdded,
		s.NodesUpdated,
		s.NodesRemoved,
		s.NodeCount,
		s.EdgeCount,
	)
}
