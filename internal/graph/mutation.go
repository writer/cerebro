package graph

import "time"

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
