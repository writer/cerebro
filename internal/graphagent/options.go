package graphagent

import "github.com/writer/cerebro/internal/ports"

// ServiceOptions controls optional orchestration features for Ask.
type ServiceOptions struct {
	TrajectoryStore             ports.AskTrajectoryStore
	EnableGraphProbes           bool
	EnableDeterministicFastPath bool
	EnableRecovery              bool
	EnableMapReduce             bool
	MaxDepth                    int
	MaxChildren                 int
	MapReduceRowThreshold       int
	MapReduceByteThreshold      int
}

// AskExecutionContext bounds one root or child Ask execution.
type AskExecutionContext struct {
	TraceID       string
	ParentTraceID string
	Depth         int
	Attempt       int
	MaxDepth      int
	MaxChildren   int
}

func normalizeServiceOptions(options ServiceOptions) ServiceOptions {
	if options.MaxDepth <= 0 {
		options.MaxDepth = 1
	}
	if options.MaxChildren <= 0 {
		options.MaxChildren = 2
	}
	if options.MapReduceRowThreshold <= 0 {
		options.MapReduceRowThreshold = 100
	}
	if options.MapReduceByteThreshold <= 0 {
		options.MapReduceByteThreshold = 64 << 10
	}
	return options
}
