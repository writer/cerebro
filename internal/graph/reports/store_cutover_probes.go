package reports

import (
	"time"

	graph "github.com/writer/cerebro/internal/graph"
)

// ClaimConflictReportParityProbe builds a reusable claim-conflict parity probe.
func ClaimConflictReportParityProbe(name string, opts ClaimConflictReportOptions) graph.StoreReportProbe {
	now := time.Now().UTC()
	if opts.ValidAt.IsZero() {
		opts.ValidAt = now
	}
	if opts.RecordedAt.IsZero() {
		opts.RecordedAt = now
	}
	return graph.StoreReportProbe{
		Name: firstNonEmpty(name, "claim-conflicts"),
		Build: func(g *graph.Graph) (any, error) {
			return graph.BuildClaimConflictReport(g, opts), nil
		},
	}
}

// EntitySummaryReportParityProbe builds a reusable entity-summary parity probe.
func EntitySummaryReportParityProbe(name string, opts EntitySummaryReportOptions) graph.StoreReportProbe {
	now := time.Now().UTC()
	if opts.ValidAt.IsZero() {
		opts.ValidAt = now
	}
	if opts.RecordedAt.IsZero() {
		opts.RecordedAt = now
	}
	return graph.StoreReportProbe{
		Name: firstNonEmpty(name, "entity-summary"),
		Build: func(g *graph.Graph) (any, error) {
			report, ok := BuildEntitySummaryReport(g, opts)
			if !ok {
				return map[string]any{"found": false}, nil
			}
			return map[string]any{
				"found":  true,
				"report": report,
			}, nil
		},
	}
}

// EvaluationTemporalAnalysisReportParityProbe builds a reusable evaluation-temporal parity probe.
func EvaluationTemporalAnalysisReportParityProbe(name string, opts EvaluationTemporalAnalysisReportOptions) graph.StoreReportProbe {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	return graph.StoreReportProbe{
		Name: firstNonEmpty(name, "evaluation-temporal-analysis"),
		Build: func(g *graph.Graph) (any, error) {
			return BuildEvaluationTemporalAnalysisReport(g, opts), nil
		},
	}
}

// PlaybookEffectivenessReportParityProbe builds a reusable playbook-effectiveness parity probe.
func PlaybookEffectivenessReportParityProbe(name string, opts PlaybookEffectivenessReportOptions) graph.StoreReportProbe {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	return graph.StoreReportProbe{
		Name: firstNonEmpty(name, "playbook-effectiveness"),
		Build: func(g *graph.Graph) (any, error) {
			return BuildPlaybookEffectivenessReport(g, opts), nil
		},
	}
}
