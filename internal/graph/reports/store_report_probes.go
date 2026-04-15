package reports

import (
	"time"

	graph "github.com/writer/cerebro/internal/graph"
)

// ClaimConflictReportProbe builds a reusable claim-conflict snapshot report probe.
func ClaimConflictReportProbe(name string, opts ClaimConflictReportOptions) graph.StoreReportProbe {
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

// EntitySummaryReportProbe builds a reusable entity-summary snapshot report probe.
func EntitySummaryReportProbe(name string, opts EntitySummaryReportOptions) graph.StoreReportProbe {
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

// EvaluationTemporalAnalysisReportProbe builds a reusable evaluation-temporal snapshot report probe.
func EvaluationTemporalAnalysisReportProbe(name string, opts EvaluationTemporalAnalysisReportOptions) graph.StoreReportProbe {
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

// PlaybookEffectivenessReportProbe builds a reusable playbook-effectiveness snapshot report probe.
func PlaybookEffectivenessReportProbe(name string, opts PlaybookEffectivenessReportOptions) graph.StoreReportProbe {
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
