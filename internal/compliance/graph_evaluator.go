package compliance

import (
	"time"

	"github.com/writer/cerebro/internal/graph"
	entities "github.com/writer/cerebro/internal/graph/entities"
)

const maxControlEvidence = 25

// EvaluationOptions tunes graph-backed compliance evaluation.
type EvaluationOptions struct {
	ValidAt              time.Time
	RecordedAt           time.Time
	GeneratedAt          time.Time
	OpenFindingsByPolicy map[string]int
}

// EvaluateFramework derives compliance control status from the current graph where possible,
// and falls back to findings counts for controls the graph cannot yet evaluate directly.
func EvaluateFramework(g *graph.Graph, framework *Framework, opts EvaluationOptions) ComplianceReport {
	if framework == nil {
		return ComplianceReport{}
	}
	now := opts.GeneratedAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	validAt := opts.ValidAt.UTC()
	if validAt.IsZero() {
		validAt = now
	}
	recordedAt := opts.RecordedAt.UTC()
	if recordedAt.IsZero() {
		recordedAt = now
	}

	evaluator := graphComplianceEvaluator{
		graph:                g,
		validAt:              validAt,
		recordedAt:           recordedAt,
		generatedAt:          now,
		openFindingsByPolicy: cloneFindingCounts(opts.OpenFindingsByPolicy),
		entityCache:          make(map[string][]entities.EntityRecord),
	}

	report := ComplianceReport{
		FrameworkID:   framework.ID,
		FrameworkName: framework.Name,
		GeneratedAt:   now.Format(time.RFC3339),
		Summary: ComplianceSummary{
			TotalControls: len(framework.Controls),
		},
		Controls: make([]ControlStatus, 0, len(framework.Controls)),
	}
	failingControlIDs := make(map[string]bool)

	for _, ctrl := range framework.Controls {
		status := evaluator.evaluateControl(ctrl)
		report.Controls = append(report.Controls, status)
		switch status.Status {
		case ControlStatePassing:
			report.Summary.PassingControls++
		case ControlStateFailing:
			report.Summary.FailingControls++
			failingControlIDs[status.ControlID] = true
		case ControlStatePartial, ControlStateUnknown:
			report.Summary.PartialControls++
			failingControlIDs[status.ControlID] = true
		case ControlStateNotApplicable:
			report.Summary.NotApplicableControls++
		}
		switch status.EvaluationSource {
		case ControlEvaluationSourceGraph, ControlEvaluationSourceHybrid:
			report.Summary.GraphEvaluatedControls++
		}
		switch status.EvaluationSource {
		case ControlEvaluationSourceFindingsFallback, ControlEvaluationSourceHybrid:
			report.Summary.FallbackControls++
		}
	}

	assessed := report.Summary.TotalControls - report.Summary.NotApplicableControls
	if assessed <= 0 {
		report.Summary.ComplianceScore = 100
	} else {
		report.Summary.ComplianceScore = float64(report.Summary.PassingControls) / float64(assessed) * 100
	}
	report.Summary.WeightedScore, _, _ = CalculateWeightedScore(framework.Controls, failingControlIDs)
	return report
}
