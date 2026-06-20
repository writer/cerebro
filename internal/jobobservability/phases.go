package jobobservability

import (
	"context"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphingest"
	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/ports"
)

type Payload map[string]any

func RunPhase[T any](ctx context.Context, service *platformjobs.Service, job *ports.Job, phase string, label string, payload func(T) Payload, run func() (T, error)) (T, error) {
	if strings.TrimSpace(label) == "" {
		label = strings.TrimSpace(phase)
	}
	started := time.Now()
	RecordPhase(ctx, service, job, phase, ports.JobStatusRunning, label+" started", nil, 0, nil)
	result, err := run()
	if err != nil {
		RecordPhase(ctx, service, job, phase, ports.JobStatusFailed, label+" failed", phasePayload(payload, result), time.Since(started), err)
		return result, err
	}
	RecordPhase(ctx, service, job, phase, ports.JobStatusCompleted, label+" completed", phasePayload(payload, result), time.Since(started), nil)
	return result, nil
}

func RecordPhase(ctx context.Context, service *platformjobs.Service, job *ports.Job, phase string, status string, message string, payload Payload, duration time.Duration, err error) {
	service.RecordPhase(ctx, job, platformjobs.PhaseRecord{
		Phase:    phase,
		Status:   status,
		Message:  message,
		Payload:  payload,
		Duration: duration,
		Err:      err,
	})
}

func phasePayload[T any](payload func(T) Payload, result T) Payload {
	if payload == nil {
		return nil
	}
	return payload(result)
}

func SourceRuntimeSyncPayload(result *cerebrov1.SyncSourceRuntimeResponse) Payload {
	if result == nil {
		return nil
	}
	return Payload{
		"pages_read":        result.GetPagesRead(),
		"events_appended":   result.GetEventsAppended(),
		"next_cursor":       result.GetRuntime().GetNextCursor() != nil,
		"runtime_returned":  result.GetRuntime() != nil,
		"checkpoint_cursor": result.GetRuntime().GetCheckpoint().GetCursorOpaque() != "",
	}
}

func GraphIngestPayload(result *graphingest.RunResult) Payload {
	if result == nil || result.Ingest == nil {
		return nil
	}
	return Payload{
		"pages_read":               result.Ingest.PagesRead,
		"events_read":              result.Ingest.EventsRead,
		"entities_projected":       result.Ingest.EntitiesProjected,
		"links_projected":          result.Ingest.LinksProjected,
		"checkpoint_persisted":     result.Ingest.CheckpointPersisted,
		"checkpoint_complete":      result.Ingest.CheckpointComplete,
		"checkpoint_already_fresh": result.Ingest.CheckpointAlreadyFresh,
		"checkpoint_resumed":       result.Ingest.CheckpointResumed,
	}
}

func FindingRulesPayload(result *findings.EvaluateRulesResult) Payload {
	if result == nil {
		return nil
	}
	var findingsEmitted int
	for _, evaluation := range result.Evaluations {
		if evaluation != nil {
			findingsEmitted += len(evaluation.Findings)
		}
	}
	return Payload{
		"events_evaluated":    result.EventsEvaluated,
		"evaluations":         len(result.Evaluations),
		"findings_emitted":    findingsEmitted,
		"runtime_returned":    result.Runtime != nil,
		"events_per_evaluate": averageUint32Int(result.EventsEvaluated, len(result.Evaluations)),
	}
}

func GraphRulesPayload(result *findings.EvaluateGraphRulesResult) Payload {
	if result == nil {
		return nil
	}
	var findingsEmitted int
	var evidenceWritten int
	var rowsRead uint32
	var truncated int
	for _, evaluation := range result.Evaluations {
		if evaluation == nil {
			continue
		}
		findingsEmitted += len(evaluation.Findings)
		evidenceWritten += len(evaluation.Evidence)
		rowsRead += evaluation.RowsRead
		if evaluation.Truncated {
			truncated++
		}
	}
	return Payload{
		"evaluations":       len(result.Evaluations),
		"findings_emitted":  findingsEmitted,
		"evidence_written":  evidenceWritten,
		"rows_read":         rowsRead,
		"truncated_rules":   truncated,
		"runtime_returned":  result.Runtime != nil,
		"rows_per_evaluate": averageUint32Int(rowsRead, len(result.Evaluations)),
	}
}

func CandidateRulesPayload(result *findings.EvaluateCandidateRulesResult) Payload {
	if result == nil {
		return nil
	}
	var candidatesEmitted int
	for _, evaluation := range result.Evaluations {
		if evaluation != nil {
			candidatesEmitted += len(evaluation.Candidates)
		}
	}
	return Payload{
		"events_evaluated":   result.EventsEvaluated,
		"evaluations":        len(result.Evaluations),
		"candidates_emitted": candidatesEmitted,
		"runtime_returned":   result.Runtime != nil,
	}
}

func averageUint32Int(total uint32, count int) float64 {
	if count <= 0 {
		return 0
	}
	return float64(total) / float64(count)
}
