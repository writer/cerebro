package decisionworkflow

import (
	"errors"
	"sort"
	"strings"
	"time"
)

var ErrInvalidWindow = errors.New("invalid decision summary window")

type Disposition string

const (
	DispositionAccepted Disposition = "accepted"
	DispositionRejected Disposition = "rejected"
	DispositionDeferred Disposition = "deferred"
)

// DecisionRecord is the durable decision state needed by the product-outcome
// read model. Authentication is recorded by the command path, never supplied
// by an end-user metric client.
type DecisionRecord struct {
	ID                  string
	TenantID            string
	Workflow            Workflow
	State               DecisionState
	Disposition         Disposition
	RecordedAt          time.Time
	AuthenticatedTenant bool
	Durable             bool
}

// OutcomeRecord is one durable terminal or reopening observation for a
// decision. Replayed records keep their stable ID so aggregation is idempotent.
type OutcomeRecord struct {
	ID                         string
	DecisionID                 string
	Outcome                    Outcome
	RecordedAt                 time.Time
	AuditPacketExportReceiptID string
}

type Summary struct {
	WindowStart       time.Time
	WindowEnd         time.Time
	Completed         int
	ByWorkflow        map[Workflow]int
	ByOutcome         map[Outcome]int
	CompletionLatency time.Duration
	ConflictedRecords int
}

// Summarize derives completed decisions from durable records. It deduplicates
// replayed events by stable ID and excludes a prior terminal result when a
// later outcome reopens the same decision.
func Summarize(decisions []DecisionRecord, outcomes []OutcomeRecord, windowStart, windowEnd time.Time) (Summary, error) {
	windowStart = windowStart.UTC()
	windowEnd = windowEnd.UTC()
	if windowStart.IsZero() || windowEnd.IsZero() || !windowStart.Before(windowEnd) {
		return Summary{}, ErrInvalidWindow
	}
	summary := Summary{
		WindowStart: windowStart, WindowEnd: windowEnd,
		ByWorkflow: map[Workflow]int{}, ByOutcome: map[Outcome]int{},
	}

	decisionsByID := make(map[string]DecisionRecord, len(decisions))
	conflictedDecisionIDs := map[string]struct{}{}
	for _, record := range decisions {
		record = normalizeDecisionRecord(record)
		if !validDecisionRecord(record) {
			continue
		}
		if _, conflicted := conflictedDecisionIDs[record.ID]; conflicted {
			continue
		}
		if current, found := decisionsByID[record.ID]; found {
			if !sameDecisionRecord(current, record) {
				delete(decisionsByID, record.ID)
				conflictedDecisionIDs[record.ID] = struct{}{}
				summary.ConflictedRecords++
			}
			continue
		}
		decisionsByID[record.ID] = record
	}

	outcomesByID := make(map[string]OutcomeRecord, len(outcomes))
	conflictedOutcomeIDs := map[string]struct{}{}
	for _, record := range outcomes {
		record = normalizeOutcomeRecord(record)
		if !validOutcomeRecord(record) {
			continue
		}
		if _, conflicted := conflictedOutcomeIDs[record.ID]; conflicted {
			continue
		}
		if current, found := outcomesByID[record.ID]; found {
			if !sameOutcomeRecord(current, record) {
				delete(outcomesByID, record.ID)
				conflictedOutcomeIDs[record.ID] = struct{}{}
				summary.ConflictedRecords++
			}
			continue
		}
		outcomesByID[record.ID] = record
	}

	byDecision := make(map[string][]OutcomeRecord, len(decisionsByID))
	for _, record := range outcomesByID {
		if _, found := decisionsByID[record.DecisionID]; found {
			byDecision[record.DecisionID] = append(byDecision[record.DecisionID], record)
		}
	}
	for decisionID, records := range byDecision {
		sort.Slice(records, func(i, j int) bool {
			if records[i].RecordedAt.Equal(records[j].RecordedAt) {
				iReopened := records[i].Outcome == OutcomeReopened
				jReopened := records[j].Outcome == OutcomeReopened
				if iReopened != jReopened {
					return !iReopened
				}
				return records[i].ID < records[j].ID
			}
			return records[i].RecordedAt.Before(records[j].RecordedAt)
		})
		latest := records[len(records)-1]
		decision := decisionsByID[decisionID]
		completion := Completion{
			Workflow: decision.Workflow, DecisionID: decision.ID, DecisionState: decision.State,
			Outcome: latest.Outcome, AuthenticatedTenant: decision.AuthenticatedTenant, Durable: decision.Durable,
			Reopened:                   latest.Outcome == OutcomeReopened,
			AuditPacketExportReceiptID: latest.AuditPacketExportReceiptID,
		}
		if !completion.Completed() || latest.RecordedAt.Before(windowStart) || !latest.RecordedAt.Before(windowEnd) {
			continue
		}
		summary.Completed++
		summary.ByWorkflow[decision.Workflow]++
		summary.ByOutcome[latest.Outcome]++
		if !decision.RecordedAt.IsZero() && !latest.RecordedAt.Before(decision.RecordedAt) {
			summary.CompletionLatency += latest.RecordedAt.Sub(decision.RecordedAt)
		}
	}
	return summary, nil
}

func normalizeDecisionRecord(record DecisionRecord) DecisionRecord {
	record.ID = strings.TrimSpace(record.ID)
	record.TenantID = strings.TrimSpace(record.TenantID)
	record.RecordedAt = record.RecordedAt.UTC()
	return record
}

func normalizeOutcomeRecord(record OutcomeRecord) OutcomeRecord {
	record.ID = strings.TrimSpace(record.ID)
	record.DecisionID = strings.TrimSpace(record.DecisionID)
	record.AuditPacketExportReceiptID = strings.TrimSpace(record.AuditPacketExportReceiptID)
	record.RecordedAt = record.RecordedAt.UTC()
	return record
}

func validDecisionRecord(record DecisionRecord) bool {
	return record.ID != "" && record.TenantID != "" && record.Workflow.valid() && record.State.valid() &&
		validDisposition(record.Disposition) && !record.RecordedAt.IsZero()
}

func validOutcomeRecord(record OutcomeRecord) bool {
	return record.ID != "" && record.DecisionID != "" && validOutcome(record.Outcome) &&
		record.Outcome != OutcomeNone && record.Outcome != OutcomeUnknown && !record.RecordedAt.IsZero()
}

func validDisposition(value Disposition) bool {
	return value == DispositionAccepted || value == DispositionRejected || value == DispositionDeferred
}

func sameDecisionRecord(left, right DecisionRecord) bool {
	return left.ID == right.ID && left.TenantID == right.TenantID && left.Workflow == right.Workflow && left.State == right.State &&
		left.Disposition == right.Disposition && left.RecordedAt.Equal(right.RecordedAt) &&
		left.AuthenticatedTenant == right.AuthenticatedTenant && left.Durable == right.Durable
}

func sameOutcomeRecord(left, right OutcomeRecord) bool {
	return left.ID == right.ID && left.DecisionID == right.DecisionID && left.Outcome == right.Outcome &&
		left.RecordedAt.Equal(right.RecordedAt) && left.AuditPacketExportReceiptID == right.AuditPacketExportReceiptID
}
