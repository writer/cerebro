package findings

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// CloseoutSummaryActor identifies the principal who ran the closeout. The
// principal is the operator-facing identity (e.g. github actor) and role_arn
// is the AWS STS role assumed when the principal was resolved via STS.
type CloseoutSummaryActor struct {
	Principal string `json:"principal"`
	RoleARN   string `json:"role_arn,omitempty"`
}

// CloseoutPerRuleCount carries one entry of the per-rule applied breakdown
// persisted into the S3 audit summary. Counts reflect rows actually tombstoned
// by the run, not just proposed.
type CloseoutPerRuleCount struct {
	RuleID  string `json:"rule_id"`
	Applied int    `json:"applied"`
}

// CloseoutSummary is the canonical JSON shape persisted to
// s3://<bucket>/closeout/<run_id>.json on every closeout run that has an audit
// bucket configured. The fields are pinned because the same document is the
// audit boundary for VAL-CLI-006 (S3 summary shape), VAL-CROSS-006 (--run-id
// idempotency) and downstream reconciliation tooling that parses the per_rule
// array.
type CloseoutSummary struct {
	RunID         string                 `json:"run_id"`
	Actor         CloseoutSummaryActor   `json:"actor"`
	Env           string                 `json:"env"`
	Selector      CloseoutSelector       `json:"selector"`
	Reason        string                 `json:"reason"`
	ChangeTicket  string                 `json:"change_ticket,omitempty"`
	ProposedCount int                    `json:"proposed_count"`
	AppliedCount  int                    `json:"applied_count"`
	BatchErrors   []string               `json:"batch_errors"`
	PerRule       []CloseoutPerRuleCount `json:"per_rule"`
	DryRun        bool                   `json:"dry_run"`
	StartedAt     time.Time              `json:"started_at"`
	FinishedAt    time.Time              `json:"finished_at"`
}

// CloseoutSummaryInputs groups the run-scoped values the CLI captures around
// the Service.TombstoneFindingsBulk call. They feed BuildCloseoutSummary so
// the document layout stays identical between the CLI's production path and
// the per-test assertions in this package.
type CloseoutSummaryInputs struct {
	Actor        CloseoutSummaryActor
	Env          string
	Selector     CloseoutSelector
	Reason       string
	ChangeTicket string
	DryRun       bool
	StartedAt    time.Time
	FinishedAt   time.Time
}

// BuildCloseoutSummary materializes the canonical S3 audit document from a
// CloseoutResult plus the run-scoped inputs. The per_rule slice is sorted by
// rule_id so the output is byte-stable for a given run, which keeps the
// downstream reconciliation parsers deterministic.
func BuildCloseoutSummary(result *CloseoutResult, inputs CloseoutSummaryInputs) CloseoutSummary {
	var (
		runID    string
		proposed int
		applied  int
	)
	batchErrors := []string{}
	perRule := []CloseoutPerRuleCount{}
	if result != nil {
		runID = strings.TrimSpace(result.RunID)
		proposed = result.ProposedCount
		applied = result.AppliedCount
		for _, err := range result.BatchErrors {
			if err == nil {
				continue
			}
			batchErrors = append(batchErrors, err.Error())
		}
		perRule = append(perRule, result.PerRule...)
		sort.SliceStable(perRule, func(i, j int) bool {
			return perRule[i].RuleID < perRule[j].RuleID
		})
	}
	return CloseoutSummary{
		RunID:         runID,
		Actor:         inputs.Actor,
		Env:           inputs.Env,
		Selector:      inputs.Selector,
		Reason:        inputs.Reason,
		ChangeTicket:  inputs.ChangeTicket,
		ProposedCount: proposed,
		AppliedCount:  applied,
		BatchErrors:   batchErrors,
		PerRule:       perRule,
		DryRun:        inputs.DryRun,
		StartedAt:     inputs.StartedAt.UTC(),
		FinishedAt:    inputs.FinishedAt.UTC(),
	}
}

// MarshalIndent serializes the summary using stable two-space indent. Callers
// MUST use this helper so the bytes uploaded to S3 match the bytes parsed by
// reconciliation tests in CI.
func (s CloseoutSummary) MarshalIndent() ([]byte, error) {
	body, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal closeout summary: %w", err)
	}
	return body, nil
}

// CloseoutSummaryKey returns the s3 object key under which a per-run summary
// document is stored. The CLI uses this for both the production PutObject and
// the closeout_run.s3_summary_key audit row, so they MUST stay in sync.
func CloseoutSummaryKey(runID string) string {
	return fmt.Sprintf("closeout/%s.json", strings.TrimSpace(runID))
}
