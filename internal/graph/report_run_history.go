package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	DefaultReportDefinitionVersion = "1.0.0"
	GraphOntologyContractVersion   = "cerebro.graph.contracts/v1alpha1"
	reportStorageClassLocalDurable = "local_durable"
	reportStorageClassMetadataOnly = "metadata_only"
	reportRetentionTierShort       = "short_term"
	reportRetentionTierMetadata    = "metadata_only"

	DefaultReportRetryMaxAttempts   = 3
	DefaultReportRetryBaseBackoffMS = int64(5000)
	DefaultReportRetryMaxBackoffMS  = int64(60000)

	ReportAttemptClassTransient     = "transient"
	ReportAttemptClassDeterministic = "deterministic"
	ReportAttemptClassCancelled     = "cancelled"
	ReportAttemptClassSuperseded    = "superseded"
)

// ReportLineage captures the graph/platform lineage context used to produce a report artifact.
type ReportLineage struct {
	GraphSnapshotID         string     `json:"graph_snapshot_id,omitempty"`
	GraphBuiltAt            *time.Time `json:"graph_built_at,omitempty"`
	GraphSchemaVersion      int64      `json:"graph_schema_version,omitempty"`
	OntologyContractVersion string     `json:"ontology_contract_version,omitempty"`
	ReportDefinitionVersion string     `json:"report_definition_version,omitempty"`
}

// ReportStoragePolicy captures storage and retention semantics for one report artifact.
type ReportStoragePolicy struct {
	StorageClass                string `json:"storage_class,omitempty"`
	RetentionTier               string `json:"retention_tier,omitempty"`
	MaterializedResultAvailable bool   `json:"materialized_result_available"`
	ResultTruncated             bool   `json:"result_truncated,omitempty"`
}

// ReportRunAttempt captures one execution attempt for a report run.
type ReportRunAttempt struct {
	ID               string     `json:"id"`
	RunID            string     `json:"run_id"`
	AttemptNumber    int        `json:"attempt_number"`
	Status           string     `json:"status"`
	Classification   string     `json:"classification,omitempty"`
	TriggerSurface   string     `json:"trigger_surface,omitempty"`
	ExecutionSurface string     `json:"execution_surface,omitempty"`
	ExecutionHost    string     `json:"execution_host,omitempty"`
	RequestedBy      string     `json:"requested_by,omitempty"`
	RetryOfAttemptID string     `json:"retry_of_attempt_id,omitempty"`
	RetryReason      string     `json:"retry_reason,omitempty"`
	RetryBackoffMS   int64      `json:"retry_backoff_ms,omitempty"`
	ScheduledFor     *time.Time `json:"scheduled_for,omitempty"`
	SubmittedAt      time.Time  `json:"submitted_at"`
	StartedAt        *time.Time `json:"started_at,omitempty"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	JobID            string     `json:"job_id,omitempty"`
	Error            string     `json:"error,omitempty"`
}

// ReportRunEvent captures one durable lifecycle event recorded against a report run.
type ReportRunEvent struct {
	ID             string         `json:"id"`
	RunID          string         `json:"run_id"`
	AttemptID      string         `json:"attempt_id,omitempty"`
	Sequence       int            `json:"sequence"`
	Type           string         `json:"type"`
	Status         string         `json:"status,omitempty"`
	TriggerSurface string         `json:"trigger_surface,omitempty"`
	Actor          string         `json:"actor,omitempty"`
	Timestamp      time.Time      `json:"timestamp"`
	Data           map[string]any `json:"data,omitempty"`
}

// ReportRunAttemptCollection is the list response for report-run attempts.
type ReportRunAttemptCollection struct {
	ReportID string             `json:"report_id"`
	RunID    string             `json:"run_id"`
	Count    int                `json:"count"`
	Attempts []ReportRunAttempt `json:"attempts"`
}

// ReportRunEventCollection is the list response for report-run events.
type ReportRunEventCollection struct {
	ReportID string           `json:"report_id"`
	RunID    string           `json:"run_id"`
	Count    int              `json:"count"`
	Events   []ReportRunEvent `json:"events"`
}

// BuildReportLineage returns the graph lineage context associated with one report execution.
func BuildReportLineage(g *Graph, definition ReportDefinition) ReportLineage {
	lineage := ReportLineage{
		OntologyContractVersion: GraphOntologyContractVersion,
		ReportDefinitionVersion: strings.TrimSpace(definition.Version),
	}
	if lineage.ReportDefinitionVersion == "" {
		lineage.ReportDefinitionVersion = DefaultReportDefinitionVersion
	}
	lineage.GraphSchemaVersion = SchemaVersion()
	if g == nil {
		return lineage
	}
	meta := g.Metadata()
	if !meta.BuiltAt.IsZero() {
		builtAt := meta.BuiltAt.UTC()
		lineage.GraphBuiltAt = &builtAt
		lineage.GraphSnapshotID = buildReportGraphSnapshotID(meta)
	}
	return lineage
}

// BuildReportStoragePolicy returns the storage policy for one report execution.
func BuildReportStoragePolicy(materializedResult bool, truncated bool) ReportStoragePolicy {
	policy := ReportStoragePolicy{
		MaterializedResultAvailable: materializedResult,
		ResultTruncated:             truncated,
		StorageClass:                reportStorageClassMetadataOnly,
		RetentionTier:               reportRetentionTierMetadata,
	}
	if materializedResult {
		policy.StorageClass = reportStorageClassLocalDurable
		policy.RetentionTier = reportRetentionTierShort
	}
	return policy
}

// NormalizeReportRetryPolicy applies durable defaults for retry/backoff behavior.
func NormalizeReportRetryPolicy(policy ReportRetryPolicy) ReportRetryPolicy {
	if policy.MaxAttempts <= 0 {
		policy.MaxAttempts = DefaultReportRetryMaxAttempts
	}
	if policy.BaseBackoffMS <= 0 {
		policy.BaseBackoffMS = DefaultReportRetryBaseBackoffMS
	}
	if policy.MaxBackoffMS <= 0 {
		policy.MaxBackoffMS = DefaultReportRetryMaxBackoffMS
	}
	if policy.MaxBackoffMS < policy.BaseBackoffMS {
		policy.MaxBackoffMS = policy.BaseBackoffMS
	}
	return policy
}

// ReportRetryBackoff returns the delay for one retry attempt number.
func ReportRetryBackoff(policy ReportRetryPolicy, attemptNumber int) time.Duration {
	policy = NormalizeReportRetryPolicy(policy)
	if attemptNumber <= 1 {
		return 0
	}
	backoffMS := policy.BaseBackoffMS
	for step := 2; step < attemptNumber; step++ {
		backoffMS *= 2
		if backoffMS >= policy.MaxBackoffMS {
			backoffMS = policy.MaxBackoffMS
			break
		}
	}
	if backoffMS > policy.MaxBackoffMS {
		backoffMS = policy.MaxBackoffMS
	}
	return time.Duration(backoffMS) * time.Millisecond
}

// NewReportRunAttempt constructs one new attempt record for a report run.
func NewReportRunAttempt(runID string, attemptNumber int, status, triggerSurface, executionSurface, executionHost, requestedBy, jobID string, submittedAt time.Time) ReportRunAttempt {
	if submittedAt.IsZero() {
		submittedAt = time.Now().UTC()
	}
	submittedAt = submittedAt.UTC()
	attemptNumber = max(1, attemptNumber)
	return ReportRunAttempt{
		ID:               fmt.Sprintf("%s:attempt:%d", strings.TrimSpace(runID), attemptNumber),
		RunID:            strings.TrimSpace(runID),
		AttemptNumber:    attemptNumber,
		Status:           strings.TrimSpace(status),
		TriggerSurface:   strings.TrimSpace(triggerSurface),
		ExecutionSurface: strings.TrimSpace(executionSurface),
		ExecutionHost:    strings.TrimSpace(executionHost),
		RequestedBy:      strings.TrimSpace(requestedBy),
		SubmittedAt:      submittedAt,
		JobID:            strings.TrimSpace(jobID),
	}
}

// AppendReportRunEvent adds one lifecycle event to the run history.
func AppendReportRunEvent(run *ReportRun, eventType, status, triggerSurface, actor string, at time.Time, data map[string]any) {
	if run == nil {
		return
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	sequence := len(run.Events) + 1
	event := ReportRunEvent{
		ID:             fmt.Sprintf("%s:event:%d", strings.TrimSpace(run.ID), sequence),
		RunID:          strings.TrimSpace(run.ID),
		AttemptID:      strings.TrimSpace(run.LatestAttemptID),
		Sequence:       sequence,
		Type:           strings.TrimSpace(eventType),
		Status:         strings.TrimSpace(status),
		TriggerSurface: strings.TrimSpace(triggerSurface),
		Actor:          strings.TrimSpace(actor),
		Timestamp:      at.UTC(),
		Data:           cloneAnyMap(data),
	}
	run.Events = append(run.Events, event)
}

// StartLatestReportRunAttempt marks the latest attempt as running.
func StartLatestReportRunAttempt(run *ReportRun, at time.Time) {
	if run == nil || len(run.Attempts) == 0 {
		return
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	at = at.UTC()
	for i := len(run.Attempts) - 1; i >= 0; i-- {
		if run.Attempts[i].ID != run.LatestAttemptID && strings.TrimSpace(run.LatestAttemptID) != "" {
			continue
		}
		run.Attempts[i].Status = ReportRunStatusRunning
		run.Attempts[i].StartedAt = &at
		run.Attempts[i].Error = ""
		return
	}
}

// CompleteLatestReportRunAttempt marks the latest attempt as completed.
func CompleteLatestReportRunAttempt(run *ReportRun, status string, completedAt time.Time, errMessage, classification string) {
	if run == nil || len(run.Attempts) == 0 {
		return
	}
	if completedAt.IsZero() {
		completedAt = time.Now().UTC()
	}
	completedAt = completedAt.UTC()
	for i := len(run.Attempts) - 1; i >= 0; i-- {
		if run.Attempts[i].ID != run.LatestAttemptID && strings.TrimSpace(run.LatestAttemptID) != "" {
			continue
		}
		run.Attempts[i].Status = strings.TrimSpace(status)
		run.Attempts[i].CompletedAt = &completedAt
		run.Attempts[i].Error = strings.TrimSpace(errMessage)
		run.Attempts[i].Classification = strings.TrimSpace(classification)
		return
	}
}

// LatestReportRunAttempt returns the latest attempt recorded for a run.
func LatestReportRunAttempt(run *ReportRun) *ReportRunAttempt {
	if run == nil || len(run.Attempts) == 0 {
		return nil
	}
	for i := len(run.Attempts) - 1; i >= 0; i-- {
		if strings.TrimSpace(run.LatestAttemptID) == "" || run.Attempts[i].ID == run.LatestAttemptID {
			attempt := run.Attempts[i]
			return &attempt
		}
	}
	return nil
}

// CloneReportRunAttempts returns a deep copy of the attempt history.
func CloneReportRunAttempts(values []ReportRunAttempt) []ReportRunAttempt {
	if len(values) == 0 {
		return nil
	}
	cloned := append([]ReportRunAttempt(nil), values...)
	for i := range cloned {
		cloned[i].ScheduledFor = cloneTimePtr(values[i].ScheduledFor)
		cloned[i].StartedAt = cloneTimePtr(values[i].StartedAt)
		cloned[i].CompletedAt = cloneTimePtr(values[i].CompletedAt)
	}
	return cloned
}

// CloneReportRunEvents returns a deep copy of the event history.
func CloneReportRunEvents(values []ReportRunEvent) []ReportRunEvent {
	if len(values) == 0 {
		return nil
	}
	cloned := append([]ReportRunEvent(nil), values...)
	for i := range cloned {
		cloned[i].Data = cloneAnyMap(values[i].Data)
	}
	return cloned
}

// CloneReportLineage returns a copy of lineage metadata.
func CloneReportLineage(lineage ReportLineage) ReportLineage {
	return ReportLineage{
		GraphSnapshotID:         lineage.GraphSnapshotID,
		GraphBuiltAt:            cloneTimePtr(lineage.GraphBuiltAt),
		GraphSchemaVersion:      lineage.GraphSchemaVersion,
		OntologyContractVersion: lineage.OntologyContractVersion,
		ReportDefinitionVersion: lineage.ReportDefinitionVersion,
	}
}

// CloneReportStoragePolicy returns a copy of storage metadata.
func CloneReportStoragePolicy(policy ReportStoragePolicy) ReportStoragePolicy {
	return ReportStoragePolicy{
		StorageClass:                policy.StorageClass,
		RetentionTier:               policy.RetentionTier,
		MaterializedResultAvailable: policy.MaterializedResultAvailable,
		ResultTruncated:             policy.ResultTruncated,
	}
}

// ReportRunAttemptCollectionSnapshot returns a typed snapshot of attempt history.
func ReportRunAttemptCollectionSnapshot(reportID, runID string, attempts []ReportRunAttempt) ReportRunAttemptCollection {
	cloned := CloneReportRunAttempts(attempts)
	sort.Slice(cloned, func(i, j int) bool {
		return cloned[i].AttemptNumber < cloned[j].AttemptNumber
	})
	return ReportRunAttemptCollection{
		ReportID: strings.TrimSpace(reportID),
		RunID:    strings.TrimSpace(runID),
		Count:    len(cloned),
		Attempts: cloned,
	}
}

// ReportRunEventCollectionSnapshot returns a typed snapshot of event history.
func ReportRunEventCollectionSnapshot(reportID, runID string, events []ReportRunEvent) ReportRunEventCollection {
	cloned := CloneReportRunEvents(events)
	sort.Slice(cloned, func(i, j int) bool {
		return cloned[i].Sequence < cloned[j].Sequence
	})
	return ReportRunEventCollection{
		ReportID: strings.TrimSpace(reportID),
		RunID:    strings.TrimSpace(runID),
		Count:    len(cloned),
		Events:   cloned,
	}
}

func buildReportGraphSnapshotID(meta Metadata) string {
	if meta.BuiltAt.IsZero() {
		return ""
	}
	providers := append([]string(nil), meta.Providers...)
	accounts := append([]string(nil), meta.Accounts...)
	sort.Strings(providers)
	sort.Strings(accounts)
	payload := fmt.Sprintf("%s|%d|%d|%s|%s",
		meta.BuiltAt.UTC().Format(time.RFC3339Nano),
		meta.NodeCount,
		meta.EdgeCount,
		strings.Join(providers, ","),
		strings.Join(accounts, ","),
	)
	sum := sha256.Sum256([]byte(payload))
	return "graph_snapshot:" + hex.EncodeToString(sum[:12])
}
