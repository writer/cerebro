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

	ReportAttemptStatusQueued     = "queued"
	ReportAttemptStatusScheduled  = "scheduled"
	ReportAttemptStatusRunning    = "running"
	ReportAttemptStatusSucceeded  = "succeeded"
	ReportAttemptStatusFailed     = "failed"
	ReportAttemptStatusCanceled   = "canceled"
	ReportAttemptStatusSuperseded = "superseded"
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

// ReportRunRetryPolicyState is the typed retry-policy control resource for one report run.
type ReportRunRetryPolicyState struct {
	ReportID            string            `json:"report_id"`
	RunID               string            `json:"run_id"`
	RetryPolicy         ReportRetryPolicy `json:"retry_policy"`
	AttemptCount        int               `json:"attempt_count"`
	RemainingAttempts   int               `json:"remaining_attempts"`
	Exhausted           bool              `json:"exhausted"`
	LatestAttemptID     string            `json:"latest_attempt_id,omitempty"`
	LatestAttemptStatus string            `json:"latest_attempt_status,omitempty"`
}

// ReportRunControl summarizes current execution-control state and allowed actions.
type ReportRunControl struct {
	ReportID            string                    `json:"report_id"`
	RunID               string                    `json:"run_id"`
	Status              string                    `json:"status"`
	ExecutionMode       string                    `json:"execution_mode"`
	Terminal            bool                      `json:"terminal"`
	Cancelable          bool                      `json:"cancelable"`
	Retryable           bool                      `json:"retryable"`
	AllowedActions      []string                  `json:"allowed_actions,omitempty"`
	LatestAttemptID     string                    `json:"latest_attempt_id,omitempty"`
	LatestAttemptStatus string                    `json:"latest_attempt_status,omitempty"`
	LatestAttemptNumber int                       `json:"latest_attempt_number,omitempty"`
	ScheduledFor        *time.Time                `json:"scheduled_for,omitempty"`
	CancelRequestedAt   *time.Time                `json:"cancel_requested_at,omitempty"`
	CancelRequestedBy   string                    `json:"cancel_requested_by,omitempty"`
	CancelReason        string                    `json:"cancel_reason,omitempty"`
	RetryPolicy         ReportRetryPolicy         `json:"retry_policy,omitempty"`
	RemainingAttempts   int                       `json:"remaining_attempts"`
	RetryPolicyState    ReportRunRetryPolicyState `json:"retry_policy_state"`
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
		Status:           normalizeReportAttemptStatus(status),
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
		if !reportAttemptTransitionAllowed(run.Attempts[i].Status, ReportAttemptStatusRunning) {
			return
		}
		run.Attempts[i].Status = ReportAttemptStatusRunning
		run.Attempts[i].StartedAt = &at
		run.Attempts[i].Error = ""
		return
	}
}

// ScheduleLatestReportRunAttempt marks the latest attempt as waiting on retry backoff.
func ScheduleLatestReportRunAttempt(run *ReportRun, scheduledFor time.Time) {
	if run == nil || len(run.Attempts) == 0 {
		return
	}
	if scheduledFor.IsZero() {
		scheduledFor = time.Now().UTC()
	}
	scheduledFor = scheduledFor.UTC()
	for i := len(run.Attempts) - 1; i >= 0; i-- {
		if run.Attempts[i].ID != run.LatestAttemptID && strings.TrimSpace(run.LatestAttemptID) != "" {
			continue
		}
		if !reportAttemptTransitionAllowed(run.Attempts[i].Status, ReportAttemptStatusScheduled) {
			return
		}
		run.Attempts[i].Status = ReportAttemptStatusScheduled
		run.Attempts[i].ScheduledFor = &scheduledFor
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
		nextStatus := normalizeReportAttemptStatus(status)
		if !reportAttemptTransitionAllowed(run.Attempts[i].Status, nextStatus) {
			return
		}
		run.Attempts[i].Status = nextStatus
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

// ReportRunRemainingAttempts returns how many more attempts may be created under the current policy.
func ReportRunRemainingAttempts(run *ReportRun) int {
	if run == nil {
		return 0
	}
	policy := NormalizeReportRetryPolicy(run.RetryPolicy)
	remaining := policy.MaxAttempts - len(run.Attempts)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ReportRunRetryPolicyStateSnapshot returns the typed retry-policy resource for one run.
func ReportRunRetryPolicyStateSnapshot(reportID string, run *ReportRun) ReportRunRetryPolicyState {
	state := ReportRunRetryPolicyState{
		ReportID:    strings.TrimSpace(reportID),
		RetryPolicy: NormalizeReportRetryPolicy(ReportRetryPolicy{}),
	}
	if run == nil {
		return state
	}
	state.RunID = strings.TrimSpace(run.ID)
	state.RetryPolicy = NormalizeReportRetryPolicy(run.RetryPolicy)
	state.AttemptCount = len(run.Attempts)
	state.RemainingAttempts = ReportRunRemainingAttempts(run)
	state.Exhausted = state.RemainingAttempts == 0
	state.LatestAttemptID = strings.TrimSpace(run.LatestAttemptID)
	if attempt := LatestReportRunAttempt(run); attempt != nil {
		state.LatestAttemptStatus = normalizeReportAttemptStatus(attempt.Status)
	}
	return state
}

// ReportRunControlSnapshot returns the typed execution-control resource for one run.
func ReportRunControlSnapshot(reportID string, run *ReportRun) ReportRunControl {
	control := ReportRunControl{
		ReportID:         strings.TrimSpace(reportID),
		RetryPolicyState: ReportRunRetryPolicyStateSnapshot(reportID, run),
	}
	if run == nil {
		return control
	}
	control.RunID = strings.TrimSpace(run.ID)
	control.Status = strings.TrimSpace(run.Status)
	control.ExecutionMode = strings.TrimSpace(run.ExecutionMode)
	control.Terminal = reportRunTerminal(run.Status)
	control.CancelRequestedAt = cloneTimePtr(run.CancelRequestedAt)
	control.CancelRequestedBy = strings.TrimSpace(run.CancelRequestedBy)
	control.CancelReason = strings.TrimSpace(run.CancelReason)
	control.RetryPolicy = NormalizeReportRetryPolicy(run.RetryPolicy)
	control.RemainingAttempts = ReportRunRemainingAttempts(run)
	control.LatestAttemptID = strings.TrimSpace(run.LatestAttemptID)
	if attempt := LatestReportRunAttempt(run); attempt != nil {
		control.LatestAttemptStatus = normalizeReportAttemptStatus(attempt.Status)
		control.LatestAttemptNumber = attempt.AttemptNumber
		control.ScheduledFor = cloneTimePtr(attempt.ScheduledFor)
	}
	control.Cancelable = reportRunCancelable(run)
	control.Retryable = reportRunRetryable(run)
	if control.Cancelable {
		control.AllowedActions = append(control.AllowedActions, "cancel")
	}
	if control.Retryable {
		control.AllowedActions = append(control.AllowedActions, "retry")
	}
	control.AllowedActions = append(control.AllowedActions, "update_retry_policy")
	return control
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

func normalizeReportAttemptStatus(status string) string {
	switch strings.TrimSpace(status) {
	case ReportAttemptStatusQueued,
		ReportAttemptStatusScheduled,
		ReportAttemptStatusRunning,
		ReportAttemptStatusSucceeded,
		ReportAttemptStatusFailed,
		ReportAttemptStatusCanceled,
		ReportAttemptStatusSuperseded:
		return strings.TrimSpace(status)
	default:
		return ReportAttemptStatusQueued
	}
}

func reportAttemptTransitionAllowed(current, next string) bool {
	current = normalizeReportAttemptStatus(current)
	next = normalizeReportAttemptStatus(next)
	switch current {
	case ReportAttemptStatusQueued:
		return next == ReportAttemptStatusScheduled || next == ReportAttemptStatusRunning || next == ReportAttemptStatusCanceled || next == ReportAttemptStatusSuperseded
	case ReportAttemptStatusScheduled:
		return next == ReportAttemptStatusRunning || next == ReportAttemptStatusCanceled || next == ReportAttemptStatusSuperseded
	case ReportAttemptStatusRunning:
		return next == ReportAttemptStatusSucceeded || next == ReportAttemptStatusFailed || next == ReportAttemptStatusCanceled
	case ReportAttemptStatusSucceeded, ReportAttemptStatusFailed, ReportAttemptStatusCanceled, ReportAttemptStatusSuperseded:
		return current == next
	default:
		return false
	}
}

func reportRunTerminal(status string) bool {
	switch strings.TrimSpace(status) {
	case ReportRunStatusSucceeded, ReportRunStatusFailed, ReportRunStatusCanceled:
		return true
	default:
		return false
	}
}

func reportRunCancelable(run *ReportRun) bool {
	if run == nil || reportRunTerminal(run.Status) || run.CancelRequestedAt != nil {
		return false
	}
	return strings.TrimSpace(run.Status) == ReportRunStatusQueued || strings.TrimSpace(run.Status) == ReportRunStatusRunning
}

func reportRunRetryable(run *ReportRun) bool {
	if run == nil || ReportRunRemainingAttempts(run) == 0 {
		return false
	}
	switch strings.TrimSpace(run.Status) {
	case ReportRunStatusFailed, ReportRunStatusCanceled:
		return true
	default:
		return false
	}
}
