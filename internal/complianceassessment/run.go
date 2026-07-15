package complianceassessment

import "time"

type AssessmentRun struct {
	ID                  string         `json:"id"`
	TenantID            string         `json:"tenant_id"`
	ProgramID           string         `json:"program_id"`
	ScopeRevisionID     string         `json:"scope_revision_id"`
	PlanRevisionID      string         `json:"plan_revision_id"`
	State               string         `json:"state"`
	Version             uint64         `json:"version"`
	PeriodStart         time.Time      `json:"period_start"`
	PeriodEnd           time.Time      `json:"period_end"`
	RequestedAt         time.Time      `json:"requested_at"`
	RequestedBy         string         `json:"requested_by"`
	RequestHash         string         `json:"request_hash"`
	IdempotencyKey      string         `json:"idempotency_key"`
	JobID               string         `json:"job_id,omitempty"`
	BaselineRunID       string         `json:"baseline_run_id,omitempty"`
	InputManifest       *InputManifest `json:"input_manifest,omitempty"`
	InputHash           string         `json:"input_hash,omitempty"`
	AutomatedResultHash string         `json:"automated_result_hash,omitempty"`
	ResultCount         uint64         `json:"result_count,omitempty"`
	FailureCode         string         `json:"failure_code,omitempty"`
	CollectionBarrierAt time.Time      `json:"collection_barrier_at,omitempty"`
	CompletedAt         time.Time      `json:"completed_at,omitempty"`
}

type ResultChunk struct {
	RunID          string            `json:"run_id"`
	Sequence       uint32            `json:"sequence"`
	FirstResultID  string            `json:"first_result_id"`
	LastResultID   string            `json:"last_result_id"`
	Count          uint32            `json:"count"`
	PreviousDigest string            `json:"previous_digest,omitempty"`
	Digest         string            `json:"digest"`
	Results        []ObjectiveResult `json:"results"`
}

type RunRequest struct {
	TenantID       string
	PlanRevisionID string
	PeriodStart    time.Time
	PeriodEnd      time.Time
	BaselineRunID  string
	IdempotencyKey string
	RequestedBy    string
}
