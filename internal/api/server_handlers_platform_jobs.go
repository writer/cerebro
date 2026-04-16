package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	reports "github.com/writer/cerebro/internal/graph/reports"
	risk "github.com/writer/cerebro/internal/graph/risk"
)

type securityAttackPathJobRequest struct {
	MaxDepth  int     `json:"max_depth,omitempty"`
	Threshold float64 `json:"threshold,omitempty"`
	Limit     int     `json:"limit,omitempty"`
}

type platformJob struct {
	ID                string             `json:"id"`
	Kind              string             `json:"kind"`
	Status            string             `json:"status"`
	SubmittedAt       time.Time          `json:"submitted_at"`
	StartedAt         *time.Time         `json:"started_at,omitempty"`
	CompletedAt       *time.Time         `json:"completed_at,omitempty"`
	CancelRequestedAt *time.Time         `json:"cancel_requested_at,omitempty"`
	CancelReason      string             `json:"cancel_reason,omitempty"`
	RequestedBy       string             `json:"requested_by,omitempty"`
	Input             map[string]any     `json:"input,omitempty"`
	Result            any                `json:"result,omitempty"`
	Error             string             `json:"error,omitempty"`
	StatusURL         string             `json:"status_url"`
	cancel            context.CancelFunc `json:"-"`
	ctx               context.Context    `json:"-"`
}

func (s *Server) createSecurityAttackPathJob(w http.ResponseWriter, r *http.Request) {
	var req securityAttackPathJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	maxDepth := req.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 6
	}
	if maxDepth > 10 {
		s.error(w, http.StatusBadRequest, "max_depth must be between 1 and 10")
		return
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		s.error(w, http.StatusBadRequest, "limit must be between 1 and 200")
		return
	}
	if req.Threshold < 0 {
		s.error(w, http.StatusBadRequest, "threshold must be greater than or equal to 0")
		return
	}
	analysisGraph, err := s.currentTenantSecurityGraphSnapshotView(r.Context())
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if analysisGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	job := s.newPlatformJob(r.Context(), "security.attack_path_analysis", map[string]any{
		"max_depth": maxDepth,
		"threshold": req.Threshold,
		"limit":     limit,
	}, GetUserID(r.Context()))

	// #nosec G118 -- platform jobs intentionally outlive the originating request and use job-owned cancellation.
	s.startPlatformJob(job.ID, func(_ context.Context) (any, error) {
		simulator := risk.NewAttackPathSimulator(analysisGraph)
		result := simulator.Simulate(maxDepth)
		if req.Threshold > 0 {
			filtered := make([]*risk.ScoredAttackPath, 0, len(result.Paths))
			for _, path := range result.Paths {
				if path.TotalScore >= req.Threshold {
					filtered = append(filtered, path)
				}
			}
			result.Paths = filtered
		}
		if len(result.Paths) > limit {
			result.Paths = result.Paths[:limit]
		}
		result.TotalPaths = len(result.Paths)
		return result, nil
	})

	s.json(w, http.StatusAccepted, job)
}

func (s *Server) getPlatformJob(w http.ResponseWriter, r *http.Request) {
	jobID := strings.TrimSpace(chi.URLParam(r, "id"))
	if jobID == "" {
		s.error(w, http.StatusBadRequest, "job id required")
		return
	}
	job, ok := s.platformJobSnapshot(jobID)
	if !ok {
		s.error(w, http.StatusNotFound, "job not found")
		return
	}
	s.json(w, http.StatusOK, job)
}

func (s *Server) newPlatformJob(parent context.Context, kind string, input map[string]any, requestedBy string) *platformJob {
	now := time.Now().UTC()
	parentCtx := context.Background()
	if parent != nil {
		parentCtx = context.WithoutCancel(parent)
	}
	// #nosec G118 -- the cancel func is stored on the job and invoked on terminal completion or explicit cancellation.
	jobCtx, cancel := context.WithCancel(parentCtx)
	job := &platformJob{
		ID:          "job:" + uuid.NewString(),
		Kind:        kind,
		Status:      "queued",
		SubmittedAt: now,
		RequestedBy: strings.TrimSpace(requestedBy),
		Input:       cloneJSONMap(input),
		cancel:      cancel,
		ctx:         jobCtx,
	}
	job.StatusURL = "/api/v1/platform/jobs/" + job.ID

	s.platformJobMu.Lock()
	s.platformJobs[job.ID] = job
	s.platformJobMu.Unlock()

	return clonePlatformJob(job)
}

func (s *Server) runPlatformJob(jobID string, runner func(context.Context) (any, error)) {
	now := time.Now().UTC()
	s.platformJobMu.Lock()
	job, ok := s.platformJobs[jobID]
	if ok {
		if job.Status == reports.ReportRunStatusCanceled || job.Status == "canceled" {
			if job.CompletedAt == nil {
				job.CompletedAt = &now
			}
			cancel := job.cancel
			job.cancel = nil
			job.ctx = nil
			s.platformJobMu.Unlock()
			if cancel != nil {
				cancel()
			}
			return
		}
		job.Status = "running"
		job.StartedAt = &now
	}
	jobCtx := context.Background()
	if ok && job.ctx != nil {
		jobCtx = job.ctx
	}
	s.platformJobMu.Unlock()
	if !ok {
		return
	}

	result, err := runner(jobCtx)
	completedAt := time.Now().UTC()

	s.platformJobMu.Lock()
	job, ok = s.platformJobs[jobID]
	if !ok {
		s.platformJobMu.Unlock()
		return
	}
	job.CompletedAt = &completedAt
	cancel := job.cancel
	job.cancel = nil
	job.ctx = nil
	if job.Status == "canceled" || errors.Is(err, context.Canceled) {
		job.Status = "canceled"
		if job.Error == "" && err != nil {
			job.Error = err.Error()
		}
		s.platformJobMu.Unlock()
		if cancel != nil {
			cancel()
		}
		return
	}
	if err != nil {
		job.Status = "failed"
		job.Error = err.Error()
		s.platformJobMu.Unlock()
		if cancel != nil {
			cancel()
		}
		return
	}
	job.Status = "succeeded"
	job.Result = cloneJSONValue(result)
	s.platformJobMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Server) startPlatformJob(jobID string, runner func(context.Context) (any, error)) {
	s.platformJobWG.Add(1)
	go func() {
		defer s.platformJobWG.Done()
		s.runPlatformJob(jobID, runner)
	}()
}

func (s *Server) platformJobSnapshot(jobID string) (*platformJob, bool) {
	s.platformJobMu.RLock()
	defer s.platformJobMu.RUnlock()
	job, ok := s.platformJobs[jobID]
	if !ok {
		return nil, false
	}
	return clonePlatformJob(job), true
}

func (s *Server) cancelPlatformJob(jobID, reason string) bool {
	now := time.Now().UTC()
	s.platformJobMu.Lock()
	job, ok := s.platformJobs[jobID]
	if !ok {
		s.platformJobMu.Unlock()
		return false
	}
	if job.Status == "succeeded" || job.Status == "failed" || job.Status == "canceled" {
		s.platformJobMu.Unlock()
		return false
	}
	job.Status = "canceled"
	job.CompletedAt = &now
	job.CancelRequestedAt = &now
	job.CancelReason = strings.TrimSpace(reason)
	if job.Error == "" {
		job.Error = job.CancelReason
	}
	cancel := job.cancel
	job.cancel = nil
	job.ctx = nil
	s.platformJobMu.Unlock()
	if cancel != nil {
		cancel()
	}
	return true
}

// attachPlatformReportRunJob links a platform job to the latest persisted run state.
// If a cancellation won the race before the job was attached, the caller should cancel
// the newly created job immediately so the run and job do not drift.

func (s *Server) attachPlatformReportRunJob(runID string, job *platformJob) (*reports.ReportRun, bool, string, error) {
	if job == nil {
		return nil, false, "", fmt.Errorf("platform job is required")
	}
	cancelJob := false
	cancelReason := ""
	stored, err := s.updatePlatformReportRunSnapshot(runID, func(updated *reports.ReportRun) {
		updated.JobID = job.ID
		updated.JobStatusURL = job.StatusURL
		for i := len(updated.Attempts) - 1; i >= 0; i-- {
			if updated.Attempts[i].ID == updated.LatestAttemptID {
				updated.Attempts[i].JobID = job.ID
				break
			}
		}
		if updated.Status == reports.ReportRunStatusCanceled {
			cancelJob = true
			cancelReason = strings.TrimSpace(updated.Error)
			if cancelReason == "" {
				cancelReason = "report run was canceled before job attachment"
			}
		}
	})
	if err != nil {
		return nil, false, "", err
	}
	return stored, cancelJob, cancelReason, nil
}

func clonePlatformJob(job *platformJob) *platformJob {
	if job == nil {
		return nil
	}
	cloned := *job
	cloned.cancel = nil
	cloned.ctx = nil
	if cloned.Input != nil {
		cloned.Input = cloneJSONMap(cloned.Input)
	}
	cloned.Result = cloneJSONValue(job.Result)
	return &cloned
}

func cloneJSONValue(value any) any {
	if value == nil {
		return nil
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return value
	}
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return value
	}
	return decoded
}
