package api

import (
	"fmt"
	"sort"
	"strings"
	"time"

	reports "github.com/writer/cerebro/internal/graph/reports"
)

func (s *Server) storePlatformReportRun(run *reports.ReportRun) error {
	if run == nil {
		return nil
	}
	s.platformReportSaveMu.Lock()
	defer s.platformReportSaveMu.Unlock()
	if s.platformReportStore != nil {
		if err := s.platformReportStore.SaveRun(run); err != nil {
			return fmt.Errorf("persist report run %q: %w", run.ID, err)
		}
	}
	s.syncPlatformJobWithReportRun(run)
	s.cachePlatformReportRun(run)
	return nil
}

func (s *Server) updatePlatformReportRun(runID string, apply func(*reports.ReportRun)) error {
	_, err := s.updatePlatformReportRunSnapshot(runID, apply)
	return err
}

func (s *Server) updatePlatformReportRunSnapshot(runID string, apply func(*reports.ReportRun)) (*reports.ReportRun, error) {
	s.platformReportSaveMu.Lock()
	defer s.platformReportSaveMu.Unlock()
	var (
		run *reports.ReportRun
		err error
	)
	if s.platformReportStore != nil {
		run, err = s.platformReportStore.LoadRun(runID)
		if err != nil {
			return nil, fmt.Errorf("load report run %q: %w", runID, err)
		}
	}
	if run == nil {
		s.platformReportRunMu.RLock()
		run = reports.CloneReportRun(s.platformReportRuns[runID])
		s.platformReportRunMu.RUnlock()
	}
	if run == nil {
		return nil, fmt.Errorf("report run not found: %s", runID)
	}
	updated := reports.CloneReportRun(run)
	apply(updated)
	if s.platformReportStore != nil {
		if err := s.platformReportStore.SaveRun(updated); err != nil {
			return nil, fmt.Errorf("persist report run %q: %w", runID, err)
		}
	}
	s.syncPlatformJobWithReportRun(updated)
	s.cachePlatformReportRun(updated)
	return reports.CloneReportRun(updated), nil
}

func (s *Server) platformReportRunSnapshot(reportID, runID string) (*reports.ReportRun, bool) {
	if s.platformReportStore != nil {
		run, err := s.platformReportStore.LoadRun(runID)
		if err == nil && run != nil && run.ReportID == reportID {
			s.cachePlatformReportRun(run)
			return reports.CloneReportRun(run), true
		}
	}
	s.platformReportRunMu.RLock()
	defer s.platformReportRunMu.RUnlock()
	run, ok := s.platformReportRuns[runID]
	if !ok || run.ReportID != reportID {
		return nil, false
	}
	return reports.CloneReportRun(run), true
}

func (s *Server) syncPlatformJobWithReportRun(run *reports.ReportRun) {
	if run == nil {
		return
	}
	jobID := strings.TrimSpace(run.JobID)
	if jobID == "" {
		return
	}
	s.platformJobMu.Lock()
	defer s.platformJobMu.Unlock()
	job, ok := s.platformJobs[jobID]
	if !ok || job == nil {
		return
	}
	if run.CancelRequestedAt != nil {
		cancelRequestedAt := *run.CancelRequestedAt
		job.CancelRequestedAt = &cancelRequestedAt
	}
	if reason := strings.TrimSpace(run.CancelReason); reason != "" {
		job.CancelReason = reason
	}
	switch run.Status {
	case reports.ReportRunStatusRunning:
		job.Status = "running"
		if run.StartedAt != nil {
			startedAt := *run.StartedAt
			job.StartedAt = &startedAt
		}
	case reports.ReportRunStatusSucceeded:
		job.Status = "succeeded"
		if run.CompletedAt != nil {
			completedAt := *run.CompletedAt
			job.CompletedAt = &completedAt
		}
		job.Error = ""
		job.Result = cloneJSONValue(reports.SummarizeReportRun(*run))
	case reports.ReportRunStatusFailed:
		job.Status = "failed"
		if run.CompletedAt != nil {
			completedAt := *run.CompletedAt
			job.CompletedAt = &completedAt
		}
		job.Error = run.Error
	case reports.ReportRunStatusCanceled:
		// Preserve cancellation metadata immediately, but do not flip an active
		// job to terminal canceled until the job-owned cancel func has been
		// invoked. Otherwise handlers that are waiting on request context
		// cancellation can hang indefinitely.
		if job.cancel == nil {
			job.Status = "canceled"
			if run.CompletedAt != nil {
				completedAt := *run.CompletedAt
				job.CompletedAt = &completedAt
			}
		}
		if job.Error == "" {
			job.Error = strings.TrimSpace(run.CancelReason)
		}
	}
}

func (s *Server) platformReportRunSummaries(reportID string) []reports.ReportRunSummary {
	if s.platformReportStore != nil {
		runs, err := s.platformReportStore.ListRuns(reportID)
		if err == nil {
			s.cachePlatformReportRuns(runs)
			summaries := make([]reports.ReportRunSummary, 0, len(runs))
			for _, run := range runs {
				if run == nil {
					continue
				}
				summaries = append(summaries, reports.SummarizeReportRun(*run))
			}
			sort.Slice(summaries, func(i, j int) bool {
				if summaries[i].SubmittedAt.Equal(summaries[j].SubmittedAt) {
					return summaries[i].ID > summaries[j].ID
				}
				return summaries[i].SubmittedAt.After(summaries[j].SubmittedAt)
			})
			return summaries
		}
	}
	s.platformReportRunMu.RLock()
	defer s.platformReportRunMu.RUnlock()
	runs := make([]reports.ReportRunSummary, 0)
	for _, run := range s.platformReportRuns {
		if run.ReportID != reportID {
			continue
		}
		runs = append(runs, reports.SummarizeReportRun(*run))
	}
	sort.Slice(runs, func(i, j int) bool {
		if runs[i].SubmittedAt.Equal(runs[j].SubmittedAt) {
			return runs[i].ID > runs[j].ID
		}
		return runs[i].SubmittedAt.After(runs[j].SubmittedAt)
	})
	return runs
}

func (s *Server) reusablePlatformReportRun(reportID, cacheKey string, lineage reports.ReportLineage, excludeRunID string) *reports.ReportRun {
	reportID = strings.TrimSpace(reportID)
	cacheKey = strings.TrimSpace(cacheKey)
	excludeRunID = strings.TrimSpace(excludeRunID)
	if reportID == "" || cacheKey == "" {
		return nil
	}
	candidates := make([]*reports.ReportRun, 0)
	if s.platformReportStore != nil {
		if storedRuns, err := s.platformReportStore.ListRuns(reportID); err == nil {
			s.cachePlatformReportRuns(storedRuns)
			candidates = append(candidates, storedRuns...)
		}
	}
	if len(candidates) == 0 {
		s.platformReportRunMu.RLock()
		for _, candidate := range s.platformReportRuns {
			candidates = append(candidates, reports.CloneReportRun(candidate))
		}
		s.platformReportRunMu.RUnlock()
	}
	var best *reports.ReportRun
	for _, candidate := range candidates {
		if candidate == nil {
			continue
		}
		if strings.TrimSpace(candidate.ID) == excludeRunID {
			continue
		}
		if candidate.ReportID != reportID || candidate.Status != reports.ReportRunStatusSucceeded {
			continue
		}
		if strings.TrimSpace(candidate.CacheKey) != cacheKey {
			continue
		}
		if len(candidate.Result) == 0 {
			continue
		}
		if !platformReportLineageCompatible(candidate.Lineage, lineage) {
			continue
		}
		if best == nil || platformReportRunCompletedAt(candidate).After(platformReportRunCompletedAt(best)) {
			best = reports.CloneReportRun(candidate)
		}
	}
	return best
}

func (s *Server) refreshPlatformReportRunCacheBinding(runID string, run *reports.ReportRun) (*reports.ReportRun, error) {
	if run == nil {
		return nil, nil
	}
	cacheSource := s.selectPlatformReportCacheSource(run)
	cacheStatus := reports.ReportCacheStatusMiss
	cacheSourceRunID := ""
	if cacheSource != nil {
		cacheStatus = reports.ReportCacheStatusHit
		cacheSourceRunID = cacheSource.ID
	}
	if strings.TrimSpace(run.CacheStatus) == cacheStatus && strings.TrimSpace(run.CacheSourceRunID) == cacheSourceRunID {
		return cacheSource, nil
	}
	if err := s.updatePlatformReportRun(runID, func(updated *reports.ReportRun) {
		updated.CacheStatus = cacheStatus
		updated.CacheSourceRunID = cacheSourceRunID
	}); err != nil {
		return nil, err
	}
	return cacheSource, nil
}

func (s *Server) selectPlatformReportCacheSource(run *reports.ReportRun) *reports.ReportRun {
	if run == nil {
		return nil
	}
	if sourceRunID := strings.TrimSpace(run.CacheSourceRunID); sourceRunID != "" && sourceRunID != strings.TrimSpace(run.ID) {
		if source, ok := s.platformReportRunSnapshot(run.ReportID, sourceRunID); ok && source != nil && platformReportRunReusableFor(source, run) {
			return source
		}
	}
	return s.reusablePlatformReportRun(run.ReportID, run.CacheKey, run.Lineage, run.ID)
}

func platformReportRunReusableFor(source, run *reports.ReportRun) bool {
	if source == nil || run == nil {
		return false
	}
	if source.ReportID != run.ReportID || source.Status != reports.ReportRunStatusSucceeded {
		return false
	}
	if strings.TrimSpace(source.CacheKey) == "" || strings.TrimSpace(source.CacheKey) != strings.TrimSpace(run.CacheKey) {
		return false
	}
	if len(source.Result) == 0 {
		return false
	}
	return platformReportLineageCompatible(source.Lineage, run.Lineage)
}

func platformReportLineageCompatible(left, right reports.ReportLineage) bool {
	if left.GraphSnapshotID != "" || right.GraphSnapshotID != "" {
		if strings.TrimSpace(left.GraphSnapshotID) != strings.TrimSpace(right.GraphSnapshotID) {
			return false
		}
	}
	return left.GraphSchemaVersion == right.GraphSchemaVersion &&
		strings.TrimSpace(left.OntologyContractVersion) == strings.TrimSpace(right.OntologyContractVersion) &&
		strings.TrimSpace(left.ReportDefinitionVersion) == strings.TrimSpace(right.ReportDefinitionVersion)
}

func platformReportRunCompletedAt(run *reports.ReportRun) time.Time {
	if run == nil {
		return time.Time{}
	}
	if run.CompletedAt != nil && !run.CompletedAt.IsZero() {
		return run.CompletedAt.UTC()
	}
	return run.SubmittedAt.UTC()
}

func (s *Server) clonePlatformReportRunsLocked() map[string]*reports.ReportRun {
	cloned := make(map[string]*reports.ReportRun, len(s.platformReportRuns))
	for id, run := range s.platformReportRuns {
		cloned[id] = reports.CloneReportRun(run)
	}
	return cloned
}

func (s *Server) cachePlatformReportRun(run *reports.ReportRun) {
	if s == nil || run == nil || strings.TrimSpace(run.ID) == "" {
		return
	}
	s.platformReportRunMu.Lock()
	s.platformReportRuns[run.ID] = reports.CloneReportRun(run)
	s.platformReportRunMu.Unlock()
}

func (s *Server) cachePlatformReportRuns(runs []*reports.ReportRun) {
	if s == nil || len(runs) == 0 {
		return
	}
	s.platformReportRunMu.Lock()
	defer s.platformReportRunMu.Unlock()
	for _, run := range runs {
		if run == nil || strings.TrimSpace(run.ID) == "" {
			continue
		}
		s.platformReportRuns[run.ID] = reports.CloneReportRun(run)
	}
}
