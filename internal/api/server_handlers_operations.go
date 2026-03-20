package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/writer/cerebro/internal/notifications"
	"github.com/writer/cerebro/internal/remediation"
	"github.com/writer/cerebro/internal/scheduler"
)

func (s *Server) schedulerStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.schedulerOperations.Status()
	if err != nil {
		if errors.Is(err, errSchedulerUnavailable) {
			s.error(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, status)
}

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) {
	pagination := ParsePagination(r, 100, 1000)
	jobs, err := s.schedulerOperations.ListJobs()
	if err != nil {
		if errors.Is(err, errSchedulerUnavailable) {
			s.error(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		s.errorFromErr(w, err)
		return
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].Name < jobs[j].Name })

	result := make([]map[string]interface{}, len(jobs))
	for i, j := range jobs {
		result[i] = map[string]interface{}{
			"name":     j.Name,
			"interval": j.Interval.String(),
			"enabled":  j.Enabled,
			"running":  j.Running,
			"next_run": j.NextRun,
		}
		if !j.LastRun.IsZero() {
			result[i]["last_run"] = j.LastRun
		}
	}
	paged, paginationResp := paginateSlice(result, pagination)
	s.json(w, http.StatusOK, map[string]interface{}{
		"jobs":        paged,
		"count":       len(paged),
		"pagination":  paginationResp,
		"total_count": len(result),
	})
}

func (s *Server) runJob(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := s.schedulerOperations.RunJob(r.Context(), name, GetUserID(r.Context())); err != nil {
		switch {
		case errors.Is(err, errSchedulerUnavailable):
			s.error(w, http.StatusServiceUnavailable, err.Error())
		case errors.Is(err, scheduler.ErrJobNotFound):
			s.error(w, http.StatusNotFound, err.Error())
		case errors.Is(err, scheduler.ErrJobAlreadyRunning):
			s.error(w, http.StatusConflict, err.Error())
		case errors.Is(err, scheduler.ErrSchedulerStopped):
			s.error(w, http.StatusServiceUnavailable, err.Error())
		default:
			s.errorFromErr(w, err)
		}
		return
	}
	s.json(w, http.StatusAccepted, map[string]string{"status": "job triggered"})
}

func (s *Server) enableJob(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := s.schedulerOperations.EnableJob(name); err != nil {
		if errors.Is(err, errSchedulerUnavailable) {
			s.error(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "job enabled"})
}

func (s *Server) disableJob(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := s.schedulerOperations.DisableJob(name); err != nil {
		if errors.Is(err, errSchedulerUnavailable) {
			s.error(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "job disabled"})
}

// Notification endpoints

func (s *Server) listNotifiers(w http.ResponseWriter, r *http.Request) {
	pagination := ParsePagination(r, 100, 1000)
	notifiers := s.app.Notifications.ListNotifiers()
	sort.Strings(notifiers)
	paged, paginationResp := paginateSlice(notifiers, pagination)
	s.json(w, http.StatusOK, map[string]interface{}{
		"notifiers":   paged,
		"count":       len(paged),
		"pagination":  paginationResp,
		"total_count": len(notifiers),
	})
}

func (s *Server) testNotifications(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Message  string `json:"message"`
		Severity string `json:"severity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Message = "Test notification from Cerebro"
		req.Severity = "info"
	}

	err := s.app.Notifications.Send(r.Context(), notifications.Event{
		Type:     "test",
		Title:    "Test Notification",
		Message:  req.Message,
		Severity: req.Severity,
	})
	if err != nil {
		s.json(w, http.StatusOK, map[string]interface{}{"status": "partial", "error": err.Error()})
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "sent"})
}

func (s *Server) dailyDigest(w http.ResponseWriter, r *http.Request) {
	handler := notifications.NewSlackCommandHandler(
		notifications.SlackCommandConfig{},
		s.app.Findings,
	)
	digest := handler.DailyDigest()
	s.json(w, http.StatusOK, digest)
}

func (s *Server) slackCommands(w http.ResponseWriter, r *http.Request) {
	handler := notifications.NewSlackCommandHandler(
		notifications.SlackCommandConfig{
			SigningSecret: s.app.Config.SlackSigningSecret,
		},
		s.app.Findings,
	)
	handler.ServeHTTP(w, r)
}

// Remediation endpoints

func (s *Server) listRemediationRules(w http.ResponseWriter, r *http.Request) {
	pagination := ParsePagination(r, 100, 1000)
	rules, err := s.remediationOperations.ListRules()
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	paged, paginationResp := paginateSlice(rules, pagination)

	s.json(w, http.StatusOK, map[string]interface{}{
		"rules":       paged,
		"count":       len(paged),
		"pagination":  paginationResp,
		"total_count": len(rules),
	})
}

func (s *Server) createRemediationRule(w http.ResponseWriter, r *http.Request) {
	var rule remediation.Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	created, err := s.remediationOperations.CreateRule(r.Context(), rule, GetUserID(r.Context()))
	if err != nil {
		if errors.Is(err, errRemediationUnavailable) {
			s.error(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusCreated, created)
}

func (s *Server) updateRemediationRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		s.error(w, http.StatusBadRequest, "rule id required")
		return
	}

	var rule remediation.Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}
	if rule.ID != "" && rule.ID != id {
		s.error(w, http.StatusBadRequest, "rule id in body must match path id")
		return
	}

	rule.ID = id
	updated, err := s.remediationOperations.UpdateRule(id, rule)
	if err != nil {
		if errors.Is(err, errRemediationUnavailable) {
			s.error(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		s.error(w, http.StatusNotFound, "rule not found")
		return
	}
	s.json(w, http.StatusOK, updated)
}

func (s *Server) deleteRemediationRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		s.error(w, http.StatusBadRequest, "rule id required")
		return
	}
	if err := s.remediationOperations.DeleteRule(id); err != nil {
		if errors.Is(err, errRemediationUnavailable) {
			s.error(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		s.error(w, http.StatusNotFound, "rule not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getRemediationRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rule, ok, err := s.remediationOperations.GetRule(id)
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if !ok {
		s.error(w, http.StatusNotFound, "rule not found")
		return
	}
	s.json(w, http.StatusOK, rule)
}

func (s *Server) enableRemediationRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.remediationOperations.EnableRule(id); err != nil {
		if errors.Is(err, errRemediationUnavailable) {
			s.error(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		s.error(w, http.StatusNotFound, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "enabled"})
}

func (s *Server) disableRemediationRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.remediationOperations.DisableRule(id); err != nil {
		if errors.Is(err, errRemediationUnavailable) {
			s.error(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		s.error(w, http.StatusNotFound, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "disabled"})
}

func (s *Server) listRemediationExecutions(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	executions, err := s.remediationOperations.ListExecutions(limit)
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{
		"executions": executions,
		"count":      len(executions),
	})
}

func (s *Server) getRemediationExecution(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	execution, ok, err := s.remediationOperations.GetExecution(id)
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if !ok {
		s.error(w, http.StatusNotFound, "execution not found")
		return
	}
	s.json(w, http.StatusOK, execution)
}

func (s *Server) approveExecution(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req struct {
		ApproverID string `json:"approver_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	if err := s.remediationOperations.ApproveExecution(r.Context(), id, req.ApproverID); err != nil {
		if errors.Is(err, errRemediationExecutorUnavailable) {
			s.error(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	s.json(w, http.StatusOK, map[string]string{"status": "approved"})
}

func (s *Server) rejectExecution(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req struct {
		RejecterID string `json:"rejecter_id"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	if err := s.remediationOperations.RejectExecution(r.Context(), id, req.RejecterID, req.Reason); err != nil {
		if errors.Is(err, errRemediationExecutorUnavailable) {
			s.error(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	s.json(w, http.StatusOK, map[string]string{"status": "rejected"})
}

// Threat Intelligence handlers
