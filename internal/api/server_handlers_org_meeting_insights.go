package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/writer/cerebro/internal/graph"
)

func (s *Server) orgMeetingInsights(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	team := strings.TrimSpace(r.URL.Query().Get("team"))
	report := graph.AnalyzeMeetingInsights(s.app.SecurityGraph, team)
	s.json(w, http.StatusOK, report)
}

func (s *Server) orgMeetingAnalysis(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	meetingID := strings.TrimSpace(chi.URLParam(r, "id"))
	if meetingID == "" {
		s.error(w, http.StatusBadRequest, "meeting id is required")
		return
	}

	analysis := graph.AnalyzeMeetingByID(s.app.SecurityGraph, meetingID)
	if analysis == nil {
		s.error(w, http.StatusNotFound, "meeting analysis not found")
		return
	}

	s.json(w, http.StatusOK, analysis)
}
