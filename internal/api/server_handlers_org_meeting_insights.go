package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

func (s *Server) orgMeetingInsights(w http.ResponseWriter, r *http.Request) {
	report, err := s.orgAnalysis.MeetingInsights(r.Context(), strings.TrimSpace(r.URL.Query().Get("team")))
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, report)
}

func (s *Server) orgMeetingAnalysis(w http.ResponseWriter, r *http.Request) {
	meetingID := strings.TrimSpace(chi.URLParam(r, "id"))
	if meetingID == "" {
		s.error(w, http.StatusBadRequest, "meeting id is required")
		return
	}

	analysis, err := s.orgAnalysis.MeetingAnalysis(r.Context(), meetingID)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if analysis == nil {
		s.error(w, http.StatusNotFound, "meeting analysis not found")
		return
	}

	s.json(w, http.StatusOK, analysis)
}
