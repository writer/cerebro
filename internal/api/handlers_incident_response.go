package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/writer/cerebro/internal/agents"
)

// Incident response endpoints

func (s *Server) createIncident(w http.ResponseWriter, r *http.Request) {
	var req agents.CreateIncidentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	if req.Title == "" {
		s.error(w, http.StatusBadRequest, "title is required")
		return
	}
	if req.Severity == "" {
		req.Severity = "medium"
	}

	ir := agents.NewIncidentResponse(s.app.Agents)
	incident, err := ir.CreateIncident(r.Context(), req)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}

	s.json(w, http.StatusCreated, incident)
}

func (s *Server) listPlaybooks(w http.ResponseWriter, r *http.Request) {
	ir := agents.NewIncidentResponse(s.app.Agents)
	playbooks := ir.ListPlaybooks()
	s.json(w, http.StatusOK, map[string]interface{}{
		"playbooks": playbooks,
		"count":     len(playbooks),
	})
}

func (s *Server) getPlaybook(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ir := agents.NewIncidentResponse(s.app.Agents)
	playbook := ir.GetPlaybook(id)
	if playbook == nil {
		s.error(w, http.StatusNotFound, "playbook not found")
		return
	}
	s.json(w, http.StatusOK, playbook)
}
