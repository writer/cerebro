package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/writer/cerebro/internal/ticketing"
)

// Ticketing endpoints

func (s *Server) listTickets(w http.ResponseWriter, r *http.Request) {
	if !s.ticketingOps.PrimaryConfigured() {
		s.json(w, http.StatusOK, map[string]interface{}{"tickets": []interface{}{}, "count": 0, "message": "no ticketing provider configured"})
		return
	}

	tickets, err := s.ticketingOps.ListTickets(r.Context(), ticketing.TicketFilter{
		Status:   r.URL.Query().Get("status"),
		Priority: r.URL.Query().Get("priority"),
		Limit:    50,
	})
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"tickets": tickets, "count": len(tickets)})
}

func (s *Server) createTicket(w http.ResponseWriter, r *http.Request) {
	if !s.ticketingOps.PrimaryConfigured() {
		s.error(w, http.StatusServiceUnavailable, "no ticketing provider configured")
		return
	}

	var req struct {
		Title       string   `json:"title"`
		Description string   `json:"description"`
		Priority    string   `json:"priority"`
		FindingIDs  []string `json:"finding_ids,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	ticket := &ticketing.Ticket{
		Title:       req.Title,
		Description: req.Description,
		Priority:    req.Priority,
		FindingIDs:  req.FindingIDs,
		Type:        "finding",
	}

	created, err := s.ticketingOps.CreateTicket(r.Context(), ticket)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusCreated, created)
}

func (s *Server) getTicket(w http.ResponseWriter, r *http.Request) {
	if !s.ticketingOps.PrimaryConfigured() {
		s.error(w, http.StatusServiceUnavailable, "no ticketing provider configured")
		return
	}

	id := chi.URLParam(r, "id")
	ticket, err := s.ticketingOps.GetTicket(r.Context(), id)
	if err != nil {
		s.error(w, http.StatusNotFound, err.Error())
		return
	}
	s.json(w, http.StatusOK, ticket)
}

func (s *Server) updateTicket(w http.ResponseWriter, r *http.Request) {
	if !s.ticketingOps.PrimaryConfigured() {
		s.error(w, http.StatusServiceUnavailable, "no ticketing provider configured")
		return
	}

	id := chi.URLParam(r, "id")
	var update ticketing.TicketUpdate
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	ticket, err := s.ticketingOps.UpdateTicket(r.Context(), id, &update)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, ticket)
}

func (s *Server) addComment(w http.ResponseWriter, r *http.Request) {
	if !s.ticketingOps.PrimaryConfigured() {
		s.error(w, http.StatusServiceUnavailable, "no ticketing provider configured")
		return
	}

	id := chi.URLParam(r, "id")
	var req struct {
		Body string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	err := s.ticketingOps.AddComment(r.Context(), id, &ticketing.Comment{Body: req.Body})
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusCreated, map[string]string{"status": "comment added"})
}

func (s *Server) closeTicket(w http.ResponseWriter, r *http.Request) {
	if !s.ticketingOps.PrimaryConfigured() {
		s.error(w, http.StatusServiceUnavailable, "no ticketing provider configured")
		return
	}

	id := chi.URLParam(r, "id")
	var req struct {
		Resolution string `json:"resolution"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	err := s.ticketingOps.CloseTicket(r.Context(), id, req.Resolution)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "closed"})
}
