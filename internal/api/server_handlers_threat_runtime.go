package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/evalops/cerebro/internal/runtime"
	"github.com/evalops/cerebro/internal/webhooks"
)

func (s *Server) listThreatFeeds(w http.ResponseWriter, r *http.Request) {
	if s.app.ThreatIntel == nil {
		s.error(w, http.StatusServiceUnavailable, "threat intel not initialized")
		return
	}
	s.json(w, http.StatusOK, s.app.ThreatIntel.ListFeeds())
}

func (s *Server) syncThreatFeed(w http.ResponseWriter, r *http.Request) {
	if s.app.ThreatIntel == nil {
		s.error(w, http.StatusServiceUnavailable, "threat intel not initialized")
		return
	}
	id := chi.URLParam(r, "id")
	if err := s.app.ThreatIntel.SyncFeed(r.Context(), id); err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.app.Webhooks != nil {
		if err := s.app.Webhooks.EmitWithErrors(r.Context(), webhooks.EventThreatIntelSynced, map[string]interface{}{
			"feed_id":      id,
			"triggered_by": GetUserID(r.Context()),
		}); err != nil {
			s.app.Logger.Warn("failed to emit threat intel sync event", "feed_id", id, "error", err)
		}
	}
	s.json(w, http.StatusOK, map[string]string{"status": "synced"})
}

func (s *Server) threatIntelStats(w http.ResponseWriter, r *http.Request) {
	if s.app.ThreatIntel == nil {
		s.error(w, http.StatusServiceUnavailable, "threat intel not initialized")
		return
	}
	s.json(w, http.StatusOK, s.app.ThreatIntel.Stats())
}

func (s *Server) lookupIP(w http.ResponseWriter, r *http.Request) {
	if s.app.ThreatIntel == nil {
		s.error(w, http.StatusServiceUnavailable, "threat intel not initialized")
		return
	}
	ip := chi.URLParam(r, "ip")
	ind, found := s.app.ThreatIntel.LookupIP(ip)
	if !found {
		s.json(w, http.StatusOK, map[string]interface{}{"found": false, "ip": ip})
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"found": true, "indicator": ind})
}

func (s *Server) lookupDomain(w http.ResponseWriter, r *http.Request) {
	if s.app.ThreatIntel == nil {
		s.error(w, http.StatusServiceUnavailable, "threat intel not initialized")
		return
	}
	domain := chi.URLParam(r, "domain")
	ind, found := s.app.ThreatIntel.LookupDomain(domain)
	if !found {
		s.json(w, http.StatusOK, map[string]interface{}{"found": false, "domain": domain})
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"found": true, "indicator": ind})
}

func (s *Server) lookupCVE(w http.ResponseWriter, r *http.Request) {
	if s.app.ThreatIntel == nil {
		s.error(w, http.StatusServiceUnavailable, "threat intel not initialized")
		return
	}
	cve := chi.URLParam(r, "cve")
	ind, found := s.app.ThreatIntel.LookupCVE(cve)
	isKEV := s.app.ThreatIntel.IsKEV(cve)
	s.json(w, http.StatusOK, map[string]interface{}{
		"found":     found,
		"cve":       cve,
		"is_kev":    isKEV,
		"indicator": ind,
	})
}

func (s *Server) listDetectionRules(w http.ResponseWriter, r *http.Request) {
	if s.app.RuntimeDetect == nil {
		s.error(w, http.StatusServiceUnavailable, "runtime detection not initialized")
		return
	}
	s.json(w, http.StatusOK, s.app.RuntimeDetect.ListRules())
}

func (s *Server) ingestRuntimeEvent(w http.ResponseWriter, r *http.Request) {
	if s.app.RuntimeDetect == nil {
		s.error(w, http.StatusServiceUnavailable, "runtime detection not initialized")
		return
	}

	var event runtime.RuntimeEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		s.error(w, http.StatusBadRequest, "invalid event")
		return
	}

	findings := s.app.RuntimeDetect.ProcessEvent(r.Context(), &event)

	if s.app.RuntimeRespond != nil {
		for _, f := range findings {
			_, _ = s.app.RuntimeRespond.ProcessFinding(r.Context(), &f)
		}
	}

	if s.app.Webhooks != nil {
		if err := s.app.Webhooks.EmitWithErrors(r.Context(), webhooks.EventRuntimeIngested, map[string]interface{}{
			"source":   "runtime_event",
			"findings": len(findings),
		}); err != nil {
			s.app.Logger.Warn("failed to emit runtime ingest event", "error", err)
		}
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"processed": true,
		"findings":  len(findings),
	})
}

func (s *Server) listRuntimeFindings(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	findings := s.app.RuntimeDetect.RecentFindings(limit)
	s.json(w, http.StatusOK, map[string]interface{}{
		"findings": findings,
		"count":    len(findings),
	})
}

func (s *Server) listResponsePolicies(w http.ResponseWriter, r *http.Request) {
	if s.app.RuntimeRespond == nil {
		s.error(w, http.StatusServiceUnavailable, "runtime response not initialized")
		return
	}
	s.json(w, http.StatusOK, s.app.RuntimeRespond.ListPolicies())
}

func (s *Server) enableResponsePolicy(w http.ResponseWriter, r *http.Request) {
	if s.app.RuntimeRespond == nil {
		s.error(w, http.StatusServiceUnavailable, "runtime response not initialized")
		return
	}
	id := chi.URLParam(r, "id")
	if err := s.app.RuntimeRespond.EnablePolicy(id); err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "enabled"})
}

func (s *Server) disableResponsePolicy(w http.ResponseWriter, r *http.Request) {
	if s.app.RuntimeRespond == nil {
		s.error(w, http.StatusServiceUnavailable, "runtime response not initialized")
		return
	}
	id := chi.URLParam(r, "id")
	if err := s.app.RuntimeRespond.DisablePolicy(id); err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "disabled"})
}

func (s *Server) ingestTelemetry(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Events       []runtime.RuntimeEvent `json:"events"`
		Node         string                 `json:"node"`
		Cluster      string                 `json:"cluster"`
		AgentVersion string                 `json:"agent_version"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		s.error(w, http.StatusBadRequest, "invalid payload")
		return
	}

	totalFindings := 0
	if s.app.RuntimeDetect != nil {
		for _, event := range payload.Events {
			findings := s.app.RuntimeDetect.ProcessEvent(r.Context(), &event)
			totalFindings += len(findings)

			if s.app.RuntimeRespond != nil {
				for _, f := range findings {
					_, _ = s.app.RuntimeRespond.ProcessFinding(r.Context(), &f)
				}
			}
		}
	}

	if s.app.Webhooks != nil {
		if err := s.app.Webhooks.EmitWithErrors(r.Context(), webhooks.EventRuntimeIngested, map[string]interface{}{
			"source":           "telemetry",
			"events_processed": len(payload.Events),
			"findings":         totalFindings,
			"node":             payload.Node,
			"cluster":          payload.Cluster,
		}); err != nil {
			s.app.Logger.Warn("failed to emit telemetry ingest event", "error", err)
		}
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"processed": len(payload.Events),
		"findings":  totalFindings,
	})
}
