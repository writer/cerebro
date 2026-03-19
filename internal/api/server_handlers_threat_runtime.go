package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/evalops/cerebro/internal/runtime"
	"github.com/evalops/cerebro/internal/webhooks"
)

func (s *Server) listThreatFeeds(w http.ResponseWriter, r *http.Request) {
	feeds, err := s.threatRuntime.ListThreatFeeds()
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	s.json(w, http.StatusOK, feeds)
}

func (s *Server) syncThreatFeed(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.threatRuntime.SyncThreatFeed(r.Context(), id, GetUserID(r.Context())); err != nil {
		if errors.Is(err, errThreatIntelUnavailable) {
			s.error(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "synced"})
}

func (s *Server) threatIntelStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.threatRuntime.ThreatIntelStats()
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	s.json(w, http.StatusOK, stats)
}

func (s *Server) lookupIP(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	ind, found, err := s.threatRuntime.LookupIP(ip)
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if !found {
		s.json(w, http.StatusOK, map[string]interface{}{"found": false, "ip": ip})
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"found": true, "indicator": ind})
}

func (s *Server) lookupDomain(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	ind, found, err := s.threatRuntime.LookupDomain(domain)
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if !found {
		s.json(w, http.StatusOK, map[string]interface{}{"found": false, "domain": domain})
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"found": true, "indicator": ind})
}

func (s *Server) lookupCVE(w http.ResponseWriter, r *http.Request) {
	cve := chi.URLParam(r, "cve")
	ind, found, isKEV, err := s.threatRuntime.LookupCVE(cve)
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{
		"found":     found,
		"cve":       cve,
		"is_kev":    isKEV,
		"indicator": ind,
	})
}

func (s *Server) listDetectionRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.threatRuntime.ListDetectionRules()
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	s.json(w, http.StatusOK, rules)
}

func (s *Server) ingestRuntimeEvent(w http.ResponseWriter, r *http.Request) {
	if s.app.RuntimeDetect == nil {
		s.error(w, http.StatusServiceUnavailable, "runtime detection not initialized")
		return
	}

	dedupeStore := s.runtimeIngestStore()

	var event runtime.RuntimeEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		s.error(w, http.StatusBadRequest, "invalid event")
		return
	}

	session, err := s.startRuntimeIngestSession(r.Context(), "runtime_event", map[string]string{
		"event_type":    event.EventType,
		"resource_id":   event.ResourceID,
		"resource_type": event.ResourceType,
		"source":        event.Source,
	})
	if err != nil {
		s.warnRuntimeIngestPersistence("start", err, "source", "runtime_event", "event_id", event.ID)
		session = nil
	}

	payloadHash, hashErr := runtimeSourceEventPayloadHash(&event)
	if hashErr != nil {
		s.warnRuntimeIngestPersistence("hash_source_event", hashErr, "source", "runtime_event", "event_id", event.ID, "run_id", session.runID())
	}
	observation, err := runtime.ObservationFromEvent(&event)
	if err != nil {
		s.warnInvalidRuntimeObservation("runtime_event", err, "event_id", event.ID, "resource_id", event.ResourceID, "resource_type", event.ResourceType)
		if session != nil {
			if rejectErr := session.recordRejectedObservation(r.Context(), &event, 1, err); rejectErr != nil {
				s.warnRuntimeIngestPersistence("record_rejected_observation", rejectErr, "source", "runtime_event", "event_id", event.ID, "run_id", session.runID())
			}
			session.fail(r.Context(), "normalize", err)
		}
		s.error(w, http.StatusBadRequest, "invalid event")
		return
	}
	if dedupeStore != nil && event.ID != "" && payloadHash != "" {
		duplicate, dedupeErr := dedupeStore.ClaimSourceEventProcessing(r.Context(), runtimeSourceEventSource(&event, "runtime_event"), event.ID, payloadHash, event.Timestamp)
		if dedupeErr != nil {
			s.warnRuntimeIngestPersistence("check_duplicate_source_event", dedupeErr, "source", "runtime_event", "event_id", event.ID, "run_id", session.runID())
			if rejectErr := session.recordRejectedObservation(r.Context(), &event, 1, fmt.Errorf("dedupe check: %w", dedupeErr)); rejectErr != nil {
				s.warnRuntimeIngestPersistence("record_rejected_observation", rejectErr, "source", "runtime_event", "event_id", event.ID, "run_id", session.runID())
			}
			session.fail(r.Context(), "dedupe", dedupeErr)
			s.error(w, http.StatusServiceUnavailable, "runtime ingest dedupe unavailable")
			return
		} else if duplicate {
			if err := session.recordDuplicateObservation(r.Context(), &event, 1); err != nil {
				s.warnRuntimeIngestPersistence("record_duplicate_observation", err, "source", "runtime_event", "event_id", event.ID, "run_id", session.runID())
			}
			if session != nil {
				if err := session.complete(r.Context(), runtime.IngestCheckpoint{
					Cursor: event.ID,
					Metadata: map[string]string{
						"processed_events": "0",
						"duplicate_events": "1",
						"finding_count":    "0",
					},
				}); err != nil {
					session.fail(r.Context(), "complete", err)
					s.warnRuntimeIngestPersistence("complete", err, "source", "runtime_event", "event_id", event.ID, "run_id", session.runID())
					session = nil
				}
			}

			response := map[string]interface{}{
				"processed": false,
				"duplicate": true,
				"findings":  0,
			}
			if session != nil && session.run != nil {
				response["run_id"] = session.run.ID
			}
			s.json(w, http.StatusOK, response)
			return
		}
	}
	findings := s.app.RuntimeDetect.ProcessNormalizedObservation(r.Context(), observation)
	if session != nil {
		if err := session.recordObservation(r.Context(), observation, len(findings), 1); err != nil {
			session.fail(r.Context(), "detect", err)
			s.warnRuntimeIngestPersistence("record_observation", err, "source", "runtime_event", "event_id", event.ID, "run_id", session.runID())
			session = nil
		}
	}

	if s.app.RuntimeRespond != nil {
		for _, f := range findings {
			_, _ = s.app.RuntimeRespond.ProcessFinding(r.Context(), &f)
		}
	}

	if dedupeStore != nil && event.ID != "" && payloadHash != "" {
		if err := dedupeStore.MarkSourceEventProcessed(r.Context(), runtimeSourceEventSource(&event, "runtime_event"), event.ID, payloadHash, event.Timestamp); err != nil {
			s.warnRuntimeIngestPersistence("mark_source_event_processed", err, "source", "runtime_event", "event_id", event.ID, "run_id", session.runID())
			if rejectErr := session.recordRejectedObservation(r.Context(), &event, 1, fmt.Errorf("mark processed: %w", err)); rejectErr != nil {
				s.warnRuntimeIngestPersistence("record_rejected_observation", rejectErr, "source", "runtime_event", "event_id", event.ID, "run_id", session.runID())
			}
			session.fail(r.Context(), "dedupe", err)
			s.error(w, http.StatusServiceUnavailable, "runtime ingest dedupe unavailable")
			return
		}
	}

	if session != nil {
		if err := session.complete(r.Context(), runtime.IngestCheckpoint{
			Cursor: observation.ID,
			Metadata: map[string]string{
				"processed_events": "1",
				"duplicate_events": "0",
				"finding_count":    strconv.Itoa(len(findings)),
			},
		}); err != nil {
			session.fail(r.Context(), "complete", err)
			s.warnRuntimeIngestPersistence("complete", err, "source", "runtime_event", "event_id", event.ID, "run_id", session.runID())
			session = nil
		}
	}

	if s.app.Webhooks != nil {
		webhookPayload := map[string]interface{}{
			"source":   "runtime_event",
			"findings": len(findings),
		}
		if session != nil && session.run != nil {
			webhookPayload["run_id"] = session.run.ID
		}
		if err := s.app.Webhooks.EmitWithErrors(r.Context(), webhooks.EventRuntimeIngested, webhookPayload); err != nil {
			s.app.Logger.Warn("failed to emit runtime ingest event", "error", err)
		}
	}

	response := map[string]interface{}{
		"processed": true,
		"duplicate": false,
		"findings":  len(findings),
	}
	if session != nil && session.run != nil {
		response["run_id"] = session.run.ID
	}
	s.json(w, http.StatusOK, response)
}

func (s *Server) listRuntimeFindings(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	findings, err := s.threatRuntime.RecentRuntimeFindings(limit)
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{
		"findings": findings,
		"count":    len(findings),
	})
}

func (s *Server) listResponsePolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := s.threatRuntime.ListResponsePolicies()
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	s.json(w, http.StatusOK, policies)
}

func (s *Server) enableResponsePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.threatRuntime.EnableResponsePolicy(id); err != nil {
		if errors.Is(err, errRuntimeResponseUnavailable) {
			s.error(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "enabled"})
}

func (s *Server) disableResponsePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.threatRuntime.DisableResponsePolicy(id); err != nil {
		if errors.Is(err, errRuntimeResponseUnavailable) {
			s.error(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "disabled"})
}

func (s *Server) ingestTelemetry(w http.ResponseWriter, r *http.Request) {
	dedupeStore := s.runtimeIngestStore()

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

	session, err := s.startRuntimeIngestSession(r.Context(), "telemetry", map[string]string{
		"cluster":       payload.Cluster,
		"node":          payload.Node,
		"agent_version": payload.AgentVersion,
		"event_count":   strconv.Itoa(len(payload.Events)),
	})
	if err != nil {
		s.warnRuntimeIngestPersistence("start", err, "source", "telemetry", "event_count", len(payload.Events), "cluster", payload.Cluster, "node", payload.Node)
		session = nil
	}

	totalFindings := 0
	processedEvents := 0
	rejectedEvents := 0
	duplicateEvents := 0
	if s.app.RuntimeDetect != nil {
		for idx, event := range payload.Events {
			payloadHash, hashErr := runtimeSourceEventPayloadHash(&event)
			if hashErr != nil {
				s.warnRuntimeIngestPersistence("hash_source_event", hashErr, "source", "telemetry", "event_id", event.ID, "index", idx+1, "run_id", session.runID())
			}
			observation, err := runtime.ObservationFromEvent(&event)
			if err != nil {
				rejectedEvents++
				s.warnInvalidRuntimeObservation("telemetry", err, "event_id", event.ID, "index", idx+1, "resource_id", event.ResourceID, "resource_type", event.ResourceType)
				if session != nil {
					if rejectErr := session.recordRejectedObservation(r.Context(), &event, idx+1, err); rejectErr != nil {
						session.fail(r.Context(), "normalize", rejectErr)
						s.warnRuntimeIngestPersistence("record_rejected_observation", rejectErr, "source", "telemetry", "event_id", event.ID, "index", idx+1, "run_id", session.runID())
						session = nil
					}
				}
				continue
			}
			observation = enrichRuntimeObservation(observation, payload.Cluster, payload.Node, payload.AgentVersion)
			if dedupeStore != nil && event.ID != "" && payloadHash != "" {
				duplicate, dedupeErr := dedupeStore.ClaimSourceEventProcessing(r.Context(), runtimeSourceEventSource(&event, "telemetry"), event.ID, payloadHash, event.Timestamp)
				if dedupeErr != nil {
					rejectedEvents++
					s.warnRuntimeIngestPersistence("check_duplicate_source_event", dedupeErr, "source", "telemetry", "event_id", event.ID, "index", idx+1, "run_id", session.runID())
					if rejectErr := session.recordRejectedObservation(r.Context(), &event, idx+1, fmt.Errorf("dedupe check: %w", dedupeErr)); rejectErr != nil {
						session.fail(r.Context(), "dedupe", dedupeErr)
						s.warnRuntimeIngestPersistence("record_rejected_observation", rejectErr, "source", "telemetry", "event_id", event.ID, "index", idx+1, "run_id", session.runID())
						session = nil
					}
					continue
				} else if duplicate {
					duplicateEvents++
					if err := session.recordDuplicateObservation(r.Context(), &event, idx+1); err != nil {
						s.warnRuntimeIngestPersistence("record_duplicate_observation", err, "source", "telemetry", "event_id", event.ID, "index", idx+1, "run_id", session.runID())
					}
					continue
				}
			}
			findings := s.app.RuntimeDetect.ProcessNormalizedObservation(r.Context(), observation)
			totalFindings += len(findings)
			if session != nil {
				if err := session.recordObservation(r.Context(), observation, len(findings), idx+1); err != nil {
					session.fail(r.Context(), "detect", err)
					s.warnRuntimeIngestPersistence("record_observation", err, "source", "telemetry", "event_id", event.ID, "index", idx+1, "run_id", session.runID())
					session = nil
				}
			}

			if s.app.RuntimeRespond != nil {
				for _, f := range findings {
					_, _ = s.app.RuntimeRespond.ProcessFinding(r.Context(), &f)
				}
			}
			if dedupeStore != nil && event.ID != "" && payloadHash != "" {
				if err := dedupeStore.MarkSourceEventProcessed(r.Context(), runtimeSourceEventSource(&event, "telemetry"), event.ID, payloadHash, event.Timestamp); err != nil {
					rejectedEvents++
					s.warnRuntimeIngestPersistence("mark_source_event_processed", err, "source", "telemetry", "event_id", event.ID, "index", idx+1, "run_id", session.runID())
					if rejectErr := session.recordRejectedObservation(r.Context(), &event, idx+1, fmt.Errorf("mark processed: %w", err)); rejectErr != nil {
						session.fail(r.Context(), "dedupe", err)
						s.warnRuntimeIngestPersistence("record_rejected_observation", rejectErr, "source", "telemetry", "event_id", event.ID, "index", idx+1, "run_id", session.runID())
						session = nil
					}
					continue
				}
			}
			processedEvents++
		}
	}

	lastCursor := ""
	if count := len(payload.Events); count > 0 {
		lastCursor = payload.Events[count-1].ID
	}
	if session != nil {
		if err := session.complete(r.Context(), runtime.IngestCheckpoint{
			Cursor: lastCursor,
			Metadata: map[string]string{
				"processed_events": strconv.Itoa(processedEvents),
				"rejected_events":  strconv.Itoa(rejectedEvents),
				"duplicate_events": strconv.Itoa(duplicateEvents),
				"finding_count":    strconv.Itoa(totalFindings),
				"cluster":          payload.Cluster,
				"node":             payload.Node,
			},
		}); err != nil {
			session.fail(r.Context(), "complete", err)
			s.warnRuntimeIngestPersistence("complete", err, "source", "telemetry", "event_count", len(payload.Events), "run_id", session.runID())
			session = nil
		}
	}

	if s.app.Webhooks != nil {
		webhookPayload := map[string]interface{}{
			"source":           "telemetry",
			"events_processed": processedEvents,
			"events_rejected":  rejectedEvents,
			"events_duplicate": duplicateEvents,
			"findings":         totalFindings,
			"node":             payload.Node,
			"cluster":          payload.Cluster,
		}
		if session != nil && session.run != nil {
			webhookPayload["run_id"] = session.run.ID
		}
		if err := s.app.Webhooks.EmitWithErrors(r.Context(), webhooks.EventRuntimeIngested, webhookPayload); err != nil {
			s.app.Logger.Warn("failed to emit telemetry ingest event", "error", err)
		}
	}

	response := map[string]interface{}{
		"processed":  processedEvents,
		"rejected":   rejectedEvents,
		"duplicates": duplicateEvents,
		"findings":   totalFindings,
	}
	if session != nil && session.run != nil {
		response["run_id"] = session.run.ID
	}
	s.json(w, http.StatusOK, response)
}

func (s *Server) warnRuntimeIngestPersistence(stage string, err error, args ...any) {
	if s == nil || s.app == nil || s.app.Logger == nil || err == nil {
		return
	}
	fields := []any{"stage", strings.TrimSpace(stage), "error", err}
	fields = append(fields, args...)
	s.app.Logger.Warn("runtime ingest persistence degraded; continuing detection and response", fields...)
}

func (s *Server) warnInvalidRuntimeObservation(source string, err error, args ...any) {
	if s == nil || s.app == nil || s.app.Logger == nil || err == nil {
		return
	}
	fields := []any{"source", strings.TrimSpace(source), "error", err}
	fields = append(fields, args...)
	s.app.Logger.Warn("runtime observation rejected during normalization", fields...)
}

func runtimeSourceEventPayloadHash(event *runtime.RuntimeEvent) (string, error) {
	if event == nil {
		return "", nil
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func runtimeSourceEventSource(event *runtime.RuntimeEvent, fallback string) string {
	if event == nil {
		return fallback
	}
	if source := strings.TrimSpace(event.Source); source != "" {
		return source
	}
	return strings.TrimSpace(fallback)
}
