package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/runtime"
	"github.com/writer/cerebro/internal/runtime/adapters"
	"github.com/writer/cerebro/internal/runtime/adapters/awsvpcflow"
	"github.com/writer/cerebro/internal/runtime/adapters/secheck"
	"github.com/writer/cerebro/internal/webhooks"
)

func telemetryAdapter(source string) (adapters.Adapter, bool) {
	switch strings.TrimSpace(source) {
	case awsvpcflow.SourceName:
		return awsvpcflow.Adapter{}, true
	case secheck.SourceName:
		return secheck.Adapter{}, true
	default:
		return nil, false
	}
}

func decodeRawTelemetryPayload(payload json.RawMessage) ([]byte, error) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, fmt.Errorf("payload is required")
	}
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var text string
		if err := json.Unmarshal(trimmed, &text); err != nil {
			return nil, fmt.Errorf("decode string payload: %w", err)
		}
		return []byte(text), nil
	}
	return trimmed, nil
}

func runtimeObservationPayloadHash(observation *runtime.RuntimeObservation) (string, error) {
	if observation == nil {
		return "", nil
	}
	payload, err := json.Marshal(observation)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func (s *Server) ingestTelemetryAdapterPayload(w http.ResponseWriter, r *http.Request, adapterSource string, payload json.RawMessage, cluster, node, agentVersion string) {
	adapter, ok := telemetryAdapter(adapterSource)
	if !ok {
		s.error(w, http.StatusBadRequest, "unsupported adapter_source")
		return
	}
	rawPayload, err := decodeRawTelemetryPayload(payload)
	if err != nil {
		s.error(w, http.StatusBadRequest, "invalid payload")
		return
	}

	session, err := s.startRuntimeIngestSession(r.Context(), adapter.Source(), map[string]string{
		"adapter_source": adapterSource,
		"cluster":        cluster,
		"node":           node,
		"agent_version":  agentVersion,
	})
	if err != nil {
		s.warnRuntimeIngestPersistence("start", err, "source", adapter.Source(), "cluster", cluster, "node", node)
		session = nil
	}

	observations, err := adapter.Normalize(r.Context(), rawPayload)
	if err != nil {
		if session != nil {
			session.fail(r.Context(), "normalize", err)
		}
		s.error(w, http.StatusBadRequest, "invalid payload")
		return
	}

	dedupeStore := s.runtimeIngestStore()
	totalFindings := 0
	processedEvents := 0
	rejectedEvents := 0
	duplicateEvents := 0

	for idx, observation := range observations {
		observation = enrichRuntimeObservation(observation, cluster, node, agentVersion)
		payloadHash, hashErr := runtimeObservationPayloadHash(observation)
		if hashErr != nil {
			s.warnRuntimeIngestPersistence("hash_source_event", hashErr, "source", adapter.Source(), "observation_id", observation.ID, "index", idx+1, "run_id", session.runID())
		}
		if dedupeStore != nil && observation != nil && observation.ID != "" && payloadHash != "" {
			duplicate, dedupeErr := dedupeStore.ClaimSourceEventProcessing(r.Context(), observation.Source, observation.ID, payloadHash, observation.ObservedAt)
			if dedupeErr != nil {
				if session != nil {
					session.fail(r.Context(), "dedupe", dedupeErr)
				}
				s.warnRuntimeIngestPersistence("check_duplicate_source_event", dedupeErr, "source", adapter.Source(), "observation_id", observation.ID, "index", idx+1, "run_id", session.runID())
				s.error(w, http.StatusServiceUnavailable, "runtime ingest dedupe unavailable")
				return
			} else if duplicate {
				duplicateEvents++
				if session != nil {
					if err := session.recordDuplicateObservation(r.Context(), nil, idx+1); err != nil {
						s.warnRuntimeIngestPersistence("record_duplicate_observation", err, "source", adapter.Source(), "observation_id", observation.ID, "index", idx+1, "run_id", session.runID())
					}
				}
				continue
			}
		}

		findings := []runtime.RuntimeFinding(nil)
		if s.app.RuntimeDetect != nil {
			findings = s.app.RuntimeDetect.ProcessNormalizedObservation(r.Context(), observation)
		}
		totalFindings += len(findings)
		processedEvents++
		if session != nil {
			if err := session.recordObservation(r.Context(), observation, len(findings), idx+1); err != nil {
				session.fail(r.Context(), "detect", err)
				s.warnRuntimeIngestPersistence("record_observation", err, "source", adapter.Source(), "observation_id", observation.ID, "index", idx+1, "run_id", session.runID())
				session = nil
			}
		}
		if s.app.RuntimeRespond != nil {
			for _, finding := range findings {
				_, _ = s.app.RuntimeRespond.ProcessFinding(r.Context(), &finding)
			}
		}
		if dedupeStore != nil && observation != nil && observation.ID != "" && payloadHash != "" {
			if err := dedupeStore.MarkSourceEventProcessed(r.Context(), observation.Source, observation.ID, payloadHash, observation.ObservedAt); err != nil {
				if session != nil {
					session.fail(r.Context(), "dedupe", err)
				}
				s.warnRuntimeIngestPersistence("mark_source_event_processed", err, "source", adapter.Source(), "observation_id", observation.ID, "index", idx+1, "run_id", session.runID())
				s.error(w, http.StatusServiceUnavailable, "runtime ingest dedupe unavailable")
				return
			}
		}
	}

	lastCursor := ""
	if count := len(observations); count > 0 {
		lastCursor = observations[count-1].ID
	}
	if session != nil {
		if err := session.complete(r.Context(), runtime.IngestCheckpoint{
			Cursor: lastCursor,
			Metadata: map[string]string{
				"processed_events": strconv.Itoa(processedEvents),
				"rejected_events":  strconv.Itoa(rejectedEvents),
				"duplicate_events": strconv.Itoa(duplicateEvents),
				"finding_count":    strconv.Itoa(totalFindings),
				"cluster":          cluster,
				"node":             node,
				"adapter_source":   adapterSource,
			},
		}); err != nil {
			session.fail(r.Context(), "complete", err)
			s.warnRuntimeIngestPersistence("complete", err, "source", adapter.Source(), "observation_count", len(observations), "run_id", session.runID())
			session = nil
		}
	}

	if s.app.Webhooks != nil {
		webhookPayload := map[string]any{
			"source":           adapter.Source(),
			"events_processed": processedEvents,
			"events_rejected":  rejectedEvents,
			"events_duplicate": duplicateEvents,
			"findings":         totalFindings,
			"node":             node,
			"cluster":          cluster,
			"adapter_source":   adapterSource,
		}
		if session != nil && session.run != nil {
			webhookPayload["run_id"] = session.run.ID
		}
		if err := s.app.Webhooks.EmitWithErrors(r.Context(), webhooks.EventRuntimeIngested, webhookPayload); err != nil {
			s.app.Logger.Warn("failed to emit telemetry ingest event", "error", err)
		}
	}

	response := map[string]any{
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
