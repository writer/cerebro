package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/webhooks"
)

type platformReportStreamMessage struct {
	Type      string                       `json:"type"`
	RunID     string                       `json:"run_id"`
	ReportID  string                       `json:"report_id"`
	Status    string                       `json:"status,omitempty"`
	EventType string                       `json:"event_type,omitempty"`
	Timestamp time.Time                    `json:"timestamp"`
	Progress  int                          `json:"progress,omitempty"`
	Data      map[string]any               `json:"data,omitempty"`
	Section   *graph.ReportSectionEmission `json:"section,omitempty"`
}

var platformReportStreamEmitHook func()

func (s *Server) registerPlatformReportStream(runID string) (<-chan platformReportStreamMessage, func()) {
	s.platformReportStreamMu.Lock()
	defer s.platformReportStreamMu.Unlock()
	if s.platformReportStreams == nil {
		s.platformReportStreams = make(map[string]map[chan platformReportStreamMessage]struct{})
	}
	subscribers, ok := s.platformReportStreams[runID]
	if !ok {
		subscribers = make(map[chan platformReportStreamMessage]struct{})
		s.platformReportStreams[runID] = subscribers
	}
	ch := make(chan platformReportStreamMessage, 32)
	subscribers[ch] = struct{}{}
	cleanup := func() {
		s.platformReportStreamMu.Lock()
		defer s.platformReportStreamMu.Unlock()
		subscribers, ok := s.platformReportStreams[runID]
		if !ok {
			return
		}
		delete(subscribers, ch)
		close(ch)
		if len(subscribers) == 0 {
			delete(s.platformReportStreams, runID)
		}
	}
	return ch, cleanup
}

func (s *Server) emitPlatformReportStreamMessage(runID string, message platformReportStreamMessage) {
	s.platformReportStreamMu.RLock()
	defer s.platformReportStreamMu.RUnlock()
	subscribers, ok := s.platformReportStreams[runID]
	if !ok {
		return
	}
	// Hold the read lock across non-blocking sends so cleanup cannot close a
	// subscriber channel between selection and delivery.
	if platformReportStreamEmitHook != nil {
		platformReportStreamEmitHook()
	}
	for ch := range subscribers {
		select {
		case ch <- message:
		default:
		}
	}
}

func (s *Server) streamPlatformIntelligenceReportRun(w http.ResponseWriter, r *http.Request) {
	reportID := strings.TrimSpace(chi.URLParam(r, "id"))
	runID := platformReportRunIDParam(r)
	if reportID == "" || runID == "" {
		s.error(w, http.StatusBadRequest, "report id and run id are required")
		return
	}
	run, ok := s.platformReportRunSnapshot(reportID, runID)
	if !ok || run == nil {
		s.error(w, http.StatusNotFound, "report run not found")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.error(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	notifyCh, cancel := s.registerPlatformReportStream(runID)
	defer cancel()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	ready := platformReportStreamMessage{
		Type:      "ready",
		RunID:     run.ID,
		ReportID:  run.ReportID,
		Status:    run.Status,
		Timestamp: time.Now().UTC(),
		Data: map[string]any{
			"status_url":  run.StatusURL,
			"snapshot_id": reportSnapshotID(run),
		},
	}
	s.writePlatformReportStreamEvent(w, "ready", ready)
	flusher.Flush()

	keepAlive := time.NewTicker(15 * time.Second)
	defer keepAlive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case message := <-notifyCh:
			eventName := "message"
			switch message.Type {
			case "lifecycle":
				eventName = "lifecycle"
			case "section":
				eventName = "section"
			}
			s.writePlatformReportStreamEvent(w, eventName, message)
			flusher.Flush()
		case <-keepAlive.C:
			_, _ = fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) writePlatformReportStreamEvent(w http.ResponseWriter, event string, payload platformReportStreamMessage) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, encoded)
}

func (s *Server) emitPlatformReportRunLifecycleStream(run *graph.ReportRun, eventType webhooks.EventType) {
	if run == nil {
		return
	}
	progress, _ := reportRunProgress(run.Status)
	s.emitPlatformReportStreamMessage(run.ID, platformReportStreamMessage{
		Type:      "lifecycle",
		RunID:     run.ID,
		ReportID:  run.ReportID,
		Status:    run.Status,
		EventType: string(eventType),
		Timestamp: time.Now().UTC(),
		Progress:  progress,
		Data:      platformReportRunEventPayload(run),
	})
}

func (s *Server) emitPlatformReportSectionStream(run *graph.ReportRun, section graph.ReportSectionEmission) {
	if run == nil {
		return
	}
	emission := graph.CloneReportSectionEmissions([]graph.ReportSectionEmission{section})[0]
	data := map[string]any{
		"status_url":    run.StatusURL,
		"snapshot_id":   reportSnapshotID(run),
		"section_key":   emission.Section.Key,
		"envelope_kind": emission.Section.EnvelopeKind,
		"content_type":  emission.Section.ContentType,
		"item_count":    emission.Section.ItemCount,
		"field_count":   emission.Section.FieldCount,
	}
	for key, value := range platformReportSectionMetadataPayload(emission.Section) {
		data[key] = value
	}
	s.emitPlatformReportStreamMessage(run.ID, platformReportStreamMessage{
		Type:      "section",
		RunID:     run.ID,
		ReportID:  run.ReportID,
		Status:    run.Status,
		EventType: string(webhooks.EventPlatformReportSectionEmitted),
		Timestamp: emission.EmittedAt,
		Progress:  emission.ProgressPercent,
		Data:      data,
		Section:   &emission,
	})
}
