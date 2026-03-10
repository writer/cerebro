package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/evalops/cerebro/internal/graph"
)

type agentSDKMCPSession struct {
	subscribers map[chan agentSDKMCPResponse]struct{}
}

type agentSDKReportProgressSubscription struct {
	SessionID     string
	ProgressToken string
}

var agentSDKMCPSessionEmitHook func()

func (s *Server) registerAgentSDKMCPSession(sessionID string) (<-chan agentSDKMCPResponse, func()) {
	s.agentSDKMCPSessionMu.Lock()
	defer s.agentSDKMCPSessionMu.Unlock()
	if s.agentSDKMCPSessions == nil {
		s.agentSDKMCPSessions = make(map[string]*agentSDKMCPSession)
	}
	session, ok := s.agentSDKMCPSessions[sessionID]
	if !ok {
		session = &agentSDKMCPSession{subscribers: make(map[chan agentSDKMCPResponse]struct{})}
		s.agentSDKMCPSessions[sessionID] = session
	}
	ch := make(chan agentSDKMCPResponse, 16)
	session.subscribers[ch] = struct{}{}
	cleanup := func() {
		s.agentSDKMCPSessionMu.Lock()
		defer s.agentSDKMCPSessionMu.Unlock()
		session, ok := s.agentSDKMCPSessions[sessionID]
		if !ok {
			return
		}
		delete(session.subscribers, ch)
		close(ch)
		if len(session.subscribers) == 0 {
			delete(s.agentSDKMCPSessions, sessionID)
		}
	}
	return ch, cleanup
}

func (s *Server) emitAgentSDKMCPNotification(sessionID string, message agentSDKMCPResponse) {
	s.agentSDKMCPSessionMu.RLock()
	defer s.agentSDKMCPSessionMu.RUnlock()
	session, ok := s.agentSDKMCPSessions[sessionID]
	if !ok {
		return
	}
	// Hold the read lock across non-blocking sends so cleanup cannot close a
	// subscriber channel during notification fanout.
	if agentSDKMCPSessionEmitHook != nil {
		agentSDKMCPSessionEmitHook()
	}
	for subscriber := range session.subscribers {
		select {
		case subscriber <- message:
		default:
		}
	}
}

func (s *Server) bindAgentSDKReportProgress(runID string, ctx context.Context) {
	sessionID := agentSDKMCPSessionID(ctx)
	progressToken := agentSDKProgressToken(ctx)
	if strings.TrimSpace(runID) == "" || strings.TrimSpace(sessionID) == "" || strings.TrimSpace(progressToken) == "" {
		return
	}
	s.agentSDKReportProgressMu.Lock()
	defer s.agentSDKReportProgressMu.Unlock()
	if s.agentSDKReportProgress == nil {
		s.agentSDKReportProgress = make(map[string]agentSDKReportProgressSubscription)
	}
	s.agentSDKReportProgress[runID] = agentSDKReportProgressSubscription{
		SessionID:     strings.TrimSpace(sessionID),
		ProgressToken: strings.TrimSpace(progressToken),
	}
}

func (s *Server) emitAgentSDKReportProgress(run *graph.ReportRun) {
	if run == nil {
		return
	}
	s.agentSDKReportProgressMu.RLock()
	subscription, ok := s.agentSDKReportProgress[run.ID]
	s.agentSDKReportProgressMu.RUnlock()
	if !ok {
		return
	}
	progress, message := reportRunProgress(run.Status)
	params := map[string]any{
		"progressToken": subscription.ProgressToken,
		"progress":      progress,
		"total":         100,
		"message":       message,
		"data": map[string]any{
			"run_id":            run.ID,
			"report_id":         run.ReportID,
			"status":            run.Status,
			"status_url":        run.StatusURL,
			"attempt_count":     run.AttemptCount,
			"event_count":       run.EventCount,
			"latest_attempt_id": run.LatestAttemptID,
			"snapshot_id":       reportSnapshotID(run),
		},
	}
	s.emitAgentSDKMCPNotification(subscription.SessionID, agentSDKMCPResponse{
		JSONRPC: "2.0",
		Method:  "notifications/progress",
		Params:  params,
	})
	if run.Status == graph.ReportRunStatusSucceeded || run.Status == graph.ReportRunStatusFailed || run.Status == graph.ReportRunStatusCanceled {
		s.agentSDKReportProgressMu.Lock()
		delete(s.agentSDKReportProgress, run.ID)
		s.agentSDKReportProgressMu.Unlock()
	}
}

func (s *Server) emitAgentSDKReportSection(run *graph.ReportRun, section graph.ReportSectionEmission) {
	if run == nil {
		return
	}
	s.agentSDKReportProgressMu.RLock()
	subscription, ok := s.agentSDKReportProgress[run.ID]
	s.agentSDKReportProgressMu.RUnlock()
	if !ok {
		return
	}
	emission := graph.CloneReportSectionEmissions([]graph.ReportSectionEmission{section})[0]
	s.emitAgentSDKMCPNotification(subscription.SessionID, agentSDKMCPResponse{
		JSONRPC: "2.0",
		Method:  "notifications/report_section",
		Params: map[string]any{
			"progressToken": subscription.ProgressToken,
			"progress":      emission.ProgressPercent,
			"run_id":        run.ID,
			"report_id":     run.ReportID,
			"status_url":    run.StatusURL,
			"section":       emission,
		},
	})
	progressData := map[string]any{
		"run_id":           run.ID,
		"report_id":        run.ReportID,
		"status_url":       run.StatusURL,
		"section_key":      emission.Section.Key,
		"envelope_kind":    emission.Section.EnvelopeKind,
		"progress_percent": emission.ProgressPercent,
	}
	for key, value := range platformReportSectionMetadataPayload(emission.Section) {
		progressData[key] = value
	}
	s.emitAgentSDKMCPNotification(subscription.SessionID, agentSDKMCPResponse{
		JSONRPC: "2.0",
		Method:  "notifications/progress",
		Params: map[string]any{
			"progressToken": subscription.ProgressToken,
			"progress":      emission.ProgressPercent,
			"total":         100,
			"message":       "section:" + emission.Section.Key,
			"data":          progressData,
		},
	})
}

func reportRunProgress(status string) (int, string) {
	switch strings.TrimSpace(status) {
	case graph.ReportRunStatusQueued:
		return 5, "queued"
	case graph.ReportRunStatusRunning:
		return 50, "running"
	case graph.ReportRunStatusSucceeded:
		return 100, "completed"
	case graph.ReportRunStatusCanceled:
		return 100, "canceled"
	case graph.ReportRunStatusFailed:
		return 100, "failed"
	default:
		return 0, "pending"
	}
}

func reportSnapshotID(run *graph.ReportRun) string {
	if run == nil || run.Snapshot == nil {
		return ""
	}
	return strings.TrimSpace(run.Snapshot.ID)
}

func (s *Server) enrichAgentSDKWriteRequest(r *http.Request, toolID string) *http.Request {
	body, err := readJSONBodyRaw(r)
	if err != nil {
		return r
	}
	payload := map[string]any{}
	if err := decodeOptionalJSON(body, &payload); err != nil {
		return r
	}
	if payload == nil {
		payload = make(map[string]any)
	}
	metadata := map[string]any{}
	if existing, ok := payload["metadata"].(map[string]any); ok && existing != nil {
		for key, value := range existing {
			metadata[key] = value
		}
	}
	writeMetadata := agentSDKAttributionMetadata(r.Context(), toolID)
	keys := make([]string, 0, len(writeMetadata))
	for key := range writeMetadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		metadata[key] = writeMetadata[key]
	}
	payload["metadata"] = metadata
	if strings.TrimSpace(stringValue(payload["source_system"])) == "" {
		payload["source_system"] = "agent_sdk"
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return r
	}
	clone := r.Clone(r.Context())
	clone.Body = io.NopCloser(bytes.NewReader(encoded))
	clone.ContentLength = int64(len(encoded))
	clone.Header = r.Header.Clone()
	clone.Header.Set("Content-Type", "application/json")
	return clone
}

func agentSDKAttributionMetadata(ctx context.Context, toolID string) map[string]any {
	metadata := make(map[string]any)
	if value := strings.TrimSpace(GetAPIClientID(ctx)); value != "" {
		metadata["sdk_client_id"] = value
	}
	if value := strings.TrimSpace(GetAPICredentialID(ctx)); value != "" {
		metadata["api_credential_id"] = value
	}
	if value := strings.TrimSpace(GetAPICredentialKind(ctx)); value != "" {
		metadata["api_credential_kind"] = value
	}
	if value := strings.TrimSpace(GetAPICredentialName(ctx)); value != "" {
		metadata["api_credential_name"] = value
	}
	if value := strings.TrimSpace(GetTraceparent(ctx)); value != "" {
		metadata["traceparent"] = value
	}
	if value := strings.TrimSpace(toolID); value != "" {
		metadata["agent_sdk_tool_id"] = value
	}
	if value := strings.TrimSpace(agentSDKInvocationSurface(ctx)); value != "" {
		metadata["agent_sdk_surface"] = value
	}
	return metadata
}
