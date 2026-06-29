package grcuploadhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/grcupload"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/telemetry"
)

const (
	defaultReplayLimit uint32 = 100
	maxReplayLimit     uint32 = 500
)

type ReplayOptions struct {
	Replayer        ports.EventReplayer
	Projector       ports.SourceProjector
	ResolveTenant   func(*http.Request) (string, error)
	AuthorizeTenant func(context.Context, string) error
	BumpCache       func(context.Context, string)
	WriteError      func(http.ResponseWriter, error)
	WriteJSON       func(http.ResponseWriter, int, any)
}

type ReplayHandler struct {
	options ReplayOptions
}

type ReplayResponse struct {
	UploadID           string `json:"upload_id"`
	Status             string `json:"status"`
	EventsFound        int    `json:"events_found"`
	EventsProjected    int    `json:"events_projected"`
	EntitiesProjected  uint32 `json:"entities_projected"`
	LinksProjected     uint32 `json:"links_projected"`
	ProjectionFailures int    `json:"projection_failures"`
}

func NewReplayHandler(options ReplayOptions) ReplayHandler {
	return ReplayHandler{options: options}
}

func (h ReplayHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	uploadID := strings.TrimSpace(r.PathValue("uploadID"))
	if uploadID == "" {
		h.writeError(w, fmt.Errorf("%w: upload_id is required", grcupload.ErrInvalidRequest))
		return
	}
	tenantID, err := h.tenantID(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if tenantID == "" {
		h.writeError(w, fmt.Errorf("%w: tenant_id is required", grcupload.ErrInvalidRequest))
		return
	}
	if h.options.AuthorizeTenant != nil {
		if err := h.options.AuthorizeTenant(r.Context(), tenantID); err != nil {
			h.writeError(w, err)
			return
		}
	}
	if h.options.Replayer == nil || h.options.Projector == nil {
		h.writeError(w, grcupload.ErrRuntimeUnavailable)
		return
	}
	limit, err := replayLimit(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	events, err := h.options.Replayer.Replay(r.Context(), ports.ReplayRequest{
		TenantID: tenantID,
		AttributeEquals: map[string]string{
			"upload_id": uploadID,
		},
		Limit: limit,
	})
	if err != nil {
		h.writeError(w, fmt.Errorf("%w: replay upload events: %w", grcupload.ErrRuntimeUnavailable, err))
		return
	}
	if len(events) == 0 {
		h.writeJSON(w, http.StatusNotFound, map[string]string{"error": "upload not found"})
		return
	}
	response := ReplayResponse{
		UploadID:    uploadID,
		Status:      "projected",
		EventsFound: len(events),
	}
	for _, event := range events {
		result, err := h.options.Projector.Project(r.Context(), event)
		if err != nil {
			response.ProjectionFailures++
			response.Status = "projection_partial"
			telemetry.CaptureError(r.Context(), "cerebro.grc.upload.replay.error", err, telemetry.Attrs(
				telemetry.Field{Key: "upload_id", Value: uploadID},
				telemetry.Field{Key: "tenant_id", Value: tenantID},
				telemetry.Field{Key: "event_kind", Value: event.GetKind()},
				telemetry.Field{Key: "error_kind", Value: telemetry.ErrorKind(err)},
			))
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				break
			}
			continue
		}
		response.EventsProjected++
		response.EntitiesProjected += result.EntitiesProjected
		response.LinksProjected += result.LinksProjected
	}
	if response.EventsProjected > 0 && h.options.BumpCache != nil {
		h.options.BumpCache(r.Context(), tenantID)
	}
	telemetry.Event(r.Context(), "cerebro.grc.upload.replay", telemetry.Attrs(
		telemetry.Field{Key: "upload_id", Value: uploadID},
		telemetry.Field{Key: "tenant_id", Value: tenantID},
		telemetry.Field{Key: "status", Value: response.Status},
		telemetry.Field{Key: "events_found", Value: response.EventsFound},
		telemetry.Field{Key: "events_projected", Value: response.EventsProjected},
		telemetry.Field{Key: "projection_failures", Value: response.ProjectionFailures},
	))
	h.writeJSON(w, http.StatusOK, response)
}

func (h ReplayHandler) tenantID(r *http.Request) (string, error) {
	if h.options.ResolveTenant == nil {
		return strings.TrimSpace(r.URL.Query().Get("tenant_id")), nil
	}
	return h.options.ResolveTenant(r)
}

func (h ReplayHandler) writeError(w http.ResponseWriter, err error) {
	if h.options.WriteError != nil {
		h.options.WriteError(w, err)
		return
	}
	statusCode := http.StatusInternalServerError
	switch {
	case errors.Is(err, grcupload.ErrInvalidRequest):
		statusCode = http.StatusBadRequest
	case errors.Is(err, grcupload.ErrRuntimeUnavailable):
		statusCode = http.StatusServiceUnavailable
	}
	http.Error(w, http.StatusText(statusCode), statusCode)
}

func (h ReplayHandler) writeJSON(w http.ResponseWriter, statusCode int, value any) {
	if h.options.WriteJSON != nil {
		h.options.WriteJSON(w, statusCode, value)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(value)
}

func replayLimit(r *http.Request) (uint32, error) {
	value := strings.TrimSpace(r.URL.Query().Get("limit"))
	if value == "" {
		return defaultReplayLimit, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: limit must be a positive integer", grcupload.ErrInvalidRequest)
	}
	if parsed == 0 {
		return defaultReplayLimit, nil
	}
	if parsed > uint64(maxReplayLimit) {
		return 0, fmt.Errorf("%w: limit must be less than or equal to %d", grcupload.ErrInvalidRequest, maxReplayLimit)
	}
	return uint32(parsed), nil
}
