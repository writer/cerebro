package deadletteradmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

const (
	maxBodyBytes   = 4 << 10
	maxReasonBytes = 1024
)

// Handler exposes the authenticated, single-record pending purge boundary.
type Handler struct {
	store           ports.AppendLogDeadLetterForcePurgeStore
	hasAuth         func(context.Context) bool
	authorizeAdmin  func(context.Context) error
	authorizeTenant func(context.Context, string) error
	actor           func(context.Context) string
}

// NewHandler wires the store to the bootstrap service's existing auth context.
func NewHandler(store ports.StateStore, hasAuth func(context.Context) bool, authorizeAdmin func(context.Context) error, authorizeTenant func(context.Context, string) error, actor func(context.Context) string) *Handler {
	forcePurgeStore, _ := store.(ports.AppendLogDeadLetterForcePurgeStore)
	return &Handler{store: forcePurgeStore, hasAuth: hasAuth, authorizeAdmin: authorizeAdmin, authorizeTenant: authorizeTenant, actor: actor}
}

type forcePurgeRequest struct {
	TenantID string `json:"tenant_id"`
	Reason   string `json:"reason"`
}

type forcePurgeResponse struct {
	DeadLetterID string `json:"dead_letter_id"`
	Outcome      string `json:"outcome"`
}

// ForcePurge deletes one explicitly identified pending record and never reads
// or returns its event envelope.
func (h *Handler) ForcePurge(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.hasAuth == nil || !h.hasAuth(r.Context()) {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if h.authorizeAdmin == nil || h.authorizeAdmin(r.Context()) != nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	actor := ""
	if h.actor != nil {
		actor = strings.TrimSpace(h.actor(r.Context()))
	}
	if actor == "" || actor == "anonymous" {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if h.store == nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	request, err := decodeRequest(w, r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(r.PathValue("deadLetterID"))
	if id == "" || len(id) > 255 || request.TenantID == "" || len(request.TenantID) > 255 || request.Reason == "" || len(request.Reason) > maxReasonBytes {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if h.authorizeTenant == nil || h.authorizeTenant(r.Context(), request.TenantID) != nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	if err := h.store.ForcePurgeAppendLogDeadLetter(r.Context(), ports.AppendLogDeadLetterForcePurgeRequest{
		ID: id, TenantID: request.TenantID, Actor: actor, Reason: request.Reason,
	}); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, forcePurgeResponse{DeadLetterID: id, Outcome: "purged"})
}

func decodeRequest(w http.ResponseWriter, r *http.Request) (forcePurgeRequest, error) {
	var request forcePurgeRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return forcePurgeRequest{}, fmt.Errorf("decode forced purge request: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return forcePurgeRequest{}, errors.New("request body must contain one JSON object")
	}
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.Reason = strings.TrimSpace(request.Reason)
	return request, nil
}

func writeStoreError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, ports.ErrAppendLogDeadLetterNotFound):
		status = http.StatusNotFound
	case errors.Is(err, ports.ErrAppendLogDeadLetterNotPending), errors.Is(err, ports.ErrAppendLogDeadLetterReplayClaimed):
		status = http.StatusConflict
	}
	http.Error(w, http.StatusText(status), status)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}
