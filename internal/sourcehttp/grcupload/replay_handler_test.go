package grcuploadhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestReplayHandlerAuthorizesTenant(t *testing.T) {
	replayer := &recordingReplayer{}
	projector := &recordingProjector{}
	handler := NewReplayHandler(ReplayOptions{
		Replayer:  replayer,
		Projector: projector,
		ResolveTenant: func(*http.Request) (string, error) {
			return "tenant-1", nil
		},
		AuthorizeTenant: func(context.Context, string) error {
			return errors.New("tenant denied")
		},
	})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/grc/policy-lifecycle/uploads/upload-1/replay", nil)
	request.SetPathValue("uploadID", "upload-1")

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusInternalServerError)
	}
	if len(replayer.requests) != 0 {
		t.Fatalf("replay requests = %d, want 0 after authorization failure", len(replayer.requests))
	}
	if len(projector.events) != 0 {
		t.Fatalf("projected events = %d, want 0 after authorization failure", len(projector.events))
	}
}

func TestReplayHandlerStopsProjectionOnCancellation(t *testing.T) {
	replayer := &recordingReplayer{events: []*cerebrov1.EventEnvelope{
		{Id: "event-1", Kind: "grc.policy"},
		{Id: "event-2", Kind: "grc.document"},
	}}
	projector := &failingReplayProjector{err: context.Canceled}
	handler := NewReplayHandler(ReplayOptions{
		Replayer:  replayer,
		Projector: projector,
		ResolveTenant: func(*http.Request) (string, error) {
			return "tenant-1", nil
		},
		AuthorizeTenant: func(context.Context, string) error {
			return nil
		},
	})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/grc/policy-lifecycle/uploads/upload-1/replay", nil)
	request.SetPathValue("uploadID", "upload-1")

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	var payload ReplayResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode replay response: %v", err)
	}
	if payload.Status != "projection_partial" || payload.ProjectionFailures != 1 {
		t.Fatalf("replay response = %+v, want one projection failure", payload)
	}
	if len(projector.events) != 1 {
		t.Fatalf("projected events = %d, want 1 before cancellation break", len(projector.events))
	}
}

func TestReplayLimitRejectsTooLargeValue(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/replay?limit=501", nil)
	if _, err := replayLimit(request); err == nil {
		t.Fatal("replayLimit() error = nil, want error for limit over max")
	}
	request = httptest.NewRequest(http.MethodPost, "/replay?limit=500", nil)
	limit, err := replayLimit(request)
	if err != nil {
		t.Fatalf("replayLimit() error = %v, want nil", err)
	}
	if limit != 500 {
		t.Fatalf("replayLimit() = %d, want 500", limit)
	}
}

type recordingReplayer struct {
	events   []*cerebrov1.EventEnvelope
	requests []ports.ReplayRequest
	err      error
}

func (r *recordingReplayer) Replay(_ context.Context, request ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	r.requests = append(r.requests, request)
	if r.err != nil {
		return nil, r.err
	}
	return r.events, nil
}

type failingReplayProjector struct {
	events []*cerebrov1.EventEnvelope
	err    error
}

func (p *failingReplayProjector) Project(_ context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	p.events = append(p.events, event)
	return ports.ProjectionResult{}, p.err
}
