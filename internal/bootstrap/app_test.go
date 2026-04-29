package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/gen/cerebro/v1/cerebrov1connect"
	"github.com/writer/cerebro/internal/buildinfo"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/sourceregistry"
)

type stubAppendLog struct {
	err error
}

func (s stubAppendLog) Ping(context.Context) error                             { return s.err }
func (s stubAppendLog) Append(context.Context, *cerebrov1.EventEnvelope) error { return s.err }

type stubStore struct {
	err error
}

func (s stubStore) Ping(context.Context) error { return s.err }

func TestBootstrapEndpoints(t *testing.T) {
	registry, err := sourceregistry.Builtin()
	if err != nil {
		t.Fatalf("Builtin() error = %v", err)
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()
	authedGet := func(path string) (*http.Response, error) {
		req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer test")
		return server.Client().Do(req)
	}

	resp, err := server.Client().Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close /health response body: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /health status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode /health response: %v", err)
	}
	if payload["status"] != "ready" {
		t.Fatalf("health status = %#v, want %q", payload["status"], "ready")
	}
	sourcesResp, err := server.Client().Get(server.URL + "/sources")
	if err != nil {
		t.Fatalf("GET /sources error = %v", err)
	}
	defer func() {
		if closeErr := sourcesResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources response body: %v", closeErr)
		}
	}()
	var sourcesPayload map[string]any
	if err := json.NewDecoder(sourcesResp.Body).Decode(&sourcesPayload); err != nil {
		t.Fatalf("decode /sources response: %v", err)
	}
	entries, ok := sourcesPayload["sources"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("/sources entries = %#v, want single entry", sourcesPayload["sources"])
	}
	checkResp, err := authedGet("/sources/github/check")
	if err != nil {
		t.Fatalf("GET /sources/github/check error = %v", err)
	}
	defer func() {
		if closeErr := checkResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources/github/check response body: %v", closeErr)
		}
	}()
	var checkPayload map[string]any
	if err := json.NewDecoder(checkResp.Body).Decode(&checkPayload); err != nil {
		t.Fatalf("decode /sources/github/check response: %v", err)
	}
	if checkPayload["status"] != "ok" {
		t.Fatalf("check status = %#v, want %q", checkPayload["status"], "ok")
	}
	discoverResp, err := authedGet("/sources/github/discover")
	if err != nil {
		t.Fatalf("GET /sources/github/discover error = %v", err)
	}
	defer func() {
		if closeErr := discoverResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources/github/discover response body: %v", closeErr)
		}
	}()
	var discoverPayload map[string]any
	if err := json.NewDecoder(discoverResp.Body).Decode(&discoverPayload); err != nil {
		t.Fatalf("decode /sources/github/discover response: %v", err)
	}
	if urns, ok := discoverPayload["urns"].([]any); !ok || len(urns) != 2 {
		t.Fatalf("discover urns = %#v, want 2 entries", discoverPayload["urns"])
	}
	readResp, err := authedGet("/sources/github/read")
	if err != nil {
		t.Fatalf("GET /sources/github/read error = %v", err)
	}
	defer func() {
		if closeErr := readResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources/github/read response body: %v", closeErr)
		}
	}()
	var readPayload map[string]any
	if err := json.NewDecoder(readResp.Body).Decode(&readPayload); err != nil {
		t.Fatalf("decode /sources/github/read response: %v", err)
	}
	if events, ok := readPayload["events"].([]any); !ok || len(events) != 1 {
		t.Fatalf("read events = %#v, want 1 entry", readPayload["events"])
	}
	repeatedCursorResp, err := authedGet("/sources/github/read?cursor=0&cursor=1")
	if err != nil {
		t.Fatalf("GET /sources/github/read repeated cursor error = %v", err)
	}
	defer func() {
		if closeErr := repeatedCursorResp.Body.Close(); closeErr != nil {
			t.Fatalf("close repeated cursor response body: %v", closeErr)
		}
	}()
	var repeatedCursorPayload map[string]any
	if err := json.NewDecoder(repeatedCursorResp.Body).Decode(&repeatedCursorPayload); err != nil {
		t.Fatalf("decode repeated cursor response: %v", err)
	}
	repeatedCursorEvents, ok := repeatedCursorPayload["events"].([]any)
	if !ok || len(repeatedCursorEvents) != 1 {
		t.Fatalf("repeated cursor events = %#v, want 1 entry", repeatedCursorPayload["events"])
	}
	repeatedCursorEvent, ok := repeatedCursorEvents[0].(map[string]any)
	if !ok || repeatedCursorEvent["id"] != "github-pr-1" {
		t.Fatalf("repeated cursor event = %#v, want github-pr-1", repeatedCursorEvents[0])
	}

	secretQueryResp, err := server.Client().Get(server.URL + "/sources/github/check?token=test")
	if err != nil {
		t.Fatalf("GET /sources/github/check secret query error = %v", err)
	}
	defer func() {
		if closeErr := secretQueryResp.Body.Close(); closeErr != nil {
			t.Fatalf("close secret query response body: %v", closeErr)
		}
	}()
	if secretQueryResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("secret query status = %d, want %d", secretQueryResp.StatusCode, http.StatusBadRequest)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	versionResp, err := client.GetVersion(context.Background(), connect.NewRequest(&cerebrov1.GetVersionRequest{}))
	if err != nil {
		t.Fatalf("GetVersion() error = %v", err)
	}
	if versionResp.Msg.ServiceName != buildinfo.ServiceName {
		t.Fatalf("ServiceName = %q, want %q", versionResp.Msg.ServiceName, buildinfo.ServiceName)
	}

	healthResp, err := client.CheckHealth(context.Background(), connect.NewRequest(&cerebrov1.CheckHealthRequest{}))
	if err != nil {
		t.Fatalf("CheckHealth() error = %v", err)
	}
	if healthResp.Msg.Status != "ready" {
		t.Fatalf("CheckHealth status = %q, want %q", healthResp.Msg.Status, "ready")
	}
	listResp, err := client.ListSources(context.Background(), connect.NewRequest(&cerebrov1.ListSourcesRequest{}))
	if err != nil {
		t.Fatalf("ListSources() error = %v", err)
	}
	if len(listResp.Msg.Sources) != 1 {
		t.Fatalf("len(ListSources.Sources) = %d, want 1", len(listResp.Msg.Sources))
	}
	checkSourceResp, err := client.CheckSource(context.Background(), connect.NewRequest(&cerebrov1.CheckSourceRequest{
		SourceId: "github",
		Config:   map[string]string{"token": "test"},
	}))
	if err != nil {
		t.Fatalf("CheckSource() error = %v", err)
	}
	if checkSourceResp.Msg.Status != "ok" {
		t.Fatalf("CheckSource status = %q, want %q", checkSourceResp.Msg.Status, "ok")
	}
	discoverSourceResp, err := client.DiscoverSource(context.Background(), connect.NewRequest(&cerebrov1.DiscoverSourceRequest{
		SourceId: "github",
		Config:   map[string]string{"token": "test"},
	}))
	if err != nil {
		t.Fatalf("DiscoverSource() error = %v", err)
	}
	if len(discoverSourceResp.Msg.Urns) != 2 {
		t.Fatalf("len(DiscoverSource.Urns) = %d, want 2", len(discoverSourceResp.Msg.Urns))
	}
	readSourceResp, err := client.ReadSource(context.Background(), connect.NewRequest(&cerebrov1.ReadSourceRequest{
		SourceId: "github",
		Config:   map[string]string{"token": "test"},
	}))
	if err != nil {
		t.Fatalf("ReadSource() error = %v", err)
	}
	if len(readSourceResp.Msg.Events) != 1 {
		t.Fatalf("len(ReadSource.Events) = %d, want 1", len(readSourceResp.Msg.Events))
	}

	_, err = client.CheckSource(context.Background(), connect.NewRequest(&cerebrov1.CheckSourceRequest{}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("CheckSource(empty) code = %v, want %v", connect.CodeOf(err), connect.CodeInvalidArgument)
	}
}

func TestBootstrapHealthDegradesOnDependencyError(t *testing.T) {
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  stubAppendLog{},
		StateStore: stubStore{err: errors.New("state store unavailable")},
		GraphStore: stubStore{},
	}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	healthResp, err := client.CheckHealth(context.Background(), connect.NewRequest(&cerebrov1.CheckHealthRequest{}))
	if err != nil {
		t.Fatalf("CheckHealth() error = %v", err)
	}
	if healthResp.Msg.Status != "degraded" {
		t.Fatalf("CheckHealth status = %q, want %q", healthResp.Msg.Status, "degraded")
	}
	if got := healthResp.Msg.Components[1].Status; got != "error" {
		t.Fatalf("state_store status = %q, want %q", got, "error")
	}
}
