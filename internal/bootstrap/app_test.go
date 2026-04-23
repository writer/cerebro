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
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceops"
	githubsource "github.com/writer/cerebro/sources/github"
	oktasource "github.com/writer/cerebro/sources/okta"
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

func TestSourceConfigFromQueryDropsBaseURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/sources/github/read?base_url=http://127.0.0.1:1&cursor=2", nil)
	req.Header.Set("Authorization", "Bearer test")

	config, err := sourceConfigFromQuery(req)
	if err != nil {
		t.Fatalf("sourceConfigFromQuery() error = %v", err)
	}
	if _, ok := config["base_url"]; ok {
		t.Fatalf("sourceConfigFromQuery() included base_url")
	}
	if _, ok := config["cursor"]; ok {
		t.Fatalf("sourceConfigFromQuery() included cursor")
	}
	if got := config["token"]; got != "test" {
		t.Fatalf("sourceConfigFromQuery()[token] = %q, want test", got)
	}
}

func TestBootstrapEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
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
	if !ok || len(entries) != 2 {
		t.Fatalf("/sources entries = %#v, want 2 entries", sourcesPayload["sources"])
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
	previewEvents, ok := readPayload["preview_events"].([]any)
	if !ok || len(previewEvents) != 1 {
		t.Fatalf("read preview_events = %#v, want 1 entry", readPayload["preview_events"])
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
	previewEvent, ok := previewEvents[0].(map[string]any)
	if !ok || previewEvent["event_id"] != "github-audit-1" {
		t.Fatalf("read preview_event = %#v, want event_id github-audit-1", previewEvents[0])
	}

	oktaCheckResp, err := authedGet("/sources/okta/check?domain=writer.okta.com&family=user")
	if err != nil {
		t.Fatalf("GET /sources/okta/check error = %v", err)
	}
	defer func() {
		if closeErr := oktaCheckResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources/okta/check response body: %v", closeErr)
		}
	}()
	var oktaCheckPayload map[string]any
	if err := json.NewDecoder(oktaCheckResp.Body).Decode(&oktaCheckPayload); err != nil {
		t.Fatalf("decode /sources/okta/check response: %v", err)
	}
	if oktaCheckPayload["status"] != "ok" {
		t.Fatalf("okta check status = %#v, want %q", oktaCheckPayload["status"], "ok")
	}
	oktaDiscoverResp, err := authedGet("/sources/okta/discover?domain=writer.okta.com&family=user")
	if err != nil {
		t.Fatalf("GET /sources/okta/discover error = %v", err)
	}
	defer func() {
		if closeErr := oktaDiscoverResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources/okta/discover response body: %v", closeErr)
		}
	}()
	var oktaDiscoverPayload map[string]any
	if err := json.NewDecoder(oktaDiscoverResp.Body).Decode(&oktaDiscoverPayload); err != nil {
		t.Fatalf("decode /sources/okta/discover response: %v", err)
	}
	if urns, ok := oktaDiscoverPayload["urns"].([]any); !ok || len(urns) != 2 {
		t.Fatalf("okta discover urns = %#v, want 2 entries", oktaDiscoverPayload["urns"])
	}
	oktaReadResp, err := authedGet("/sources/okta/read?domain=writer.okta.com&family=user")
	if err != nil {
		t.Fatalf("GET /sources/okta/read error = %v", err)
	}
	defer func() {
		if closeErr := oktaReadResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources/okta/read response body: %v", closeErr)
		}
	}()
	var oktaReadPayload map[string]any
	if err := json.NewDecoder(oktaReadResp.Body).Decode(&oktaReadPayload); err != nil {
		t.Fatalf("decode /sources/okta/read response: %v", err)
	}
	if events, ok := oktaReadPayload["events"].([]any); !ok || len(events) != 1 {
		t.Fatalf("okta read events = %#v, want 1 entry", oktaReadPayload["events"])
	}
	oktaPreviewEvents, ok := oktaReadPayload["preview_events"].([]any)
	if !ok || len(oktaPreviewEvents) != 1 {
		t.Fatalf("okta read preview_events = %#v, want 1 entry", oktaReadPayload["preview_events"])
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
	if len(listResp.Msg.Sources) != 2 {
		t.Fatalf("len(ListSources.Sources) = %d, want 2", len(listResp.Msg.Sources))
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

	_, err = client.CheckSource(context.Background(), connect.NewRequest(&cerebrov1.CheckSourceRequest{SourceId: "github"}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("CheckSource(missing token) code = %v, want %v", connect.CodeOf(err), connect.CodeInvalidArgument)
	}

	_, err = client.ReadSource(context.Background(), connect.NewRequest(&cerebrov1.ReadSourceRequest{
		SourceId: "github",
		Config:   map[string]string{"token": "test"},
		Cursor:   &cerebrov1.SourceCursor{Opaque: "-1"},
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("ReadSource(invalid cursor) code = %v, want %v", connect.CodeOf(err), connect.CodeInvalidArgument)
	}

	_, err = client.CheckSource(context.Background(), connect.NewRequest(&cerebrov1.CheckSourceRequest{
		SourceId: "github",
		Config:   map[string]string{"token": "test", "base_url": "https://example.com/api/v3/"},
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("CheckSource(base_url) code = %v, want %v", connect.CodeOf(err), connect.CodeInvalidArgument)
	}
	oktaCheckSourceResp, err := client.CheckSource(context.Background(), connect.NewRequest(&cerebrov1.CheckSourceRequest{
		SourceId: "okta",
		Config: map[string]string{
			"domain": "writer.okta.com",
			"family": "user",
			"token":  "test",
		},
	}))
	if err != nil {
		t.Fatalf("CheckSource(okta) error = %v", err)
	}
	if oktaCheckSourceResp.Msg.Status != "ok" {
		t.Fatalf("CheckSource(okta) status = %q, want %q", oktaCheckSourceResp.Msg.Status, "ok")
	}
	oktaDiscoverSourceResp, err := client.DiscoverSource(context.Background(), connect.NewRequest(&cerebrov1.DiscoverSourceRequest{
		SourceId: "okta",
		Config: map[string]string{
			"domain": "writer.okta.com",
			"family": "user",
			"token":  "test",
		},
	}))
	if err != nil {
		t.Fatalf("DiscoverSource(okta) error = %v", err)
	}
	if len(oktaDiscoverSourceResp.Msg.Urns) != 2 {
		t.Fatalf("len(DiscoverSource(okta).Urns) = %d, want 2", len(oktaDiscoverSourceResp.Msg.Urns))
	}
	oktaReadSourceResp, err := client.ReadSource(context.Background(), connect.NewRequest(&cerebrov1.ReadSourceRequest{
		SourceId: "okta",
		Config: map[string]string{
			"domain": "writer.okta.com",
			"family": "user",
			"token":  "test",
		},
	}))
	if err != nil {
		t.Fatalf("ReadSource(okta) error = %v", err)
	}
	if len(oktaReadSourceResp.Msg.Events) != 1 {
		t.Fatalf("len(ReadSource(okta).Events) = %d, want 1", len(oktaReadSourceResp.Msg.Events))
	}
	if len(oktaReadSourceResp.Msg.PreviewEvents) != 1 {
		t.Fatalf("len(ReadSource(okta).PreviewEvents) = %d, want 1", len(oktaReadSourceResp.Msg.PreviewEvents))
	}
	if !oktaReadSourceResp.Msg.PreviewEvents[0].PayloadDecoded {
		t.Fatal("ReadSource(okta).PreviewEvents[0].PayloadDecoded = false, want true")
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

func newFixtureRegistry() (*sourcecdk.Registry, error) {
	source, err := githubsource.NewFixture()
	if err != nil {
		return nil, err
	}
	okta, err := oktasource.NewFixture()
	if err != nil {
		return nil, err
	}
	return sourcecdk.NewRegistry(source, okta)
}

func TestSourceConnectErrorMapping(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	deadlineCtx, deadlineCancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer deadlineCancel()
	cases := []struct {
		name string
		err  error
		want connect.Code
	}{
		{"invalid_id", sourceops.ErrInvalidSourceID, connect.CodeInvalidArgument},
		{"not_found", sourceops.ErrSourceNotFound, connect.CodeNotFound},
		{"invalid_config", sourceops.ErrInvalidSourceConfig, connect.CodeInvalidArgument},
		{"wrapped_invalid_config", errors.Join(sourceops.ErrInvalidSourceConfig, errors.New("repository is required")), connect.CodeInvalidArgument},
		{"canceled", ctx.Err(), connect.CodeCanceled},
		{"deadline", deadlineCtx.Err(), connect.CodeDeadlineExceeded},
		{"opaque", errors.New("internal token leak boom"), connect.CodeInternal},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := sourceConnectError(tc.err)
			var connectErr *connect.Error
			if !errors.As(got, &connectErr) {
				t.Fatalf("sourceConnectError(%v) = %v, want connect.Error", tc.err, got)
			}
			if connectErr.Code() != tc.want {
				t.Fatalf("code = %v, want %v", connectErr.Code(), tc.want)
			}
			if tc.name == "opaque" && connectErr.Message() != "internal error" {
				t.Fatalf("message = %q, want %q", connectErr.Message(), "internal error")
			}
		})
	}
}
