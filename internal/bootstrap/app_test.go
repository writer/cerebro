package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/gen/cerebro/v1/cerebrov1connect"
	"github.com/writer/cerebro/internal/buildinfo"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceruntime"
	githubsource "github.com/writer/cerebro/sources/github"
	oktasource "github.com/writer/cerebro/sources/okta"
)

func sourceGet(t *testing.T, server *httptest.Server, path string, config map[string]string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
	if err != nil {
		return nil, err
	}
	if len(config) > 0 {
		payload, err := json.Marshal(config)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-Cerebro-Source-Config", string(payload))
	}
	return server.Client().Do(req)
}

type stubAppendLog struct {
	err error
}

func (s stubAppendLog) Ping(context.Context) error                             { return s.err }
func (s stubAppendLog) Append(context.Context, *cerebrov1.EventEnvelope) error { return s.err }

type stubStore struct {
	err error
}

func (s stubStore) Ping(context.Context) error { return s.err }

type recordingAppendLog struct {
	err    error
	events []*cerebrov1.EventEnvelope
}

func (s *recordingAppendLog) Ping(context.Context) error { return s.err }

func (s *recordingAppendLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	if s.err != nil {
		return s.err
	}
	s.events = append(s.events, proto.Clone(event).(*cerebrov1.EventEnvelope))
	return nil
}

type stubRuntimeStore struct {
	err      error
	runtimes map[string]*cerebrov1.SourceRuntime
	entities map[string]*ports.ProjectedEntity
	links    map[string]*ports.ProjectedLink
}

func (s *stubRuntimeStore) Ping(context.Context) error { return s.err }

func (s *stubRuntimeStore) PutSourceRuntime(_ context.Context, runtime *cerebrov1.SourceRuntime) error {
	if s.err != nil {
		return s.err
	}
	if s.runtimes == nil {
		s.runtimes = make(map[string]*cerebrov1.SourceRuntime)
	}
	s.runtimes[runtime.GetId()] = proto.Clone(runtime).(*cerebrov1.SourceRuntime)
	return nil
}

func (s *stubRuntimeStore) GetSourceRuntime(_ context.Context, id string) (*cerebrov1.SourceRuntime, error) {
	if s.err != nil {
		return nil, s.err
	}
	runtime, ok := s.runtimes[id]
	if !ok {
		return nil, ports.ErrSourceRuntimeNotFound
	}
	return proto.Clone(runtime).(*cerebrov1.SourceRuntime), nil
}

func (s *stubRuntimeStore) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	if s.err != nil {
		return s.err
	}
	if entity == nil {
		return nil
	}
	if s.entities == nil {
		s.entities = make(map[string]*ports.ProjectedEntity)
	}
	s.entities[entity.URN] = cloneProjectedEntity(entity)
	return nil
}

func (s *stubRuntimeStore) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if s.err != nil {
		return s.err
	}
	if link == nil {
		return nil
	}
	if s.links == nil {
		s.links = make(map[string]*ports.ProjectedLink)
	}
	s.links[projectedLinkKey(link)] = cloneProjectedLink(link)
	return nil
}

type stubGraphStore struct {
	err      error
	entities map[string]*ports.ProjectedEntity
	links    map[string]*ports.ProjectedLink
}

func (s *stubGraphStore) Ping(context.Context) error {
	return s.err
}

func (s *stubGraphStore) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	if s.err != nil {
		return s.err
	}
	if entity == nil {
		return nil
	}
	if s.entities == nil {
		s.entities = make(map[string]*ports.ProjectedEntity)
	}
	s.entities[entity.URN] = cloneProjectedEntity(entity)
	return nil
}

func (s *stubGraphStore) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if s.err != nil {
		return s.err
	}
	if link == nil {
		return nil
	}
	if s.links == nil {
		s.links = make(map[string]*ports.ProjectedLink)
	}
	s.links[projectedLinkKey(link)] = cloneProjectedLink(link)
	return nil
}

func TestSourceConfigFromRequestDropsBaseURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/sources/github/read?owner=writer&base_url=http://127.0.0.1:1&cursor=2", nil)
	req.Header.Set("Authorization", "Bearer test")
	config, err := sourceConfigFromRequest(req)
	if err != nil {
		t.Fatalf("sourceConfigFromRequest() error = %v", err)
	}
	if _, ok := config["base_url"]; ok {
		t.Fatalf("sourceConfigFromRequest() included base_url")
	}
	if _, ok := config["cursor"]; ok {
		t.Fatalf("sourceConfigFromRequest() included cursor")
	}
	if got := config["token"]; got != "test" {
		t.Fatalf("sourceConfigFromRequest()[token] = %q, want test", got)
	}
	if got := config["owner"]; got != "writer" {
		t.Fatalf("sourceConfigFromRequest()[owner] = %q, want writer", got)
	}
	badReq := httptest.NewRequest(http.MethodGet, "/sources/github/read?token=test", nil)
	if _, err := sourceConfigFromRequest(badReq); err == nil {
		t.Fatal("sourceConfigFromRequest(token query) error = nil, want error")
	}
}

func TestSourceConfigFromRequestDropsReservedHeaderKeys(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/sources/github/read?owner=writer", nil)
	req.Header.Set("X-Cerebro-Source-Config", `{"base_url":"http://127.0.0.1:1","cursor":"2","family":"audit"}`)

	config, err := sourceConfigFromRequest(req)
	if err != nil {
		t.Fatalf("sourceConfigFromRequest() error = %v", err)
	}
	if _, ok := config["base_url"]; ok {
		t.Fatal("sourceConfigFromRequest() included header base_url")
	}
	if _, ok := config["cursor"]; ok {
		t.Fatal("sourceConfigFromRequest() included header cursor")
	}
	if got := config["family"]; got != "audit" {
		t.Fatalf("sourceConfigFromRequest()[family] = %q, want audit", got)
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
	checkResp, err := sourceGet(t, server, "/sources/github/check", map[string]string{"token": "test"})
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
	discoverResp, err := sourceGet(t, server, "/sources/github/discover", map[string]string{"token": "test"})
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
	readResp, err := sourceGet(t, server, "/sources/github/read", map[string]string{"token": "test"})
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
	oktaCheckResp, err := sourceGet(t, server, "/sources/okta/check?domain=writer.okta.com&family=user", map[string]string{"token": "test"})
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
	oktaDiscoverResp, err := sourceGet(t, server, "/sources/okta/discover?domain=writer.okta.com&family=user", map[string]string{"token": "test"})
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
	oktaReadResp, err := sourceGet(t, server, "/sources/okta/read?domain=writer.okta.com&family=user", map[string]string{"token": "test"})
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
	leakyQueryResp, err := server.Client().Get(server.URL + "/sources/github/check?token=secret")
	if err != nil {
		t.Fatalf("GET /sources/github/check leaky query error = %v", err)
	}
	defer func() {
		if closeErr := leakyQueryResp.Body.Close(); closeErr != nil {
			t.Fatalf("close leaky query response body: %v", closeErr)
		}
	}()
	if leakyQueryResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("leaky query status = %d, want %d", leakyQueryResp.StatusCode, http.StatusBadRequest)
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
	if len(readSourceResp.Msg.PreviewEvents) != 1 {
		t.Fatalf("len(ReadSource.PreviewEvents) = %d, want 1", len(readSourceResp.Msg.PreviewEvents))
	}
	if !readSourceResp.Msg.PreviewEvents[0].PayloadDecoded {
		t.Fatal("ReadSource.PreviewEvents[0].PayloadDecoded = false, want true")
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

func TestSourceRuntimeEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	appendLog := &recordingAppendLog{}
	runtimeStore := &stubRuntimeStore{}
	graphStore := &stubGraphStore{}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  appendLog,
		StateStore: runtimeStore,
		GraphStore: graphStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	badPutReq, err := http.NewRequest(http.MethodPut, server.URL+"/source-runtimes/writer-okta-users", strings.NewReader("{"))
	if err != nil {
		t.Fatalf("new bad put request: %v", err)
	}
	badPutReq.Header.Set("Content-Type", "application/json")
	badPutResp, err := server.Client().Do(badPutReq)
	if err != nil {
		t.Fatalf("PUT /source-runtimes/{id} malformed body error = %v", err)
	}
	defer func() {
		if closeErr := badPutResp.Body.Close(); closeErr != nil {
			t.Fatalf("close bad put runtime response body: %v", closeErr)
		}
	}()
	if badPutResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad put status = %d, want %d", badPutResp.StatusCode, http.StatusBadRequest)
	}

	putBody, err := protojson.Marshal(&cerebrov1.PutSourceRuntimeRequest{
		Runtime: &cerebrov1.SourceRuntime{
			SourceId: "okta",
			TenantId: "writer",
			Config: map[string]string{
				"domain": "writer.okta.com",
				"family": "user",
				"token":  "test",
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal put runtime body: %v", err)
	}
	putReq, err := http.NewRequest(http.MethodPut, server.URL+"/source-runtimes/writer-okta-users", bytes.NewReader(putBody))
	if err != nil {
		t.Fatalf("new put request: %v", err)
	}
	putReq.Header.Set("Content-Type", "application/json")
	putResp, err := server.Client().Do(putReq)
	if err != nil {
		t.Fatalf("PUT /source-runtimes/{id} error = %v", err)
	}
	defer func() {
		if closeErr := putResp.Body.Close(); closeErr != nil {
			t.Fatalf("close put runtime response body: %v", closeErr)
		}
	}()
	var putPayload map[string]any
	if err := json.NewDecoder(putResp.Body).Decode(&putPayload); err != nil {
		t.Fatalf("decode put runtime response: %v", err)
	}
	runtimePayload, ok := putPayload["runtime"].(map[string]any)
	if !ok {
		t.Fatalf("put runtime payload = %#v, want object", putPayload["runtime"])
	}
	configPayload, ok := runtimePayload["config"].(map[string]any)
	if !ok {
		t.Fatalf("put runtime config = %#v, want object", runtimePayload["config"])
	}
	if got := configPayload["token"]; got != "[redacted]" {
		t.Fatalf("put runtime token = %#v, want [redacted]", got)
	}
	if got := runtimePayload["tenant_id"]; got != "writer" {
		t.Fatalf("put runtime tenant_id = %#v, want writer", got)
	}

	getResp, err := server.Client().Get(server.URL + "/source-runtimes/writer-okta-users")
	if err != nil {
		t.Fatalf("GET /source-runtimes/{id} error = %v", err)
	}
	defer func() {
		if closeErr := getResp.Body.Close(); closeErr != nil {
			t.Fatalf("close get runtime response body: %v", closeErr)
		}
	}()
	var getPayload map[string]any
	if err := json.NewDecoder(getResp.Body).Decode(&getPayload); err != nil {
		t.Fatalf("decode get runtime response: %v", err)
	}
	getRuntimePayload, ok := getPayload["runtime"].(map[string]any)
	if !ok {
		t.Fatalf("get runtime payload = %#v, want object", getPayload["runtime"])
	}
	if got := getRuntimePayload["source_id"]; got != "okta" {
		t.Fatalf("get runtime source_id = %#v, want okta", got)
	}
	if got := getRuntimePayload["tenant_id"]; got != "writer" {
		t.Fatalf("get runtime tenant_id = %#v, want writer", got)
	}

	syncReq, err := http.NewRequest(http.MethodPost, server.URL+"/source-runtimes/writer-okta-users/sync?page_limit=1", nil)
	if err != nil {
		t.Fatalf("new sync request: %v", err)
	}
	syncResp, err := server.Client().Do(syncReq)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/sync error = %v", err)
	}
	defer func() {
		if closeErr := syncResp.Body.Close(); closeErr != nil {
			t.Fatalf("close sync runtime response body: %v", closeErr)
		}
	}()
	var syncPayload map[string]any
	if err := json.NewDecoder(syncResp.Body).Decode(&syncPayload); err != nil {
		t.Fatalf("decode sync runtime response: %v", err)
	}
	if got := syncPayload["events_appended"]; got != float64(1) {
		t.Fatalf("sync events_appended = %#v, want 1", got)
	}
	if got := syncPayload["entities_projected"]; got != float64(3) {
		t.Fatalf("sync entities_projected = %#v, want 3", got)
	}
	if got := syncPayload["links_projected"]; got != float64(2) {
		t.Fatalf("sync links_projected = %#v, want 2", got)
	}

	badSyncReq, err := http.NewRequest(http.MethodPost, server.URL+"/source-runtimes/writer-okta-users/sync?page_limit=not-a-number", nil)
	if err != nil {
		t.Fatalf("new bad sync request: %v", err)
	}
	badSyncResp, err := server.Client().Do(badSyncReq)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/sync bad page_limit error = %v", err)
	}
	defer func() {
		if closeErr := badSyncResp.Body.Close(); closeErr != nil {
			t.Fatalf("close bad sync runtime response body: %v", closeErr)
		}
	}()
	if badSyncResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad sync status = %d, want %d", badSyncResp.StatusCode, http.StatusBadRequest)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	putRuntimeResp, err := client.PutSourceRuntime(context.Background(), connect.NewRequest(&cerebrov1.PutSourceRuntimeRequest{
		Runtime: &cerebrov1.SourceRuntime{
			Id:       "writer-github",
			SourceId: "github",
			TenantId: "writer",
			Config:   map[string]string{"token": "test"},
		},
	}))
	if err != nil {
		t.Fatalf("PutSourceRuntime() error = %v", err)
	}
	if got := putRuntimeResp.Msg.GetRuntime().GetConfig()["token"]; got != "[redacted]" {
		t.Fatalf("PutSourceRuntime token = %q, want [redacted]", got)
	}
	if got := putRuntimeResp.Msg.GetRuntime().GetTenantId(); got != "writer" {
		t.Fatalf("PutSourceRuntime tenant_id = %q, want writer", got)
	}

	getRuntimeResp, err := client.GetSourceRuntime(context.Background(), connect.NewRequest(&cerebrov1.GetSourceRuntimeRequest{
		Id: "writer-okta-users",
	}))
	if err != nil {
		t.Fatalf("GetSourceRuntime() error = %v", err)
	}
	if got := getRuntimeResp.Msg.GetRuntime().GetSourceId(); got != "okta" {
		t.Fatalf("GetSourceRuntime source_id = %q, want okta", got)
	}
	if got := getRuntimeResp.Msg.GetRuntime().GetTenantId(); got != "writer" {
		t.Fatalf("GetSourceRuntime tenant_id = %q, want writer", got)
	}

	syncRuntimeResp, err := client.SyncSourceRuntime(context.Background(), connect.NewRequest(&cerebrov1.SyncSourceRuntimeRequest{
		Id:        "writer-okta-users",
		PageLimit: 1,
	}))
	if err != nil {
		t.Fatalf("SyncSourceRuntime() error = %v", err)
	}
	if syncRuntimeResp.Msg.GetEventsAppended() != 1 {
		t.Fatalf("SyncSourceRuntime events_appended = %d, want 1", syncRuntimeResp.Msg.GetEventsAppended())
	}
	if syncRuntimeResp.Msg.GetEntitiesProjected() != 3 {
		t.Fatalf("SyncSourceRuntime entities_projected = %d, want 3", syncRuntimeResp.Msg.GetEntitiesProjected())
	}
	if syncRuntimeResp.Msg.GetLinksProjected() != 2 {
		t.Fatalf("SyncSourceRuntime links_projected = %d, want 2", syncRuntimeResp.Msg.GetLinksProjected())
	}
	if len(appendLog.events) != 2 {
		t.Fatalf("len(appendLog.events) = %d, want 2", len(appendLog.events))
	}
	if len(runtimeStore.entities) == 0 || len(graphStore.entities) == 0 {
		t.Fatalf("projected entities = state:%d graph:%d, want non-zero", len(runtimeStore.entities), len(graphStore.entities))
	}
}

func TestSourceRuntimeRPCErrorCodes(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	service := &bootstrapService{
		sources: registry,
		deps: Dependencies{
			StateStore: &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{}},
			AppendLog:  &recordingAppendLog{},
		},
	}

	if _, err := service.GetSourceRuntime(context.Background(), connect.NewRequest(&cerebrov1.GetSourceRuntimeRequest{Id: "missing"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("GetSourceRuntime() code = %v, want %v", connect.CodeOf(err), connect.CodeNotFound)
	}
	if _, err := service.SyncSourceRuntime(context.Background(), connect.NewRequest(&cerebrov1.SyncSourceRuntimeRequest{})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("SyncSourceRuntime() empty request code = %v, want %v", connect.CodeOf(err), connect.CodeInvalidArgument)
	}

	unavailable := &bootstrapService{sources: registry}
	if _, err := unavailable.SyncSourceRuntime(context.Background(), connect.NewRequest(&cerebrov1.SyncSourceRuntimeRequest{Id: "runtime"})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("SyncSourceRuntime() unavailable code = %v, want %v", connect.CodeOf(err), connect.CodeUnavailable)
	}
}

func TestWriteSourceRuntimeErrorHidesInternalDetails(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeSourceRuntimeError(recorder, errors.New("dial tcp credential@db.internal:5432: i/o timeout"))

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
	}
	if got := recorder.Body.String(); got != http.StatusText(http.StatusInternalServerError)+"\n" {
		t.Fatalf("body = %q, want generic status text", got)
	}
	if bytes.Contains(recorder.Body.Bytes(), []byte("credential")) || bytes.Contains(recorder.Body.Bytes(), []byte("db.internal")) {
		t.Fatalf("body exposed internal error details: %q", recorder.Body.String())
	}

	invalid := httptest.NewRecorder()
	writeSourceRuntimeError(invalid, sourceruntime.ErrInvalidRequest)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid request status = %d, want %d", invalid.Code, http.StatusBadRequest)
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

func cloneProjectedEntity(entity *ports.ProjectedEntity) *ports.ProjectedEntity {
	if entity == nil {
		return nil
	}
	attributes := make(map[string]string, len(entity.Attributes))
	for key, value := range entity.Attributes {
		attributes[key] = value
	}
	return &ports.ProjectedEntity{
		URN:        entity.URN,
		TenantID:   entity.TenantID,
		SourceID:   entity.SourceID,
		EntityType: entity.EntityType,
		Label:      entity.Label,
		Attributes: attributes,
	}
}

func cloneProjectedLink(link *ports.ProjectedLink) *ports.ProjectedLink {
	if link == nil {
		return nil
	}
	attributes := make(map[string]string, len(link.Attributes))
	for key, value := range link.Attributes {
		attributes[key] = value
	}
	return &ports.ProjectedLink{
		TenantID:   link.TenantID,
		SourceID:   link.SourceID,
		FromURN:    link.FromURN,
		ToURN:      link.ToURN,
		Relation:   link.Relation,
		Attributes: attributes,
	}
}

func projectedLinkKey(link *ports.ProjectedLink) string {
	return link.FromURN + "|" + link.Relation + "|" + link.ToURN
}
