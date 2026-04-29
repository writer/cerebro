package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/gen/cerebro/v1/cerebrov1connect"
	"github.com/writer/cerebro/internal/buildinfo"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	githubsource "github.com/writer/cerebro/sources/github"
	oktasource "github.com/writer/cerebro/sources/okta"
	sdksource "github.com/writer/cerebro/sources/sdk"
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

type recordingAppendLog struct {
	err          error
	events       []*cerebrov1.EventEnvelope
	replayEvents []*cerebrov1.EventEnvelope
}

func (s *recordingAppendLog) Ping(context.Context) error { return s.err }

func (s *recordingAppendLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	if s.err != nil {
		return s.err
	}
	s.events = append(s.events, proto.Clone(event).(*cerebrov1.EventEnvelope))
	return nil
}

func (s *recordingAppendLog) Replay(_ context.Context, request ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	if s.err != nil {
		return nil, s.err
	}
	source := s.events
	if len(s.replayEvents) != 0 {
		source = s.replayEvents
	}
	events := make([]*cerebrov1.EventEnvelope, 0, len(source))
	for _, event := range source {
		if event == nil {
			continue
		}
		if event.GetAttributes()[ports.EventAttributeSourceRuntimeID] != request.RuntimeID {
			continue
		}
		events = append(events, proto.Clone(event).(*cerebrov1.EventEnvelope))
		if request.Limit != 0 && uint32(len(events)) >= request.Limit {
			break
		}
	}
	return events, nil
}

type stubRuntimeStore struct {
	err                             error
	runtimes                        map[string]*cerebrov1.SourceRuntime
	entities                        map[string]*ports.ProjectedEntity
	links                           map[string]*ports.ProjectedLink
	claims                          map[string]*ports.ClaimRecord
	claimListRequest                ports.ListClaimsRequest
	findings                        map[string]*ports.FindingRecord
	findingListRequest              ports.ListFindingsRequest
	findingEvaluationRuns           map[string]*cerebrov1.FindingEvaluationRun
	findingEvaluationRunListRequest ports.ListFindingEvaluationRunsRequest
	reportRuns                      map[string]*cerebrov1.ReportRun
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

func (s *stubRuntimeStore) UpsertFinding(_ context.Context, finding *ports.FindingRecord) (*ports.FindingRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	if finding == nil {
		return nil, nil
	}
	if s.findings == nil {
		s.findings = make(map[string]*ports.FindingRecord)
	}
	s.findings[finding.ID] = cloneFinding(finding)
	return cloneFinding(finding), nil
}

func (s *stubRuntimeStore) UpsertClaim(_ context.Context, claim *ports.ClaimRecord) (*ports.ClaimRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	if claim == nil {
		return nil, nil
	}
	if s.claims == nil {
		s.claims = make(map[string]*ports.ClaimRecord)
	}
	s.claims[claim.ID] = cloneClaim(claim)
	return cloneClaim(claim), nil
}

func (s *stubRuntimeStore) ListClaims(_ context.Context, request ports.ListClaimsRequest) ([]*ports.ClaimRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.claimListRequest = request
	claims := []*ports.ClaimRecord{}
	for _, claim := range s.claims {
		if !claimMatches(request, claim) {
			continue
		}
		claims = append(claims, cloneClaim(claim))
	}
	sort.Slice(claims, func(i, j int) bool {
		left := claims[i]
		right := claims[j]
		switch {
		case left.ObservedAt.Equal(right.ObservedAt):
			return left.ID < right.ID
		case left.ObservedAt.IsZero():
			return false
		case right.ObservedAt.IsZero():
			return true
		default:
			return left.ObservedAt.After(right.ObservedAt)
		}
	})
	if request.Limit != 0 && len(claims) > int(request.Limit) {
		claims = claims[:int(request.Limit)]
	}
	return claims, nil
}

func (s *stubRuntimeStore) ListFindings(_ context.Context, request ports.ListFindingsRequest) ([]*ports.FindingRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.findingListRequest = request
	findings := []*ports.FindingRecord{}
	for _, finding := range s.findings {
		if !findingMatches(request, finding) {
			continue
		}
		findings = append(findings, cloneFinding(finding))
	}
	sort.Slice(findings, func(i, j int) bool {
		left := findings[i]
		right := findings[j]
		switch {
		case left.LastObservedAt.Equal(right.LastObservedAt):
			return left.ID < right.ID
		case left.LastObservedAt.IsZero():
			return false
		case right.LastObservedAt.IsZero():
			return true
		default:
			return left.LastObservedAt.After(right.LastObservedAt)
		}
	})
	if request.Limit != 0 && len(findings) > int(request.Limit) {
		findings = findings[:int(request.Limit)]
	}
	return findings, nil
}

func (s *stubRuntimeStore) PutFindingEvaluationRun(_ context.Context, run *cerebrov1.FindingEvaluationRun) error {
	if s.err != nil {
		return s.err
	}
	if run == nil {
		return nil
	}
	if s.findingEvaluationRuns == nil {
		s.findingEvaluationRuns = make(map[string]*cerebrov1.FindingEvaluationRun)
	}
	s.findingEvaluationRuns[run.GetId()] = cloneFindingEvaluationRun(run)
	return nil
}

func (s *stubRuntimeStore) GetFindingEvaluationRun(_ context.Context, id string) (*cerebrov1.FindingEvaluationRun, error) {
	if s.err != nil {
		return nil, s.err
	}
	run, ok := s.findingEvaluationRuns[id]
	if !ok {
		return nil, ports.ErrFindingEvaluationRunNotFound
	}
	return cloneFindingEvaluationRun(run), nil
}

func (s *stubRuntimeStore) ListFindingEvaluationRuns(_ context.Context, request ports.ListFindingEvaluationRunsRequest) ([]*cerebrov1.FindingEvaluationRun, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.findingEvaluationRunListRequest = request
	runs := []*cerebrov1.FindingEvaluationRun{}
	for _, run := range s.findingEvaluationRuns {
		if !findingEvaluationRunMatches(request, run) {
			continue
		}
		runs = append(runs, cloneFindingEvaluationRun(run))
	}
	sort.Slice(runs, func(i, j int) bool {
		left := runs[i]
		right := runs[j]
		switch {
		case left.GetStartedAt().AsTime().Equal(right.GetStartedAt().AsTime()):
			return left.GetId() < right.GetId()
		default:
			return left.GetStartedAt().AsTime().After(right.GetStartedAt().AsTime())
		}
	})
	if request.Limit != 0 && len(runs) > int(request.Limit) {
		runs = runs[:int(request.Limit)]
	}
	return runs, nil
}

func (s *stubRuntimeStore) PutReportRun(_ context.Context, run *cerebrov1.ReportRun) error {
	if s.err != nil {
		return s.err
	}
	if run == nil {
		return nil
	}
	if s.reportRuns == nil {
		s.reportRuns = make(map[string]*cerebrov1.ReportRun)
	}
	s.reportRuns[run.GetId()] = cloneReportRun(run)
	return nil
}

func (s *stubRuntimeStore) GetReportRun(_ context.Context, id string) (*cerebrov1.ReportRun, error) {
	if s.err != nil {
		return nil, s.err
	}
	run, ok := s.reportRuns[id]
	if !ok {
		return nil, ports.ErrReportRunNotFound
	}
	return cloneReportRun(run), nil
}

type stubGraphStore struct {
	err                 error
	entities            map[string]*ports.ProjectedEntity
	links               map[string]*ports.ProjectedLink
	neighborhood        *ports.EntityNeighborhood
	neighborhoodRootURN string
	neighborhoodLimit   int
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

func (s *stubGraphStore) GetEntityNeighborhood(_ context.Context, rootURN string, limit int) (*ports.EntityNeighborhood, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.neighborhoodRootURN = rootURN
	s.neighborhoodLimit = limit
	if s.neighborhood == nil {
		return nil, ports.ErrGraphEntityNotFound
	}
	return cloneNeighborhood(s.neighborhood), nil
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
	if !ok || len(entries) != 3 {
		t.Fatalf("/sources entries = %#v, want 3 entries", sourcesPayload["sources"])
	}
	checkResp, err := server.Client().Get(server.URL + "/sources/github/check?token=test")
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
	discoverResp, err := server.Client().Get(server.URL + "/sources/github/discover?token=test")
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
	readResp, err := server.Client().Get(server.URL + "/sources/github/read?token=test")
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
	oktaCheckResp, err := server.Client().Get(server.URL + "/sources/okta/check?domain=writer.okta.com&family=user&token=test")
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
	oktaDiscoverResp, err := server.Client().Get(server.URL + "/sources/okta/discover?domain=writer.okta.com&family=user&token=test")
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
	oktaReadResp, err := server.Client().Get(server.URL + "/sources/okta/read?domain=writer.okta.com&family=user&token=test")
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
	if len(listResp.Msg.Sources) != 3 {
		t.Fatalf("len(ListSources.Sources) = %d, want 3", len(listResp.Msg.Sources))
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

func TestFindingRuleEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/finding-rules")
	if err != nil {
		t.Fatalf("GET /finding-rules error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close /finding-rules response body: %v", closeErr)
		}
	}()
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode /finding-rules response: %v", err)
	}
	rulesPayload, ok := payload["rules"].([]any)
	if !ok || len(rulesPayload) != 1 {
		t.Fatalf("/finding-rules payload = %#v, want 1 rule", payload["rules"])
	}
	rulePayload, ok := rulesPayload[0].(map[string]any)
	if !ok {
		t.Fatalf("/finding-rules rule entry = %#v, want object", rulesPayload[0])
	}
	if got := rulePayload["id"]; got != "identity-okta-policy-rule-lifecycle-tampering" {
		t.Fatalf("/finding-rules rule id = %#v, want identity-okta-policy-rule-lifecycle-tampering", got)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	listResp, err := client.ListFindingRules(context.Background(), connect.NewRequest(&cerebrov1.ListFindingRulesRequest{}))
	if err != nil {
		t.Fatalf("ListFindingRules() error = %v", err)
	}
	if got := len(listResp.Msg.GetRules()); got != 1 {
		t.Fatalf("len(ListFindingRules().Rules) = %d, want 1", got)
	}
	if got := listResp.Msg.GetRules()[0].GetId(); got != "identity-okta-policy-rule-lifecycle-tampering" {
		t.Fatalf("ListFindingRules().Rules[0].Id = %q, want identity-okta-policy-rule-lifecycle-tampering", got)
	}
}

func TestFindingEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	appendLog := &recordingAppendLog{
		replayEvents: []*cerebrov1.EventEnvelope{
			findingTestEvent("okta-audit-1", "user.session.start", "SUCCESS"),
			findingTestEvent("okta-audit-2", "policy.rule.update", "SUCCESS"),
		},
	}
	runtimeStore := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {
				Id:       "writer-okta-audit",
				SourceId: "okta",
				TenantId: "writer",
			},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  appendLog,
		StateStore: runtimeStore,
		GraphStore: &stubGraphStore{},
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	evaluateReq, err := http.NewRequest(http.MethodPost, server.URL+"/source-runtimes/writer-okta-audit/findings/evaluate?event_limit=2&rule_id=identity-okta-policy-rule-lifecycle-tampering", nil)
	if err != nil {
		t.Fatalf("new evaluate findings request: %v", err)
	}
	evaluateResp, err := server.Client().Do(evaluateReq)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/findings/evaluate error = %v", err)
	}
	defer func() {
		if closeErr := evaluateResp.Body.Close(); closeErr != nil {
			t.Fatalf("close evaluate findings response body: %v", closeErr)
		}
	}()
	var evaluatePayload map[string]any
	if err := json.NewDecoder(evaluateResp.Body).Decode(&evaluatePayload); err != nil {
		t.Fatalf("decode evaluate findings response: %v", err)
	}
	if got := evaluatePayload["events_evaluated"]; got != float64(2) {
		t.Fatalf("evaluate findings events_evaluated = %#v, want 2", got)
	}
	if got := evaluatePayload["findings_upserted"]; got != float64(1) {
		t.Fatalf("evaluate findings findings_upserted = %#v, want 1", got)
	}
	findingsPayload, ok := evaluatePayload["findings"].([]any)
	if !ok || len(findingsPayload) != 1 {
		t.Fatalf("evaluate findings payload = %#v, want 1 entry", evaluatePayload["findings"])
	}
	findingPayload, ok := findingsPayload[0].(map[string]any)
	if !ok {
		t.Fatalf("evaluate finding payload = %#v, want object", findingsPayload[0])
	}
	if got := findingPayload["rule_id"]; got != "identity-okta-policy-rule-lifecycle-tampering" {
		t.Fatalf("evaluate finding rule_id = %#v, want identity-okta-policy-rule-lifecycle-tampering", got)
	}
	if got := findingPayload["summary"]; got != "admin@writer.com performed policy.rule.update on pol-1" {
		t.Fatalf("evaluate finding summary = %#v, want admin summary", got)
	}
	runPayload, ok := evaluatePayload["run"].(map[string]any)
	if !ok {
		t.Fatalf("evaluate run payload = %#v, want object", evaluatePayload["run"])
	}
	runID, ok := runPayload["id"].(string)
	if !ok || runID == "" {
		t.Fatalf("evaluate run id = %#v, want non-empty string", runPayload["id"])
	}
	if got := runPayload["status"]; got != "completed" {
		t.Fatalf("evaluate run status = %#v, want completed", got)
	}
	if got := runPayload["rule_id"]; got != "identity-okta-policy-rule-lifecycle-tampering" {
		t.Fatalf("evaluate run rule_id = %#v, want identity-okta-policy-rule-lifecycle-tampering", got)
	}
	listResp, err := server.Client().Get(server.URL + "/source-runtimes/writer-okta-audit/findings?rule_id=identity-okta-policy-rule-lifecycle-tampering&status=open&event_id=okta-audit-2&limit=1")
	if err != nil {
		t.Fatalf("GET /source-runtimes/{id}/findings error = %v", err)
	}
	defer func() {
		if closeErr := listResp.Body.Close(); closeErr != nil {
			t.Fatalf("close list findings response body: %v", closeErr)
		}
	}()
	var listPayload map[string]any
	if err := json.NewDecoder(listResp.Body).Decode(&listPayload); err != nil {
		t.Fatalf("decode list findings response: %v", err)
	}
	listedFindings, ok := listPayload["findings"].([]any)
	if !ok || len(listedFindings) != 1 {
		t.Fatalf("list findings payload = %#v, want 1 entry", listPayload["findings"])
	}
	listedFinding, ok := listedFindings[0].(map[string]any)
	if !ok {
		t.Fatalf("list findings entry = %#v, want object", listedFindings[0])
	}
	if got := listedFinding["rule_id"]; got != "identity-okta-policy-rule-lifecycle-tampering" {
		t.Fatalf("list finding rule_id = %#v, want identity-okta-policy-rule-lifecycle-tampering", got)
	}
	runListResp, err := server.Client().Get(server.URL + "/source-runtimes/writer-okta-audit/finding-evaluation-runs?rule_id=identity-okta-policy-rule-lifecycle-tampering&status=completed&limit=1")
	if err != nil {
		t.Fatalf("GET /source-runtimes/{id}/finding-evaluation-runs error = %v", err)
	}
	defer func() {
		if closeErr := runListResp.Body.Close(); closeErr != nil {
			t.Fatalf("close list evaluation runs response body: %v", closeErr)
		}
	}()
	var runListPayload map[string]any
	if err := json.NewDecoder(runListResp.Body).Decode(&runListPayload); err != nil {
		t.Fatalf("decode list evaluation runs response: %v", err)
	}
	runEntries, ok := runListPayload["runs"].([]any)
	if !ok || len(runEntries) != 1 {
		t.Fatalf("list evaluation runs payload = %#v, want 1 entry", runListPayload["runs"])
	}
	runEntry, ok := runEntries[0].(map[string]any)
	if !ok {
		t.Fatalf("list evaluation run entry = %#v, want object", runEntries[0])
	}
	if got := runEntry["id"]; got != runID {
		t.Fatalf("list evaluation run id = %#v, want %q", got, runID)
	}
	getRunResp, err := server.Client().Get(server.URL + "/finding-evaluation-runs/" + runID)
	if err != nil {
		t.Fatalf("GET /finding-evaluation-runs/{id} error = %v", err)
	}
	defer func() {
		if closeErr := getRunResp.Body.Close(); closeErr != nil {
			t.Fatalf("close get evaluation run response body: %v", closeErr)
		}
	}()
	var getRunPayload map[string]any
	if err := json.NewDecoder(getRunResp.Body).Decode(&getRunPayload); err != nil {
		t.Fatalf("decode get evaluation run response: %v", err)
	}
	getRunBody, ok := getRunPayload["run"].(map[string]any)
	if !ok {
		t.Fatalf("get evaluation run payload = %#v, want object", getRunPayload["run"])
	}
	if got := getRunBody["id"]; got != runID {
		t.Fatalf("get evaluation run id = %#v, want %q", got, runID)
	}
	missingRuleResp, err := server.Client().Post(server.URL+"/source-runtimes/writer-okta-audit/findings/evaluate?rule_id=does-not-exist", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/findings/evaluate unknown rule error = %v", err)
	}
	defer func() {
		if closeErr := missingRuleResp.Body.Close(); closeErr != nil {
			t.Fatalf("close unknown rule response body: %v", closeErr)
		}
	}()
	if got := missingRuleResp.StatusCode; got != http.StatusNotFound {
		t.Fatalf("unknown rule status = %d, want %d", got, http.StatusNotFound)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	evaluateFindingsResp, err := client.EvaluateSourceRuntimeFindings(context.Background(), connect.NewRequest(&cerebrov1.EvaluateSourceRuntimeFindingsRequest{
		Id:         "writer-okta-audit",
		RuleId:     "identity-okta-policy-rule-lifecycle-tampering",
		EventLimit: 5,
	}))
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeFindings() error = %v", err)
	}
	if got := evaluateFindingsResp.Msg.GetEventsEvaluated(); got != 2 {
		t.Fatalf("EvaluateSourceRuntimeFindings events_evaluated = %d, want 2", got)
	}
	if got := evaluateFindingsResp.Msg.GetFindingsUpserted(); got != 1 {
		t.Fatalf("EvaluateSourceRuntimeFindings findings_upserted = %d, want 1", got)
	}
	if len(evaluateFindingsResp.Msg.GetFindings()) != 1 {
		t.Fatalf("len(EvaluateSourceRuntimeFindings.Findings) = %d, want 1", len(evaluateFindingsResp.Msg.GetFindings()))
	}
	if got := evaluateFindingsResp.Msg.GetRule().GetId(); got != "identity-okta-policy-rule-lifecycle-tampering" {
		t.Fatalf("EvaluateSourceRuntimeFindings rule id = %q, want identity-okta-policy-rule-lifecycle-tampering", got)
	}
	if got := evaluateFindingsResp.Msg.GetRun().GetId(); got == "" {
		t.Fatal("EvaluateSourceRuntimeFindings run id = empty, want non-empty")
	}
	listFindingsResp, err := client.ListFindings(context.Background(), connect.NewRequest(&cerebrov1.ListFindingsRequest{
		RuntimeId:   "writer-okta-audit",
		RuleId:      "identity-okta-policy-rule-lifecycle-tampering",
		Severity:    "HIGH",
		Status:      "open",
		ResourceUrn: "urn:cerebro:writer:okta_resource:policyrule:pol-1",
		EventId:     "okta-audit-2",
		Limit:       1,
	}))
	if err != nil {
		t.Fatalf("ListFindings() error = %v", err)
	}
	if got := len(listFindingsResp.Msg.GetFindings()); got != 1 {
		t.Fatalf("len(ListFindings().Findings) = %d, want 1", got)
	}
	if got := listFindingsResp.Msg.GetFindings()[0].GetId(); got == "" {
		t.Fatal("ListFindings().Findings[0].ID = empty, want non-empty")
	}
	if got := runtimeStore.findingListRequest.RuleID; got != "identity-okta-policy-rule-lifecycle-tampering" {
		t.Fatalf("runtimeStore.findingListRequest.RuleID = %q, want identity-okta-policy-rule-lifecycle-tampering", got)
	}
	if got := runtimeStore.findingListRequest.ResourceURN; got != "urn:cerebro:writer:okta_resource:policyrule:pol-1" {
		t.Fatalf("runtimeStore.findingListRequest.ResourceURN = %q, want policy rule urn", got)
	}
	if got := runtimeStore.findingListRequest.EventID; got != "okta-audit-2" {
		t.Fatalf("runtimeStore.findingListRequest.EventID = %q, want okta-audit-2", got)
	}
	listRunsResp, err := client.ListFindingEvaluationRuns(context.Background(), connect.NewRequest(&cerebrov1.ListFindingEvaluationRunsRequest{
		RuntimeId: "writer-okta-audit",
		RuleId:    "identity-okta-policy-rule-lifecycle-tampering",
		Status:    "completed",
		Limit:     1,
	}))
	if err != nil {
		t.Fatalf("ListFindingEvaluationRuns() error = %v", err)
	}
	if got := len(listRunsResp.Msg.GetRuns()); got != 1 {
		t.Fatalf("len(ListFindingEvaluationRuns().Runs) = %d, want 1", got)
	}
	getEvaluationRunResp, err := client.GetFindingEvaluationRun(context.Background(), connect.NewRequest(&cerebrov1.GetFindingEvaluationRunRequest{
		Id: evaluateFindingsResp.Msg.GetRun().GetId(),
	}))
	if err != nil {
		t.Fatalf("GetFindingEvaluationRun() error = %v", err)
	}
	if got := getEvaluationRunResp.Msg.GetRun().GetId(); got != evaluateFindingsResp.Msg.GetRun().GetId() {
		t.Fatalf("GetFindingEvaluationRun().Run.Id = %q, want %q", got, evaluateFindingsResp.Msg.GetRun().GetId())
	}
	if got := runtimeStore.findingEvaluationRunListRequest.RuleID; got != "identity-okta-policy-rule-lifecycle-tampering" {
		t.Fatalf("runtimeStore.findingEvaluationRunListRequest.RuleID = %q, want identity-okta-policy-rule-lifecycle-tampering", got)
	}
	if got := runtimeStore.findingEvaluationRunListRequest.Status; got != "completed" {
		t.Fatalf("runtimeStore.findingEvaluationRunListRequest.Status = %q, want completed", got)
	}
	if len(runtimeStore.findingEvaluationRuns) != 2 {
		t.Fatalf("len(runtimeStore.findingEvaluationRuns) = %d, want 2", len(runtimeStore.findingEvaluationRuns))
	}
	if len(runtimeStore.findings) != 1 {
		t.Fatalf("len(runtimeStore.findings) = %d, want 1", len(runtimeStore.findings))
	}
}

func TestClaimEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	runtimeStore := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-jira": {
				Id:       "writer-jira",
				SourceId: "sdk",
				TenantId: "writer",
				Config: map[string]string{
					"integration": "jira",
				},
			},
		},
	}
	graphStore := &stubGraphStore{}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  &recordingAppendLog{},
		StateStore: runtimeStore,
		GraphStore: graphStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	issueURN := "urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123"
	userURN := "urn:cerebro:writer:runtime:writer-jira:user:acct:42"
	writeBody, err := protojson.Marshal(&cerebrov1.WriteClaimsRequest{
		Claims: []*cerebrov1.Claim{
			{
				SubjectRef: &cerebrov1.EntityRef{
					Urn:        issueURN,
					EntityType: "ticket",
					Label:      "ENG-123",
				},
				Predicate:     "status",
				ObjectValue:   "in_progress",
				ClaimType:     "attribute",
				SourceEventId: "jira-event-1",
			},
			{
				SubjectRef: &cerebrov1.EntityRef{
					Urn:        issueURN,
					EntityType: "ticket",
					Label:      "ENG-123",
				},
				Predicate: "assigned_to",
				ObjectRef: &cerebrov1.EntityRef{
					Urn:        userURN,
					EntityType: "user",
					Label:      "Alice",
				},
				ClaimType:     "relation",
				SourceEventId: "jira-event-1",
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal write claims body: %v", err)
	}
	writeReq, err := http.NewRequest(http.MethodPost, server.URL+"/source-runtimes/writer-jira/claims", bytes.NewReader(writeBody))
	if err != nil {
		t.Fatalf("new write claims request: %v", err)
	}
	writeReq.Header.Set("Content-Type", "application/json")
	writeResp, err := server.Client().Do(writeReq)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/claims error = %v", err)
	}
	defer func() {
		if closeErr := writeResp.Body.Close(); closeErr != nil {
			t.Fatalf("close write claims response body: %v", closeErr)
		}
	}()
	var writePayload map[string]any
	if err := json.NewDecoder(writeResp.Body).Decode(&writePayload); err != nil {
		t.Fatalf("decode write claims response: %v", err)
	}
	if got := writePayload["claims_written"]; got != float64(2) {
		t.Fatalf("write claims claims_written = %#v, want 2", got)
	}
	if got := writePayload["entities_upserted"]; got != float64(2) {
		t.Fatalf("write claims entities_upserted = %#v, want 2", got)
	}
	if got := writePayload["relation_links_projected"]; got != float64(1) {
		t.Fatalf("write claims relation_links_projected = %#v, want 1", got)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	writeClaimsResp, err := client.WriteClaims(context.Background(), connect.NewRequest(&cerebrov1.WriteClaimsRequest{
		RuntimeId: "writer-jira",
		Claims: []*cerebrov1.Claim{
			{
				SubjectRef: &cerebrov1.EntityRef{
					Urn:        issueURN,
					EntityType: "ticket",
					Label:      "ENG-123",
				},
				Predicate:  "exists",
				ClaimType:  "existence",
				ObservedAt: timestamppb.New(time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)),
			},
		},
	}))
	if err != nil {
		t.Fatalf("WriteClaims() error = %v", err)
	}
	if got := writeClaimsResp.Msg.GetClaimsWritten(); got != 1 {
		t.Fatalf("WriteClaims claims_written = %d, want 1", got)
	}
	if len(runtimeStore.claims) != 3 {
		t.Fatalf("len(runtimeStore.claims) = %d, want 3", len(runtimeStore.claims))
	}
	if len(runtimeStore.entities) != 2 {
		t.Fatalf("len(runtimeStore.entities) = %d, want 2", len(runtimeStore.entities))
	}
	if len(graphStore.links) != 1 {
		t.Fatalf("len(graphStore.links) = %d, want 1", len(graphStore.links))
	}

	listResp, err := server.Client().Get(server.URL + "/source-runtimes/writer-jira/claims?predicate=assigned_to&source_event_id=jira-event-1&limit=1")
	if err != nil {
		t.Fatalf("GET /source-runtimes/{id}/claims error = %v", err)
	}
	defer func() {
		if closeErr := listResp.Body.Close(); closeErr != nil {
			t.Fatalf("close list claims response body: %v", closeErr)
		}
	}()
	var listPayload map[string]any
	if err := json.NewDecoder(listResp.Body).Decode(&listPayload); err != nil {
		t.Fatalf("decode list claims response: %v", err)
	}
	listedClaims, ok := listPayload["claims"].([]any)
	if !ok || len(listedClaims) != 1 {
		t.Fatalf("list claims payload = %#v, want 1 claim", listPayload["claims"])
	}
	listedClaim, ok := listedClaims[0].(map[string]any)
	if !ok {
		t.Fatalf("list claims entry = %#v, want object", listedClaims[0])
	}
	if got := listedClaim["predicate"]; got != "assigned_to" {
		t.Fatalf("list claims predicate = %#v, want assigned_to", got)
	}

	listClaimsResp, err := client.ListClaims(context.Background(), connect.NewRequest(&cerebrov1.ListClaimsRequest{
		RuntimeId:     "writer-jira",
		Predicate:     "status",
		ObjectValue:   "in_progress",
		SourceEventId: "jira-event-1",
		Limit:         1,
	}))
	if err != nil {
		t.Fatalf("ListClaims() error = %v", err)
	}
	if got := len(listClaimsResp.Msg.GetClaims()); got != 1 {
		t.Fatalf("len(ListClaims().Claims) = %d, want 1", got)
	}
	if got := listClaimsResp.Msg.GetClaims()[0].GetObjectValue(); got != "in_progress" {
		t.Fatalf("ListClaims().Claims[0].ObjectValue = %q, want in_progress", got)
	}
	if got := runtimeStore.claimListRequest.Predicate; got != "status" {
		t.Fatalf("runtimeStore.claimListRequest.Predicate = %q, want status", got)
	}
	if got := runtimeStore.claimListRequest.ObjectValue; got != "in_progress" {
		t.Fatalf("runtimeStore.claimListRequest.ObjectValue = %q, want in_progress", got)
	}
	if got := runtimeStore.claimListRequest.SourceEventID; got != "jira-event-1" {
		t.Fatalf("runtimeStore.claimListRequest.SourceEventID = %q, want jira-event-1", got)
	}
}

func TestWriteClaimsReplaceExistingReportsRetractedClaims(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	runtimeStore := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-jira": {
				Id:       "writer-jira",
				SourceId: "sdk",
				TenantId: "writer",
				Config:   map[string]string{"integration": "jira"},
			},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  &recordingAppendLog{},
		StateStore: runtimeStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	issueURN := "urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123"
	userURN := "urn:cerebro:writer:runtime:writer-jira:user:acct:42"
	if _, err := client.WriteClaims(context.Background(), connect.NewRequest(&cerebrov1.WriteClaimsRequest{
		RuntimeId: "writer-jira",
		Claims: []*cerebrov1.Claim{
			{
				SubjectRef:    &cerebrov1.EntityRef{Urn: issueURN, EntityType: "ticket", Label: "ENG-123"},
				Predicate:     "status",
				ObjectValue:   "in_progress",
				ClaimType:     "attribute",
				SourceEventId: "jira-event-1",
			},
			{
				SubjectRef:    &cerebrov1.EntityRef{Urn: issueURN, EntityType: "ticket", Label: "ENG-123"},
				Predicate:     "assigned_to",
				ObjectRef:     &cerebrov1.EntityRef{Urn: userURN, EntityType: "user", Label: "Alice"},
				ClaimType:     "relation",
				SourceEventId: "jira-event-1",
			},
		},
	})); err != nil {
		t.Fatalf("seed WriteClaims() error = %v", err)
	}

	resp, err := client.WriteClaims(context.Background(), connect.NewRequest(&cerebrov1.WriteClaimsRequest{
		RuntimeId:       "writer-jira",
		ReplaceExisting: true,
		Claims: []*cerebrov1.Claim{
			{
				SubjectRef:    &cerebrov1.EntityRef{Urn: issueURN, EntityType: "ticket", Label: "ENG-123"},
				Predicate:     "status",
				ObjectValue:   "done",
				ClaimType:     "attribute",
				SourceEventId: "jira-event-2",
				ObservedAt:    timestamppb.New(time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)),
			},
		},
	}))
	if err != nil {
		t.Fatalf("replace WriteClaims() error = %v", err)
	}
	if got := resp.Msg.GetClaimsWritten(); got != 1 {
		t.Fatalf("replace claims_written = %d, want 1", got)
	}
	if got := resp.Msg.GetClaimsRetracted(); got != 1 {
		t.Fatalf("replace claims_retracted = %d, want 1", got)
	}
	if len(runtimeStore.claims) != 2 {
		t.Fatalf("len(runtimeStore.claims) = %d, want 2", len(runtimeStore.claims))
	}
	var retracted *ports.ClaimRecord
	for _, claim := range runtimeStore.claims {
		if claim != nil && claim.Predicate == "assigned_to" {
			retracted = claim
			break
		}
	}
	if retracted == nil {
		t.Fatal("retracted assigned_to claim = nil, want non-nil")
	}
	if got := retracted.Status; got != "retracted" {
		t.Fatalf("retracted claim status = %q, want retracted", got)
	}
	if got := retracted.SourceEventID; got != "jira-event-2" {
		t.Fatalf("retracted claim source_event_id = %q, want jira-event-2", got)
	}
}

func TestGraphNeighborhoodEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	graphStore := &stubGraphStore{
		neighborhood: &ports.EntityNeighborhood{
			Root: &ports.NeighborhoodNode{
				URN:        "urn:cerebro:writer:github_pull_request:writer/cerebro#447",
				EntityType: "github.pull_request",
				Label:      "writer/cerebro#447",
			},
			Neighbors: []*ports.NeighborhoodNode{
				{URN: "urn:cerebro:writer:github_repo:writer/cerebro", EntityType: "github.repo", Label: "writer/cerebro"},
				{URN: "urn:cerebro:writer:github_user:alice", EntityType: "github.user", Label: "Alice"},
			},
			Relations: []*ports.NeighborhoodRelation{
				{FromURN: "urn:cerebro:writer:github_user:alice", Relation: "authored", ToURN: "urn:cerebro:writer:github_pull_request:writer/cerebro#447"},
				{FromURN: "urn:cerebro:writer:github_pull_request:writer/cerebro#447", Relation: "belongs_to", ToURN: "urn:cerebro:writer:github_repo:writer/cerebro"},
			},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  &recordingAppendLog{},
		StateStore: &stubRuntimeStore{},
		GraphStore: graphStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/graph/neighborhood?root_urn=urn:cerebro:writer:github_pull_request:writer/cerebro%23447&limit=5")
	if err != nil {
		t.Fatalf("GET /graph/neighborhood error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close /graph/neighborhood response body: %v", closeErr)
		}
	}()
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode /graph/neighborhood response: %v", err)
	}
	rootPayload, ok := payload["root"].(map[string]any)
	if !ok {
		t.Fatalf("graph root payload = %#v, want object", payload["root"])
	}
	if got := rootPayload["entity_type"]; got != "github.pull_request" {
		t.Fatalf("graph root entity_type = %#v, want github.pull_request", got)
	}
	neighborsPayload, ok := payload["neighbors"].([]any)
	if !ok || len(neighborsPayload) != 2 {
		t.Fatalf("graph neighbors payload = %#v, want 2 entries", payload["neighbors"])
	}
	if graphStore.neighborhoodRootURN != "urn:cerebro:writer:github_pull_request:writer/cerebro#447" {
		t.Fatalf("graph neighborhood root urn = %q, want pull request urn", graphStore.neighborhoodRootURN)
	}
	if graphStore.neighborhoodLimit != 5 {
		t.Fatalf("graph neighborhood limit = %d, want 5", graphStore.neighborhoodLimit)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	neighborhoodResp, err := client.GetEntityNeighborhood(context.Background(), connect.NewRequest(&cerebrov1.GetEntityNeighborhoodRequest{
		RootUrn: "urn:cerebro:writer:github_pull_request:writer/cerebro#447",
		Limit:   2,
	}))
	if err != nil {
		t.Fatalf("GetEntityNeighborhood() error = %v", err)
	}
	if got := neighborhoodResp.Msg.GetRoot().GetUrn(); got != "urn:cerebro:writer:github_pull_request:writer/cerebro#447" {
		t.Fatalf("GetEntityNeighborhood root urn = %q, want pull request urn", got)
	}
	if len(neighborhoodResp.Msg.GetNeighbors()) != 2 {
		t.Fatalf("len(GetEntityNeighborhood.Neighbors) = %d, want 2", len(neighborhoodResp.Msg.GetNeighbors()))
	}
	if len(neighborhoodResp.Msg.GetRelations()) != 2 {
		t.Fatalf("len(GetEntityNeighborhood.Relations) = %d, want 2", len(neighborhoodResp.Msg.GetRelations()))
	}
}

func TestReportEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	runtimeStore := &stubRuntimeStore{
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:           "finding-1",
				RuntimeID:    "writer-okta-audit",
				RuleID:       "identity-okta-policy-rule-lifecycle-tampering",
				Severity:     "HIGH",
				Status:       "open",
				ResourceURNs: []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
				Attributes: map[string]string{
					"primary_resource_urn": "urn:cerebro:writer:okta_resource:policyrule:pol-1",
				},
			},
			"finding-2": {
				ID:           "finding-2",
				RuntimeID:    "writer-okta-audit",
				RuleID:       "identity-okta-policy-rule-lifecycle-tampering",
				Severity:     "HIGH",
				Status:       "resolved",
				ResourceURNs: []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
				Attributes: map[string]string{
					"primary_resource_urn": "urn:cerebro:writer:okta_resource:policyrule:pol-1",
				},
			},
		},
	}
	graphStore := &stubGraphStore{
		neighborhood: &ports.EntityNeighborhood{
			Root: &ports.NeighborhoodNode{
				URN:        "urn:cerebro:writer:okta_resource:policyrule:pol-1",
				EntityType: "okta.resource",
				Label:      "Require MFA",
			},
			Neighbors: []*ports.NeighborhoodNode{
				{URN: "urn:cerebro:writer:okta_user:00u2", EntityType: "okta.user", Label: "admin@writer.com"},
			},
			Relations: []*ports.NeighborhoodRelation{
				{FromURN: "urn:cerebro:writer:okta_user:00u2", Relation: "acted_on", ToURN: "urn:cerebro:writer:okta_resource:policyrule:pol-1"},
			},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  &recordingAppendLog{},
		StateStore: runtimeStore,
		GraphStore: graphStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	listResp, err := server.Client().Get(server.URL + "/reports")
	if err != nil {
		t.Fatalf("GET /reports error = %v", err)
	}
	defer func() {
		if closeErr := listResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /reports response body: %v", closeErr)
		}
	}()
	var listPayload map[string]any
	if err := json.NewDecoder(listResp.Body).Decode(&listPayload); err != nil {
		t.Fatalf("decode /reports response: %v", err)
	}
	reportsPayload, ok := listPayload["reports"].([]any)
	if !ok || len(reportsPayload) != 1 {
		t.Fatalf("/reports payload = %#v, want 1 entry", listPayload["reports"])
	}

	runReq, err := http.NewRequest(http.MethodPost, server.URL+"/reports/finding-summary/runs?runtime_id=writer-okta-audit&graph_limit=2", nil)
	if err != nil {
		t.Fatalf("new run report request: %v", err)
	}
	runResp, err := server.Client().Do(runReq)
	if err != nil {
		t.Fatalf("POST /reports/{id}/runs error = %v", err)
	}
	defer func() {
		if closeErr := runResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /reports/{id}/runs response body: %v", closeErr)
		}
	}()
	var runPayload map[string]any
	if err := json.NewDecoder(runResp.Body).Decode(&runPayload); err != nil {
		t.Fatalf("decode /reports/{id}/runs response: %v", err)
	}
	runBody, ok := runPayload["run"].(map[string]any)
	if !ok {
		t.Fatalf("run payload = %#v, want object", runPayload["run"])
	}
	if got := runBody["report_id"]; got != "finding-summary" {
		t.Fatalf("run report_id = %#v, want finding-summary", got)
	}
	resultBody, ok := runBody["result"].(map[string]any)
	if !ok {
		t.Fatalf("run result payload = %#v, want object", runBody["result"])
	}
	if got := resultBody["total_findings"]; got != float64(2) {
		t.Fatalf("run total_findings = %#v, want 2", got)
	}
	if got := resultBody["graph_evidence_status"]; got != "included" {
		t.Fatalf("run graph_evidence_status = %#v, want included", got)
	}
	graphEvidencePayload, ok := resultBody["graph_evidence"].([]any)
	if !ok || len(graphEvidencePayload) != 1 {
		t.Fatalf("run graph_evidence = %#v, want 1 entry", resultBody["graph_evidence"])
	}
	graphEvidenceEntry, ok := graphEvidencePayload[0].(map[string]any)
	if !ok {
		t.Fatalf("run graph evidence entry = %#v, want object", graphEvidencePayload[0])
	}
	if got := graphEvidenceEntry["resource_urn"]; got != "urn:cerebro:writer:okta_resource:policyrule:pol-1" {
		t.Fatalf("run graph evidence resource_urn = %#v, want policy rule urn", got)
	}
	runID, ok := runBody["id"].(string)
	if !ok || runID == "" {
		t.Fatalf("run id = %#v, want non-empty string", runBody["id"])
	}
	if len(runtimeStore.reportRuns) != 1 {
		t.Fatalf("len(runtimeStore.reportRuns) = %d, want 1", len(runtimeStore.reportRuns))
	}
	if graphStore.neighborhoodRootURN != "urn:cerebro:writer:okta_resource:policyrule:pol-1" {
		t.Fatalf("graph evidence root urn = %q, want policy rule urn", graphStore.neighborhoodRootURN)
	}
	if graphStore.neighborhoodLimit != 2 {
		t.Fatalf("graph evidence limit = %d, want 2", graphStore.neighborhoodLimit)
	}

	getResp, err := server.Client().Get(server.URL + "/report-runs/" + runID)
	if err != nil {
		t.Fatalf("GET /report-runs/{id} error = %v", err)
	}
	defer func() {
		if closeErr := getResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /report-runs/{id} response body: %v", closeErr)
		}
	}()
	var getPayload map[string]any
	if err := json.NewDecoder(getResp.Body).Decode(&getPayload); err != nil {
		t.Fatalf("decode /report-runs/{id} response: %v", err)
	}
	getRunPayload, ok := getPayload["run"].(map[string]any)
	if !ok {
		t.Fatalf("get run payload = %#v, want object", getPayload["run"])
	}
	if got := getRunPayload["id"]; got != runID {
		t.Fatalf("get run id = %#v, want %q", got, runID)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	listReportsResp, err := client.ListReportDefinitions(context.Background(), connect.NewRequest(&cerebrov1.ListReportDefinitionsRequest{}))
	if err != nil {
		t.Fatalf("ListReportDefinitions() error = %v", err)
	}
	if len(listReportsResp.Msg.GetReports()) != 1 {
		t.Fatalf("len(ListReportDefinitions.Reports) = %d, want 1", len(listReportsResp.Msg.GetReports()))
	}
	runReportResp, err := client.RunReport(context.Background(), connect.NewRequest(&cerebrov1.RunReportRequest{
		ReportId: "finding-summary",
		Parameters: map[string]string{
			"runtime_id": "writer-okta-audit",
		},
	}))
	if err != nil {
		t.Fatalf("RunReport() error = %v", err)
	}
	if got := runReportResp.Msg.GetRun().GetReportId(); got != "finding-summary" {
		t.Fatalf("RunReport report id = %q, want finding-summary", got)
	}
	getRunResp, err := client.GetReportRun(context.Background(), connect.NewRequest(&cerebrov1.GetReportRunRequest{
		Id: runReportResp.Msg.GetRun().GetId(),
	}))
	if err != nil {
		t.Fatalf("GetReportRun() error = %v", err)
	}
	if got := getRunResp.Msg.GetRun().GetId(); got != runReportResp.Msg.GetRun().GetId() {
		t.Fatalf("GetReportRun id = %q, want %q", got, runReportResp.Msg.GetRun().GetId())
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
	sdk, err := sdksource.New()
	if err != nil {
		return nil, err
	}
	return sourcecdk.NewRegistry(source, okta, sdk)
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

func cloneFinding(finding *ports.FindingRecord) *ports.FindingRecord {
	if finding == nil {
		return nil
	}
	resourceURNs := make([]string, len(finding.ResourceURNs))
	copy(resourceURNs, finding.ResourceURNs)
	eventIDs := make([]string, len(finding.EventIDs))
	copy(eventIDs, finding.EventIDs)
	attributes := make(map[string]string, len(finding.Attributes))
	for key, value := range finding.Attributes {
		attributes[key] = value
	}
	return &ports.FindingRecord{
		ID:              finding.ID,
		Fingerprint:     finding.Fingerprint,
		TenantID:        finding.TenantID,
		RuntimeID:       finding.RuntimeID,
		RuleID:          finding.RuleID,
		Title:           finding.Title,
		Severity:        finding.Severity,
		Status:          finding.Status,
		Summary:         finding.Summary,
		ResourceURNs:    resourceURNs,
		EventIDs:        eventIDs,
		Attributes:      attributes,
		FirstObservedAt: finding.FirstObservedAt,
		LastObservedAt:  finding.LastObservedAt,
	}
}

func findingMatches(request ports.ListFindingsRequest, finding *ports.FindingRecord) bool {
	if finding == nil {
		return false
	}
	if strings.TrimSpace(finding.RuntimeID) != strings.TrimSpace(request.RuntimeID) {
		return false
	}
	if request.FindingID != "" && strings.TrimSpace(finding.ID) != strings.TrimSpace(request.FindingID) {
		return false
	}
	if request.RuleID != "" && strings.TrimSpace(finding.RuleID) != strings.TrimSpace(request.RuleID) {
		return false
	}
	if request.Severity != "" && strings.TrimSpace(finding.Severity) != strings.TrimSpace(request.Severity) {
		return false
	}
	if request.Status != "" && strings.TrimSpace(finding.Status) != strings.TrimSpace(request.Status) {
		return false
	}
	if request.ResourceURN != "" && !containsTrimmed(finding.ResourceURNs, request.ResourceURN) {
		return false
	}
	if request.EventID != "" && !containsTrimmed(finding.EventIDs, request.EventID) {
		return false
	}
	return true
}

func cloneClaim(claim *ports.ClaimRecord) *ports.ClaimRecord {
	if claim == nil {
		return nil
	}
	attributes := make(map[string]string, len(claim.Attributes))
	for key, value := range claim.Attributes {
		attributes[key] = value
	}
	return &ports.ClaimRecord{
		ID:            claim.ID,
		RuntimeID:     claim.RuntimeID,
		TenantID:      claim.TenantID,
		SubjectURN:    claim.SubjectURN,
		SubjectRef:    cloneEntityRef(claim.SubjectRef),
		Predicate:     claim.Predicate,
		ObjectURN:     claim.ObjectURN,
		ObjectRef:     cloneEntityRef(claim.ObjectRef),
		ObjectValue:   claim.ObjectValue,
		ClaimType:     claim.ClaimType,
		Status:        claim.Status,
		SourceEventID: claim.SourceEventID,
		ObservedAt:    claim.ObservedAt,
		ValidFrom:     claim.ValidFrom,
		ValidTo:       claim.ValidTo,
		Attributes:    attributes,
	}
}

func claimMatches(request ports.ListClaimsRequest, claim *ports.ClaimRecord) bool {
	if claim == nil {
		return false
	}
	if strings.TrimSpace(claim.RuntimeID) != strings.TrimSpace(request.RuntimeID) {
		return false
	}
	if request.ClaimID != "" && strings.TrimSpace(claim.ID) != strings.TrimSpace(request.ClaimID) {
		return false
	}
	if request.SubjectURN != "" && strings.TrimSpace(claim.SubjectURN) != strings.TrimSpace(request.SubjectURN) {
		return false
	}
	if request.Predicate != "" && strings.TrimSpace(claim.Predicate) != strings.TrimSpace(request.Predicate) {
		return false
	}
	if request.ObjectURN != "" && strings.TrimSpace(claim.ObjectURN) != strings.TrimSpace(request.ObjectURN) {
		return false
	}
	if request.ObjectValue != "" && strings.TrimSpace(claim.ObjectValue) != strings.TrimSpace(request.ObjectValue) {
		return false
	}
	if request.ClaimType != "" && strings.TrimSpace(claim.ClaimType) != strings.TrimSpace(request.ClaimType) {
		return false
	}
	if request.Status != "" && strings.TrimSpace(claim.Status) != strings.TrimSpace(request.Status) {
		return false
	}
	if request.SourceEventID != "" && strings.TrimSpace(claim.SourceEventID) != strings.TrimSpace(request.SourceEventID) {
		return false
	}
	return true
}

func containsTrimmed(values []string, expected string) bool {
	trimmedExpected := strings.TrimSpace(expected)
	for _, value := range values {
		if strings.TrimSpace(value) == trimmedExpected {
			return true
		}
	}
	return false
}

func findingEvaluationRunMatches(request ports.ListFindingEvaluationRunsRequest, run *cerebrov1.FindingEvaluationRun) bool {
	if run == nil {
		return false
	}
	if strings.TrimSpace(run.GetRuntimeId()) != strings.TrimSpace(request.RuntimeID) {
		return false
	}
	if request.RuleID != "" && strings.TrimSpace(run.GetRuleId()) != strings.TrimSpace(request.RuleID) {
		return false
	}
	if request.Status != "" && strings.TrimSpace(run.GetStatus()) != strings.TrimSpace(request.Status) {
		return false
	}
	return true
}

func cloneReportRun(run *cerebrov1.ReportRun) *cerebrov1.ReportRun {
	if run == nil {
		return nil
	}
	return proto.Clone(run).(*cerebrov1.ReportRun)
}

func cloneFindingEvaluationRun(run *cerebrov1.FindingEvaluationRun) *cerebrov1.FindingEvaluationRun {
	if run == nil {
		return nil
	}
	return proto.Clone(run).(*cerebrov1.FindingEvaluationRun)
}

func cloneNeighborhood(neighborhood *ports.EntityNeighborhood) *ports.EntityNeighborhood {
	if neighborhood == nil {
		return nil
	}
	cloned := &ports.EntityNeighborhood{
		Root:      cloneNeighborhoodNode(neighborhood.Root),
		Neighbors: make([]*ports.NeighborhoodNode, 0, len(neighborhood.Neighbors)),
		Relations: make([]*ports.NeighborhoodRelation, 0, len(neighborhood.Relations)),
	}
	for _, neighbor := range neighborhood.Neighbors {
		cloned.Neighbors = append(cloned.Neighbors, cloneNeighborhoodNode(neighbor))
	}
	for _, relation := range neighborhood.Relations {
		cloned.Relations = append(cloned.Relations, cloneNeighborhoodRelation(relation))
	}
	return cloned
}

func cloneNeighborhoodNode(node *ports.NeighborhoodNode) *ports.NeighborhoodNode {
	if node == nil {
		return nil
	}
	return &ports.NeighborhoodNode{
		URN:        node.URN,
		EntityType: node.EntityType,
		Label:      node.Label,
	}
}

func cloneNeighborhoodRelation(relation *ports.NeighborhoodRelation) *ports.NeighborhoodRelation {
	if relation == nil {
		return nil
	}
	return &ports.NeighborhoodRelation{
		FromURN:  relation.FromURN,
		Relation: relation.Relation,
		ToURN:    relation.ToURN,
	}
}

func findingTestEvent(id string, eventType string, outcome string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "okta",
		Kind:       "okta.audit",
		OccurredAt: timestamppb.New(time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)),
		SchemaRef:  "okta/audit/v1",
		Attributes: map[string]string{
			"domain":                            "writer.okta.com",
			"event_type":                        eventType,
			"resource_id":                       "pol-1",
			"resource_type":                     "PolicyRule",
			"actor_id":                          "00u2",
			"actor_type":                        "User",
			"actor_alternate_id":                "admin@writer.com",
			"actor_display_name":                "Admin Example",
			"outcome_result":                    outcome,
			ports.EventAttributeSourceRuntimeID: "writer-okta-audit",
		},
	}
}

func projectedLinkKey(link *ports.ProjectedLink) string {
	return link.FromURN + "|" + link.Relation + "|" + link.ToURN
}

func cloneEntityRef(ref *cerebrov1.EntityRef) *cerebrov1.EntityRef {
	if ref == nil {
		return nil
	}
	return proto.Clone(ref).(*cerebrov1.EntityRef)
}
