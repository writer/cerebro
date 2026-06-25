package graphrebuild

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
)

type runtimeStore struct {
	runtimes map[string]*cerebrov1.SourceRuntime
}

func (s *runtimeStore) Ping(context.Context) error {
	return nil
}

func (s *runtimeStore) PutSourceRuntime(_ context.Context, runtime *cerebrov1.SourceRuntime) error {
	if s.runtimes == nil {
		s.runtimes = make(map[string]*cerebrov1.SourceRuntime)
	}
	s.runtimes[runtime.GetId()] = proto.Clone(runtime).(*cerebrov1.SourceRuntime)
	return nil
}

func (s *runtimeStore) GetSourceRuntime(_ context.Context, id string) (*cerebrov1.SourceRuntime, error) {
	runtime, ok := s.runtimes[id]
	if !ok {
		return nil, ports.ErrSourceRuntimeNotFound
	}
	return proto.Clone(runtime).(*cerebrov1.SourceRuntime), nil
}

type testSource struct {
	spec      *cerebrov1.SourceSpec
	pages     [][]*cerebrov1.EventEnvelope
	delay     time.Duration
	readToken string
}

func (s *testSource) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

func (s *testSource) Check(context.Context, sourcecdk.Config) error {
	return nil
}

func (s *testSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (s *testSource) Read(_ context.Context, config sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	s.readToken, _ = config.Lookup("token")
	index := 0
	if cursor != nil && cursor.GetOpaque() != "" {
		parsed, err := strconv.Atoi(cursor.GetOpaque())
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		index = parsed
	}
	if index >= len(s.pages) {
		return sourcecdk.Pull{}, nil
	}
	events := make([]*cerebrov1.EventEnvelope, 0, len(s.pages[index]))
	for _, event := range s.pages[index] {
		if event == nil {
			events = append(events, nil)
			continue
		}
		events = append(events, proto.Clone(event).(*cerebrov1.EventEnvelope))
	}
	checkpoint := &cerebrov1.SourceCheckpoint{CursorOpaque: strconv.Itoa(index + 1)}
	if len(events) != 0 {
		checkpoint.Watermark = events[len(events)-1].GetOccurredAt()
	}
	pull := sourcecdk.Pull{
		Events:     events,
		Checkpoint: checkpoint,
	}
	if index+1 < len(s.pages) {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: strconv.Itoa(index + 1)}
	}
	return pull, nil
}

type eventReplayer struct {
	requests []ports.ReplayRequest
	events   []*cerebrov1.EventEnvelope
}

func (r *eventReplayer) Replay(_ context.Context, req ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	r.requests = append(r.requests, req)
	replayed := make([]*cerebrov1.EventEnvelope, 0, len(r.events))
	for _, event := range r.events {
		if event == nil {
			continue
		}
		if event.GetAttributes()[ports.EventAttributeSourceRuntimeID] != req.RuntimeID {
			continue
		}
		replayed = append(replayed, proto.Clone(event).(*cerebrov1.EventEnvelope))
		if req.Limit > 0 && uint64(len(replayed)) >= uint64(req.Limit) { // #nosec G115 -- replayed length is widened only for comparison with uint32 request limit.
			break
		}
	}
	return replayed, nil
}

var errSummaryProbe = errors.New("summary probe failure")

type summaryProbeStore struct {
	delay     time.Duration
	failStage string
	mu        sync.Mutex
	active    int
	maxActive int
}

func (s *summaryProbeStore) observe(ctx context.Context, stage string) error {
	s.mu.Lock()
	s.active++
	if s.active > s.maxActive {
		s.maxActive = s.active
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.active--
		s.mu.Unlock()
	}()
	if s.delay > 0 {
		timer := time.NewTimer(s.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if s.failStage == stage {
		return errSummaryProbe
	}
	return nil
}

func (s *summaryProbeStore) maxObservedActive() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxActive
}

func (s *summaryProbeStore) Counts(ctx context.Context) (graphstore.Counts, error) {
	if err := s.observe(ctx, "counts"); err != nil {
		return graphstore.Counts{}, err
	}
	return graphstore.Counts{Nodes: 7, Relations: 11}, nil
}

func (s *summaryProbeStore) IntegrityChecks(ctx context.Context) ([]graphstore.IntegrityCheck, error) {
	if err := s.observe(ctx, "integrity"); err != nil {
		return nil, err
	}
	return []graphstore.IntegrityCheck{{Name: "fixture_check", Passed: true}}, nil
}

func (s *summaryProbeStore) PathPatterns(ctx context.Context, _ int) ([]graphstore.PathPattern, error) {
	if err := s.observe(ctx, "patterns"); err != nil {
		return nil, err
	}
	return []graphstore.PathPattern{{
		FromType:       "github.user",
		FirstRelation:  "authored",
		ViaType:        "github.pull_request",
		SecondRelation: "belongs_to",
		ToType:         "github.code.repository",
		Count:          2,
	}}, nil
}

func (s *summaryProbeStore) Topology(ctx context.Context) (graphstore.Topology, error) {
	if err := s.observe(ctx, "topology"); err != nil {
		return graphstore.Topology{}, err
	}
	return graphstore.Topology{SourcesOnly: 2, SinksOnly: 3, Intermediates: 4}, nil
}

func (s *summaryProbeStore) SampleTraversals(ctx context.Context, _ int) ([]graphstore.Traversal, error) {
	if err := s.observe(ctx, "traversals"); err != nil {
		return nil, err
	}
	return []graphstore.Traversal{{
		FromURN:        "user:octocat",
		FirstRelation:  "authored",
		ViaURN:         "pr:418",
		SecondRelation: "belongs_to",
		ToURN:          "repo:cerebro",
	}}, nil
}

func TestCollectGraphSummaryRunsReadsConcurrently(t *testing.T) {
	store := &summaryProbeStore{delay: 20 * time.Millisecond}

	summary, err := collectGraphSummary(context.Background(), store, 3)
	if err != nil {
		t.Fatalf("collectGraphSummary() error = %v", err)
	}
	if got := store.maxObservedActive(); got < 2 {
		t.Fatalf("max concurrent summary reads = %d, want at least 2", got)
	}
	if summary.counts.Nodes != 7 || summary.counts.Relations != 11 {
		t.Fatalf("summary counts = %#v, want fixture counts", summary.counts)
	}
	if len(summary.integrityChecks) != 1 {
		t.Fatalf("len(integrityChecks) = %d, want 1", len(summary.integrityChecks))
	}
	if len(summary.pathPatterns) != 1 {
		t.Fatalf("len(pathPatterns) = %d, want 1", len(summary.pathPatterns))
	}
	if summary.topology.Intermediates != 4 {
		t.Fatalf("topology.Intermediates = %d, want 4", summary.topology.Intermediates)
	}
	if len(summary.traversals) != 1 {
		t.Fatalf("len(traversals) = %d, want 1", len(summary.traversals))
	}
	if summary.countDurationMillis == 0 || summary.integrityDurationMillis == 0 || summary.patternDurationMillis == 0 || summary.topologyDurationMillis == 0 || summary.traversalDurationMillis == 0 {
		t.Fatalf("summary durations include zero values: %#v", summary)
	}
}

func TestCollectGraphSummaryPropagatesReadErrors(t *testing.T) {
	store := &summaryProbeStore{failStage: "patterns"}

	_, err := collectGraphSummary(context.Background(), store, 3)
	if !errors.Is(err, errSummaryProbe) {
		t.Fatalf("collectGraphSummary() error = %v, want %v", err, errSummaryProbe)
	}
	var summaryErr *graphSummaryReadError
	if !errors.As(err, &summaryErr) {
		t.Fatalf("collectGraphSummary() error = %v, want graphSummaryReadError", err)
	}
	if summaryErr.stage != "verify graph path patterns" {
		t.Fatalf("summary error stage = %q, want path pattern context", summaryErr.stage)
	}
}

func TestRebuildDryRunProjectsRuntimeIntoTemporaryGraph(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(&testSource{
		spec: &cerebrov1.SourceSpec{Id: "github", Name: "GitHub"},
		pages: [][]*cerebrov1.EventEnvelope{
			{
				testEvent("github-audit-1", "github.audit", map[string]string{
					"org":           "writer",
					"repo":          "writer/cerebro",
					"resource_id":   "writer/cerebro",
					"resource_type": "repository",
					"actor":         "octocat",
					"action":        "repo.create",
				}),
			},
			{
				testEvent("github-pr-1", "github.pull_request", map[string]string{
					"owner":       "writer",
					"repository":  "writer/cerebro",
					"pull_number": "418",
					"author":      "octocat",
					"state":       "open",
					"html_url":    "https://github.com/writer/cerebro/pull/418",
				}),
			},
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-github": {
				Id:       "writer-github",
				SourceId: "github",
				TenantId: "writer-dogfood",
				Config:   map[string]string{"token": "fixture-token"},
			},
		},
	}
	service := New(registry, store, nil)

	result, err := service.RebuildDryRun(context.Background(), Request{
		RuntimeID:    "writer-github",
		PageLimit:    2,
		PreviewLimit: 10,
	})
	if err != nil {
		t.Fatalf("RebuildDryRun() error = %v", err)
	}
	if result.PagesRead != 2 {
		t.Fatalf("PagesRead = %d, want 2", result.PagesRead)
	}
	if result.EventsRead != 2 {
		t.Fatalf("EventsRead = %d, want 2", result.EventsRead)
	}
	if result.EntitiesProjected != 11 {
		t.Fatalf("EntitiesProjected = %d, want 11", result.EntitiesProjected)
	}
	if result.LinksProjected != 13 {
		t.Fatalf("LinksProjected = %d, want 13", result.LinksProjected)
	}
	if result.GraphNodes != 6 {
		t.Fatalf("GraphNodes = %d, want 6", result.GraphNodes)
	}
	if result.GraphLinks != 8 {
		t.Fatalf("GraphLinks = %d, want 8", result.GraphLinks)
	}
	if len(result.StageConfirmations) != 9 {
		t.Fatalf("len(StageConfirmations) = %d, want 9", len(result.StageConfirmations))
	}
	assertStageNames(t, result.StageConfirmations, "resolve_runtime", "open_graph", "read_source", "project_graph", "count_graph", "verify_integrity", "verify_path_patterns", "verify_topology", "verify_traversals")
	if got := result.StageConfirmations[5].AssertionsPassed; got != 8 {
		t.Fatalf("verify_integrity assertions_passed = %d, want 8", got)
	}
	if got := result.StageConfirmations[5].AssertionsFailed; got != 0 {
		t.Fatalf("verify_integrity assertions_failed = %d, want 0", got)
	}
	if got := result.StageConfirmations[6].PatternsVerified; got != 6 {
		t.Fatalf("verify_path_patterns patterns_verified = %d, want 6", got)
	}
	if got := result.StageConfirmations[7].TopologyBuckets; got != 4 {
		t.Fatalf("verify_topology topology_buckets = %d, want 4", got)
	}
	if got := result.StageConfirmations[8].TraversalsVerified; got != 6 {
		t.Fatalf("verify_traversals traversals_verified = %d, want 6", got)
	}
	if len(result.ReadPages) != 2 {
		t.Fatalf("len(ReadPages) = %d, want 2", len(result.ReadPages))
	}
	assertReadPage(t, result.ReadPages[0], 1, 1, "1", "1", "github-audit-1", "github-audit-1")
	assertReadPage(t, result.ReadPages[1], 2, 1, "2", "", "github-pr-1", "github-pr-1")
	if len(result.EventProjections) != 2 {
		t.Fatalf("len(EventProjections) = %d, want 2", len(result.EventProjections))
	}
	assertEventProjection(t, result.EventProjections[0], "github-audit-1", "github.audit", 5, 6, 5, 6)
	assertEventProjection(t, result.EventProjections[1], "github-pr-1", "github.pull_request", 6, 7, 6, 8)
	if got := countValue(result.EventKinds, "github.audit"); got != 1 {
		t.Fatalf("event kind github.audit = %d, want 1", got)
	}
	if got := countValue(result.EventKinds, "github.pull_request"); got != 1 {
		t.Fatalf("event kind github.pull_request = %d, want 1", got)
	}
	if got := countValue(result.GraphEntityTypes, "github.pull_request"); got != 1 {
		t.Fatalf("graph entity type github.pull_request = %d, want 1", got)
	}
	if got := countValue(result.GraphEntityTypes, "identifier.login"); got != 1 {
		t.Fatalf("graph entity type identifier.login = %d, want 1", got)
	}
	if got := countValue(result.GraphRelationTypes, "belongs_to"); got != 2 {
		t.Fatalf("graph relation type belongs_to = %d, want 2", got)
	}
	if got := countValue(result.GraphRelationTypes, "authored"); got != 1 {
		t.Fatalf("graph relation type authored = %d, want 1", got)
	}
	if len(result.GraphAssertions) != 8 {
		t.Fatalf("len(GraphAssertions) = %d, want 8", len(result.GraphAssertions))
	}
	if !containsAssertion(result.GraphAssertions, "cross_kind_identity_fragmentation", 0, 0, true) {
		t.Fatalf("GraphAssertions missing cross_kind_identity_fragmentation: %#v", result.GraphAssertions)
	}
	if !containsAssertion(result.GraphAssertions, "tenant_mismatched_relations", 0, 0, true) {
		t.Fatalf("GraphAssertions missing tenant_mismatched_relations: %#v", result.GraphAssertions)
	}
	if !containsAssertion(result.GraphAssertions, "self_referential_relations", 0, 0, true) {
		t.Fatalf("GraphAssertions missing self_referential_relations: %#v", result.GraphAssertions)
	}
	if !containsAssertion(result.GraphAssertions, "github_code_repositories_without_owner_link", 0, 0, true) {
		t.Fatalf("GraphAssertions missing github_code_repositories_without_owner_link: %#v", result.GraphAssertions)
	}
	if !containsAssertion(result.GraphAssertions, "aws_public_endpoints_without_instance_link", 0, 0, true) {
		t.Fatalf("GraphAssertions missing aws_public_endpoints_without_instance_link: %#v", result.GraphAssertions)
	}
	if len(result.GraphPathPatterns) != 6 {
		t.Fatalf("len(GraphPathPatterns) = %d, want 6", len(result.GraphPathPatterns))
	}
	if !containsPathPatternPreview(result.GraphPathPatterns, "github.user -[authored]-> github.pull_request -[belongs_to]-> github.code.repository", 1) {
		t.Fatalf("GraphPathPatterns missing authored pattern: %#v", result.GraphPathPatterns)
	}
	if len(result.GraphTopology) != 4 {
		t.Fatalf("len(GraphTopology) = %d, want 4", len(result.GraphTopology))
	}
	if !containsTopologyPreview(result.GraphTopology, "isolated", 0) {
		t.Fatalf("GraphTopology missing isolated bucket: %#v", result.GraphTopology)
	}
	if !containsTopologyPreview(result.GraphTopology, "sources_only", 1) {
		t.Fatalf("GraphTopology missing sources_only bucket: %#v", result.GraphTopology)
	}
	if !containsTopologyPreview(result.GraphTopology, "sinks_only", 1) {
		t.Fatalf("GraphTopology missing sinks_only bucket: %#v", result.GraphTopology)
	}
	if !containsTopologyPreview(result.GraphTopology, "intermediates", 4) {
		t.Fatalf("GraphTopology missing intermediates bucket: %#v", result.GraphTopology)
	}
	if len(result.GraphTraversals) != 6 {
		t.Fatalf("len(GraphTraversals) = %d, want 6", len(result.GraphTraversals))
	}
	if !containsTraversalPath(result.GraphTraversals, "octocat -[authored]-> writer/cerebro#418 -[belongs_to]-> writer/cerebro") {
		t.Fatalf("GraphTraversals missing authored path: %#v", result.GraphTraversals)
	}
	if len(result.Events) != 2 {
		t.Fatalf("len(Events) = %d, want 2", len(result.Events))
	}
	if !containsEntityURN(result.PreviewEntities, "urn:cerebro:writer-dogfood:github_pull_request:writer/cerebro#418") {
		t.Fatalf("PreviewEntities missing projected pull request: %#v", result.PreviewEntities)
	}
	if !containsEntityURN(result.PreviewEntities, "urn:cerebro:writer-dogfood:identifier:login:octocat") {
		t.Fatalf("PreviewEntities missing identifier node: %#v", result.PreviewEntities)
	}
	if !containsLink(result.PreviewLinks, "urn:cerebro:writer-dogfood:github_user:octocat", "authored", "urn:cerebro:writer-dogfood:github_pull_request:writer/cerebro#418") {
		t.Fatalf("PreviewLinks missing authored relation: %#v", result.PreviewLinks)
	}
}

func TestRebuildDryRunResolvesRuntimeConfigReferences(t *testing.T) {
	source := &testSource{
		spec:  &cerebrov1.SourceSpec{Id: "github", Name: "GitHub"},
		pages: [][]*cerebrov1.EventEnvelope{{testEvent("github-audit-1", "github.audit", nil)}},
	}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &runtimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"writer-github": {
			Id:       "writer-github",
			SourceId: "github",
			TenantId: "writer",
			Config:   map[string]string{"token": "env:TOKEN"},
		},
	}}
	service := New(registry, store, nil).WithConfigPreparer(func(_ context.Context, _ string, values map[string]string) (map[string]string, error) {
		if got := values[sourceconfig.RuntimeTenantIDKey]; got != "writer" {
			t.Fatalf("runtime tenant config = %q, want writer", got)
		}
		resolved := make(map[string]string, len(values))
		for key, value := range values {
			if value == "env:TOKEN" {
				resolved[key] = "resolved-token"
				continue
			}
			resolved[key] = value
		}
		return resolved, nil
	})

	if _, err := service.RebuildDryRun(context.Background(), Request{RuntimeID: "writer-github"}); err != nil {
		t.Fatalf("RebuildDryRun() error = %v", err)
	}
	if source.readToken != "resolved-token" {
		t.Fatalf("source read token = %q, want resolved-token", source.readToken)
	}
}

func TestRebuildDryRunProjectsEventsBeyondPreviewLimit(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(&testSource{
		spec: &cerebrov1.SourceSpec{Id: "github", Name: "GitHub"},
		pages: [][]*cerebrov1.EventEnvelope{
			{
				testEvent("github-audit-1", "github.audit", map[string]string{
					"org":           "writer",
					"repo":          "writer/cerebro",
					"resource_id":   "writer/cerebro",
					"resource_type": "repository",
					"actor":         "octocat",
					"action":        "repo.create",
				}),
				testEvent("github-pr-1", "github.pull_request", map[string]string{
					"owner":       "writer",
					"repository":  "writer/cerebro",
					"pull_number": "418",
					"author":      "octocat",
					"state":       "open",
					"html_url":    "https://github.com/writer/cerebro/pull/418",
				}),
			},
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := New(registry, &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-github": {Id: "writer-github", SourceId: "github", TenantId: "writer-dogfood", Config: map[string]string{"token": "fixture-token"}},
		},
	}, nil)

	result, err := service.RebuildDryRun(context.Background(), Request{RuntimeID: "writer-github", PreviewLimit: 1})
	if err != nil {
		t.Fatalf("RebuildDryRun() error = %v", err)
	}
	if got := len(result.Events); got != 1 {
		t.Fatalf("len(Events) = %d, want preview limit 1", got)
	}
	if result.EventsRead != 2 {
		t.Fatalf("EventsRead = %d, want 2", result.EventsRead)
	}
	if result.GraphNodes < 6 {
		t.Fatalf("GraphNodes = %d, want graph to include events beyond preview limit", result.GraphNodes)
	}
}

func TestRebuildDryRunContinuesAfterEmptyPageWithCursor(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(&testSource{
		spec: &cerebrov1.SourceSpec{Id: "github", Name: "GitHub"},
		pages: [][]*cerebrov1.EventEnvelope{
			{},
			{
				testEvent("github-audit-1", "github.audit", map[string]string{
					"org":           "writer",
					"repo":          "writer/cerebro",
					"resource_id":   "writer/cerebro",
					"resource_type": "repository",
					"actor":         "octocat",
					"action":        "repo.create",
				}),
			},
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := New(registry, &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-github": {Id: "writer-github", SourceId: "github", TenantId: "writer-dogfood", Config: map[string]string{"token": "fixture-token"}},
		},
	}, nil)

	result, err := service.RebuildDryRun(context.Background(), Request{RuntimeID: "writer-github", PageLimit: 2, PreviewLimit: 10})
	if err != nil {
		t.Fatalf("RebuildDryRun() error = %v", err)
	}
	if result.PagesRead != 2 {
		t.Fatalf("PagesRead = %d, want 2", result.PagesRead)
	}
	if result.EventsRead != 1 {
		t.Fatalf("EventsRead = %d, want 1", result.EventsRead)
	}
	if len(result.ReadPages) != 2 {
		t.Fatalf("len(ReadPages) = %d, want 2", len(result.ReadPages))
	}
	if got := result.ReadPages[0].Page; got != 1 {
		t.Fatalf("ReadPages[0].Page = %d, want 1", got)
	}
	if got := result.ReadPages[0].Events; got != 0 {
		t.Fatalf("ReadPages[0].Events = %d, want 0", got)
	}
	if got := result.ReadPages[0].CheckpointCursor; got != "1" {
		t.Fatalf("ReadPages[0].CheckpointCursor = %q, want 1", got)
	}
	if got := result.ReadPages[0].NextCursor; got != "1" {
		t.Fatalf("ReadPages[0].NextCursor = %q, want 1", got)
	}
	assertReadPage(t, result.ReadPages[1], 2, 1, "2", "", "github-audit-1", "github-audit-1")
	if got := countValue(result.EventKinds, "github.audit"); got != 1 {
		t.Fatalf("event kind github.audit = %d, want 1", got)
	}
}

func TestRebuildDryRunDoesNotChargeReadTimeToProjectStage(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(&testSource{
		spec:  &cerebrov1.SourceSpec{Id: "github", Name: "GitHub"},
		pages: [][]*cerebrov1.EventEnvelope{{}},
		delay: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := New(registry, &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-github": {Id: "writer-github", SourceId: "github", TenantId: "writer-dogfood", Config: map[string]string{"token": "fixture-token"}},
		},
	}, nil)

	result, err := service.RebuildDryRun(context.Background(), Request{RuntimeID: "writer-github", PageLimit: 1, PreviewLimit: 10})
	if err != nil {
		t.Fatalf("RebuildDryRun() error = %v", err)
	}
	readStage := stageByName(result.StageConfirmations, "read_source")
	if readStage == nil {
		t.Fatalf("read_source stage missing: %#v", result.StageConfirmations)
	}
	if readStage.DurationMillis == 0 {
		t.Fatal("read_source duration = 0, want delayed read time")
	}
	projectStage := stageByName(result.StageConfirmations, "project_graph")
	if projectStage == nil {
		t.Fatalf("project_graph stage missing: %#v", result.StageConfirmations)
	}
	if projectStage.DurationMillis != 0 {
		t.Fatalf("project_graph duration = %d, want 0 with no projected events", projectStage.DurationMillis)
	}
}

func TestRebuildDryRunProjectsDependabotAlertGraph(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(&testSource{
		spec: &cerebrov1.SourceSpec{Id: "github", Name: "GitHub"},
		pages: [][]*cerebrov1.EventEnvelope{
			{
				testEvent("github-dependabot-alert-1", "github.dependabot_alert", map[string]string{
					"advisory_ghsa_id": "GHSA-1234-5678-90ab",
					"alert_number":     "5",
					"ecosystem":        "gomod",
					"html_url":         "https://github.com/writer/cerebro/security/dependabot/5",
					"owner":            "writer",
					"package":          "golang.org/x/net",
					"repository":       "writer/cerebro",
					"severity":         "HIGH",
					"state":            "open",
				}),
			},
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := New(registry, &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-github": {
				Id:       "writer-github",
				SourceId: "github",
				TenantId: "writer-dogfood",
				Config:   map[string]string{"token": "fixture-token"},
			},
		},
	}, nil)

	result, err := service.RebuildDryRun(context.Background(), Request{
		RuntimeID:    "writer-github",
		PreviewLimit: 10,
	})
	if err != nil {
		t.Fatalf("RebuildDryRun() error = %v", err)
	}
	if result.EventsRead != 1 {
		t.Fatalf("EventsRead = %d, want 1", result.EventsRead)
	}
	if result.EntitiesProjected != 7 {
		t.Fatalf("EntitiesProjected = %d, want 7", result.EntitiesProjected)
	}
	if result.LinksProjected != 8 {
		t.Fatalf("LinksProjected = %d, want 8", result.LinksProjected)
	}
	if result.GraphNodes != 7 {
		t.Fatalf("GraphNodes = %d, want 7", result.GraphNodes)
	}
	if result.GraphLinks != 8 {
		t.Fatalf("GraphLinks = %d, want 8", result.GraphLinks)
	}
	if len(result.EventProjections) != 1 {
		t.Fatalf("len(EventProjections) = %d, want 1", len(result.EventProjections))
	}
	assertEventProjection(t, result.EventProjections[0], "github-dependabot-alert-1", "github.dependabot_alert", 7, 8, 7, 8)
	if got := countValue(result.GraphEntityTypes, "github.dependabot_alert"); got != 1 {
		t.Fatalf("graph entity type github.dependabot_alert = %d, want 1", got)
	}
	if got := countValue(result.GraphEntityTypes, "github.security_advisory"); got != 1 {
		t.Fatalf("graph entity type github.security_advisory = %d, want 1", got)
	}
	if got := countValue(result.GraphEntityTypes, "package"); got != 2 {
		t.Fatalf("graph entity type package = %d, want 2", got)
	}
	if got := countValue(result.GraphEntityTypes, "vulnerability"); got != 1 {
		t.Fatalf("graph entity type vulnerability = %d, want 1", got)
	}
	if got := countValue(result.GraphRelationTypes, "belongs_to"); got != 2 {
		t.Fatalf("graph relation type belongs_to = %d, want 2", got)
	}
	if got := countValue(result.GraphRelationTypes, "affected_by"); got != 4 {
		t.Fatalf("graph relation type affected_by = %d, want 4", got)
	}
	if got := countValue(result.GraphRelationTypes, "affects"); got != 1 {
		t.Fatalf("graph relation type affects = %d, want 1", got)
	}
	if got := countValue(result.GraphRelationTypes, "represents"); got != 1 {
		t.Fatalf("graph relation type represents = %d, want 1", got)
	}
	alertURN := "urn:cerebro:writer-dogfood:github_dependabot_alert:writer/cerebro:5"
	advisoryURN := "urn:cerebro:writer-dogfood:github_advisory:GHSA-1234-5678-90ab"
	packageURN := "urn:cerebro:writer-dogfood:package:gomod:golang.org/x/net"
	canonicalPackageURN := "urn:cerebro:writer-dogfood:package:canonical:golang.org/x/net"
	vulnerabilityURN := "urn:cerebro:writer-dogfood:vulnerability:ghsa-1234-5678-90ab"
	if !containsEntityURN(result.PreviewEntities, alertURN) {
		t.Fatalf("PreviewEntities missing Dependabot alert: %#v", result.PreviewEntities)
	}
	if !containsEntityURN(result.PreviewEntities, advisoryURN) {
		t.Fatalf("PreviewEntities missing advisory: %#v", result.PreviewEntities)
	}
	if !containsEntityURN(result.PreviewEntities, packageURN) {
		t.Fatalf("PreviewEntities missing package: %#v", result.PreviewEntities)
	}
	if !containsEntityURN(result.PreviewEntities, vulnerabilityURN) {
		t.Fatalf("PreviewEntities missing canonical vulnerability: %#v", result.PreviewEntities)
	}
	if !containsEntityURN(result.PreviewEntities, canonicalPackageURN) {
		t.Fatalf("PreviewEntities missing canonical package: %#v", result.PreviewEntities)
	}
	if !containsLink(result.PreviewLinks, alertURN, "affected_by", advisoryURN) {
		t.Fatalf("PreviewLinks missing advisory relation: %#v", result.PreviewLinks)
	}
	if !containsLink(result.PreviewLinks, alertURN, "affects", packageURN) {
		t.Fatalf("PreviewLinks missing package relation: %#v", result.PreviewLinks)
	}
	if !containsLink(result.PreviewLinks, alertURN, "affected_by", vulnerabilityURN) {
		t.Fatalf("PreviewLinks missing canonical vulnerability relation: %#v", result.PreviewLinks)
	}
	if !containsLink(result.PreviewLinks, packageURN, "affected_by", vulnerabilityURN) {
		t.Fatalf("PreviewLinks missing package vulnerability relation: %#v", result.PreviewLinks)
	}
	if !containsLink(result.PreviewLinks, packageURN, "represents", canonicalPackageURN) {
		t.Fatalf("PreviewLinks missing package identity relation: %#v", result.PreviewLinks)
	}
	if !containsLink(result.PreviewLinks, canonicalPackageURN, "affected_by", vulnerabilityURN) {
		t.Fatalf("PreviewLinks missing canonical package vulnerability relation: %#v", result.PreviewLinks)
	}
}

func TestRebuildDryRunDefaultsToSinglePage(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(&testSource{
		spec: &cerebrov1.SourceSpec{Id: "github", Name: "GitHub"},
		pages: [][]*cerebrov1.EventEnvelope{
			{
				testEvent("github-audit-1", "github.audit", map[string]string{
					"org":           "writer",
					"repo":          "writer/cerebro",
					"resource_id":   "writer/cerebro",
					"resource_type": "repository",
					"actor":         "octocat",
					"action":        "repo.create",
				}),
			},
			{
				testEvent("github-pr-1", "github.pull_request", map[string]string{
					"owner":       "writer",
					"repository":  "writer/cerebro",
					"pull_number": "418",
					"author":      "octocat",
				}),
			},
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := New(registry, &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-github": {
				Id:       "writer-github",
				SourceId: "github",
				TenantId: "writer-dogfood",
				Config:   map[string]string{"token": "fixture-token"},
			},
		},
	}, nil)

	result, err := service.RebuildDryRun(context.Background(), Request{RuntimeID: "writer-github"})
	if err != nil {
		t.Fatalf("RebuildDryRun() error = %v", err)
	}
	if result.PagesRead != 1 {
		t.Fatalf("PagesRead = %d, want 1", result.PagesRead)
	}
	if result.EventsRead != 1 {
		t.Fatalf("EventsRead = %d, want 1", result.EventsRead)
	}
	if result.GraphNodes != 5 {
		t.Fatalf("GraphNodes = %d, want 5", result.GraphNodes)
	}
	if result.GraphLinks != 6 {
		t.Fatalf("GraphLinks = %d, want 6", result.GraphLinks)
	}
	if got := countValue(result.EventKinds, "github.audit"); got != 1 {
		t.Fatalf("event kind github.audit = %d, want 1", got)
	}
	if got := countValue(result.GraphEntityTypes, "github.code.repository"); got != 1 {
		t.Fatalf("graph entity type github.code.repository = %d, want 1", got)
	}
	// The broad acted_on audit chain is suppressed from traversal previews.
	if len(result.GraphTraversals) != 4 {
		t.Fatalf("len(GraphTraversals) = %d, want 4", len(result.GraphTraversals))
	}
	if got := result.StageConfirmations[5].AssertionsPassed; got != 8 {
		t.Fatalf("verify_integrity assertions_passed = %d, want 8", got)
	}
	if got := result.StageConfirmations[6].PatternsVerified; got != 4 {
		t.Fatalf("verify_path_patterns patterns_verified = %d, want 4", got)
	}
	if got := result.StageConfirmations[7].TopologyBuckets; got != 4 {
		t.Fatalf("verify_topology topology_buckets = %d, want 4", got)
	}
	if got := result.StageConfirmations[8].TraversalsVerified; got != 4 {
		t.Fatalf("verify_traversals traversals_verified = %d, want 4", got)
	}
	if len(result.ReadPages) != 1 {
		t.Fatalf("len(ReadPages) = %d, want 1", len(result.ReadPages))
	}
	assertReadPage(t, result.ReadPages[0], 1, 1, "1", "1", "github-audit-1", "github-audit-1")
	if len(result.EventProjections) != 1 {
		t.Fatalf("len(EventProjections) = %d, want 1", len(result.EventProjections))
	}
	assertEventProjection(t, result.EventProjections[0], "github-audit-1", "github.audit", 5, 6, 5, 6)
	if len(result.GraphPathPatterns) != 4 {
		t.Fatalf("len(GraphPathPatterns) = %d, want 4", len(result.GraphPathPatterns))
	}
	if containsPathPatternPreview(result.GraphPathPatterns, "github.user -[acted_on]-> github.code.repository -[belongs_to]-> github.org", 1) {
		t.Fatalf("GraphPathPatterns included suppressed acted_on pattern: %#v", result.GraphPathPatterns)
	}
	// identifier.login moved from sinks_only to intermediate after gaining
	// the reverse represents_identity edge to identity.login.
	if !containsTopologyPreview(result.GraphTopology, "isolated", 0) || !containsTopologyPreview(result.GraphTopology, "sources_only", 1) || !containsTopologyPreview(result.GraphTopology, "sinks_only", 1) || !containsTopologyPreview(result.GraphTopology, "intermediates", 3) {
		t.Fatalf("GraphTopology unexpected values: %#v", result.GraphTopology)
	}
	if containsTraversalPath(result.GraphTraversals, "octocat -[acted_on]-> writer/cerebro -[belongs_to]-> writer") {
		t.Fatalf("GraphTraversals included suppressed acted_on path: %#v", result.GraphTraversals)
	}
}

func TestRebuildDryRunReplaysRuntimeIntoTemporaryGraph(t *testing.T) {
	replayer := &eventReplayer{
		events: []*cerebrov1.EventEnvelope{
			testRuntimeEvent("github-audit-1", "github.audit", "writer-github", map[string]string{
				"org":           "writer",
				"repo":          "writer/cerebro",
				"resource_id":   "writer/cerebro",
				"resource_type": "repository",
				"actor":         "octocat",
				"action":        "repo.create",
			}),
			testRuntimeEvent("github-pr-1", "github.pull_request", "writer-github", map[string]string{
				"owner":       "writer",
				"repository":  "writer/cerebro",
				"pull_number": "418",
				"author":      "octocat",
				"state":       "open",
				"html_url":    "https://github.com/writer/cerebro/pull/418",
			}),
			testRuntimeEvent("github-pr-2", "github.pull_request", "other-runtime", map[string]string{
				"owner":       "writer",
				"repository":  "writer/platform",
				"pull_number": "419",
				"author":      "hubot",
			}),
		},
	}
	service := New(nil, &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-github": {
				Id:       "writer-github",
				SourceId: "github",
				TenantId: "writer-dogfood",
			},
		},
	}, replayer)

	result, err := service.RebuildDryRun(context.Background(), Request{
		Mode:         modeReplay,
		RuntimeID:    "writer-github",
		EventLimit:   2,
		PreviewLimit: 10,
	})
	if err != nil {
		t.Fatalf("RebuildDryRun() error = %v", err)
	}
	if len(replayer.requests) != 1 {
		t.Fatalf("len(replayer.requests) = %d, want 1", len(replayer.requests))
	}
	if got := replayer.requests[0].RuntimeID; got != "writer-github" {
		t.Fatalf("Replay().RuntimeID = %q, want %q", got, "writer-github")
	}
	if got := replayer.requests[0].Limit; got != 2 {
		t.Fatalf("Replay().Limit = %d, want 2", got)
	}
	if result.Mode != modeReplay {
		t.Fatalf("result.Mode = %q, want %q", result.Mode, modeReplay)
	}
	if result.PagesRead != 0 {
		t.Fatalf("PagesRead = %d, want 0", result.PagesRead)
	}
	if result.EventsRead != 2 {
		t.Fatalf("EventsRead = %d, want 2", result.EventsRead)
	}
	if len(result.ReadPages) != 0 {
		t.Fatalf("len(ReadPages) = %d, want 0", len(result.ReadPages))
	}
	if len(result.StageConfirmations) != 9 {
		t.Fatalf("len(StageConfirmations) = %d, want 9", len(result.StageConfirmations))
	}
	assertStageNames(t, result.StageConfirmations, "resolve_runtime", "open_graph", "replay_log", "project_graph", "count_graph", "verify_integrity", "verify_path_patterns", "verify_topology", "verify_traversals")
	if got := result.StageConfirmations[2].EventsRead; got != 2 {
		t.Fatalf("replay_log events_read = %d, want 2", got)
	}
	if result.GraphNodes != 6 {
		t.Fatalf("GraphNodes = %d, want 6", result.GraphNodes)
	}
	if result.GraphLinks != 8 {
		t.Fatalf("GraphLinks = %d, want 8", result.GraphLinks)
	}
	if !containsTraversalPath(result.GraphTraversals, "octocat -[authored]-> writer/cerebro#418 -[belongs_to]-> writer/cerebro") {
		t.Fatalf("GraphTraversals missing authored path: %#v", result.GraphTraversals)
	}
}

func TestRebuildDryRunReplaysGRCVulnerabilityTargetIntegrationGraph(t *testing.T) {
	replayer := &eventReplayer{
		events: []*cerebrov1.EventEnvelope{
			testRuntimeEvent("grc-integration-1", "grc.integration", "writer-grc", map[string]string{
				"provider":       "vanta",
				"integration_id": "integration-1",
				"display_name":   "GitHub Dependabot",
			}),
			testRuntimeEvent("grc-vulnerability-1", "grc.vulnerability", "writer-grc", map[string]string{
				"provider":         "vanta",
				"vulnerability_id": "vuln-1",
				"name":             "CVE-2026-4242",
				"package":          "example/module",
				"target_id":        "target-1",
				"integration_id":   "integration-1",
			}),
		},
	}
	for _, event := range replayer.events {
		event.SourceId = "grc"
		event.TenantId = "writer"
	}
	service := New(nil, &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-grc": {
				Id:       "writer-grc",
				SourceId: "grc",
				TenantId: "writer",
			},
		},
	}, replayer)

	result, err := service.RebuildDryRun(context.Background(), Request{
		Mode:         modeReplay,
		RuntimeID:    "writer-grc",
		EventLimit:   2,
		PreviewLimit: 20,
	})
	if err != nil {
		t.Fatalf("RebuildDryRun() error = %v", err)
	}

	targetURN := "urn:cerebro:writer:grc_target:vanta:target-1"
	integrationURN := "urn:cerebro:writer:source:vanta:integration:integration-1"
	if result.GraphNodes != 5 {
		t.Fatalf("GraphNodes = %d, want 5", result.GraphNodes)
	}
	if result.GraphLinks != 6 {
		t.Fatalf("GraphLinks = %d, want 6", result.GraphLinks)
	}
	if !containsEntityPreview(result.PreviewEntities, integrationURN, "source", "GitHub Dependabot") {
		t.Fatalf("PreviewEntities missing named integration: %#v", result.PreviewEntities)
	}
	if !containsLinkPreview(result.PreviewLinks, targetURN, "belongs_to", integrationURN) {
		t.Fatalf("PreviewLinks missing target belongs_to integration: %#v", result.PreviewLinks)
	}
}

func TestRebuildDryRunRejectsNilEventWithPageContext(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(&testSource{
		spec:  &cerebrov1.SourceSpec{Id: "github", Name: "GitHub"},
		pages: [][]*cerebrov1.EventEnvelope{{nil}},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := New(registry, &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-github": {
				Id:       "writer-github",
				SourceId: "github",
				TenantId: "writer-dogfood",
				Config:   map[string]string{"token": "fixture-token"},
			},
		},
	}, nil)

	_, err = service.RebuildDryRun(context.Background(), Request{RuntimeID: "writer-github"})
	if err == nil || !strings.Contains(fmt.Sprint(err), "read source page 1: nil event at index 0") {
		t.Fatalf("RebuildDryRun() error = %v, want nil event page context", err)
	}
}

func testEvent(id string, kind string, attributes map[string]string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		SourceId:   "github",
		TenantId:   "fixture-tenant",
		Kind:       kind,
		OccurredAt: timestamppb.Now(),
		Attributes: attributes,
	}
}

func testRuntimeEvent(id string, kind string, runtimeID string, attributes map[string]string) *cerebrov1.EventEnvelope {
	event := testEvent(id, kind, attributes)
	if event.Attributes == nil {
		event.Attributes = make(map[string]string)
	}
	event.Attributes[ports.EventAttributeSourceRuntimeID] = runtimeID
	return event
}

func containsEntityURN(entities []*EntityPreview, want string) bool {
	for _, entity := range entities {
		if entity != nil && entity.URN == want {
			return true
		}
	}
	return false
}

func containsLink(links []*LinkPreview, fromURN string, relation string, toURN string) bool {
	for _, link := range links {
		if link == nil {
			continue
		}
		if link.FromURN == fromURN && link.Relation == relation && link.ToURN == toURN {
			return true
		}
	}
	return false
}

func countValue(counts []*CountPreview, name string) uint32 {
	for _, count := range counts {
		if count != nil && count.Name == name {
			return count.Count
		}
	}
	return 0
}

func assertStageNames(t *testing.T, stages []*StageConfirmation, want ...string) {
	t.Helper()
	if len(stages) != len(want) {
		t.Fatalf("len(stages) = %d, want %d", len(stages), len(want))
	}
	for index, stage := range stages {
		if stage == nil {
			t.Fatalf("stage %d = nil", index)
		}
		if stage.Name != want[index] {
			t.Fatalf("stage %d name = %q, want %q", index, stage.Name, want[index])
		}
		if stage.Status != stageStatusSuccess {
			t.Fatalf("stage %d status = %q, want %q", index, stage.Status, stageStatusSuccess)
		}
	}
}

func stageByName(stages []*StageConfirmation, name string) *StageConfirmation {
	for _, stage := range stages {
		if stage != nil && stage.Name == name {
			return stage
		}
	}
	return nil
}

func containsTraversalPath(traversals []*TraversalPreview, want string) bool {
	for _, traversal := range traversals {
		if traversal != nil && traversal.Path == want {
			return true
		}
	}
	return false
}

//nolint:unparam // Helper keeps assertion fields explicit even when current fixtures use zero actuals.
func containsAssertion(assertions []*AssertionPreview, name string, actual int64, expected int64, passed bool) bool {
	for _, assertion := range assertions {
		if assertion == nil {
			continue
		}
		if assertion.Name == name && assertion.Actual == actual && assertion.Expected == expected && assertion.Passed == passed {
			return true
		}
	}
	return false
}

func containsPathPatternPreview(patterns []*PathPatternPreview, label string, count int64) bool {
	for _, pattern := range patterns {
		if pattern != nil && pattern.Pattern == label && pattern.Count == count {
			return true
		}
	}
	return false
}

func containsEntityPreview(entities []*EntityPreview, urn string, entityType string, label string) bool {
	for _, entity := range entities {
		if entity != nil && entity.URN == urn && entity.EntityType == entityType && entity.Label == label {
			return true
		}
	}
	return false
}

func containsLinkPreview(links []*LinkPreview, fromURN string, relation string, toURN string) bool {
	for _, link := range links {
		if link != nil && link.FromURN == fromURN && link.Relation == relation && link.ToURN == toURN {
			return true
		}
	}
	return false
}

func containsTopologyPreview(topology []*TopologyPreview, name string, count int64) bool {
	for _, bucket := range topology {
		if bucket != nil && bucket.Name == name && bucket.Count == count {
			return true
		}
	}
	return false
}

//nolint:unparam // Helper keeps expected event count explicit in read-page assertions.
func assertReadPage(t *testing.T, page *ReadPagePreview, wantPage uint32, wantEvents uint32, wantCheckpoint string, wantNext string, wantFirstEventID string, wantLastEventID string) {
	t.Helper()
	if page == nil {
		t.Fatal("read page = nil")
	}
	if page.Page != wantPage {
		t.Fatalf("page.Page = %d, want %d", page.Page, wantPage)
	}
	if page.Events != wantEvents {
		t.Fatalf("page.Events = %d, want %d", page.Events, wantEvents)
	}
	if page.CheckpointCursor != wantCheckpoint {
		t.Fatalf("page.CheckpointCursor = %q, want %q", page.CheckpointCursor, wantCheckpoint)
	}
	if page.NextCursor != wantNext {
		t.Fatalf("page.NextCursor = %q, want %q", page.NextCursor, wantNext)
	}
	if page.FirstEventID != wantFirstEventID {
		t.Fatalf("page.FirstEventID = %q, want %q", page.FirstEventID, wantFirstEventID)
	}
	if page.LastEventID != wantLastEventID {
		t.Fatalf("page.LastEventID = %q, want %q", page.LastEventID, wantLastEventID)
	}
	if page.Watermark == "" {
		t.Fatal("page.Watermark = empty, want non-empty")
	}
}

func assertEventProjection(t *testing.T, projection *EventProjectionPreview, wantEventID string, wantKind string, wantEntities uint32, wantLinks uint32, wantGraphNodes int64, wantGraphLinks int64) {
	t.Helper()
	if projection == nil {
		t.Fatal("event projection = nil")
	}
	if projection.EventID != wantEventID {
		t.Fatalf("projection.EventID = %q, want %q", projection.EventID, wantEventID)
	}
	if projection.Kind != wantKind {
		t.Fatalf("projection.Kind = %q, want %q", projection.Kind, wantKind)
	}
	if projection.EntitiesProjected != wantEntities {
		t.Fatalf("projection.EntitiesProjected = %d, want %d", projection.EntitiesProjected, wantEntities)
	}
	if projection.LinksProjected != wantLinks {
		t.Fatalf("projection.LinksProjected = %d, want %d", projection.LinksProjected, wantLinks)
	}
	if projection.GraphNodesAfter != wantGraphNodes {
		t.Fatalf("projection.GraphNodesAfter = %d, want %d", projection.GraphNodesAfter, wantGraphNodes)
	}
	if projection.GraphLinksAfter != wantGraphLinks {
		t.Fatalf("projection.GraphLinksAfter = %d, want %d", projection.GraphLinksAfter, wantGraphLinks)
	}
}
