package graphrebuild

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
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
	spec  *cerebrov1.SourceSpec
	pages [][]*cerebrov1.EventEnvelope
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

func (s *testSource) Read(_ context.Context, _ sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
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
	pull := sourcecdk.Pull{
		Events: events,
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    events[len(events)-1].GetOccurredAt(),
			CursorOpaque: strconv.Itoa(index + 1),
		},
	}
	if index+1 < len(s.pages) {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: strconv.Itoa(index + 1)}
	}
	return pull, nil
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
	service := New(registry, store)

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
	if result.EntitiesProjected != 9 {
		t.Fatalf("EntitiesProjected = %d, want 9", result.EntitiesProjected)
	}
	if result.LinksProjected != 7 {
		t.Fatalf("LinksProjected = %d, want 7", result.LinksProjected)
	}
	if result.GraphNodes != 5 {
		t.Fatalf("GraphNodes = %d, want 5", result.GraphNodes)
	}
	if result.GraphLinks != 5 {
		t.Fatalf("GraphLinks = %d, want 5", result.GraphLinks)
	}
	if len(result.StageConfirmations) != 5 {
		t.Fatalf("len(StageConfirmations) = %d, want 5", len(result.StageConfirmations))
	}
	assertStageNames(t, result.StageConfirmations, "resolve_runtime", "open_graph", "read_source", "project_graph", "count_graph")
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
	})

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
	if result.GraphNodes != 4 {
		t.Fatalf("GraphNodes = %d, want 4", result.GraphNodes)
	}
	if result.GraphLinks != 3 {
		t.Fatalf("GraphLinks = %d, want 3", result.GraphLinks)
	}
	if got := countValue(result.EventKinds, "github.audit"); got != 1 {
		t.Fatalf("event kind github.audit = %d, want 1", got)
	}
	if got := countValue(result.GraphEntityTypes, "github.repo"); got != 1 {
		t.Fatalf("graph entity type github.repo = %d, want 1", got)
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
	})

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
