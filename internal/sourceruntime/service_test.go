package sourceruntime

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	githubsource "github.com/writer/cerebro/sources/github"
	oktasource "github.com/writer/cerebro/sources/okta"
)

type runtimeStore struct {
	runtimes map[string]*cerebrov1.SourceRuntime
	err      error
}

func (s *runtimeStore) Ping(context.Context) error {
	return s.err
}

func (s *runtimeStore) PutSourceRuntime(_ context.Context, runtime *cerebrov1.SourceRuntime) error {
	if s.err != nil {
		return s.err
	}
	if s.runtimes == nil {
		s.runtimes = make(map[string]*cerebrov1.SourceRuntime)
	}
	s.runtimes[runtime.GetId()] = proto.Clone(runtime).(*cerebrov1.SourceRuntime)
	return nil
}

func (s *runtimeStore) GetSourceRuntime(_ context.Context, id string) (*cerebrov1.SourceRuntime, error) {
	if s.err != nil {
		return nil, s.err
	}
	runtime, ok := s.runtimes[id]
	if !ok {
		return nil, ports.ErrSourceRuntimeNotFound
	}
	return proto.Clone(runtime).(*cerebrov1.SourceRuntime), nil
}

type appendLog struct {
	err    error
	events []*cerebrov1.EventEnvelope
}

func (l *appendLog) Ping(context.Context) error {
	return l.err
}

func (l *appendLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	if l.err != nil {
		return l.err
	}
	l.events = append(l.events, proto.Clone(event).(*cerebrov1.EventEnvelope))
	return nil
}

type projector struct {
	err    error
	result ports.ProjectionResult
	events []*cerebrov1.EventEnvelope
}

func (p *projector) Project(_ context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	if p.err != nil {
		return ports.ProjectionResult{}, p.err
	}
	p.events = append(p.events, proto.Clone(event).(*cerebrov1.EventEnvelope))
	return p.result, nil
}

func TestPutAndGetRuntimeRedactsSensitiveConfig(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	store := &runtimeStore{}
	service := New(registry, store, nil, nil)

	putResp, err := service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{
		Runtime: &cerebrov1.SourceRuntime{
			Id:       "writer-okta-users",
			SourceId: "okta",
			Config: map[string]string{
				"apiKey":     "api-key-value",
				"domain":     "writer.okta.com",
				"family":     "user",
				"privateKey": "private-key-value",
				"token":      "super-secret",
			},
		},
	})
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if got := putResp.GetRuntime().GetConfig()["token"]; got != redactedValue {
		t.Fatalf("Put().Runtime.Config[token] = %q, want %q", got, redactedValue)
	}
	if got := putResp.GetRuntime().GetConfig()["apiKey"]; got != redactedValue {
		t.Fatalf("Put().Runtime.Config[apiKey] = %q, want %q", got, redactedValue)
	}
	if got := putResp.GetRuntime().GetConfig()["privateKey"]; got != redactedValue {
		t.Fatalf("Put().Runtime.Config[privateKey] = %q, want %q", got, redactedValue)
	}

	getResp, err := service.Get(context.Background(), &cerebrov1.GetSourceRuntimeRequest{Id: "writer-okta-users"})
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got := getResp.GetRuntime().GetConfig()["token"]; got != redactedValue {
		t.Fatalf("Get().Runtime.Config[token] = %q, want %q", got, redactedValue)
	}
	if got := getResp.GetRuntime().GetConfig()["apiKey"]; got != redactedValue {
		t.Fatalf("Get().Runtime.Config[apiKey] = %q, want %q", got, redactedValue)
	}
	if got := getResp.GetRuntime().GetConfig()["privateKey"]; got != redactedValue {
		t.Fatalf("Get().Runtime.Config[privateKey] = %q, want %q", got, redactedValue)
	}
	if got := store.runtimes["writer-okta-users"].GetConfig()["token"]; got != "super-secret" {
		t.Fatalf("stored runtime token = %q, want %q", got, "super-secret")
	}
	if got := store.runtimes["writer-okta-users"].GetConfig()["apiKey"]; got != "api-key-value" {
		t.Fatalf("stored runtime apiKey = %q, want api-key-value", got)
	}
}

func TestPutRejectsReservedConfigKeys(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	service := New(registry, &runtimeStore{}, nil, nil)

	_, err = service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{
		Runtime: &cerebrov1.SourceRuntime{
			Id:       "writer-github",
			SourceId: "github",
			Config: map[string]string{
				"base_url": "https://attacker.example.com",
				"token":    "test",
			},
		},
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Put() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestPutPreservesProgressWhenConfigIsUnchanged(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	store := &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-github": {
				Id:       "writer-github",
				SourceId: "github",
				TenantId: "writer",
				Config:   map[string]string{"token": "test"},
				Checkpoint: &cerebrov1.SourceCheckpoint{
					CursorOpaque: "1",
				},
				NextCursor:   &cerebrov1.SourceCursor{Opaque: "1"},
				LastSyncedAt: timestamppb.Now(),
			},
		},
	}
	service := New(registry, store, nil, nil)

	resp, err := service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{
		Runtime: &cerebrov1.SourceRuntime{
			Id:       "writer-github",
			SourceId: "github",
			Config:   map[string]string{"token": "test"},
		},
	})
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if resp.GetRuntime().GetTenantId() != "writer" {
		t.Fatalf("Put().Runtime.TenantId = %q, want %q", resp.GetRuntime().GetTenantId(), "writer")
	}
	if resp.GetRuntime().GetNextCursor().GetOpaque() != "1" {
		t.Fatalf("Put().Runtime.NextCursor = %#v, want cursor 1", resp.GetRuntime().GetNextCursor())
	}
}

func TestSyncRuntimeAppendsEventsAndUpdatesProgress(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	store := &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-github": {
				Id:       "writer-github",
				SourceId: "github",
				Config:   map[string]string{"token": "test"},
			},
		},
	}
	log := &appendLog{}
	service := New(registry, store, log, nil)

	resp, err := service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{
		Id:        "writer-github",
		PageLimit: 2,
	})
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if resp.GetEventsAppended() != 2 {
		t.Fatalf("Sync().EventsAppended = %d, want 2", resp.GetEventsAppended())
	}
	if resp.GetPagesRead() != 2 {
		t.Fatalf("Sync().PagesRead = %d, want 2", resp.GetPagesRead())
	}
	if len(log.events) != 2 {
		t.Fatalf("len(appendLog.events) = %d, want 2", len(log.events))
	}
	runtime := store.runtimes["writer-github"]
	if runtime.GetCheckpoint().GetCursorOpaque() != "2" {
		t.Fatalf("stored checkpoint cursor = %q, want %q", runtime.GetCheckpoint().GetCursorOpaque(), "2")
	}
	if runtime.GetNextCursor() != nil {
		t.Fatalf("stored next cursor = %#v, want nil", runtime.GetNextCursor())
	}
	if runtime.GetLastSyncedAt() == nil {
		t.Fatal("stored last_synced_at = nil, want non-nil")
	}
}

func TestPutResetsProgressWhenTenantChanges(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	store := &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-github": {
				Id:       "writer-github",
				SourceId: "github",
				TenantId: "writer",
				Config:   map[string]string{"token": "test"},
				Checkpoint: &cerebrov1.SourceCheckpoint{
					CursorOpaque: "1",
				},
				NextCursor:   &cerebrov1.SourceCursor{Opaque: "1"},
				LastSyncedAt: timestamppb.Now(),
			},
		},
	}
	service := New(registry, store, nil, nil)

	resp, err := service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{
		Runtime: &cerebrov1.SourceRuntime{
			Id:       "writer-github",
			SourceId: "github",
			TenantId: "writer-next",
			Config:   map[string]string{"token": "test"},
		},
	})
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if got := resp.GetRuntime().GetCheckpoint(); got != nil {
		t.Fatalf("Put().Runtime.Checkpoint = %#v, want nil", got)
	}
	if got := resp.GetRuntime().GetNextCursor(); got != nil {
		t.Fatalf("Put().Runtime.NextCursor = %#v, want nil", got)
	}
	if got := resp.GetRuntime().GetLastSyncedAt(); got != nil {
		t.Fatalf("Put().Runtime.LastSyncedAt = %#v, want nil", got)
	}
}

func TestSyncRuntimeProjectsWithRuntimeTenant(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	store := &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-users": {
				Id:       "writer-okta-users",
				SourceId: "okta",
				TenantId: "writer",
				Config: map[string]string{
					"domain": "writer.okta.com",
					"family": "user",
					"token":  "test",
				},
			},
		},
	}
	log := &appendLog{}
	projector := &projector{result: ports.ProjectionResult{EntitiesProjected: 3, LinksProjected: 2}}
	service := New(registry, store, log, projector)

	resp, err := service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{
		Id:        "writer-okta-users",
		PageLimit: 1,
	})
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if resp.GetEntitiesProjected() != 3 {
		t.Fatalf("Sync().EntitiesProjected = %d, want 3", resp.GetEntitiesProjected())
	}
	if resp.GetLinksProjected() != 2 {
		t.Fatalf("Sync().LinksProjected = %d, want 2", resp.GetLinksProjected())
	}
	if len(log.events) != 1 {
		t.Fatalf("len(appendLog.events) = %d, want 1", len(log.events))
	}
	if got := log.events[0].GetTenantId(); got != "writer" {
		t.Fatalf("appended event tenant_id = %q, want %q", got, "writer")
	}
	if len(projector.events) != 1 {
		t.Fatalf("len(projector.events) = %d, want 1", len(projector.events))
	}
	if got := projector.events[0].GetTenantId(); got != "writer" {
		t.Fatalf("projected event tenant_id = %q, want %q", got, "writer")
	}
}

func TestSyncRuntimeRequiresDependencies(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	service := New(registry, nil, nil, nil)
	_, err = service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "writer-github"})
	if !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("Sync() error = %v, want ErrRuntimeUnavailable", err)
	}
}

func TestGetRejectsNilRequest(t *testing.T) {
	service := New(nil, &runtimeStore{}, nil, nil)
	if _, err := service.Get(context.Background(), nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Get() error = %v, want ErrInvalidRequest", err)
	}
}

func TestSyncRejectsNilRequest(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	service := New(registry, &runtimeStore{}, &appendLog{}, nil)
	if _, err := service.Sync(context.Background(), nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Sync() error = %v, want ErrInvalidRequest", err)
	}
}

func TestSameConfigComparesKeyPresence(t *testing.T) {
	if sameConfig(map[string]string{"a": ""}, map[string]string{"b": ""}) {
		t.Fatal("sameConfig() = true, want false for different key sets")
	}
}

func newFixtureRegistry() (*sourcecdk.Registry, error) {
	github, err := githubsource.NewFixture()
	if err != nil {
		return nil, err
	}
	okta, err := oktasource.NewFixture()
	if err != nil {
		return nil, err
	}
	return sourcecdk.NewRegistry(github, okta)
}
