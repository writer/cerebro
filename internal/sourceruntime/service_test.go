package sourceruntime

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	githubsource "github.com/writer/cerebro/sources/github"
	oktasource "github.com/writer/cerebro/sources/okta"
)

type runtimeStore struct {
	runtimes map[string]*cerebrov1.SourceRuntime
	err      error
	putCount int
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
	s.putCount++
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

func (s *runtimeStore) ListSourceRuntimes(_ context.Context, filter ports.SourceRuntimeFilter) ([]*cerebrov1.SourceRuntime, error) {
	if s.err != nil {
		return nil, s.err
	}
	var ids []string
	for id := range s.runtimes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var runtimes []*cerebrov1.SourceRuntime
	for _, id := range ids {
		runtime := s.runtimes[id]
		if filter.TenantID != "" && runtime.GetTenantId() != filter.TenantID {
			continue
		}
		if filter.SourceID != "" && runtime.GetSourceId() != filter.SourceID {
			continue
		}
		runtimes = append(runtimes, proto.Clone(runtime).(*cerebrov1.SourceRuntime))
		if filter.Limit > 0 && uint32(len(runtimes)) >= filter.Limit {
			break
		}
	}
	return runtimes, nil
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

type emptyPageSource struct{}

func (emptyPageSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: "empty_page"}
}

func (emptyPageSource) Check(context.Context, sourcecdk.Config) error {
	return nil
}

func (emptyPageSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (emptyPageSource) Read(_ context.Context, _ sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	if cursor.GetOpaque() == "" {
		return sourcecdk.Pull{NextCursor: &cerebrov1.SourceCursor{Opaque: "second"}}, nil
	}
	return sourcecdk.Pull{
		Events: []*cerebrov1.EventEnvelope{{
			Id:       "event-after-empty-page",
			TenantId: "writer",
			SourceId: "empty_page",
			Kind:     "empty_page.event",
		}},
		Checkpoint: &cerebrov1.SourceCheckpoint{CursorOpaque: "second"},
	}, nil
}

type failingSource struct {
	err error
}

func (s failingSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: "failing"}
}

func (s failingSource) Check(context.Context, sourcecdk.Config) error {
	return s.err
}

func (s failingSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, s.err
}

func (s failingSource) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return sourcecdk.Pull{}, s.err
}

type tokenSource struct {
	checked string
	read    string
}

func (s *tokenSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: "token_source"}
}

func (s *tokenSource) Check(_ context.Context, config sourcecdk.Config) error {
	value, _ := config.Lookup("token")
	s.checked = value
	if value != "resolved-token" {
		return sourcecdk.ErrInvalidConfig
	}
	return nil
}

func (s *tokenSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (s *tokenSource) Read(_ context.Context, config sourcecdk.Config, _ *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	value, _ := config.Lookup("token")
	s.read = value
	return sourcecdk.Pull{Events: []*cerebrov1.EventEnvelope{{
		Id:       "token-event",
		SourceId: "token_source",
		Kind:     "token.event",
	}}}, nil
}

func TestPutAndGetRuntimeRedactsSensitiveConfig(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	store := &runtimeStore{}
	service := New(registry, store, nil, nil).WithConfigResolver(config.ResolveSourceRuntimeConfigSecretReferences)

	putResp, err := service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{
		Runtime: &cerebrov1.SourceRuntime{
			Id:       "writer-okta-users",
			SourceId: "okta",
			Config: map[string]string{
				"domain": "writer.okta.com",
				"family": "user",
				"token":  "super-secret",
			},
		},
	})
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if got := putResp.GetRuntime().GetConfig()["token"]; got != redactedValue {
		t.Fatalf("Put().Runtime.Config[token] = %q, want %q", got, redactedValue)
	}

	getResp, err := service.Get(context.Background(), &cerebrov1.GetSourceRuntimeRequest{Id: "writer-okta-users"})
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got := getResp.GetRuntime().GetConfig()["token"]; got != redactedValue {
		t.Fatalf("Get().Runtime.Config[token] = %q, want %q", got, redactedValue)
	}
	if got := store.runtimes["writer-okta-users"].GetConfig()["token"]; got != "super-secret" {
		t.Fatalf("stored runtime token = %q, want %q", got, "super-secret")
	}
}

func TestPutStoresSecretReferenceAfterResolvingForValidation(t *testing.T) {
	source := &tokenSource{}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &runtimeStore{}
	service := New(registry, store, nil, nil).WithConfigResolver(config.ResolveSourceRuntimeConfigSecretReferences)
	t.Setenv("CEREBRO_SOURCE_TOKEN_SOURCE_TOKEN", "resolved-token")

	_, err = service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{
		Runtime: &cerebrov1.SourceRuntime{
			Id:       "writer-token",
			SourceId: "token_source",
			Config:   map[string]string{"token": "env:CEREBRO_SOURCE_TOKEN_SOURCE_TOKEN"},
		},
	})
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if source.checked != "resolved-token" {
		t.Fatalf("source checked token = %q, want resolved-token", source.checked)
	}
	if got := store.runtimes["writer-token"].GetConfig()["token"]; got != "env:CEREBRO_SOURCE_TOKEN_SOURCE_TOKEN" {
		t.Fatalf("stored token = %q, want env reference", got)
	}
	if _, ok := store.runtimes["writer-token"].GetConfig()[runtimeProgressConfigHashKey]; ok {
		t.Fatal("stored sensitive-only env config wrote progress hash")
	}
}

func TestSyncResetsProgressWhenResolvedSelectorReferenceChanges(t *testing.T) {
	source := &tokenSource{}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	oldHash := progressConfigHash(map[string]string{
		"domain": "old.example.com",
		"token":  "resolved-token",
	})
	store := &runtimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"writer-token": {
			Id:       "writer-token",
			SourceId: "token_source",
			Config: map[string]string{
				"domain":                     "env:CEREBRO_SOURCE_TOKEN_SOURCE_DOMAIN",
				"token":                      "env:CEREBRO_SOURCE_TOKEN_SOURCE_TOKEN",
				runtimeProgressConfigHashKey: oldHash,
			},
			Checkpoint:   &cerebrov1.SourceCheckpoint{CursorOpaque: "old-cursor"},
			NextCursor:   &cerebrov1.SourceCursor{Opaque: "old-cursor"},
			LastSyncedAt: timestamppb.Now(),
		},
	}}
	t.Setenv("CEREBRO_SOURCE_TOKEN_SOURCE_DOMAIN", "new.example.com")
	t.Setenv("CEREBRO_SOURCE_TOKEN_SOURCE_TOKEN", "resolved-token")
	service := New(registry, store, &appendLog{}, nil).WithConfigResolver(config.ResolveSourceRuntimeConfigSecretReferences)

	if _, err := service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "writer-token"}); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	stored := store.runtimes["writer-token"]
	if stored.GetCheckpoint() != nil || stored.GetNextCursor() != nil {
		t.Fatalf("stored cursor progress was preserved after selector change: checkpoint=%v cursor=%v", stored.GetCheckpoint(), stored.GetNextCursor())
	}
	if got := stored.GetConfig()[runtimeProgressConfigHashKey]; got == "" || got == oldHash {
		t.Fatalf("stored progress hash = %q, want new non-empty hash", got)
	}
	if source.read != "resolved-token" {
		t.Fatalf("source read token = %q, want resolved-token", source.read)
	}
	if _, ok := redactRuntime(stored).GetConfig()[runtimeProgressConfigHashKey]; ok {
		t.Fatal("redacted runtime exposed internal progress hash")
	}
}

func TestProgressConfigHashIncludesNonSecretKeySelectors(t *testing.T) {
	rawConfig := map[string]string{
		"lookup_key": "env:CEREBRO_SOURCE_TOKEN_SOURCE_LOOKUP_KEY",
		"token":      "env:CEREBRO_SOURCE_TOKEN_SOURCE_TOKEN",
	}
	hashA, ok := progressConfigHashForRuntime(rawConfig, map[string]string{
		"lookup_key": "team-a",
		"token":      "resolved-token",
	})
	if !ok {
		t.Fatal("progressConfigHashForRuntime() did not include env-backed lookup_key selector")
	}
	hashB, ok := progressConfigHashForRuntime(rawConfig, map[string]string{
		"lookup_key": "team-b",
		"token":      "resolved-token",
	})
	if !ok {
		t.Fatal("progressConfigHashForRuntime() did not include changed env-backed lookup_key selector")
	}
	if hashA == hashB {
		t.Fatal("progress config hash did not change when lookup_key changed")
	}
}

func TestProgressConfigHashIgnoresPreservedLiteralEnvQuerySelectors(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{
		Id:           "writer-github",
		SourceId:     "github",
		Config:       map[string]string{"phrase": "env:prod"},
		Checkpoint:   &cerebrov1.SourceCheckpoint{CursorOpaque: "old-cursor"},
		NextCursor:   &cerebrov1.SourceCursor{Opaque: "next"},
		LastSyncedAt: timestamppb.New(time.Date(2026, 5, 7, 0, 0, 0, 0, time.UTC)),
	}

	refreshRuntimeProgressConfig(runtime, map[string]string{"phrase": "env:prod"})

	if runtime.GetCheckpoint().GetCursorOpaque() != "old-cursor" {
		t.Fatalf("checkpoint cursor = %q, want old-cursor", runtime.GetCheckpoint().GetCursorOpaque())
	}
	if runtime.GetNextCursor().GetOpaque() != "next" {
		t.Fatalf("next cursor = %q, want next", runtime.GetNextCursor().GetOpaque())
	}
	if runtime.GetLastSyncedAt() == nil {
		t.Fatal("last_synced_at = nil, want preserved timestamp")
	}
	if _, ok := runtime.GetConfig()[runtimeProgressConfigHashKey]; ok {
		t.Fatal("literal env query selector wrote progress hash")
	}
}

func TestProgressConfigHashIgnoresAccessKeyIDCredentials(t *testing.T) {
	rawConfig := map[string]string{
		"access_key_id": "env:CEREBRO_SOURCE_AWS_ACCESS_KEY_ID",
		"lookup_key":    "env:CEREBRO_SOURCE_AWS_LOOKUP_KEY",
	}
	hashA, ok := progressConfigHashForRuntime(rawConfig, map[string]string{
		"access_key_id": "first",
		"lookup_key":    "inventory",
	})
	if !ok {
		t.Fatal("progressConfigHashForRuntime() did not include env-backed lookup_key selector")
	}
	hashB, ok := progressConfigHashForRuntime(rawConfig, map[string]string{
		"access_key_id": "second",
		"lookup_key":    "inventory",
	})
	if !ok {
		t.Fatal("progressConfigHashForRuntime() did not include env-backed lookup_key selector after credential change")
	}
	if hashA != hashB {
		t.Fatal("progress config hash changed when only access_key_id changed")
	}
}

func TestListRedactsSensitiveConfigAndFilters(t *testing.T) {
	service := New(nil, &runtimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"writer-token": {Id: "writer-token", SourceId: "github", TenantId: "writer", Config: map[string]string{"token": "env:CEREBRO_TEST_TOKEN", "lookup_key": "prod", "group_key": "eng"}},
		"other-token":  {Id: "other-token", SourceId: "okta", TenantId: "other", Config: map[string]string{"token": "env:OTHER"}},
	}}, nil, nil)

	runtimes, err := service.List(context.Background(), ports.SourceRuntimeFilter{TenantID: "writer"})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(runtimes) != 1 {
		t.Fatalf("List() returned %d runtimes, want 1", len(runtimes))
	}
	if got := runtimes[0].GetConfig()["token"]; got != redactedValue {
		t.Fatalf("listed token = %q, want %q", got, redactedValue)
	}
	if got := runtimes[0].GetConfig()["lookup_key"]; got != "prod" {
		t.Fatalf("listed lookup_key = %q, want prod", got)
	}
	if got := runtimes[0].GetConfig()["group_key"]; got != "eng" {
		t.Fatalf("listed group_key = %q, want eng", got)
	}
}

func TestSensitiveConfigKeyCatchesCommonCamelCaseSecrets(t *testing.T) {
	for _, key := range []string{
		"apiKey",
		"accessKeyId",
		"clientSecret",
		"privateKey",
		"signing_key",
		"sessionToken",
	} {
		t.Run(key, func(t *testing.T) {
			if !sensitiveConfigKey(key) {
				t.Fatalf("sensitiveConfigKey(%q) = false, want true", key)
			}
		})
	}
}

func TestSensitiveConfigKeyAllowsSelectorKeys(t *testing.T) {
	for _, key := range []string{"lookup_key", "group_key"} {
		t.Run(key, func(t *testing.T) {
			if sensitiveConfigKey(key) {
				t.Fatalf("sensitiveConfigKey(%q) = true, want false", key)
			}
		})
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

func TestPutSourceConfigValidationErrorsAreInvalidRequests(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	service := New(registry, &runtimeStore{}, nil, nil)

	_, err = service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{
		Runtime: &cerebrov1.SourceRuntime{
			Id:       "writer-github",
			SourceId: "github",
		},
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Put() error = %v, want ErrInvalidRequest", err)
	}
}

func TestPutSourceReachabilityErrorsAreNotInvalidRequests(t *testing.T) {
	upstreamErr := errors.New("upstream timeout")
	registry, err := sourcecdk.NewRegistry(failingSource{err: upstreamErr})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := New(registry, &runtimeStore{}, nil, nil)
	_, err = service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{
		Runtime: &cerebrov1.SourceRuntime{
			Id:       "writer-failing",
			SourceId: "failing",
		},
	})
	if !errors.Is(err, upstreamErr) || errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Put() error = %v, want upstream error without ErrInvalidRequest", err)
	}
}

func TestPutPreservesSuppliedProgressForNewRuntime(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	store := &runtimeStore{}
	service := New(registry, store, nil, nil)
	syncedAt := timestamppb.New(time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC))

	resp, err := service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{
		Runtime: &cerebrov1.SourceRuntime{
			Id:           "writer-github",
			SourceId:     "github",
			TenantId:     "writer",
			Config:       map[string]string{"token": "test"},
			Checkpoint:   &cerebrov1.SourceCheckpoint{CursorOpaque: "restored"},
			NextCursor:   &cerebrov1.SourceCursor{Opaque: "next"},
			LastSyncedAt: syncedAt,
		},
	})
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if got := resp.GetRuntime().GetCheckpoint().GetCursorOpaque(); got != "restored" {
		t.Fatalf("Put().Runtime.Checkpoint = %q, want restored", got)
	}
	if got := store.runtimes["writer-github"].GetNextCursor().GetOpaque(); got != "next" {
		t.Fatalf("stored next cursor = %q, want next", got)
	}
	if got := store.runtimes["writer-github"].GetLastSyncedAt().AsTime(); !got.Equal(syncedAt.AsTime()) {
		t.Fatalf("stored last_synced_at = %s, want %s", got, syncedAt.AsTime())
	}
}

func TestPutIgnoresClientSuppliedProgress(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	syncedAt := timestamppb.Now()
	store := &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-github": {
				Id:           "writer-github",
				SourceId:     "github",
				TenantId:     "writer",
				Config:       map[string]string{"token": "test"},
				Checkpoint:   &cerebrov1.SourceCheckpoint{CursorOpaque: "stored"},
				NextCursor:   &cerebrov1.SourceCursor{Opaque: "stored"},
				LastSyncedAt: syncedAt,
			},
		},
	}
	service := New(registry, store, nil, nil)

	resp, err := service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{
		Runtime: &cerebrov1.SourceRuntime{
			Id:           "writer-github",
			SourceId:     "github",
			TenantId:     "writer",
			Config:       map[string]string{"token": "test"},
			Checkpoint:   &cerebrov1.SourceCheckpoint{CursorOpaque: "client"},
			NextCursor:   &cerebrov1.SourceCursor{Opaque: "client"},
			LastSyncedAt: timestamppb.Now(),
		},
	})
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if got := resp.GetRuntime().GetCheckpoint().GetCursorOpaque(); got != "stored" {
		t.Fatalf("Put().Runtime.Checkpoint = %q, want stored", got)
	}
	if got := store.runtimes["writer-github"].GetNextCursor().GetOpaque(); got != "stored" {
		t.Fatalf("stored next cursor = %q, want stored", got)
	}
	if got := store.runtimes["writer-github"].GetLastSyncedAt().AsTime(); !got.Equal(syncedAt.AsTime()) {
		t.Fatalf("stored last synced at = %v, want %v", got, syncedAt.AsTime())
	}
}

func TestPutRestoresRedactedSensitiveConfigBeforeMerge(t *testing.T) {
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
				Config:   map[string]string{"token": "preserved-value"},
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
			Config:   map[string]string{"token": redactedValue},
		},
	})
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if got := store.runtimes["writer-github"].GetConfig()["token"]; got != "preserved-value" {
		t.Fatalf("stored token = %q, want preserved secret", got)
	}
	if got := resp.GetRuntime().GetConfig()["token"]; got != redactedValue {
		t.Fatalf("response token = %q, want redacted", got)
	}
	if got := store.runtimes["writer-github"].GetNextCursor().GetOpaque(); got != "1" {
		t.Fatalf("stored next cursor = %q, want preserved cursor", got)
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
	if got := log.events[0].GetAttributes()[ports.EventAttributeSourceRuntimeID]; got != "writer-github" {
		t.Fatalf("appended event source_runtime_id = %q, want %q", got, "writer-github")
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
	if store.putCount != 2 {
		t.Fatalf("PutSourceRuntime calls = %d, want 2", store.putCount)
	}
}

func TestSyncRuntimeContinuesPastEmptyPagesWithCursor(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(emptyPageSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-empty-page": {
				Id:       "writer-empty-page",
				SourceId: "empty_page",
				TenantId: "writer",
			},
		},
	}
	log := &appendLog{}
	service := New(registry, store, log, nil)

	resp, err := service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{
		Id:        "writer-empty-page",
		PageLimit: 2,
	})
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if resp.GetPagesRead() != 2 {
		t.Fatalf("Sync().PagesRead = %d, want 2", resp.GetPagesRead())
	}
	if resp.GetEventsAppended() != 1 {
		t.Fatalf("Sync().EventsAppended = %d, want 1", resp.GetEventsAppended())
	}
	if len(log.events) != 1 {
		t.Fatalf("len(appendLog.events) = %d, want 1", len(log.events))
	}
	if store.putCount != 2 {
		t.Fatalf("PutSourceRuntime calls = %d, want 2", store.putCount)
	}
	if got := store.runtimes["writer-empty-page"].GetNextCursor(); got != nil {
		t.Fatalf("stored next cursor = %#v, want nil", got)
	}
}

func TestPutRejectsTenantChanges(t *testing.T) {
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
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Put() error = %v, want ErrInvalidRequest", err)
	}
	if resp != nil {
		t.Fatalf("Put() response = %#v, want nil", resp)
	}
	if got := store.runtimes["writer-github"].GetTenantId(); got != "writer" {
		t.Fatalf("stored tenant = %q, want writer", got)
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
	if got := projector.events[0].GetAttributes()[ports.EventAttributeSourceRuntimeID]; got != "writer-okta-users" {
		t.Fatalf("projected event source_runtime_id = %q, want %q", got, "writer-okta-users")
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

func TestValidationErrorsAreInvalidRequests(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	service := New(registry, &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-github": {Id: "writer-github", SourceId: "github", TenantId: "writer", Config: map[string]string{"token": "test"}},
		},
	}, &appendLog{}, nil)
	for _, tt := range []struct {
		name string
		err  error
	}{
		{name: "put nil runtime", err: func() error {
			_, err := service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{})
			return err
		}()},
		{name: "get empty id", err: func() error {
			_, err := service.Get(context.Background(), &cerebrov1.GetSourceRuntimeRequest{})
			return err
		}()},
		{name: "sync page limit", err: func() error {
			_, err := service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "writer-github", PageLimit: maxPageLimit + 1})
			return err
		}()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.err, ErrInvalidRequest) {
				t.Fatalf("error = %v, want ErrInvalidRequest", tt.err)
			}
		})
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
