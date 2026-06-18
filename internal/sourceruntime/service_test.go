package sourceruntime

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/resourcescope"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
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

func (s *runtimeStore) PutSourceRuntimes(_ context.Context, runtimes []*cerebrov1.SourceRuntime) error {
	if s.err != nil {
		return s.err
	}
	cloned := make(map[string]*cerebrov1.SourceRuntime, len(s.runtimes)+len(runtimes))
	for id, runtime := range s.runtimes {
		cloned[id] = proto.Clone(runtime).(*cerebrov1.SourceRuntime)
	}
	for _, runtime := range runtimes {
		cloned[runtime.GetId()] = proto.Clone(runtime).(*cerebrov1.SourceRuntime)
	}
	s.putCount += len(runtimes)
	s.runtimes = cloned
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
		if filter.RuntimeID != "" && runtime.GetId() != filter.RuntimeID {
			continue
		}
		if len(filter.RuntimeIDs) != 0 && !stringInSlice(filter.RuntimeIDs, runtime.GetId()) {
			continue
		}
		if filter.TenantID != "" && runtime.GetTenantId() != filter.TenantID {
			continue
		}
		if filter.SourceID != "" && runtime.GetSourceId() != filter.SourceID {
			continue
		}
		runtimes = append(runtimes, proto.Clone(runtime).(*cerebrov1.SourceRuntime))
		if filter.Limit > 0 && boundedUint32(len(runtimes)) >= filter.Limit {
			break
		}
	}
	return runtimes, nil
}

func stringInSlice(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
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

func runtimeTestEvent(id string, sourceID string, kind string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   sourceID,
		Kind:       kind,
		OccurredAt: timestamppb.New(time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)),
		SchemaRef:  strings.ReplaceAll(kind, ".", "/") + "/v1",
		Payload:    []byte(`{"fixture":true}`),
		Attributes: map[string]string{"event_type": "fixture"},
	}
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
		Events:     []*cerebrov1.EventEnvelope{runtimeTestEvent("event-after-empty-page", "empty_page", "empty_page.event")},
		Checkpoint: &cerebrov1.SourceCheckpoint{CursorOpaque: "second"},
	}, nil
}

type checkpointResumeSource struct {
	seenCursor string
}

func (s *checkpointResumeSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: "checkpoint_resume"}
}

func (s *checkpointResumeSource) Check(context.Context, sourcecdk.Config) error {
	return nil
}

func (s *checkpointResumeSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (s *checkpointResumeSource) Read(_ context.Context, _ sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	s.seenCursor = cursor.GetOpaque()
	return sourcecdk.Pull{}, nil
}

type persistedCheckpointResumeSource struct {
	checkpointCursor string
	seenCursors      []string
}

func (s *persistedCheckpointResumeSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: "persisted_checkpoint_resume"}
}

func (s *persistedCheckpointResumeSource) Check(context.Context, sourcecdk.Config) error {
	return nil
}

func (s *persistedCheckpointResumeSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (s *persistedCheckpointResumeSource) Read(_ context.Context, _ sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	opaque := cursor.GetOpaque()
	s.seenCursors = append(s.seenCursors, opaque)
	if len(s.seenCursors) == 1 {
		return sourcecdk.Pull{
			Events: []*cerebrov1.EventEnvelope{
				runtimeTestEvent("okta-policy-rule-terminal", "persisted_checkpoint_resume", "okta.policy_rule"),
			},
			Checkpoint: &cerebrov1.SourceCheckpoint{
				Watermark:    timestamppb.New(time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)),
				CursorOpaque: s.checkpointCursor,
			},
		}, nil
	}
	if strings.TrimSpace(opaque) == "" {
		return sourcecdk.Pull{}, errors.New("unexpected fresh start after persisted checkpoint")
	}
	return sourcecdk.Pull{}, nil
}

type nilEventSource struct{}

func (nilEventSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: "nil_event"}
}

func (nilEventSource) Check(context.Context, sourcecdk.Config) error {
	return nil
}

func (nilEventSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (nilEventSource) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return sourcecdk.Pull{Events: []*cerebrov1.EventEnvelope{
		nil,
		runtimeTestEvent("event-after-nil", "nil_event", "nil_event.event"),
	}}, nil
}

type invalidEventSource struct{}

func (invalidEventSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: "invalid_event"}
}

func (invalidEventSource) Check(context.Context, sourcecdk.Config) error {
	return nil
}

func (invalidEventSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (invalidEventSource) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	event := runtimeTestEvent("invalid-event", "invalid_event", "invalid_event.event")
	event.Payload = nil
	return sourcecdk.Pull{Events: []*cerebrov1.EventEnvelope{event}}, nil
}

type contractEventSource struct{}

func (contractEventSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: "contract_event"}
}

func (contractEventSource) EventContracts() []sourcecdk.EventContract {
	return []sourcecdk.EventContract{{
		Kind:                  "contract_event.event",
		SchemaRef:             "contract_event/event/v1",
		RequiredAttributes:    []string{"required_attribute"},
		RequiredPayloadFields: []string{"required_payload"},
	}}
}

func (contractEventSource) Check(context.Context, sourcecdk.Config) error {
	return nil
}

func (contractEventSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (contractEventSource) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	event := runtimeTestEvent("contract-event", "contract_event", "contract_event.event")
	event.Payload = []byte(`{"fixture":true}`)
	return sourcecdk.Pull{Events: []*cerebrov1.EventEnvelope{event}}, nil
}

type evidenceCASMissingSourceSystemSource struct{}

func (evidenceCASMissingSourceSystemSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: "evidence_cas"}
}

func (evidenceCASMissingSourceSystemSource) EventContracts() []sourcecdk.EventContract {
	return []sourcecdk.EventContract{{
		Kind:                  "evidence_cas.object",
		SchemaRef:             "evidence_cas/object/v1",
		RequiredAttributes:    []string{"tenant_id", "source_system", "source_event_id", "evidence_id", "evidence_type", "resource_urn", "evidence_cas_uri", "evidence_cas_digest"},
		RequiredPayloadFields: []string{"uri", "digest", "manifest_version"},
	}}
}

func (evidenceCASMissingSourceSystemSource) Check(context.Context, sourcecdk.Config) error {
	return nil
}

func (evidenceCASMissingSourceSystemSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (evidenceCASMissingSourceSystemSource) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	event := runtimeTestEvent("evidence-cas-missing-source-system", "evidence_cas", "evidence_cas.object")
	event.SchemaRef = "evidence_cas/object/v1"
	event.Payload = []byte(`{"uri":"evidencecas://cases/case-123/evidence/evidence-456","digest":"sha256canonical","manifest_version":2}`)
	event.Attributes = map[string]string{
		"tenant_id":             "tenant-123",
		"source_event_id":       "iris-event-123",
		"evidence_id":           "evidence-456",
		"evidence_type":         "evidence_cas.artifact",
		"resource_urn":          "urn:cerebro:tenant-123:case:case-123",
		"evidence_cas_uri":      "evidencecas://cases/case-123/evidence/evidence-456",
		"evidence_cas_digest":   "sha256canonical",
		"evidence_cas_ref_type": "evidencecas.manifest.v2",
	}
	return sourcecdk.Pull{Events: []*cerebrov1.EventEnvelope{event}}, nil
}

type unmatchedContractEventSource struct{}

func (unmatchedContractEventSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: "unmatched_contract_event"}
}

func (unmatchedContractEventSource) EventContracts() []sourcecdk.EventContract {
	return []sourcecdk.EventContract{{
		Kind:                  "unmatched_contract_event.event",
		SchemaRef:             "unmatched_contract_event/event/v1",
		RequiredAttributes:    []string{"event_type"},
		RequiredPayloadFields: []string{"fixture"},
	}}
}

func (unmatchedContractEventSource) Check(context.Context, sourcecdk.Config) error {
	return nil
}

func (unmatchedContractEventSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (unmatchedContractEventSource) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	event := runtimeTestEvent("unmatched-contract-event", "unmatched_contract_event", "unmatched_contract_event.other")
	event.SchemaRef = "unmatched_contract_event/other/v1"
	return sourcecdk.Pull{Events: []*cerebrov1.EventEnvelope{event}}, nil
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
	return sourcecdk.Pull{Events: []*cerebrov1.EventEnvelope{runtimeTestEvent("token-event", "token_source", "token.event")}}, nil
}

type tenantCheckSource struct {
	checkedTenant string
}

func (s *tenantCheckSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: "tenant_check"}
}

func (s *tenantCheckSource) Check(_ context.Context, config sourcecdk.Config) error {
	s.checkedTenant, _ = config.Lookup(sourceconfig.RuntimeTenantIDKey)
	if s.checkedTenant != "writer" {
		return sourcecdk.ErrInvalidConfig
	}
	return nil
}

func (s *tenantCheckSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (s *tenantCheckSource) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return sourcecdk.Pull{}, nil
}

type checkpointAwareRuntimeSource struct {
	seenCheckpoint *cerebrov1.SourceCheckpoint
	pull           sourcecdk.Pull
}

func (s *checkpointAwareRuntimeSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: "checkpoint_aware"}
}

func (s *checkpointAwareRuntimeSource) Check(context.Context, sourcecdk.Config) error {
	return nil
}

func (s *checkpointAwareRuntimeSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (s *checkpointAwareRuntimeSource) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return sourcecdk.Pull{}, errors.New("Read called instead of ReadWithCheckpoint")
}

func (s *checkpointAwareRuntimeSource) ReadWithCheckpoint(_ context.Context, _ sourcecdk.Config, _ *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
	s.seenCheckpoint = cloneCheckpoint(checkpoint)
	return s.pull, nil
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
				"token":  "fake-sensitive-value",
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
	if got := store.runtimes["writer-okta-users"].GetConfig()["token"]; got != "fake-sensitive-value" {
		t.Fatalf("stored runtime token = %q, want %q", got, "fake-sensitive-value")
	}
}

func TestPutRuntimesValidatesBatchBeforeWriting(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(emptyPageSource{}, failingSource{err: sourcecdk.ErrInvalidConfig})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &runtimeStore{}
	service := New(registry, store, nil, nil)

	_, err = service.PutRuntimes(context.Background(), PutRuntimesRequest{Runtimes: []*cerebrov1.SourceRuntime{
		{Id: "runtime-1", SourceId: "empty_page"},
		{Id: "runtime-2", SourceId: "failing"},
	}})
	if err == nil {
		t.Fatal("PutRuntimes() error = nil, want non-nil")
	}
	if store.putCount != 0 {
		t.Fatalf("store.putCount = %d, want 0", store.putCount)
	}
	if len(store.runtimes) != 0 {
		t.Fatalf("store.runtimes len = %d, want 0", len(store.runtimes))
	}
}

func TestPutRuntimesRejectsDuplicateRuntimeIDs(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(emptyPageSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &runtimeStore{}
	service := New(registry, store, nil, nil)

	_, err = service.PutRuntimes(context.Background(), PutRuntimesRequest{Runtimes: []*cerebrov1.SourceRuntime{
		{Id: "runtime-1", SourceId: "empty_page"},
		{Id: " runtime-1 ", SourceId: "empty_page"},
	}})
	if err == nil {
		t.Fatal("PutRuntimes() error = nil, want non-nil")
	}
	if store.putCount != 0 {
		t.Fatalf("store.putCount = %d, want 0", store.putCount)
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
			Config:   map[string]string{"token": "env:CEREBRO_SOURCE_TOKEN_SOURCE_TOKEN"}, // #nosec G101 -- test env reference string, not a secret value.
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
			Config: map[string]string{ // #nosec G101 -- test env reference strings, not secret values.
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
	rawConfig := map[string]string{ // #nosec G101 -- test env reference strings, not secret values.
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

func TestProgressConfigHashIgnoresInternalRuntimeMetadata(t *testing.T) {
	base := progressConfigHash(map[string]string{
		"lookup_key": "inventory",
	})
	withInternal := progressConfigHash(map[string]string{
		"lookup_key":                           "inventory",
		sourceconfig.RuntimeIDKey:              "writer-inventory",
		sourceconfig.RuntimeTenantIDKey:        "writer",
		sourceconfig.AWSAssumeRoleAllowlistKey: "writer=arn:aws:iam::123456789012:role/cerebro-org-scan-role",
		sourceconfig.GCPWIFAllowlistKey:        "writer=//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/aws|scanner@writer-iam.iam.gserviceaccount.com",
		runtimeProgressConfigHashKey:           "old-hash",
	})
	if base != withInternal {
		t.Fatal("progressConfigHash changed when only internal runtime metadata changed")
	}
}

func TestUserConfigStripsInternalAssumeRoleAllowlist(t *testing.T) {
	config := userConfig(map[string]string{
		"family":                               "public_endpoint",
		runtimeProgressConfigHashKey:           "hash",
		sourceconfig.AWSAssumeRoleAllowlistKey: "caller-controlled",
		sourceconfig.GCPWIFAllowlistKey:        "caller-controlled",
		sourceconfig.RuntimeIDKey:              "writer-endpoint",
		sourceconfig.RuntimeTenantIDKey:        "writer",
	})
	if got := config["family"]; got != "public_endpoint" {
		t.Fatalf("family = %q, want public_endpoint", got)
	}
	if _, ok := config[sourceconfig.AWSAssumeRoleAllowlistKey]; ok {
		t.Fatal("userConfig preserved internal assume-role allowlist key")
	}
	if _, ok := config[sourceconfig.GCPWIFAllowlistKey]; ok {
		t.Fatal("userConfig preserved internal gcp wif allowlist key")
	}
	if _, ok := config[runtimeProgressConfigHashKey]; ok {
		t.Fatal("userConfig preserved progress config hash key")
	}
	if _, ok := config[sourceconfig.RuntimeIDKey]; ok {
		t.Fatal("userConfig preserved internal runtime id key")
	}
	if _, ok := config[sourceconfig.RuntimeTenantIDKey]; ok {
		t.Fatal("userConfig preserved internal runtime tenant key")
	}
}

func TestResolveConfigPreservesTrustedInternalRuntimeConfig(t *testing.T) {
	service := New(nil, nil, nil, nil).WithConfigResolver(func(_ context.Context, _ string, values map[string]string) (map[string]string, error) {
		if _, ok := values[sourceconfig.AWSAssumeRoleAllowlistKey]; ok {
			t.Fatal("resolver input preserved caller-controlled allowlist")
		}
		if _, ok := values[sourceconfig.GCPWIFAllowlistKey]; ok {
			t.Fatal("resolver input preserved caller-controlled gcp wif allowlist")
		}
		if got := values[sourceconfig.RuntimeIDKey]; got != "writer-endpoint" {
			t.Fatalf("resolver runtime id = %q, want writer-endpoint", got)
		}
		if got := values[sourceconfig.RuntimeTenantIDKey]; got != "writer" {
			t.Fatalf("resolver runtime tenant = %q, want writer", got)
		}
		return map[string]string{
			"family":                               "public_endpoint",
			runtimeProgressConfigHashKey:           "hash",
			sourceconfig.AWSAssumeRoleAllowlistKey: "writer=arn:aws:iam::123456789012:role/cerebro-org-scan-role",
			sourceconfig.GCPWIFAllowlistKey:        "writer=//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/aws|scanner@writer-iam.iam.gserviceaccount.com",
		}, nil
	})

	resolved, err := service.resolveConfig(context.Background(), "aws", "writer", "writer-endpoint", map[string]string{
		sourceconfig.AWSAssumeRoleAllowlistKey: "caller-controlled",
		sourceconfig.GCPWIFAllowlistKey:        "caller-controlled",
	})
	if err != nil {
		t.Fatalf("resolveConfig() error = %v", err)
	}
	if got := resolved[sourceconfig.AWSAssumeRoleAllowlistKey]; got != "writer=arn:aws:iam::123456789012:role/cerebro-org-scan-role" {
		t.Fatalf("assume-role allowlist = %q, want trusted resolver value", got)
	}
	if got := resolved[sourceconfig.GCPWIFAllowlistKey]; got != "writer=//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/aws|scanner@writer-iam.iam.gserviceaccount.com" {
		t.Fatalf("gcp wif allowlist = %q, want trusted resolver value", got)
	}
	if got := resolved[sourceconfig.RuntimeTenantIDKey]; got != "writer" {
		t.Fatalf("runtime tenant = %q, want writer", got)
	}
	if got := resolved[sourceconfig.RuntimeIDKey]; got != "writer-endpoint" {
		t.Fatalf("runtime id = %q, want writer-endpoint", got)
	}
	if _, ok := resolved[runtimeProgressConfigHashKey]; ok {
		t.Fatal("resolveConfig preserved progress hash")
	}
}

func TestListRedactsSensitiveConfigAndFilters(t *testing.T) {
	service := New(nil, &runtimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"writer-token": {Id: "writer-token", SourceId: "github", TenantId: "writer", Config: map[string]string{"token": "env:CEREBRO_TEST_TOKEN", "lookup_key": "prod", "group_key": "eng"}}, // #nosec G101 -- env-reference test fixture, not credential material.
		"other-token":  {Id: "other-token", SourceId: "okta", TenantId: "other", Config: map[string]string{"token": "env:OTHER"}},                                                            // #nosec G101 -- env-reference test fixture, not credential material.
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

	runtimes, err = service.List(context.Background(), ports.SourceRuntimeFilter{RuntimeID: "other-token"})
	if err != nil {
		t.Fatalf("List(runtime_id) error = %v", err)
	}
	if len(runtimes) != 1 || runtimes[0].GetId() != "other-token" {
		t.Fatalf("List(runtime_id) returned %#v, want other-token", runtimes)
	}
}

func TestListSupportsRuntimeIDsFilter(t *testing.T) {
	service := New(nil, &runtimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"runtime-a": {Id: "runtime-a", SourceId: "okta", TenantId: "writer"},
		"runtime-b": {Id: "runtime-b", SourceId: "github", TenantId: "writer"},
		"runtime-c": {Id: "runtime-c", SourceId: "aws", TenantId: "writer"},
	}}, nil, nil)

	runtimes, err := service.List(context.Background(), ports.SourceRuntimeFilter{RuntimeIDs: []string{"runtime-b", "runtime-a", "runtime-b"}})
	if err != nil {
		t.Fatalf("List(runtime_ids) error = %v", err)
	}
	got := []string{}
	for _, runtime := range runtimes {
		got = append(got, runtime.GetId())
	}
	sort.Strings(got)
	if len(got) != 2 || got[0] != "runtime-a" || got[1] != "runtime-b" {
		t.Fatalf("List(runtime_ids) ids = %#v, want runtime-a/runtime-b", got)
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

func TestPutMergesStoredTenantBeforeValidation(t *testing.T) {
	source := &tenantCheckSource{}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-tenant-check": {
				Id:       "writer-tenant-check",
				SourceId: "tenant_check",
				TenantId: "writer",
				Config:   map[string]string{"lookup_key": "inventory"},
			},
		},
	}
	service := New(registry, store, nil, nil)

	resp, err := service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{
		Runtime: &cerebrov1.SourceRuntime{
			Id:       "writer-tenant-check",
			SourceId: "tenant_check",
			Config:   map[string]string{"lookup_key": "inventory"},
		},
	})
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if source.checkedTenant != "writer" {
		t.Fatalf("source checked tenant = %q, want writer", source.checkedTenant)
	}
	if resp.GetRuntime().GetTenantId() != "writer" {
		t.Fatalf("Put().Runtime.TenantId = %q, want writer", resp.GetRuntime().GetTenantId())
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

func TestRuntimeWatermarkLagUsesCheckpointWatermark(t *testing.T) {
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	watermark := now.Add(-2 * time.Hour)
	runtime := &cerebrov1.SourceRuntime{
		Checkpoint: &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(watermark)},
	}

	gotWatermark, lagSeconds, ok := runtimeWatermarkLag(runtime, now)
	if !ok {
		t.Fatal("runtimeWatermarkLag ok = false, want true")
	}
	if !gotWatermark.Equal(watermark) {
		t.Fatalf("watermark = %s, want %s", gotWatermark, watermark)
	}
	if lagSeconds != int64((2 * time.Hour).Seconds()) {
		t.Fatalf("lagSeconds = %d, want 7200", lagSeconds)
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

func TestPutPreservesOmittedResourceScopePolicyOnRedactedRoundTrip(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(emptyPageSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	scopeValue, err := resourcescope.ConfigValue(resourcescope.Policy{ExcludedFamilies: []string{"empty_page.event"}})
	if err != nil {
		t.Fatalf("scope ConfigValue() error = %v", err)
	}
	store := &runtimeStore{}
	service := New(registry, store, nil, nil)

	_, err = service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{
		Runtime: &cerebrov1.SourceRuntime{
			Id:       "writer-empty-page",
			SourceId: "empty_page",
			TenantId: "writer",
			Config: map[string]string{
				"owner":                 "platform",
				resourcescope.ConfigKey: scopeValue,
			},
			Checkpoint: &cerebrov1.SourceCheckpoint{CursorOpaque: "1"},
			NextCursor: &cerebrov1.SourceCursor{Opaque: "1"},
		},
	})
	if err != nil {
		t.Fatalf("initial Put() error = %v", err)
	}
	getResp, err := service.Get(context.Background(), &cerebrov1.GetSourceRuntimeRequest{Id: "writer-empty-page"})
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if _, ok := getResp.GetRuntime().GetConfig()[resourcescope.ConfigKey]; ok {
		t.Fatal("redacted Get() response exposed resource scope config")
	}

	_, err = service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{Runtime: getResp.GetRuntime()})
	if err != nil {
		t.Fatalf("round-trip Put() error = %v", err)
	}
	stored := store.runtimes["writer-empty-page"]
	if got := stored.GetConfig()[resourcescope.ConfigKey]; got != scopeValue {
		t.Fatalf("stored scope policy = %q, want preserved %q", got, scopeValue)
	}
	if got := stored.GetNextCursor().GetOpaque(); got != "1" {
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
	if got := log.events[0].GetAttributes()["trace_id"]; got != "" {
		t.Fatalf("appended event trace_id = %q, want omitted", got)
	}
	if got := log.events[0].GetAttributes()["span_id"]; got != "" {
		t.Fatalf("appended event span_id = %q, want omitted", got)
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

func TestSyncRuntimeTelemetryClassifiesErrorsWithoutRawSecret(t *testing.T) {
	secretErr := errors.New("upstream failed credential=fake-sensitive-value")
	registry, err := sourcecdk.NewRegistry(failingSource{err: secretErr})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-failing": {
				Id:       "writer-failing",
				SourceId: "failing",
			},
		},
	}
	service := New(registry, store, &appendLog{}, nil)

	stderr := captureSourceRuntimeStderr(t, func() {
		_, err := service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "writer-failing"})
		if !errors.Is(err, secretErr) {
			t.Fatalf("Sync() error = %v, want wrapped secret error", err)
		}
	})

	payload := sourceRuntimeTelemetryPayload(t, stderr, "source_runtime.sync")
	if got := payload["error_kind"]; got != "sync_failed" {
		t.Fatalf("telemetry error_kind = %#v, want sync_failed; payload=%#v", got, payload)
	}
	if strings.Contains(stderr, "fake-sensitive-value") || strings.Contains(stderr, "credential=") {
		t.Fatalf("source runtime telemetry leaked raw error: %s", stderr)
	}
	stored := store.runtimes["writer-failing"]
	if got := stored.GetConfig()[runtimeStatusConfigKey]; got != "failed" {
		t.Fatalf("runtime status = %q, want failed", got)
	}
	if got := stored.GetConfig()[runtimeLastFailureCategoryConfigKey]; got != "sync_failed" {
		t.Fatalf("failure category = %q, want sync_failed", got)
	}
}

func TestSyncRuntimeTelemetryKeepsTenantContextOnEarlyFailure(t *testing.T) {
	registry, err := sourcecdk.NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-missing-source": {
				Id:       "writer-missing-source",
				SourceId: "missing_source",
				TenantId: "writer",
			},
		},
	}
	service := New(registry, store, &appendLog{}, nil)

	stderr := captureSourceRuntimeStderr(t, func() {
		_, err := service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "writer-missing-source"})
		if err == nil {
			t.Fatal("Sync() error = nil, want missing source error")
		}
	})

	payload := sourceRuntimeTelemetryPayload(t, stderr, "source_runtime.sync")
	for key, want := range map[string]any{
		"runtime_id":                         "writer-missing-source",
		"source_id":                          "missing_source",
		"tenant_id":                          "writer",
		"source_runtime.id":                  "writer-missing-source",
		"source_runtime.source_id":           "missing_source",
		"source_runtime.tenant_id":           "writer",
		"source_runtime.sync.status":         "failed",
		"source_runtime.sync.runtime_loaded": true,
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry %s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
}

func TestSyncRuntimeTelemetryIncludesBoundedFreshnessMetadata(t *testing.T) {
	checkpoint := sourcecdk.FamilyFreshnessCheckpoint("github", "audit", nil, sourcecdk.FamilyFreshnessProbe{
		Kind:       "audit_log_latest_event",
		ResourceID: "github-audit-sensitive-document-id",
		Hash:       "sensitive-canary-hash",
		Confidence: sourcecdk.FamilyFreshnessConfidenceHeuristic,
		SkipCount:  2,
		Reason:     sourcecdk.FamilyFreshnessReasonShortCircuit,
	})
	source := &checkpointAwareRuntimeSource{pull: sourcecdk.Pull{
		Checkpoint:         checkpoint,
		ShortCircuitReason: sourcecdk.PullShortCircuitReasonNotModified,
	}}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &runtimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"writer-checkpoint-aware": {
			Id:       "writer-checkpoint-aware",
			SourceId: "checkpoint_aware",
			TenantId: "writer",
		},
	}}
	service := New(registry, store, &appendLog{}, nil)

	stderr := captureSourceRuntimeStderr(t, func() {
		if _, err := service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "writer-checkpoint-aware"}); err != nil {
			t.Fatalf("Sync() error = %v", err)
		}
	})

	payload := sourceRuntimeTelemetryPayload(t, stderr, "source_runtime.sync")
	for key, want := range map[string]any{
		"family_freshness_source":           "github",
		"family_freshness_family":           "audit",
		"family_freshness_confidence":       "heuristic",
		"family_freshness_reconcile_reason": "short_circuit",
		"family_freshness_forced_reconcile": false,
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry %s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	if got := payload["family_freshness_skip_count"]; got != float64(2) {
		t.Fatalf("telemetry family_freshness_skip_count = %#v, want 2; payload=%#v", got, payload)
	}
	if strings.Contains(stderr, "github-audit-sensitive-document-id") || strings.Contains(stderr, "sensitive-canary-hash") {
		t.Fatalf("freshness telemetry leaked raw canary metadata: %s", stderr)
	}
}

func TestSyncRuntimePersistsFailureCategories(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		want string
	}{
		{name: "auth", err: errors.New("provider returned 401 unauthorized"), want: "auth_error"},
		{name: "rate limited", err: errors.New("provider returned 429 too many requests"), want: "rate_limited"},
		{name: "unavailable", err: errors.New("connection refused"), want: "provider_unavailable"},
		{name: "invalid config", err: sourcecdk.ErrInvalidConfig, want: "invalid_source_config"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			registry, err := sourcecdk.NewRegistry(failingSource{err: tt.err})
			if err != nil {
				t.Fatalf("NewRegistry() error = %v", err)
			}
			store := &runtimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-failing": {Id: "writer-failing", SourceId: "failing"},
			}}
			service := New(registry, store, &appendLog{}, nil)
			_, err = service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "writer-failing"})
			if !errors.Is(err, tt.err) {
				t.Fatalf("Sync() error = %v, want %v", err, tt.err)
			}
			stored := store.runtimes["writer-failing"]
			if got := stored.GetConfig()[runtimeStatusConfigKey]; got != "failed" {
				t.Fatalf("runtime status = %q, want failed", got)
			}
			if got := stored.GetConfig()[runtimeLastFailureCategoryConfigKey]; got != tt.want {
				t.Fatalf("failure category = %q, want %q", got, tt.want)
			}
		})
	}
}

func FuzzInvalidEventFailureClassification(f *testing.F) {
	f.Add("missing required attribute source_system")
	f.Add("missing required payload field uri")
	f.Add("provider returned 401 unauthorized")
	f.Add("provider returned 429 too many requests")
	f.Add("connection refused")
	f.Fuzz(func(t *testing.T, message string) {
		err := errors.New(message)
		category := sourceRuntimeFailureCategory(err)
		switch category {
		case "auth_error", "rate_limited", "provider_unavailable", "sync_failed":
		default:
			t.Fatalf("unexpected source runtime failure category %q", category)
		}
		invalidCategory := invalidEventFailureCategory(err)
		switch invalidCategory {
		case "missing_required_attribute", "missing_required_payload_field", "invalid_event":
		default:
			t.Fatalf("unexpected invalid event failure category %q", invalidCategory)
		}
		field := invalidEventFieldName(err)
		if strings.Contains(field, " ") || strings.Contains(field, ":") {
			t.Fatalf("invalid event field was not bounded to field token: %q", field)
		}
	})
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

func TestSyncRuntimeStartsFromResumableCheckpointCursor(t *testing.T) {
	source := &checkpointResumeSource{}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	checkpointCursor := `{"source":"cosmo.message","resumable_checkpoint":true,"since":"2026-05-14T00:00:00Z"}`
	store := &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-checkpoint": {
				Id:       "writer-checkpoint",
				SourceId: "checkpoint_resume",
				TenantId: "writer",
				Checkpoint: &cerebrov1.SourceCheckpoint{
					CursorOpaque: checkpointCursor,
				},
			},
		},
	}
	service := New(registry, store, &appendLog{}, nil)

	if _, err := service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "writer-checkpoint"}); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if source.seenCursor != checkpointCursor {
		t.Fatalf("source cursor = %q, want checkpoint cursor", source.seenCursor)
	}
}

func TestSyncRuntimeFollowUpUsesPersistedResumableCheckpointCursor(t *testing.T) {
	checkpointCursor := `{"policy_type_index":2,"resumable_checkpoint":true}`
	source := &persistedCheckpointResumeSource{checkpointCursor: checkpointCursor}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-policy-rule": {
				Id:       "writer-okta-policy-rule",
				SourceId: "persisted_checkpoint_resume",
				TenantId: "writer",
			},
		},
	}
	service := New(registry, store, &appendLog{}, nil)

	if _, err := service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "writer-okta-policy-rule"}); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}
	stored := store.runtimes["writer-okta-policy-rule"]
	if got := stored.GetCheckpoint().GetCursorOpaque(); got != checkpointCursor {
		t.Fatalf("stored checkpoint cursor = %q, want %q", got, checkpointCursor)
	}
	if stored.GetNextCursor() != nil {
		t.Fatalf("stored next cursor = %#v, want nil terminal page", stored.GetNextCursor())
	}

	if _, err := service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "writer-okta-policy-rule"}); err != nil {
		t.Fatalf("follow-up Sync() error = %v", err)
	}
	if len(source.seenCursors) != 2 {
		t.Fatalf("seen cursors = %v, want initial and follow-up reads", source.seenCursors)
	}
	if source.seenCursors[0] != "" {
		t.Fatalf("initial sync cursor = %q, want fresh start", source.seenCursors[0])
	}
	if source.seenCursors[1] != checkpointCursor {
		t.Fatalf("follow-up sync cursor = %q, want persisted checkpoint cursor %q", source.seenCursors[1], checkpointCursor)
	}
}

func TestSyncRuntimePassesCheckpointAndPersistsShortCircuitReason(t *testing.T) {
	watermark := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	existingCheckpoint := &cerebrov1.SourceCheckpoint{
		Watermark:    timestamppb.New(watermark),
		CursorOpaque: `{"source":"github","resumable_checkpoint":true}`,
	}
	source := &checkpointAwareRuntimeSource{pull: sourcecdk.Pull{
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    timestamppb.New(watermark),
			CursorOpaque: `{"source":"github","family":"pull_request","resumable_checkpoint":true}`,
		},
		ShortCircuitReason: sourcecdk.PullShortCircuitReasonNotModified,
	}}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &runtimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"writer-checkpoint-aware": {
			Id:         "writer-checkpoint-aware",
			SourceId:   "checkpoint_aware",
			TenantId:   "writer",
			Checkpoint: existingCheckpoint,
		},
	}}
	log := &appendLog{}
	service := New(registry, store, log, nil)

	resp, err := service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "writer-checkpoint-aware"})
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if !proto.Equal(source.seenCheckpoint, existingCheckpoint) {
		t.Fatalf("ReadWithCheckpoint checkpoint = %v, want %v", source.seenCheckpoint, existingCheckpoint)
	}
	if resp.GetPagesRead() != 1 || resp.GetEventsAppended() != 0 {
		t.Fatalf("Sync() pages/events = %d/%d, want 1/0", resp.GetPagesRead(), resp.GetEventsAppended())
	}
	if len(log.events) != 0 {
		t.Fatalf("len(appendLog.events) = %d, want 0", len(log.events))
	}
	stored := store.runtimes["writer-checkpoint-aware"]
	if got := stored.GetConfig()[runtimeShortCircuitReasonConfigKey]; got != "not_modified" {
		t.Fatalf("short circuit reason = %q, want not_modified", got)
	}
	if got := stored.GetCheckpoint().GetCursorOpaque(); got != source.pull.Checkpoint.GetCursorOpaque() {
		t.Fatalf("stored checkpoint cursor = %q, want %q", got, source.pull.Checkpoint.GetCursorOpaque())
	}
}

func TestSyncRuntimePersistsReconciliationReason(t *testing.T) {
	source := &checkpointAwareRuntimeSource{pull: sourcecdk.Pull{
		Events:               []*cerebrov1.EventEnvelope{runtimeTestEvent("event-1", "checkpoint_aware", "checkpoint_aware.event")},
		ReconciliationReason: sourcecdk.PullReconciliationReasonMaxConsecutiveSkips,
	}}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &runtimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"writer-checkpoint-aware": {
			Id:       "writer-checkpoint-aware",
			SourceId: "checkpoint_aware",
			TenantId: "writer",
		},
	}}
	service := New(registry, store, &appendLog{}, nil)

	resp, err := service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "writer-checkpoint-aware"})
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if resp.GetEventsAppended() != 1 {
		t.Fatalf("EventsAppended = %d, want 1", resp.GetEventsAppended())
	}
	stored := store.runtimes["writer-checkpoint-aware"]
	if got := stored.GetConfig()[runtimeReconciliationReasonConfigKey]; got != "max_consecutive_skips" {
		t.Fatalf("reconciliation reason = %q, want max_consecutive_skips", got)
	}
	if got := stored.GetConfig()[runtimeShortCircuitReasonConfigKey]; got != "" {
		t.Fatalf("short circuit reason = %q, want empty", got)
	}
}

func TestSyncRuntimeDoesNotRegressCheckpointWatermark(t *testing.T) {
	newer := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	older := newer.Add(-time.Hour)
	existingEnvelope := sourcecdk.CursorEnvelope{
		Version:             1,
		Source:              "github",
		Family:              "pull_request",
		Mode:                "incremental_watermark",
		ResumableCheckpoint: true,
		Token:               "2",
		BoundaryIDs:         []string{"newer"},
	}
	sourcecdk.SetCursorWatermark(&existingEnvelope, newer)
	existingCursor, err := sourcecdk.EncodeCursorEnvelope(existingEnvelope)
	if err != nil {
		t.Fatalf("EncodeCursorEnvelope(existing) error = %v", err)
	}
	source := &checkpointAwareRuntimeSource{pull: sourcecdk.Pull{
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    timestamppb.New(older),
			CursorOpaque: "older",
		},
	}}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &runtimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"writer-checkpoint-aware": {
			Id:       "writer-checkpoint-aware",
			SourceId: "checkpoint_aware",
			TenantId: "writer",
			Checkpoint: &cerebrov1.SourceCheckpoint{
				Watermark:    timestamppb.New(newer),
				CursorOpaque: existingCursor,
			},
		},
	}}
	service := New(registry, store, &appendLog{}, nil)

	if _, err := service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "writer-checkpoint-aware"}); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	stored := store.runtimes["writer-checkpoint-aware"]
	if got := stored.GetCheckpoint().GetWatermark().AsTime(); !got.Equal(newer) {
		t.Fatalf("stored watermark = %s, want %s", got, newer)
	}
	storedEnvelope, ok := sourcecdk.DecodeCursorEnvelope(stored.GetCheckpoint().GetCursorOpaque())
	if !ok {
		t.Fatal("stored checkpoint cursor is not an envelope")
	}
	if storedEnvelope.Token != "" {
		t.Fatalf("stored token = %q, want terminal checkpoint without continuation token", storedEnvelope.Token)
	}
	if got := storedEnvelope.BoundaryIDs; len(got) != 1 || got[0] != "newer" {
		t.Fatalf("stored boundary IDs = %#v, want newer", got)
	}
	if got := stored.GetConfig()[runtimeShortCircuitReasonConfigKey]; got != "checkpoint_advanced" {
		t.Fatalf("short circuit reason = %q, want checkpoint_advanced", got)
	}
}

func TestSyncRuntimeMergesEqualWatermarkCheckpointBoundaries(t *testing.T) {
	watermark := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	existingEnvelope := sourcecdk.CursorEnvelope{
		Version:             1,
		Source:              "github",
		Family:              "pull_request",
		Mode:                "incremental_watermark",
		ResumableCheckpoint: true,
		Token:               "2",
		BoundaryIDs:         []string{"first"},
		Extra: map[string]string{
			sourcecdk.FamilyFreshnessExtraKind:       "repo_updated_at",
			sourcecdk.FamilyFreshnessExtraResourceID: "writer/cerebro",
			sourcecdk.FamilyFreshnessExtraHash:       "old-hash",
			"preserved":                              "yes",
		},
	}
	sourcecdk.SetCursorWatermark(&existingEnvelope, watermark)
	existingCursor, err := sourcecdk.EncodeCursorEnvelope(existingEnvelope)
	if err != nil {
		t.Fatalf("EncodeCursorEnvelope(existing) error = %v", err)
	}
	nextEnvelope := sourcecdk.CursorEnvelope{
		Version:             1,
		Source:              "github",
		Family:              "pull_request",
		Mode:                "incremental_watermark",
		ResumableCheckpoint: true,
		BoundaryIDs:         []string{"second"},
		Extra: map[string]string{
			sourcecdk.FamilyFreshnessExtraHash: "new-hash",
		},
	}
	sourcecdk.SetCursorWatermark(&nextEnvelope, watermark)
	nextCursor, err := sourcecdk.EncodeCursorEnvelope(nextEnvelope)
	if err != nil {
		t.Fatalf("EncodeCursorEnvelope(next) error = %v", err)
	}
	source := &checkpointAwareRuntimeSource{pull: sourcecdk.Pull{
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    timestamppb.New(watermark),
			CursorOpaque: nextCursor,
		},
	}}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &runtimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"writer-checkpoint-aware": {
			Id:       "writer-checkpoint-aware",
			SourceId: "checkpoint_aware",
			TenantId: "writer",
			Checkpoint: &cerebrov1.SourceCheckpoint{
				Watermark:    timestamppb.New(watermark),
				CursorOpaque: existingCursor,
			},
		},
	}}
	service := New(registry, store, &appendLog{}, nil)

	if _, err := service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "writer-checkpoint-aware"}); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	storedEnvelope, ok := sourcecdk.DecodeCursorEnvelope(store.runtimes["writer-checkpoint-aware"].GetCheckpoint().GetCursorOpaque())
	if !ok {
		t.Fatal("stored checkpoint cursor is not an envelope")
	}
	if storedEnvelope.Token != "" {
		t.Fatalf("stored token = %q, want terminal checkpoint without continuation token", storedEnvelope.Token)
	}
	if got := storedEnvelope.BoundaryIDs; len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Fatalf("stored boundary IDs = %#v, want first and second", got)
	}
	if got := storedEnvelope.Extra["preserved"]; got != "yes" {
		t.Fatalf("stored preserved extra = %q, want yes", got)
	}
	if got := storedEnvelope.Extra[sourcecdk.FamilyFreshnessExtraHash]; got != "new-hash" {
		t.Fatalf("stored canary hash = %q, want next checkpoint hash", got)
	}
	if got := storedEnvelope.Extra[sourcecdk.FamilyFreshnessExtraKind]; got != "repo_updated_at" {
		t.Fatalf("stored canary kind = %q, want existing kind", got)
	}
}

func TestSyncRuntimeSkipsNilEvents(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(nilEventSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-nil-event": {
				Id:       "writer-nil-event",
				SourceId: "nil_event",
				TenantId: "writer",
			},
		},
	}
	log := &appendLog{}
	service := New(registry, store, log, nil)

	resp, err := service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "writer-nil-event"})
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if resp.GetEventsAppended() != 1 {
		t.Fatalf("Sync().EventsAppended = %d, want 1", resp.GetEventsAppended())
	}
	if len(log.events) != 1 {
		t.Fatalf("len(appendLog.events) = %d, want 1", len(log.events))
	}
	if got := log.events[0].GetId(); got != "event-after-nil" {
		t.Fatalf("appended event id = %q, want event-after-nil", got)
	}
	if got := log.events[0].GetAttributes()[ports.EventAttributeSourceRuntimeID]; got != "writer-nil-event" {
		t.Fatalf("appended event source_runtime_id = %q, want writer-nil-event", got)
	}
}

func TestSyncRuntimeRejectsInvalidSourceEvents(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(invalidEventSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"example-invalid-event": {
				Id:       "example-invalid-event",
				SourceId: "invalid_event",
				TenantId: "example",
			},
		},
	}
	log := &appendLog{}
	service := New(registry, store, log, nil)

	_, err = service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "example-invalid-event"})
	if !errors.Is(err, sourcecdk.ErrInvalidEventEnvelope) {
		t.Fatalf("Sync() error = %v, want ErrInvalidEventEnvelope", err)
	}
	if len(log.events) != 0 {
		t.Fatalf("len(appendLog.events) = %d, want 0", len(log.events))
	}
}

func TestSyncRuntimeRejectsEventsMissingCatalogContractFields(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(contractEventSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"example-contract-event": {
				Id:       "example-contract-event",
				SourceId: "contract_event",
				TenantId: "example",
			},
		},
	}
	log := &appendLog{}
	service := New(registry, store, log, nil)

	var resp *cerebrov1.SyncSourceRuntimeResponse
	stderr := captureSourceRuntimeStderr(t, func() {
		var syncErr error
		resp, syncErr = service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "example-contract-event"})
		if syncErr != nil {
			t.Fatalf("Sync() error = %v", syncErr)
		}
	})
	if len(log.events) != 0 {
		t.Fatalf("len(appendLog.events) = %d, want 0", len(log.events))
	}
	if resp.GetEventsAppended() != 0 {
		t.Fatalf("Sync().EventsAppended = %d, want 0", resp.GetEventsAppended())
	}
	stored := store.runtimes["example-contract-event"]
	for key, want := range map[string]string{
		runtimeStatusConfigKey:              "completed",
		runtimeRecordsScannedConfigKey:      "1",
		runtimeRecordsAcceptedConfigKey:     "0",
		runtimeRecordsRejectedConfigKey:     "1",
		runtimeLastFailureCategoryConfigKey: "missing_required_attribute",
		runtimeLastInvalidFieldConfigKey:    "required_attribute",
		runtimeLastInvalidStatusConfigKey:   "terminal",
		runtimeContractProbeStateConfigKey:  "failure",
	} {
		if got := stored.GetConfig()[key]; got != want {
			t.Fatalf("stored config[%s] = %q, want %q", key, got, want)
		}
	}
	if stored.GetLastSyncedAt() == nil {
		t.Fatal("LastSyncedAt is nil, want terminal rejection to commit sync status")
	}
	validationPayload := sourceRuntimeTelemetryEventPayload(t, stderr, "source_runtime.validation")
	for key, want := range map[string]any{
		"runtime_id":                    "example-contract-event",
		"source_id":                     "contract_event",
		"tenant_id":                     "example",
		"failure_category":              "missing_required_attribute",
		"missing_canonical_field_class": "attribute",
	} {
		if got := validationPayload[key]; got != want {
			t.Fatalf("validation telemetry %s = %#v, want %#v; payload=%#v", key, got, want, validationPayload)
		}
	}
	probePayload := sourceRuntimeTelemetryEventPayload(t, stderr, "source_runtime.contract_probe")
	for key, want := range map[string]any{
		"runtime_id":            "example-contract-event",
		"source_id":             "contract_event",
		"tenant_id":             "example",
		"contract_probe_state":  "failure",
		"contract_probe_status": "failure",
	} {
		if got := probePayload[key]; got != want {
			t.Fatalf("contract probe telemetry %s = %#v, want %#v; payload=%#v", key, got, want, probePayload)
		}
	}
}

func TestEmitSourceRuntimeContractProbeMapsPassingState(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{
		Id:       "example-contract-event",
		SourceId: "contract_event",
		TenantId: "example",
		Config: map[string]string{
			runtimeContractProbeStateConfigKey: "passing",
		},
	}
	stderr := captureSourceRuntimeStderr(t, func() {
		emitSourceRuntimeContractProbe(context.Background(), runtime)
	})

	payload := sourceRuntimeTelemetryEventPayload(t, stderr, "source_runtime.contract_probe")
	if got := payload["contract_probe_status"]; got != "success" {
		t.Fatalf("contract_probe_status = %#v, want success; payload=%#v", got, payload)
	}
	if got := payload["contract_probe_state"]; got != "passing" {
		t.Fatalf("contract_probe_state = %#v, want passing; payload=%#v", got, payload)
	}
}

func TestSyncRuntimeQuarantinesEvidenceCASMissingSourceSystem(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(evidenceCASMissingSourceSystemSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"example-evidence-cas": {
				Id:       "example-evidence-cas",
				SourceId: "evidence_cas",
				TenantId: "tenant-123",
			},
		},
	}
	log := &appendLog{}
	service := New(registry, store, log, nil)

	resp, err := service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "example-evidence-cas"})
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if len(log.events) != 0 {
		t.Fatalf("len(appendLog.events) = %d, want 0", len(log.events))
	}
	if resp.GetEventsAppended() != 0 {
		t.Fatalf("Sync().EventsAppended = %d, want 0", resp.GetEventsAppended())
	}
	stored := store.runtimes["example-evidence-cas"]
	for key, want := range map[string]string{
		runtimeStatusConfigKey:                "completed",
		runtimeRecordsScannedConfigKey:        "1",
		runtimeRecordsAcceptedConfigKey:       "0",
		runtimeRecordsRejectedConfigKey:       "1",
		runtimeLastFailureCategoryConfigKey:   "missing_required_attribute",
		runtimeLastInvalidEventIDConfigKey:    "iris-event-123",
		runtimeLastInvalidFieldConfigKey:      "source_system",
		runtimeLastInvalidStatusConfigKey:     "terminal",
		runtimeLastInvalidDiagnosticConfigKey: "missing required field source_system",
		runtimeLastInvalidRetryableConfigKey:  "false",
		runtimeContractProbeStateConfigKey:    "failure",
	} {
		if got := stored.GetConfig()[key]; got != want {
			t.Fatalf("stored config[%s] = %q, want %q", key, got, want)
		}
	}
	if stored.GetConfig()[runtimeLastInvalidObservedAtConfigKey] == "" {
		t.Fatal("stored invalid observed_at is empty")
	}
	if stored.GetConfig()[runtimeLastInvalidOccurredAtConfigKey] == "" {
		t.Fatal("stored invalid occurred_at is empty")
	}
	if stored.GetLastSyncedAt() == nil {
		t.Fatal("LastSyncedAt is nil, want terminal quarantine to commit sync status")
	}
}

func TestSyncRuntimeRejectsEventsWithoutCatalogContract(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(unmatchedContractEventSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"example-unmatched-contract-event": {
				Id:       "example-unmatched-contract-event",
				SourceId: "unmatched_contract_event",
				TenantId: "example",
			},
		},
	}
	log := &appendLog{}
	service := New(registry, store, log, nil)

	_, err = service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "example-unmatched-contract-event"})
	if !errors.Is(err, sourcecdk.ErrInvalidEventEnvelope) {
		t.Fatalf("Sync() error = %v, want ErrInvalidEventEnvelope", err)
	}
	if len(log.events) != 0 {
		t.Fatalf("len(appendLog.events) = %d, want 0", len(log.events))
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
