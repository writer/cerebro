package complianceexchange

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

func TestStageIsTenantScopedIdempotentAndRejectsDigestConflict(t *testing.T) {
	fixture := buildFixture(t)
	store := newMemoryStagingStore()
	service := stagingServiceAt(t, store, nil, exchangeTestTime)
	request := StagePackageRequest{
		TenantID: "tenant-1", IdempotencyKey: "upload-1", Package: fixture.built,
		ExpiresAt: exchangeTestTime.Add(time.Hour),
	}
	first, created, err := service.Stage(context.Background(), request)
	if err != nil || !created {
		t.Fatalf("first Stage() = created %v, error %v", created, err)
	}
	second, created, err := service.Stage(context.Background(), request)
	if err != nil || created || second.ID != first.ID || second.PackageDigest != first.PackageDigest {
		t.Fatalf("replay Stage() = %+v, created %v, error %v", second, created, err)
	}

	request.Package.Files = cloneFiles(request.Package.Files)
	request.Package.Files[0].Data = []byte("different staged bytes")
	if _, _, err := service.Stage(context.Background(), request); !errors.Is(err, ErrStagingDigest) {
		t.Fatalf("conflicting Stage() error = %v, want ErrStagingDigest", err)
	}
	if len(store.packages) != 1 {
		t.Fatalf("staged package count = %d, want 1", len(store.packages))
	}
}

func TestStageEnforcesExpiryAndByteLimitsBeforePersistence(t *testing.T) {
	fixture := buildFixture(t)
	store := newMemoryStagingStore()
	service := stagingServiceAt(t, store, nil, exchangeTestTime)
	base := StagePackageRequest{TenantID: "tenant-1", IdempotencyKey: "upload-1", Package: fixture.built}
	for _, test := range []struct {
		name      string
		expiresAt time.Time
		limits    StagingLimits
	}{
		{name: "expired", expiresAt: exchangeTestTime},
		{name: "ttl", expiresAt: exchangeTestTime.Add(25 * time.Hour)},
		{name: "size", expiresAt: exchangeTestTime.Add(time.Hour), limits: StagingLimits{MaxStagedBytes: 1, MaxTTL: time.Hour}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := base
			request.ExpiresAt = test.expiresAt
			request.Limits = test.limits
			if _, _, err := service.Stage(context.Background(), request); !errors.Is(err, ErrStagingInvalid) {
				t.Fatalf("Stage() error = %v, want ErrStagingInvalid", err)
			}
		})
	}
	if len(store.packages) != 0 {
		t.Fatal("invalid staging requests reached persistence")
	}
}

func TestValidateStagedReplayDoesNotMutateCanonicalState(t *testing.T) {
	fixture := buildFixture(t)
	store := newMemoryStagingStore()
	log := &recordingExchangeAppendLog{}
	service := stagingServiceAt(t, store, log, exchangeTestTime)
	stage := stageFixture(t, service, fixture.built)

	resolverCalls := 0
	trust := TrustResolverFunc(func(ctx context.Context, keyID string, algorithm string) (crypto.PublicKey, error) {
		resolverCalls++
		return fixture.trust.ResolveTrustedKey(ctx, keyID, algorithm)
	})
	first, err := service.ValidateStaged(context.Background(), ValidateStagedRequest{
		TenantID: "tenant-1", StagingID: stage.ID, ExpectedStagingVersion: 1,
		PolicyVersion: "trust-policy/v1", Trust: trust,
	})
	if err != nil || first.Status != ValidationValid || first.Replayed || first.Signature == nil || first.Result.ChangePlan == nil {
		t.Fatalf("first validation = %+v, error %v", first, err)
	}
	second, err := service.ValidateStaged(context.Background(), ValidateStagedRequest{
		TenantID: "tenant-1", StagingID: stage.ID, ExpectedStagingVersion: stage.Version,
		PolicyVersion: "trust-policy/v1", Trust: trust,
	})
	if err != nil || !second.Replayed || second.StagingVersion != first.StagingVersion {
		t.Fatalf("validation replay = %+v, error %v", second, err)
	}
	if resolverCalls != 1 || store.validationWrites != 1 {
		t.Fatalf("resolver calls=%d validation writes=%d, want one each", resolverCalls, store.validationWrites)
	}
	if store.canonicalWrites != 0 || len(log.events) != 0 || store.commitIntentWrites != 0 {
		t.Fatalf("validate-only mutated commit boundary: canonical=%d events=%d intents=%d", store.canonicalWrites, len(log.events), store.commitIntentWrites)
	}
}

func TestInvalidValidationPersistsIssuesWithoutPlanOrSignatureReceipt(t *testing.T) {
	fixture := buildFixture(t)
	fixture.built.Files[0].Data = []byte("altered")
	store := newMemoryStagingStore()
	service := stagingServiceAt(t, store, nil, exchangeTestTime)
	stage := stageFixture(t, service, fixture.built)
	result, err := service.ValidateStaged(context.Background(), ValidateStagedRequest{
		TenantID: "tenant-1", StagingID: stage.ID, ExpectedStagingVersion: 1,
		PolicyVersion: "trust-policy/v1", Trust: fixture.trust,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != ValidationInvalid || len(result.Result.Issues) == 0 || result.Result.ChangePlan != nil || result.Signature != nil {
		t.Fatalf("invalid validation persisted incorrectly: %+v", result)
	}
	stored := store.packages[stageKey("tenant-1", stage.ID)]
	if stored.Status != StagingStatusInvalid || stored.Version != 2 {
		t.Fatalf("staged status/version = %s/%d", stored.Status, stored.Version)
	}
}

func TestCommitIntentRequiresAuthorizationAndAppendsBeforeStateTransition(t *testing.T) {
	fixture := buildFixture(t)
	store := newMemoryStagingStore()
	log := &recordingExchangeAppendLog{}
	service := stagingServiceAt(t, store, log, exchangeTestTime)
	stage := stageFixture(t, service, fixture.built)
	validation := validateFixture(t, service, fixture, stage)
	intent, created, err := service.CreateCommitIntent(context.Background(), CreateCommitIntentRequest{
		TenantID: "tenant-1", StagingID: stage.ID, ExpectedStagingVersion: validation.StagingVersion,
		IdempotencyKey: "commit-1", RequestedBy: "reviewer-1",
	})
	if err != nil || !created || intent.Status != CommitIntentAwaitingAuthorization || intent.RequiredScope != ComplianceExchangeCommitScope {
		t.Fatalf("commit intent = %+v, created %v, error %v", intent, created, err)
	}
	request := AppendCommitIntentRequest{
		TenantID: "tenant-1", IntentID: intent.ID, ExpectedIntentVersion: 1,
		ExpectedStagingVersion: validation.StagingVersion,
	}
	if _, err := service.AppendCommitIntent(context.Background(), request); !errors.Is(err, ErrCommitAuthorization) {
		t.Fatalf("unauthorized append error = %v", err)
	}
	request.Authorization = AuthorizationReceipt{
		ActorID: "approver-1", DecisionID: "decision-1", Scope: ComplianceExchangeCommitScope,
		GrantedAt: exchangeTestTime,
	}
	committed, err := service.AppendCommitIntent(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if committed.Status != CommitIntentEventAppended || committed.Version != 2 || len(log.events) != 1 || store.markWrites != 1 {
		t.Fatalf("commit append = %+v events=%d marks=%d", committed, len(log.events), store.markWrites)
	}
	event := log.events[0]
	if event.Kind != workflowevents.EventKindComplianceExchangeCommitRequested || event.TenantId != "tenant-1" {
		t.Fatalf("event = %+v payload=%s", event, event.Payload)
	}
	aggregate, err := workflowevents.DecodeComplianceAggregate(event)
	if err != nil {
		t.Fatal(err)
	}
	var commitRequest map[string]any
	if err := json.Unmarshal([]byte(aggregate.PayloadJSON), &commitRequest); err != nil {
		t.Fatal(err)
	}
	if aggregate.AggregateID != stage.ID || aggregate.RevisionID != intent.ID || aggregate.AggregateVersion != 2 ||
		commitRequest["expected_staging_version"] != float64(2) || commitRequest["authorized_by"] != "approver-1" ||
		commitRequest["authorization_scope"] != ComplianceExchangeCommitScope {
		t.Fatalf("aggregate = %+v commit request = %#v", aggregate, commitRequest)
	}
	if bytesContainAny(event.Payload, fixture.built.ManifestBytes, fixture.built.Files[0].Data) {
		t.Fatal("commit event copied staged package content")
	}
	if store.canonicalWrites != 0 {
		t.Fatal("commit intent path mutated canonical state directly")
	}
	replayed, err := service.AppendCommitIntent(context.Background(), request)
	if err != nil || replayed.EventID != committed.EventID || len(log.events) != 1 || store.markWrites != 1 {
		t.Fatalf("commit append replay = %+v error=%v events=%d marks=%d", replayed, err, len(log.events), store.markWrites)
	}
	request.Authorization.DecisionID = "different-decision"
	if _, err := service.AppendCommitIntent(context.Background(), request); !errors.Is(err, ErrStagingDigest) {
		t.Fatalf("conflicting authorization replay error = %v, want ErrStagingDigest", err)
	}
}

func TestAppendFailureDoesNotAdvanceCommitIntent(t *testing.T) {
	fixture := buildFixture(t)
	store := newMemoryStagingStore()
	appendErr := errors.New("append unavailable")
	service := stagingServiceAt(t, store, &recordingExchangeAppendLog{err: appendErr}, exchangeTestTime)
	stage := stageFixture(t, service, fixture.built)
	validation := validateFixture(t, service, fixture, stage)
	intent, _, err := service.CreateCommitIntent(context.Background(), CreateCommitIntentRequest{
		TenantID: "tenant-1", StagingID: stage.ID, ExpectedStagingVersion: validation.StagingVersion,
		IdempotencyKey: "commit-1", RequestedBy: "reviewer-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.AppendCommitIntent(context.Background(), AppendCommitIntentRequest{
		TenantID: "tenant-1", IntentID: intent.ID, ExpectedIntentVersion: 1,
		ExpectedStagingVersion: validation.StagingVersion,
		Authorization:          AuthorizationReceipt{ActorID: "approver-1", DecisionID: "decision-1", Scope: ComplianceExchangeCommitScope, GrantedAt: exchangeTestTime},
	})
	if !errors.Is(err, appendErr) || store.markWrites != 0 {
		t.Fatalf("append error=%v mark writes=%d", err, store.markWrites)
	}
	stored := store.intents[intentKey("tenant-1", intent.ID)]
	if stored.Status != CommitIntentAwaitingAuthorization || stored.Version != 1 {
		t.Fatalf("intent advanced before append: %+v", stored)
	}
}

func TestComplianceAggregateVersionRejectsOverflow(t *testing.T) {
	if _, err := complianceAggregateVersion(^uint64(0)); !errors.Is(err, ErrStagingVersion) {
		t.Fatalf("complianceAggregateVersion() error = %v, want ErrStagingVersion", err)
	}
}

func bytesContainAny(content []byte, values ...[]byte) bool {
	for _, value := range values {
		if len(value) > 0 && strings.Contains(string(content), string(value)) {
			return true
		}
	}
	return false
}

func stagingServiceAt(t *testing.T, store StagingStore, log ports.AppendLog, now time.Time) *StagingService {
	t.Helper()
	service, err := NewStagingService(store, log)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	return service
}

func stageFixture(t *testing.T, service *StagingService, pkg Package) StagedPackage {
	t.Helper()
	stage, _, err := service.Stage(context.Background(), StagePackageRequest{
		TenantID: "tenant-1", IdempotencyKey: "upload-1", Package: pkg,
		ExpiresAt: exchangeTestTime.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return stage
}

func validateFixture(t *testing.T, service *StagingService, fixture packageFixture, stage StagedPackage) StagedValidation {
	t.Helper()
	result, err := service.ValidateStaged(context.Background(), ValidateStagedRequest{
		TenantID: "tenant-1", StagingID: stage.ID, ExpectedStagingVersion: stage.Version,
		PolicyVersion: "trust-policy/v1", Trust: fixture.trust,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

type memoryStagingStore struct {
	mu                 sync.Mutex
	packages           map[string]StagedPackage
	validations        map[string]StagedValidation
	intents            map[string]CommitIntent
	validationWrites   int
	commitIntentWrites int
	markWrites         int
	canonicalWrites    int
}

func newMemoryStagingStore() *memoryStagingStore {
	return &memoryStagingStore{packages: map[string]StagedPackage{}, validations: map[string]StagedValidation{}, intents: map[string]CommitIntent{}}
}

func (s *memoryStagingStore) PutStagedPackage(_ context.Context, stage StagedPackage) (StagedPackage, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, prior := range s.packages {
		if prior.TenantID == stage.TenantID && prior.IdempotencyKey == stage.IdempotencyKey {
			if prior.PackageDigest != stage.PackageDigest {
				return StagedPackage{}, false, ErrStagingDigest
			}
			return prior, false, nil
		}
	}
	s.packages[stageKey(stage.TenantID, stage.ID)] = stage
	return stage, true, nil
}

func (s *memoryStagingStore) GetStagedPackage(_ context.Context, tenantID string, stagingID string) (StagedPackage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stage, ok := s.packages[stageKey(tenantID, stagingID)]
	if !ok {
		return StagedPackage{}, ErrStagingNotFound
	}
	stage.Files = cloneStagedFiles(stage.Files)
	return stage, nil
}

func (s *memoryStagingStore) GetStagedValidation(_ context.Context, tenantID string, stagingID string, digest string) (StagedValidation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, ok := s.validations[validationKey(tenantID, stagingID, digest)]
	if !ok {
		return StagedValidation{}, ErrValidationNotFound
	}
	return result, nil
}

func (s *memoryStagingStore) PutStagedValidation(_ context.Context, validation StagedValidation, expected uint64) (StagedValidation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := validationKey(validation.TenantID, validation.StagingID, validation.RequestDigest)
	if prior, ok := s.validations[key]; ok {
		return prior, true, nil
	}
	stageKeyValue := stageKey(validation.TenantID, validation.StagingID)
	stage, ok := s.packages[stageKeyValue]
	if !ok {
		return StagedValidation{}, false, ErrStagingNotFound
	}
	if stage.Version != expected {
		return StagedValidation{}, false, ErrStagingVersion
	}
	stage.Version++
	validation.StagingVersion = stage.Version
	stage.Status = StagingStatusInvalid
	if validation.Status == ValidationValid {
		stage.Status = StagingStatusValid
	}
	stage.LatestValidationRequestDigest = validation.RequestDigest
	stage.ChangePlanDigest = validation.ChangePlanDigest
	stage.ValidatedAt = validation.ValidatedAt
	stage.UpdatedAt = validation.ValidatedAt
	if validation.Signature != nil {
		stage.SignerKeyID = validation.Signature.SignerKeyID
		stage.Algorithm = validation.Signature.Algorithm
	}
	s.packages[stageKeyValue] = stage
	s.validations[key] = validation
	s.validationWrites++
	return validation, false, nil
}

func (s *memoryStagingStore) PutCommitIntent(_ context.Context, intent CommitIntent) (CommitIntent, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, prior := range s.intents {
		if prior.TenantID == intent.TenantID && prior.IdempotencyKey == intent.IdempotencyKey {
			if prior.IntentDigest != intent.IntentDigest {
				return CommitIntent{}, false, ErrStagingDigest
			}
			return prior, false, nil
		}
	}
	s.intents[intentKey(intent.TenantID, intent.ID)] = intent
	s.commitIntentWrites++
	return intent, true, nil
}

func (s *memoryStagingStore) GetCommitIntent(_ context.Context, tenantID string, id string) (CommitIntent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	intent, ok := s.intents[intentKey(tenantID, id)]
	if !ok {
		return CommitIntent{}, ErrCommitIntentNotFound
	}
	return intent, nil
}

func (s *memoryStagingStore) MarkCommitIntentEventAppended(_ context.Context, intent CommitIntent, auth AuthorizationReceipt, eventID string) (CommitIntent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := intentKey(intent.TenantID, intent.ID)
	stored, ok := s.intents[key]
	if !ok {
		return CommitIntent{}, ErrCommitIntentNotFound
	}
	stageKeyValue := stageKey(intent.TenantID, intent.StagingID)
	stage := s.packages[stageKeyValue]
	if stored.Version != intent.Version || stage.Version != intent.ExpectedStagingVersion {
		return CommitIntent{}, ErrStagingVersion
	}
	stored.Status = CommitIntentEventAppended
	stored.Version++
	stored.AuthorizedBy = auth.ActorID
	stored.AuthorizationDecisionID = auth.DecisionID
	stored.AuthorizedAt = auth.GrantedAt
	stored.EventID = eventID
	stored.UpdatedAt = auth.GrantedAt
	stage.Status = StagingStatusCommitEventAppended
	stage.Version++
	s.intents[key] = stored
	s.packages[stageKeyValue] = stage
	s.markWrites++
	return stored, nil
}

func stageKey(tenantID string, stagingID string) string { return tenantID + "\x00" + stagingID }
func validationKey(tenantID string, stagingID string, digest string) string {
	return stageKey(tenantID, stagingID) + "\x00" + digest
}
func intentKey(tenantID string, intentID string) string { return tenantID + "\x00" + intentID }

type recordingExchangeAppendLog struct {
	events []*cerebrov1.EventEnvelope
	err    error
}

func (l *recordingExchangeAppendLog) Ping(context.Context) error { return l.err }
func (l *recordingExchangeAppendLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	if l.err != nil {
		return l.err
	}
	l.events = append(l.events, event)
	return nil
}
