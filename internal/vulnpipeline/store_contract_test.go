package vulnpipeline

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/statestore/postgres"
)

// TestStoreContract runs the pipeline end to end against every store
// implementation: always the in-memory store, and Postgres when
// CEREBRO_POSTGRES_DSN is set.
func TestStoreContract(t *testing.T) {
	t.Run("memory", func(t *testing.T) { runStoreContract(t, newMemStore(), "tenant-a") })
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Log("set CEREBRO_POSTGRES_DSN to run the Postgres store contract")
		return
	}
	t.Run("postgres", func(t *testing.T) {
		store, err := postgres.Open(config.StateStoreConfig{Driver: config.StateStoreDriverPostgres, PostgresDSN: dsn})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		t.Cleanup(func() { _ = store.Close() })
		runStoreContract(t, store, fmt.Sprintf("vuln-contract-%d", time.Now().UnixNano()))
	})
}

func runStoreContract(t *testing.T, store ports.VulnerabilityPipelineStore, tenantID string) {
	ctx := context.Background()
	// Behind the database clock so pull claims (which use it) see due work.
	clock := &testClock{now: time.Now().UTC().Add(-time.Minute).Truncate(time.Second)}
	bucket := &fakeS3{objects: map[string]string{"a.json": strixPage}, order: []string{"a.json"}}
	service := NewService(store, Options{
		Now:     clock.Now,
		Pullers: []Puller{S3Puller{AllowAmbientCredentials: true, NewClient: func(context.Context, S3Settings) (S3API, error) { return bucket, nil }}},
	})

	if _, err := service.CreateProfile(ctx, tenantID, "alice", ProfileInput{SourceID: "strix"}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateProfile(ctx, tenantID, "alice", ProfileInput{SourceID: "bugtracker"}); err != nil {
		t.Fatal(err)
	}

	first, err := service.Ingest(ctx, IngestRequest{TenantID: tenantID, ProfileID: "strix", Payload: []byte(strixPage), IdempotencyKey: "k1", FullSnapshot: true})
	if err != nil || first.Accepted != 2 {
		t.Fatalf("strix ingest = %+v, %v", first, err)
	}
	replay, err := service.Ingest(ctx, IngestRequest{TenantID: tenantID, ProfileID: "strix", Payload: []byte(strixPage), IdempotencyKey: "k1"})
	if err != nil || !replay.Replayed {
		t.Fatalf("idempotent replay = %+v, %v", replay, err)
	}
	only := `{"items":[{"id":"v-2","scan_id":"s-1","title":"Vulnerable lodash","target":"github.com/acme/web","severity":"high","cve":"CVE-2021-23337","status":"open","created_at":"2025-12-01T00:00:00Z","finding_type":"dependency"}]}`
	second, err := service.Ingest(ctx, IngestRequest{TenantID: tenantID, ProfileID: "strix", Payload: []byte(only), FullSnapshot: true})
	if err != nil || second.Resolved != 1 {
		t.Fatalf("snapshot ingest = %+v, %v", second, err)
	}

	held, err := service.Ingest(ctx, IngestRequest{TenantID: tenantID, ProfileID: "bugtracker", Payload: []byte(internalServicePayload)})
	if err != nil || held.Status != BatchPendingMapping {
		t.Fatalf("held ingest = %+v, %v", held, err)
	}
	activation, err := service.ActivateMapping(ctx, tenantID, "bugtracker", "alice", nil)
	if err != nil || len(activation.Replayed) != 1 || activation.Replayed[0].Accepted != 3 {
		t.Fatalf("activation = %+v, %v", activation, err)
	}

	all, err := service.ListObservations(ctx, ports.VulnerabilityObservationFilter{TenantID: tenantID, Limit: 200})
	if err != nil || len(all.Observations) != 5 {
		t.Fatalf("list = %d, %v", len(all.Observations), err)
	}
	var web *ObservationView
	for index := range all.Observations {
		if all.Observations[index].SourceRecordID == "v-2" {
			web = &all.Observations[index]
		}
	}
	if web == nil || web.FirstSeenAt == nil || !web.FirstSeenAt.Equal(time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("first_seen_at should move to the earlier source date: %+v", web)
	}
	if all.Observations[0].Severity != SeverityCritical {
		t.Fatalf("list must be ordered worst first, got %q", all.Observations[0].Severity)
	}

	seen := map[string]bool{}
	cursor := ""
	for pages := 0; pages < 10; pages++ {
		page, err := service.ListObservations(ctx, ports.VulnerabilityObservationFilter{TenantID: tenantID, Limit: 2, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		for _, observation := range page.Observations {
			if seen[observation.ID] {
				t.Fatalf("observation %s returned twice across pages", observation.ID)
			}
			seen[observation.ID] = true
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if len(seen) != 5 {
		t.Fatalf("pagination returned %d observations, want 5", len(seen))
	}

	filtered, err := service.ListObservations(ctx, ports.VulnerabilityObservationFilter{TenantID: tenantID, SourceIDs: []string{"bugtracker"}, VulnerabilityID: "cve-2021-44228"})
	if err != nil || len(filtered.Observations) != 1 || filtered.Observations[0].SourceID != "bugtracker" {
		t.Fatalf("filtered = %+v, %v", filtered, err)
	}
	searched, err := service.ListObservations(ctx, ports.VulnerabilityObservationFilter{TenantID: tenantID, Search: "100%_openssl"})
	if err != nil || len(searched.Observations) != 0 {
		t.Fatalf("search with wildcard characters = %+v, %v", searched, err)
	}

	summary, err := service.Summary(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != 5 || summary.Open != 3 || len(summary.BySource) != 2 || summary.Profiles != 2 {
		t.Fatalf("summary = %+v", summary)
	}

	if _, err := service.GetObservation(ctx, "other-tenant", web.ID); err == nil {
		t.Fatal("observation must not be readable from another tenant")
	}

	if _, err := service.UpdateProfile(ctx, tenantID, "strix", "alice", ProfileInput{Pull: &PullInput{Kind: PullKindS3, Config: map[string]string{"bucket": "vuln-exports", "mode": "latest_snapshot"}, IntervalSeconds: 300}}); err != nil {
		t.Fatal(err)
	}
	runs, err := service.RunDuePulls(ctx, "worker-a")
	if err != nil {
		t.Fatal(err)
	}
	ran := false
	for _, run := range runs {
		if run.ProfileID == "strix" {
			ran = true
			if run.Error != "" || run.Accepted != 2 {
				t.Fatalf("pull run = %+v", run)
			}
		}
	}
	if !ran {
		t.Fatalf("due profile was not claimed: %+v", runs)
	}
	profile, err := service.GetProfile(ctx, tenantID, "strix")
	if err != nil || profile.NextPullAt == nil || !profile.NextPullAt.After(clock.Now().Add(4*time.Minute)) {
		t.Fatalf("profile next pull = %+v, %v", profile, err)
	}
	batches, err := service.ListBatches(ctx, tenantID, "strix", "", 50)
	if err != nil || len(batches) < 3 {
		t.Fatalf("batches = %d, %v", len(batches), err)
	}
	if err := service.DeleteProfile(ctx, tenantID, "bugtracker"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetProfile(ctx, tenantID, "bugtracker"); err == nil {
		t.Fatal("deleted profile is still readable")
	}
	orphaned, err := service.ListObservations(ctx, ports.VulnerabilityObservationFilter{TenantID: tenantID, SourceIDs: []string{"bugtracker"}, Limit: 50})
	if err != nil || len(orphaned.Observations) != 3 {
		t.Fatalf("deleted profile observations = %+v, %v; want them kept as history", orphaned, err)
	}
	for _, observation := range orphaned.Observations {
		if OpenStatus(observation.Status) || observation.ResolvedAt == nil {
			t.Fatalf("observation %s of a deleted profile is still open: %+v", observation.SourceRecordID, observation)
		}
		if observation.SourceRecordID == "BT-1" && observation.Resolution != ports.VulnerabilityResolutionProfileDeleted {
			t.Fatalf("resolution = %q, want %q", observation.Resolution, ports.VulnerabilityResolutionProfileDeleted)
		}
	}
}

// storeContractCases are regression cases every store must satisfy. Each
// case gets its own tenant so Postgres runs do not interfere.
var storeContractCases = map[string]func(t *testing.T, store ports.VulnerabilityPipelineStore, tenantID string, onPostgres bool){
	"failed delivery is reprocessed on retry":            contractFailedDeliveryRetries,
	"concurrent deliveries with one key process once":    contractConcurrentIdempotency,
	"stale processing reservation is taken over":         contractStaleReservation,
	"older delivery never overwrites newer":              contractStaleUpsertSkipped,
	"snapshot lock serializes one profile":               contractSnapshotLock,
	"untrustworthy snapshots do not resolve":             contractSnapshotResolutionGuards,
	"claim leases one due profile at a time":             contractClaimDue,
	"held batches are capped and expired":                contractHeldRetention,
	"replay pages held batches and expires payloadless":  contractReplayPaging,
	"text with NUL bytes and large batches persist":      contractNULAndMultiRow,
	"profile writes keep scheduler state and versioning": contractProfileWrites,
	"tampered cursor is an invalid request":              contractTamperedCursor,
	"filters and summary agree across stores":            contractFiltersAndSummary,
	"long-resolved observations are pruned":              contractResolvedRetention,
}

func TestStoreContractCases(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	var pg *postgres.Store
	if dsn != "" {
		store, err := postgres.Open(config.StateStoreConfig{Driver: config.StateStoreDriverPostgres, PostgresDSN: dsn})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		t.Cleanup(func() { _ = store.Close() })
		pg = store
	}
	for name, run := range storeContractCases {
		t.Run(name, func(t *testing.T) {
			t.Run("memory", func(t *testing.T) { run(t, newMemStore(), "tenant-a", false) })
			if pg != nil {
				t.Run("postgres", func(t *testing.T) { run(t, pg, fmt.Sprintf("vuln-case-%d", time.Now().UnixNano()), true) })
			}
		})
	}
}

func newContractService(store ports.VulnerabilityPipelineStore) (*Service, *testClock) {
	clock := &testClock{now: time.Now().UTC().Add(-time.Hour).Truncate(time.Second)}
	return NewService(store, Options{Now: clock.Now}), clock
}

func nativePayload(ids ...string) string {
	records := make([]string, 0, len(ids))
	for _, id := range ids {
		if strings.HasPrefix(id, "bad") {
			records = append(records, fmt.Sprintf(`{"id":%q}`, id))
			continue
		}
		records = append(records, fmt.Sprintf(`{"id":%q,"title":"Finding %s","severity":"high","asset":{"type":"host","identifier":"host-%s"}}`, id, id, id))
	}
	return `{"schema":"cerebro.vulnerability/v1","scanner":"contract","observations":[` + strings.Join(records, ",") + `]}`
}

func mustContractProfile(t *testing.T, service *Service, tenantID string, sourceID string) {
	t.Helper()
	if _, err := service.CreateProfile(context.Background(), tenantID, "alice", ProfileInput{SourceID: sourceID}); err != nil {
		t.Fatalf("CreateProfile(%s) error = %v", sourceID, err)
	}
}

type failingUpsertStore struct {
	ports.VulnerabilityPipelineStore
	failures atomic.Int32
}

func (f *failingUpsertStore) UpsertVulnerabilityObservations(ctx context.Context, observations []*ports.VulnerabilityObservation) (ports.VulnerabilityUpsertResult, error) {
	if f.failures.Add(-1) >= 0 {
		return ports.VulnerabilityUpsertResult{}, errors.New("injected upsert failure")
	}
	return f.VulnerabilityPipelineStore.UpsertVulnerabilityObservations(ctx, observations)
}

func contractFailedDeliveryRetries(t *testing.T, store ports.VulnerabilityPipelineStore, tenantID string, _ bool) {
	ctx := context.Background()
	failing := &failingUpsertStore{VulnerabilityPipelineStore: store}
	failing.failures.Store(1)
	service, _ := newContractService(failing)
	mustContractProfile(t, service, tenantID, "scanner")
	request := IngestRequest{TenantID: tenantID, ProfileID: "scanner", Payload: []byte(nativePayload("a", "b")), IdempotencyKey: "object-1"}
	if result, err := service.Ingest(ctx, request); err == nil || result == nil || result.Status != BatchFailed {
		t.Fatalf("first delivery = %+v, %v; want a failed batch", result, err)
	}
	retry, err := service.Ingest(ctx, request)
	if err != nil || retry.Replayed || retry.Accepted != 2 || retry.Status != BatchCompleted {
		t.Fatalf("retry after failure = %+v, %v; want a fresh successful run", retry, err)
	}
	again, err := service.Ingest(ctx, request)
	if err != nil || !again.Replayed || again.BatchID != retry.BatchID {
		t.Fatalf("retry after success = %+v, %v; want the successful batch replayed", again, err)
	}
	batches, err := service.ListBatches(ctx, tenantID, "scanner", BatchFailed, 10)
	if err != nil || len(batches) != 1 {
		t.Fatalf("failed batch history = %+v, %v", batches, err)
	}
}

func contractConcurrentIdempotency(t *testing.T, store ports.VulnerabilityPipelineStore, tenantID string, _ bool) {
	ctx := context.Background()
	service, _ := newContractService(store)
	mustContractProfile(t, service, tenantID, "scanner")
	request := IngestRequest{TenantID: tenantID, ProfileID: "scanner", Payload: []byte(nativePayload("a", "b", "c")), IdempotencyKey: "same"}
	const workers = 8
	var wg sync.WaitGroup
	results := make([]*IngestResult, workers)
	errs := make([]error, workers)
	for index := range workers {
		wg.Go(func() { results[index], errs[index] = service.Ingest(ctx, request) })
	}
	wg.Wait()
	processed := 0
	for index := range workers {
		switch {
		case errs[index] == nil && !results[index].Replayed:
			processed++
		case errs[index] == nil && results[index].Replayed:
		case errors.Is(errs[index], ErrInProgress) && errors.Is(errs[index], ErrConflict):
		default:
			t.Fatalf("worker %d = %+v, %v; want success, replay, or in-progress conflict", index, results[index], errs[index])
		}
	}
	if processed != 1 {
		t.Fatalf("processed %d times, want exactly once", processed)
	}
	if _, err := service.Ingest(ctx, IngestRequest{TenantID: tenantID, ProfileID: "scanner", Payload: []byte(nativePayload("z")), IdempotencyKey: "same"}); !errors.Is(err, ErrConflict) || errors.Is(err, ErrInProgress) {
		t.Fatalf("different payload with a used key = %v, want a plain conflict", err)
	}
}

func contractStaleReservation(t *testing.T, store ports.VulnerabilityPipelineStore, tenantID string, _ bool) {
	ctx := context.Background()
	service, clock := newContractService(store)
	mustContractProfile(t, service, tenantID, "scanner")
	payload := []byte(nativePayload("a"))
	reserve := func(id string, createdAt time.Time) {
		t.Helper()
		_, reserved, err := store.ReserveVulnerabilityIngestBatch(ctx, &ports.VulnerabilityIngestBatch{
			TenantID: tenantID, ID: id, ProfileID: "scanner", Transport: TransportPushAPI, ContentDigest: payloadDigest(payload),
			IdempotencyKey: "k", Status: BatchProcessing, CreatedAt: createdAt,
		}, createdAt.Add(-ingestReservationTTL))
		if err != nil || !reserved {
			t.Fatalf("reserve %s = %v, %v", id, reserved, err)
		}
	}
	reserve("vbat_live", clock.Now())
	request := IngestRequest{TenantID: tenantID, ProfileID: "scanner", Payload: payload, IdempotencyKey: "k"}
	if _, err := service.Ingest(ctx, request); !errors.Is(err, ErrInProgress) {
		t.Fatalf("in-flight key error = %v, want ErrInProgress", err)
	}

	other := "scanner-2"
	mustContractProfile(t, service, tenantID, other)
	_, reserved, err := store.ReserveVulnerabilityIngestBatch(ctx, &ports.VulnerabilityIngestBatch{
		TenantID: tenantID, ID: "vbat_abandoned", ProfileID: other, Transport: TransportPushAPI, ContentDigest: payloadDigest(payload),
		IdempotencyKey: "k", Status: BatchProcessing, CreatedAt: clock.Now().Add(-2 * ingestReservationTTL),
	}, clock.Now().Add(-3*ingestReservationTTL))
	if err != nil || !reserved {
		t.Fatalf("reserve abandoned = %v, %v", reserved, err)
	}
	result, err := service.Ingest(ctx, IngestRequest{TenantID: tenantID, ProfileID: other, Payload: payload, IdempotencyKey: "k"})
	if err != nil || result.Replayed || result.Accepted != 1 {
		t.Fatalf("takeover of abandoned reservation = %+v, %v", result, err)
	}
}

func contractObservation(tenantID string, id string, title string, ingestedAt time.Time) *ports.VulnerabilityObservation {
	observation := &ports.VulnerabilityObservation{
		TenantID: tenantID, ID: id, ProfileID: "scanner", SourceID: "scanner", SourceRecordID: id, CorrelationKey: "ck-" + id, Format: FormatNative,
	}
	observation.Title, observation.Class, observation.Severity, observation.Status = title, ClassHost, SeverityHigh, StatusOpen
	observation.ObservedAt, observation.IngestedAt = ingestedAt, ingestedAt
	return observation
}

func contractStaleUpsertSkipped(t *testing.T, store ports.VulnerabilityPipelineStore, tenantID string, _ bool) {
	ctx := context.Background()
	newer := time.Now().UTC().Truncate(time.Second)
	if _, err := store.UpsertVulnerabilityObservations(ctx, []*ports.VulnerabilityObservation{contractObservation(tenantID, "o1", "newer", newer)}); err != nil {
		t.Fatal(err)
	}
	written, err := store.UpsertVulnerabilityObservations(ctx, []*ports.VulnerabilityObservation{
		contractObservation(tenantID, "o1", "older", newer.Add(-time.Minute)),
		contractObservation(tenantID, "o2", "fresh", newer.Add(-time.Minute)),
	})
	if err != nil || written.Written != 1 || written.SkippedStale != 1 {
		t.Fatalf("stale upsert = %+v, %v", written, err)
	}
	stored, err := store.GetVulnerabilityObservation(ctx, tenantID, "o1")
	if err != nil || stored.Title != "newer" {
		t.Fatalf("stored = %+v, %v; an older delivery overwrote newer data", stored, err)
	}
}

func contractSnapshotLock(t *testing.T, store ports.VulnerabilityPipelineStore, tenantID string, _ bool) {
	ctx := context.Background()
	unlock, err := store.LockVulnerabilityProfileSnapshot(ctx, tenantID, "scanner")
	if err != nil {
		t.Fatal(err)
	}
	acquired := make(chan func(), 1)
	go func() {
		second, err := store.LockVulnerabilityProfileSnapshot(ctx, tenantID, "scanner")
		if err != nil {
			acquired <- func() {}
			return
		}
		acquired <- second
	}()
	other, err := store.LockVulnerabilityProfileSnapshot(ctx, tenantID, "other-profile")
	if err != nil {
		t.Fatalf("another profile must not be blocked: %v", err)
	}
	other()
	select {
	case <-acquired:
		t.Fatal("second snapshot lock acquired while the first was held")
	case <-time.After(150 * time.Millisecond):
	}
	unlock()
	unlock()
	select {
	case second := <-acquired:
		second()
	case <-time.After(10 * time.Second):
		t.Fatal("second snapshot lock was not granted after unlock")
	}
}

func contractSnapshotResolutionGuards(t *testing.T, store ports.VulnerabilityPipelineStore, tenantID string, _ bool) {
	ctx := context.Background()
	service, _ := newContractService(store)
	mustContractProfile(t, service, tenantID, "scanner")
	ingest := func(payload string) *IngestResult {
		t.Helper()
		result, err := service.Ingest(ctx, IngestRequest{TenantID: tenantID, ProfileID: "scanner", Payload: []byte(payload), FullSnapshot: true})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	ids := make([]string, 0, 30)
	for index := range 30 {
		ids = append(ids, fmt.Sprintf("r%02d", index))
	}
	if first := ingest(nativePayload(ids...)); first.Accepted != 30 {
		t.Fatalf("seed snapshot = %+v", first)
	}
	if result := ingest(nativePayload("r00", "bad-1")); result.Resolved != 0 || !hasProblem(result, "quarantined") {
		t.Fatalf("snapshot with quarantined records = %+v; want no resolution", result)
	}
	if result := ingest(`{"schema":"cerebro.vulnerability/v1","observations":[]}`); result.Resolved != 0 || !hasProblem(result, "no record normalized") {
		t.Fatalf("empty builtin snapshot = %+v; want no resolution", result)
	}
	if result := ingest(nativePayload("r00")); result.Resolved != 0 || !hasProblem(result, "withheld") {
		t.Fatalf("snapshot dropping 29 of 30 = %+v; want resolution withheld", result)
	}
	if _, err := service.Ingest(ctx, IngestRequest{TenantID: tenantID, ProfileID: "scanner", Payload: []byte(nativePayload("r01"))}); err != nil {
		t.Fatal(err)
	}
	if result := ingest(nativePayload("r00")); result.Resolved != 0 || !hasProblem(result, "withheld") {
		t.Fatalf("snapshot after an intervening delivery = %+v; want resolution withheld again", result)
	}
	if result := ingest(nativePayload("r00")); result.Resolved != 29 {
		t.Fatalf("second consecutive snapshot dropping 29 of 30 = %+v; want the confirmed resolution", result)
	}
	if result := ingest(nativePayload(ids...)); result.Accepted != 30 || result.Resolved != 0 {
		t.Fatalf("reseed snapshot = %+v", result)
	}
	if result := ingest(nativePayload(ids[:20]...)); result.Resolved != 10 {
		t.Fatalf("snapshot dropping 10 of 30 = %+v; want 10 resolved", result)
	}
}

func hasProblem(result *IngestResult, fragment string) bool {
	for _, problem := range result.Problems {
		if strings.Contains(problem, fragment) {
			return true
		}
	}
	return false
}

func contractClaimDue(t *testing.T, store ports.VulnerabilityPipelineStore, tenantID string, onPostgres bool) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	for index, id := range []string{"due-a", "due-b"} {
		due := now.Add(-time.Duration(10-index) * time.Minute)
		profile := &ports.VulnerabilityProfile{TenantID: tenantID, ID: id, SourceID: id, Format: FormatAuto, Enabled: true, CreatedAt: now, UpdatedAt: now}
		profile.PullKind, profile.PullConfigJSON, profile.PullIntervalSeconds, profile.NextPullAt = PullKindS3, "{}", 300, &due
		if err := store.PutVulnerabilityProfile(ctx, profile); err != nil {
			t.Fatal(err)
		}
	}
	claimNow := now
	if onPostgres {
		// Postgres must ignore the caller's clock; a far-past value would
		// otherwise make nothing due.
		claimNow = now.Add(-24 * time.Hour)
	}
	claimed := map[string]bool{}
	for range 2 {
		profiles, err := store.ClaimDueVulnerabilityProfiles(ctx, claimNow, "worker", time.Minute, 1)
		if err != nil {
			t.Fatal(err)
		}
		for _, profile := range profiles {
			if profile.TenantID == tenantID {
				claimed[profile.ID] = true
			}
		}
		if len(profiles) > 1 {
			t.Fatalf("limit 1 claimed %d profiles", len(profiles))
		}
	}
	if !claimed["due-a"] || !claimed["due-b"] {
		t.Fatalf("claimed = %v, want both due profiles over two single claims", claimed)
	}
	again, err := store.ClaimDueVulnerabilityProfiles(ctx, claimNow, "other", time.Minute, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range again {
		if profile.TenantID == tenantID {
			t.Fatalf("leased profile %s was claimed again", profile.ID)
		}
	}
}

func heldBatch(tenantID string, id string, createdAt time.Time, payload []byte) *ports.VulnerabilityIngestBatch {
	return &ports.VulnerabilityIngestBatch{
		TenantID: tenantID, ID: id, ProfileID: "scanner", Transport: TransportPushAPI, Format: FormatGeneric,
		ContentDigest: payloadDigest(payload), Status: BatchPendingMapping, RawPayload: payload, CreatedAt: createdAt,
	}
}

func contractHeldRetention(t *testing.T, store ports.VulnerabilityPipelineStore, tenantID string, _ bool) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if err := store.PutVulnerabilityIngestBatch(ctx, heldBatch(tenantID, "held-ancient", now.Add(-15*24*time.Hour), []byte(`[1]`))); err != nil {
		t.Fatal(err)
	}
	for index := range 52 {
		if err := store.PutVulnerabilityIngestBatch(ctx, heldBatch(tenantID, fmt.Sprintf("held-%02d", index), now.Add(time.Duration(index)*time.Second), []byte(`[1]`))); err != nil {
			t.Fatal(err)
		}
	}
	held, err := store.ListHeldVulnerabilityIngestBatches(ctx, tenantID, "scanner", 500)
	if err != nil || len(held) != 50 {
		t.Fatalf("held = %d, %v; want the newest 50", len(held), err)
	}
	if held[0].ID != "held-02" || held[49].ID != "held-51" {
		t.Fatalf("held order = %s..%s, want oldest first from held-02", held[0].ID, held[49].ID)
	}
	listed, err := store.ListVulnerabilityIngestBatches(ctx, tenantID, "scanner", BatchPendingMapping, 10)
	if err != nil || len(listed) == 0 || listed[0].RawPayload != nil {
		t.Fatalf("listing held batches must not load payloads: %+v, %v", listed, err)
	}
	payload, err := store.GetVulnerabilityIngestBatchPayload(ctx, tenantID, "held-51")
	if err != nil || string(payload) != `[1]` {
		t.Fatalf("payload = %q, %v", payload, err)
	}
	for _, id := range []string{"held-ancient", "held-00", "held-01"} {
		payload, err := store.GetVulnerabilityIngestBatchPayload(ctx, tenantID, id)
		if err != nil || len(payload) != 0 {
			t.Fatalf("expired %s payload = %q, %v; want cleared", id, payload, err)
		}
	}
	expired, err := store.ListVulnerabilityIngestBatches(ctx, tenantID, "scanner", BatchExpired, 10)
	if err != nil || len(expired) != 3 {
		t.Fatalf("expired = %d, %v; want 3", len(expired), err)
	}
}

func contractReplayPaging(t *testing.T, store ports.VulnerabilityPipelineStore, tenantID string, _ bool) {
	ctx := context.Background()
	service, clock := newContractService(store)
	mustContractProfile(t, service, tenantID, "bugtracker")
	for range 3 {
		held, err := service.Ingest(ctx, IngestRequest{TenantID: tenantID, ProfileID: "bugtracker", Payload: []byte(internalServicePayload)})
		if err != nil || held.Status != BatchPendingMapping {
			t.Fatalf("held = %+v, %v", held, err)
		}
	}
	payloadless := heldBatch(tenantID, "held-too-large", clock.Now(), nil)
	payloadless.ProfileID = "bugtracker"
	if err := store.PutVulnerabilityIngestBatch(ctx, payloadless); err != nil {
		t.Fatal(err)
	}
	activation, err := service.ActivateMapping(ctx, tenantID, "bugtracker", "alice", nil)
	if err != nil || len(activation.Replayed) != 3 {
		t.Fatalf("activation = %+v, %v; want 3 replays", activation, err)
	}
	remaining, err := store.ListHeldVulnerabilityIngestBatches(ctx, tenantID, "bugtracker", 50)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("held after activation = %+v, %v", remaining, err)
	}
	expired, err := store.ListVulnerabilityIngestBatches(ctx, tenantID, "bugtracker", BatchExpired, 10)
	if err != nil || len(expired) != 1 || expired[0].ID != "held-too-large" {
		t.Fatalf("expired = %+v, %v", expired, err)
	}
}

func contractNULAndMultiRow(t *testing.T, store ports.VulnerabilityPipelineStore, tenantID string, onPostgres bool) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	hostile := contractObservation(tenantID, "nul-1", "bad\x00title", now)
	hostile.VulnerabilityIDs = []string{"CVE-2024-0001\x00"}
	hostile.Attributes = map[string]string{"k\x00": "v\x00"}
	observations := []*ports.VulnerabilityObservation{hostile}
	for index := range 1200 {
		observations = append(observations, contractObservation(tenantID, fmt.Sprintf("bulk-%04d", index), "bulk", now))
	}
	written, err := store.UpsertVulnerabilityObservations(ctx, observations)
	if err != nil || written.Written != 1201 {
		t.Fatalf("upsert = %+v, %v", written, err)
	}
	stored, err := store.GetVulnerabilityObservation(ctx, tenantID, "nul-1")
	if err != nil {
		t.Fatal(err)
	}
	if onPostgres && (stored.Title != "badtitle" || stored.Attributes["k"] != "v" || stored.VulnerabilityIDs[0] != "CVE-2024-0001") {
		t.Fatalf("stored = %+v; want NUL bytes stripped", stored)
	}
	if err := store.PutVulnerabilityQuarantineRecords(ctx, []*ports.VulnerabilityQuarantineRecord{{
		TenantID: tenantID, ID: "q1", BatchID: "b", ProfileID: "scanner", Reason: "r\x00", RecordJSON: "{\x00}", CreatedAt: now,
	}}); err != nil {
		t.Fatalf("quarantine with NUL = %v", err)
	}
}

func contractProfileWrites(t *testing.T, store ports.VulnerabilityPipelineStore, tenantID string, _ bool) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	newProfile := func(createdAt time.Time) *ports.VulnerabilityProfile {
		next := now
		profile := &ports.VulnerabilityProfile{TenantID: tenantID, ID: "p", SourceID: "p", Format: FormatAuto, Enabled: true, CreatedAt: createdAt, UpdatedAt: createdAt}
		profile.PullKind, profile.PullConfigJSON, profile.PullIntervalSeconds, profile.NextPullAt = PullKindS3, "{}", 300, &next
		return profile
	}
	if err := store.PutVulnerabilityProfile(ctx, newProfile(now)); err != nil {
		t.Fatal(err)
	}
	if err := store.PutVulnerabilityProfile(ctx, newProfile(now.Add(time.Second))); !errors.Is(err, ErrConflict) {
		t.Fatalf("racing create error = %v, want ErrConflict", err)
	}
	service, _ := newContractService(store)
	if _, err := service.CreateProfile(ctx, tenantID, "alice", ProfileInput{SourceID: "p"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate create error = %v, want ErrConflict", err)
	}

	first, err := store.GetVulnerabilityProfile(ctx, tenantID, "p")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.GetVulnerabilityProfile(ctx, tenantID, "p")
	if err != nil {
		t.Fatal(err)
	}
	cursor := "scheduler-cursor"
	if err := store.RecordVulnerabilityProfileIngest(ctx, tenantID, "p", ports.VulnerabilityProfileIngestUpdate{At: now, Status: ProfileStatusHealthy, PullCursor: &cursor}); err != nil {
		t.Fatal(err)
	}
	scheduled := now.Add(time.Hour)
	if err := store.CompleteVulnerabilityProfileClaim(ctx, tenantID, "p", "", scheduled); err != nil {
		t.Fatal(err)
	}
	later := now.Add(3 * time.Hour)
	first.NextPullAt, second.NextPullAt = &later, &later

	activatedA, activatedB := now.Add(time.Minute), now.Add(2*time.Minute)
	first.MappingJSON, first.MappingActivatedAt, first.MappingVersion = `{"a":1}`, &activatedA, first.MappingVersion+1
	if err := store.PutVulnerabilityProfile(ctx, first); err != nil {
		t.Fatal(err)
	}
	second.MappingJSON, second.MappingActivatedAt, second.MappingVersion = `{"b":1}`, &activatedB, second.MappingVersion+1
	second.DisplayName = "edited"
	if err := store.PutVulnerabilityProfile(ctx, second); err != nil {
		t.Fatal(err)
	}
	stored, err := store.GetVulnerabilityProfile(ctx, tenantID, "p")
	if err != nil {
		t.Fatal(err)
	}
	if stored.MappingVersion != 2 || second.MappingVersion != 2 {
		t.Fatalf("mapping version = %d (returned %d), want 2 after two activations", stored.MappingVersion, second.MappingVersion)
	}
	if stored.PullCursor != cursor || stored.NextPullAt == nil || !stored.NextPullAt.Equal(scheduled) || stored.DisplayName != "edited" {
		t.Fatalf("profile update clobbered scheduler state: cursor=%q next=%v name=%q", stored.PullCursor, stored.NextPullAt, stored.DisplayName)
	}
	queued := now.Add(-time.Minute)
	stored.NextPullAt = &queued
	if err := store.PutVulnerabilityProfile(ctx, stored); err != nil || stored.NextPullAt == nil || !stored.NextPullAt.Equal(queued) {
		t.Fatalf("queueing an earlier pull = %v, %v", stored.NextPullAt, err)
	}
	stored.PullKind, stored.PullConfigJSON, stored.PullCursor, stored.NextPullAt = "", "", "", nil
	if err := store.PutVulnerabilityProfile(ctx, stored); err != nil {
		t.Fatal(err)
	}
	removed, err := store.GetVulnerabilityProfile(ctx, tenantID, "p")
	if err != nil || removed.PullCursor != "" || removed.NextPullAt != nil {
		t.Fatalf("removing the pull must clear scheduler state: %+v, %v", removed, err)
	}
}

func contractTamperedCursor(t *testing.T, store ports.VulnerabilityPipelineStore, tenantID string, _ bool) {
	ctx := context.Background()
	service, _ := newContractService(store)
	encode := func(raw string) string { return base64.RawURLEncoding.EncodeToString([]byte(raw)) }
	for name, cursor := range map[string]string{
		"not base64":   "%%%",
		"rank":         encode("9|0|x"),
		"negative":     encode("-1|0|x"),
		"time range":   encode("3|9223372036854775807|x"),
		"missing id":   encode("3|0|"),
		"not a number": encode("a|b|c"),
	} {
		if _, err := service.ListObservations(ctx, ports.VulnerabilityObservationFilter{TenantID: tenantID, Cursor: cursor}); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s cursor error = %v, want ErrInvalidRequest", name, err)
		}
	}
}

func contractFiltersAndSummary(t *testing.T, store ports.VulnerabilityPipelineStore, tenantID string, _ bool) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	a := contractObservation(tenantID, "f1", "one", now)
	a.AssetIdentifier, a.CorrelationKey, a.PrimaryVulnerabilityID, a.VulnerabilityIDs = "host-1", "shared", "CVE-2024-1", []string{"CVE-2024-1", "GHSA-x"}
	b := contractObservation(tenantID, "f2", "two", now)
	b.ProfileID, b.SourceID, b.CorrelationKey, b.Class = "other", "other", "shared", ClassPackage
	c := contractObservation(tenantID, "f3", "three", now)
	c.Status = StatusFixed
	if _, err := store.UpsertVulnerabilityObservations(ctx, []*ports.VulnerabilityObservation{a, b, c}); err != nil {
		t.Fatal(err)
	}
	count := func(filter ports.VulnerabilityObservationFilter) int {
		t.Helper()
		filter.TenantID = tenantID
		page, err := store.ListVulnerabilityObservations(ctx, filter)
		if err != nil {
			t.Fatal(err)
		}
		return len(page.Observations)
	}
	checks := map[string][2]int{
		"profile":     {count(ports.VulnerabilityObservationFilter{ProfileID: "other"}), 1},
		"class":       {count(ports.VulnerabilityObservationFilter{Classes: []string{ClassPackage}}), 1},
		"asset":       {count(ports.VulnerabilityObservationFilter{AssetIdentifier: "host-1"}), 1},
		"correlation": {count(ports.VulnerabilityObservationFilter{CorrelationKey: "shared"}), 2},
		"alias id":    {count(ports.VulnerabilityObservationFilter{VulnerabilityID: "GHSA-x"}), 1},
		"search id":   {count(ports.VulnerabilityObservationFilter{Search: "cve-2024-1"}), 1},
	}
	for name, check := range checks {
		if check[0] != check[1] {
			t.Errorf("%s filter = %d, want %d", name, check[0], check[1])
		}
	}
	summary, err := store.SummarizeVulnerabilityObservations(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != 3 || summary.Open != 2 || summary.MultiSourceOpen != 1 || summary.DistinctOpenVulns != 2 || summary.OldestOpenSeenAt == nil {
		t.Fatalf("summary = %+v", summary)
	}
	for _, source := range summary.BySource {
		if source.LastIngestAt == nil {
			t.Fatalf("source %s has no last ingest time", source.SourceID)
		}
	}
}

func contractResolvedRetention(t *testing.T, store ports.VulnerabilityPipelineStore, tenantID string, _ bool) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	old := contractObservation(tenantID, "old", "old", now.Add(-400*24*time.Hour))
	resolvedAt := now.Add(-400 * 24 * time.Hour)
	old.Status, old.ResolvedAt, old.Resolution = StatusFixed, &resolvedAt, ResolutionAbsentFromSnapshot
	recent := contractObservation(tenantID, "recent", "recent", now)
	if _, err := store.UpsertVulnerabilityObservations(ctx, []*ports.VulnerabilityObservation{old, recent}); err != nil {
		t.Fatal(err)
	}
	batch := &ports.VulnerabilityIngestBatch{TenantID: tenantID, ID: "b1", ProfileID: "scanner", Transport: TransportPushAPI, ContentDigest: "d", Status: BatchCompleted, CreatedAt: now}
	if err := store.PutVulnerabilityIngestBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetVulnerabilityObservation(ctx, tenantID, "old"); !errors.Is(err, ports.ErrVulnerabilityObservationNotFound) {
		t.Fatalf("observation resolved 400 days ago = %v, want pruned", err)
	}
	if _, err := store.GetVulnerabilityObservation(ctx, tenantID, "recent"); err != nil {
		t.Fatalf("open observation was pruned: %v", err)
	}
}
