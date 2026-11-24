package vulnpipeline

import (
	"context"
	"fmt"
	"os"
	"strings"
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
	clock := &testClock{now: time.Now().UTC().Truncate(time.Second)}
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
}
