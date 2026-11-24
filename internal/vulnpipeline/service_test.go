package vulnpipeline

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(time.Millisecond)
	return c.now
}

func newTestService(t *testing.T, pullers ...Puller) (*Service, *memStore) {
	t.Helper()
	store := newMemStore()
	clock := &testClock{now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	service := NewService(store, Options{
		Now:               clock.Now,
		Pullers:           pullers,
		IsSecretReference: func(value string) bool { return strings.HasPrefix(value, "env:") },
		ResolveConfig: func(_ context.Context, _ *portsProfile, values map[string]string) (map[string]string, error) {
			out := map[string]string{}
			for key, value := range values {
				out[key] = strings.TrimPrefix(value, "env:resolved-")
			}
			return out, nil
		},
	})
	return service, store
}

func mustCreateProfile(t *testing.T, service *Service, input ProfileInput) *ProfileView {
	t.Helper()
	view, err := service.CreateProfile(context.Background(), "tenant-a", "alice@example.com", input)
	if err != nil {
		t.Fatalf("CreateProfile() error = %v", err)
	}
	return view
}

const strixPage = `{"items":[
 {"id":"v-1","scan_id":"s-1","title":"SQL injection in login","target":"https://app.example.com","severity":"critical","cve":null,"cvss":9.8,"status":"open","created_at":"2026-01-01T00:00:00Z","status_changed_at":"2026-01-01T01:00:00Z","display_number":12,"finding_type":"live_pentest"},
 {"id":"v-2","scan_id":"s-1","title":"Vulnerable lodash","target":"github.com/acme/web","severity":"high","cve":"CVE-2021-23337","cvss":7.2,"status":"fixed","created_at":"2026-01-01T00:00:00Z","display_number":13,"finding_type":"dependency","dependency_metadata":{"package":"lodash","ecosystem":"npm","installed_version":"4.17.15","fixed_version":"4.17.21","manifest_path":"package.json"}}
],"meta":{"page":1,"limit":100,"total_items":2,"total_pages":1,"has_next":false,"has_prev":false}}`

func TestIngestStrixTagsSourceAndNormalizes(t *testing.T) {
	service, store := newTestService(t)
	mustCreateProfile(t, service, ProfileInput{SourceID: "strix"})
	result, err := service.Ingest(context.Background(), IngestRequest{TenantID: "tenant-a", ProfileID: "strix", Payload: []byte(strixPage), IdempotencyKey: "delivery-1"})
	if err != nil {
		t.Fatalf("Ingest() error = %v", err)
	}
	if result.Format != FormatStrix || result.Status != BatchCompleted || result.Accepted != 2 {
		t.Fatalf("result = %+v", result)
	}
	observations := store.ObservationsFor("strix")
	if len(observations) != 2 {
		t.Fatalf("observations = %d", len(observations))
	}
	web, dep := observations[0], observations[1]
	if web.SourceID != "strix" || web.Severity != SeverityCritical || web.Class != ClassWebApplication || web.Status != StatusOpen {
		t.Fatalf("web observation = %+v", web)
	}
	if web.Attributes["strix.display_id"] != "STRIX-12" {
		t.Fatalf("web attributes = %v", web.Attributes)
	}
	if dep.PrimaryVulnerabilityID != "CVE-2021-23337" || dep.PackageName != "lodash" || dep.FixedVersion != "4.17.21" || dep.Class != ClassPackage {
		t.Fatalf("dependency observation = %+v", dep)
	}
	if dep.Status != StatusFixed || dep.Resolution != ResolutionSourceReported || dep.ResolvedAt == nil {
		t.Fatalf("fixed dependency should be source-resolved: %+v", dep)
	}

	replay, err := service.Ingest(context.Background(), IngestRequest{TenantID: "tenant-a", ProfileID: "strix", Payload: []byte(strixPage), IdempotencyKey: "delivery-1"})
	if err != nil || !replay.Replayed || replay.BatchID != result.BatchID {
		t.Fatalf("replay = %+v, %v", replay, err)
	}
	_, err = service.Ingest(context.Background(), IngestRequest{TenantID: "tenant-a", ProfileID: "strix", Payload: []byte(`{"items":[]}`), IdempotencyKey: "delivery-1"})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("reused key with different payload error = %v", err)
	}
}

func TestIngestFullSnapshotResolvesAbsentObservations(t *testing.T) {
	service, store := newTestService(t)
	mustCreateProfile(t, service, ProfileInput{SourceID: "strix"})
	ctx := context.Background()
	if _, err := service.Ingest(ctx, IngestRequest{TenantID: "tenant-a", ProfileID: "strix", Payload: []byte(strixPage), FullSnapshot: true}); err != nil {
		t.Fatal(err)
	}
	only := `{"items":[{"id":"v-2","scan_id":"s-1","title":"Vulnerable lodash","severity":"high","status":"open","finding_type":"dependency"}]}`
	result, err := service.Ingest(ctx, IngestRequest{TenantID: "tenant-a", ProfileID: "strix", Payload: []byte(only), FullSnapshot: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Resolved != 1 {
		t.Fatalf("resolved = %d, want 1", result.Resolved)
	}
	for _, observation := range store.ObservationsFor("strix") {
		switch observation.SourceRecordID {
		case "v-1":
			if observation.Resolution != ResolutionAbsentFromSnapshot || observation.Status != StatusFixed {
				t.Fatalf("absent observation = %+v", observation)
			}
		case "v-2":
			if observation.Status != StatusOpen || observation.ResolvedAt != nil {
				t.Fatalf("reopened observation = %+v", observation)
			}
		}
	}
}

const internalServicePayload = `{"meta":{"service":"bugtracker"},"data":{"issues":[
 {"issue_id":"BT-1","name":"Outdated OpenSSL on bastion","risk":"P1","host":"bastion-1.internal","cve_list":["CVE-2024-6119"],"state":"Active","first_found":"2025-12-01T10:00:00Z","package_name":"openssl","installed_version":"3.0.2"},
 {"issue_id":"BT-2","name":"Weak TLS ciphers","risk":"P3","host":"api-1.internal","cve_list":[],"state":"Resolved","first_found":"2025-11-01T10:00:00Z"},
 {"issue_id":"BT-3","name":"Log4Shell in search","risk":"P0","host":"search-2.internal","cve_list":["CVE-2021-44228"],"state":"Active","first_found":"2025-10-01T10:00:00Z","package_name":"log4j-core","installed_version":"2.14.1"}
]}}`

func TestUnknownFormatIsLearnedHeldAndReplayedOnActivation(t *testing.T) {
	service, store := newTestService(t)
	mustCreateProfile(t, service, ProfileInput{SourceID: "bugtracker"})
	ctx := context.Background()
	result, err := service.Ingest(ctx, IngestRequest{TenantID: "tenant-a", ProfileID: "bugtracker", Payload: []byte(internalServicePayload), FullSnapshot: true})
	if err != nil {
		t.Fatalf("Ingest() error = %v", err)
	}
	if result.Status != BatchPendingMapping || result.DraftMapping == nil {
		t.Fatalf("result = %+v", result)
	}
	if len(store.ObservationsFor("bugtracker")) != 0 {
		t.Fatal("observations must not be written before a mapping is activated")
	}
	draft := result.DraftMapping
	if draft.Mapping.RecordsPath != "data.issues" {
		t.Fatalf("records path = %q", draft.Mapping.RecordsPath)
	}
	want := map[string]string{
		FieldSourceRecordID:   "issue_id",
		FieldTitle:            "name",
		FieldSeverity:         "risk",
		FieldAssetIdentifier:  "host",
		FieldVulnerabilityIDs: "cve_list[*]",
		FieldStatus:           "state",
		FieldPackageName:      "package_name",
	}
	for field, path := range want {
		if got := draft.Report.Fields[field].Path; got != path {
			t.Errorf("learned %s path = %q, want %q (report %+v)", field, got, path, draft.Report.Fields)
		}
	}
	if !draft.Report.ReadyToActivate {
		t.Fatalf("draft should be ready to activate: %+v", draft.Report)
	}

	profile, err := service.GetProfile(ctx, "tenant-a", "bugtracker")
	if err != nil || profile.DraftMapping == nil || profile.LastStatus != ProfileStatusPendingMapping {
		t.Fatalf("profile = %+v, %v", profile, err)
	}
	activation, err := service.ActivateMapping(ctx, "tenant-a", "bugtracker", "alice@example.com", nil)
	if err != nil {
		t.Fatalf("ActivateMapping() error = %v", err)
	}
	if len(activation.Replayed) != 1 || activation.Replayed[0].Accepted != 3 {
		t.Fatalf("replayed = %+v", activation.Replayed)
	}
	if activation.Profile.MappingVersion != 1 || activation.Profile.DraftMapping != nil || activation.Profile.Format != FormatGeneric {
		t.Fatalf("activated profile = %+v", activation.Profile)
	}
	byID := map[string]string{}
	for _, observation := range store.ObservationsFor("bugtracker") {
		byID[observation.SourceRecordID] = observation.Severity + "/" + observation.Status
		if observation.SourceID != "bugtracker" || observation.MappingVersion != 1 {
			t.Fatalf("observation = %+v", observation)
		}
	}
	if byID["BT-1"] != "high/open" || byID["BT-2"] != "low/fixed" || byID["BT-3"] != "critical/open" {
		t.Fatalf("severity/status = %v", byID)
	}
	batches, err := service.ListBatches(ctx, "tenant-a", "bugtracker", BatchPendingMapping, 10)
	if err != nil || len(batches) != 0 {
		t.Fatalf("held batches after replay = %+v, %v", batches, err)
	}
}

func TestActiveMappingQuarantinesDriftedRecords(t *testing.T) {
	service, store := newTestService(t)
	mapping := &Mapping{
		RecordsPath: "results",
		Fields: map[string]FieldRule{
			FieldSourceRecordID: {Paths: []string{"key"}},
			FieldTitle:          {Paths: []string{"headline"}},
			FieldSeverity:       {Paths: []string{"sev"}},
		},
		SeverityScale: SeverityScaleOneFive,
	}
	mustCreateProfile(t, service, ProfileInput{SourceID: "scanner-x", Format: ptr(FormatGeneric), Mapping: mapping})
	payload := `{"results":[{"key":"a","headline":"Thing one","sev":5},{"key":"b","sev":2},{"key":"c","renamed_title":"x"}]}`
	result, err := service.Ingest(context.Background(), IngestRequest{TenantID: "tenant-a", ProfileID: "scanner-x", Payload: []byte(payload), FullSnapshot: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != BatchPartial || result.Accepted != 1 || result.Quarantined != 2 {
		t.Fatalf("result = %+v", result)
	}
	observations := store.ObservationsFor("scanner-x")
	if len(observations) != 1 || observations[0].Severity != SeverityCritical {
		t.Fatalf("observations = %+v", observations)
	}
	quarantined, err := service.ListQuarantine(context.Background(), "tenant-a", "scanner-x", 10)
	if err != nil || len(quarantined) != 2 {
		t.Fatalf("quarantine = %+v, %v", quarantined, err)
	}
	profile, _ := service.GetProfile(context.Background(), "tenant-a", "scanner-x")
	if profile.LastStatus != ProfileStatusDrift {
		t.Fatalf("profile status = %q, want drift", profile.LastStatus)
	}
}

func TestSnapshotThatNormalizesNothingDoesNotResolve(t *testing.T) {
	service, store := newTestService(t)
	mapping := &Mapping{Fields: map[string]FieldRule{FieldSourceRecordID: {Paths: []string{"id"}}, FieldTitle: {Paths: []string{"title"}}}}
	mustCreateProfile(t, service, ProfileInput{SourceID: "svc", Format: ptr(FormatGeneric), Mapping: mapping})
	ctx := context.Background()
	if _, err := service.Ingest(ctx, IngestRequest{TenantID: "tenant-a", ProfileID: "svc", Payload: []byte(`[{"id":"1","title":"a"}]`), FullSnapshot: true}); err != nil {
		t.Fatal(err)
	}
	result, err := service.Ingest(ctx, IngestRequest{TenantID: "tenant-a", ProfileID: "svc", Payload: []byte(`[{"identifier":"1","name":"a"}]`), FullSnapshot: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Resolved != 0 || result.Status != BatchQuarantined {
		t.Fatalf("result = %+v", result)
	}
	if observations := store.ObservationsFor("svc"); observations[0].ResolvedAt != nil {
		t.Fatal("a broken mapping must not resolve existing observations")
	}
}

func TestNativeFormatAndNDJSON(t *testing.T) {
	service, store := newTestService(t)
	mustCreateProfile(t, service, ProfileInput{SourceID: "internal-scanner"})
	native := `{"schema":"cerebro.vulnerability/v1","scanner":"acme-scan","observations":[{"id":"n-1","title":"Old nginx","vulnerability_ids":["cve-2023-44487"],"severity":"high","asset":{"type":"host","identifier":"web-1"},"package":{"ecosystem":"deb","name":"nginx","version":"1.18.0"},"attributes":{"team":"edge"}}]}`
	result, err := service.Ingest(context.Background(), IngestRequest{TenantID: "tenant-a", ProfileID: "internal-scanner", Payload: []byte(native)})
	if err != nil || result.Format != FormatNative || result.Accepted != 1 {
		t.Fatalf("native ingest = %+v, %v", result, err)
	}
	observation := store.ObservationsFor("internal-scanner")[0]
	if observation.Scanner != "acme-scan" || observation.PrimaryVulnerabilityID != "CVE-2023-44487" || observation.Attributes["team"] != "edge" {
		t.Fatalf("native observation = %+v", observation)
	}

	mustCreateProfile(t, service, ProfileInput{SourceID: "stream", Format: ptr(FormatStrix)})
	ndjson := "{\"id\":\"x1\",\"scan_id\":\"s\",\"title\":\"XSS\",\"severity\":\"medium\",\"finding_type\":\"code\"}\n{\"id\":\"x2\",\"scan_id\":\"s\",\"title\":\"SSRF\",\"severity\":\"high\",\"finding_type\":\"code\"}\n"
	result, err = service.Ingest(context.Background(), IngestRequest{TenantID: "tenant-a", ProfileID: "stream", Payload: []byte(ndjson), ContentType: "application/x-ndjson"})
	if err != nil || result.Accepted != 2 {
		t.Fatalf("ndjson ingest = %+v, %v", result, err)
	}
}

func TestIngestRejectsBadRequests(t *testing.T) {
	service, _ := newTestService(t)
	mustCreateProfile(t, service, ProfileInput{SourceID: "strix", Enabled: ptr(false)})
	ctx := context.Background()
	cases := map[string]IngestRequest{
		"empty":          {TenantID: "tenant-a", ProfileID: "strix"},
		"unknown format": {TenantID: "tenant-a", ProfileID: "strix", Payload: []byte(`{}`), Format: "nessus-xml"},
		"disabled":       {TenantID: "tenant-a", ProfileID: "strix", Payload: []byte(`{}`)},
		"other tenant":   {TenantID: "tenant-b", ProfileID: "strix", Payload: []byte(`{}`)},
	}
	for name, request := range cases {
		if _, err := service.Ingest(ctx, request); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := service.Ingest(ctx, IngestRequest{TenantID: "tenant-b", ProfileID: "strix", Payload: []byte(`{}`)}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant ingest error = %v, want not found", err)
	}
	if _, err := NewService(nil, Options{}).Ingest(ctx, IngestRequest{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil store error = %v", err)
	}
}

func TestProfileValidation(t *testing.T) {
	service, _ := newTestService(t, StrixPuller{})
	ctx := context.Background()
	if _, err := service.CreateProfile(ctx, "tenant-a", "a", ProfileInput{SourceID: "Bad Source!"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("bad source id error = %v", err)
	}
	_, err := service.CreateProfile(ctx, "tenant-a", "a", ProfileInput{SourceID: "strix", Pull: &PullInput{Kind: PullKindStrix, Config: map[string]string{"api_token": "raw-token-value"}}})
	if !errors.Is(err, ErrInvalidRequest) || !errors.Is(err, ErrRawSecret) {
		t.Fatalf("raw secret error = %v", err)
	}
	view, err := service.CreateProfile(ctx, "tenant-a", "a", ProfileInput{SourceID: "strix", Pull: &PullInput{Kind: PullKindStrix, Config: map[string]string{"api_token": "env:resolved-token"}}}) // #nosec G101 -- test credential reference, not a secret value.
	if err != nil {
		t.Fatal(err)
	}
	if len(view.PullSecretKeys) != 1 || view.PullConfig["api_token"] != "" || view.PullInterval != int64(defaultPullInterval/time.Second) {
		t.Fatalf("view leaks or misses pull config: %+v", view)
	}
	if _, err := service.CreateProfile(ctx, "tenant-a", "a", ProfileInput{SourceID: "strix"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate error = %v", err)
	}
	if _, err := service.UpdateProfile(ctx, "tenant-a", "strix", "a", ProfileInput{SourceID: "other"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("source change error = %v", err)
	}
	if _, err := service.UpdateProfile(ctx, "tenant-a", "strix", "a", ProfileInput{Pull: &PullInput{IntervalSeconds: 10}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("short interval error = %v", err)
	}
}

func TestPreviewDoesNotPersist(t *testing.T) {
	service, store := newTestService(t)
	preview, err := service.Preview(PreviewRequest{Payload: []byte(internalServicePayload)})
	if err != nil {
		t.Fatal(err)
	}
	if preview.Format != FormatGeneric || preview.Report == nil || preview.Accepted != 3 || len(preview.Observations) != 3 {
		t.Fatalf("preview = %+v", preview)
	}
	if observations, batches := store.Counts(); observations != 0 || batches != 0 {
		t.Fatal("preview persisted data")
	}
}

func TestSummaryCountsBySource(t *testing.T) {
	service, _ := newTestService(t)
	mustCreateProfile(t, service, ProfileInput{SourceID: "strix"})
	ctx := context.Background()
	if _, err := service.Ingest(ctx, IngestRequest{TenantID: "tenant-a", ProfileID: "strix", Payload: []byte(strixPage)}); err != nil {
		t.Fatal(err)
	}
	summary, err := service.Summary(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != 2 || summary.Open != 1 || summary.BySeverity[SeverityCritical] != 1 || summary.BySeverity[SeverityLow] != 0 {
		t.Fatalf("summary = %+v", summary)
	}
	if len(summary.BySource) != 1 || summary.BySource[0].SourceID != "strix" || summary.Profiles != 1 {
		t.Fatalf("by source = %+v", summary.BySource)
	}
	page, err := service.ListObservations(ctx, portsFilter("tenant-a", "critical"))
	if err != nil || len(page.Observations) != 1 || page.Observations[0].SourceID != "strix" {
		t.Fatalf("filtered list = %+v, %v", page, err)
	}
	if _, err := service.ListObservations(ctx, portsFilter("tenant-a", "severe")); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unknown severity error = %v", err)
	}
}

func ptr[T any](value T) *T { return &value }
