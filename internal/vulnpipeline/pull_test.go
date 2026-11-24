package vulnpipeline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

var loopbackHTTP = HTTPOptions{AllowLoopback: true}

// syncNow queues a manual sync and runs the scheduler poll that picks it up.
func syncNow(t *testing.T, service *Service, profileID string) *PullRunResult {
	t.Helper()
	queued, err := service.SyncProfile(context.Background(), "tenant-a", profileID, "alice@example.com")
	if err != nil {
		t.Fatalf("SyncProfile(%s) error = %v", profileID, err)
	}
	if queued.Status != PullStatusQueued || queued.QueuedAt == nil || queued.Pages != 0 {
		t.Fatalf("SyncProfile(%s) = %+v, want a queued result", profileID, queued)
	}
	results, err := service.RunDuePulls(context.Background(), "worker-test")
	if err != nil {
		t.Fatalf("RunDuePulls() error = %v", err)
	}
	for _, result := range results {
		if result.ProfileID == profileID {
			return result
		}
	}
	t.Fatalf("profile %s did not run: %+v", profileID, results)
	return nil
}

type stubPuller struct {
	kind string
	pull func(ctx context.Context, request PullRequest, emit func(PullPage) error) (PullOutcome, error)
}

func (p stubPuller) Kind() string                         { return p.kind }
func (stubPuller) SecretKeys() []string                   { return nil }
func (stubPuller) ValidateConfig(map[string]string) error { return nil }
func (p stubPuller) Pull(ctx context.Context, request PullRequest, emit func(PullPage) error) (PullOutcome, error) {
	return p.pull(ctx, request, emit)
}

func TestStrixPullerPagesAndResolvesSnapshot(t *testing.T) {
	var mu sync.Mutex
	requests := []string{}
	items := map[int]string{
		1: `{"id":"v-1","scan_id":"s","title":"IDOR on orders","severity":"high","status":"open","finding_type":"live_pentest","display_number":1}`,
		2: `{"id":"v-2","scan_id":"s","title":"Open redirect","severity":"low","status":"open","finding_type":"live_pentest","display_number":2}`,
	}
	serveV2 := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer token-123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		requests = append(requests, r.URL.RequestURI())
		page := r.URL.Query().Get("page")
		if r.URL.Query().Get("finding_type") != "live_pentest" || r.URL.Path != "/api/v1/vulnerabilities" {
			_, _ = fmt.Fprint(w, `{"items":[],"meta":{"has_next":false}}`)
			return
		}
		switch {
		case page == "1":
			_, _ = fmt.Fprintf(w, `{"items":[%s],"meta":{"page":1,"has_next":%t}}`, items[1], serveV2)
		case page == "2" && serveV2:
			_, _ = fmt.Fprintf(w, `{"items":[%s],"meta":{"page":2,"has_next":false}}`, items[2])
		default:
			_, _ = fmt.Fprint(w, `{"items":[],"meta":{"has_next":false}}`)
		}
	}))
	defer server.Close()

	service, store := newTestService(t, StrixPuller{Options: loopbackHTTP})
	mustCreateProfile(t, service, ProfileInput{SourceID: "strix", Pull: &PullInput{Kind: PullKindStrix, Config: map[string]string{ // #nosec G101 -- test credential references, not secret values.
		"api_token": "env:resolved-token-123", "base_url": server.URL + "/api/v1", "finding_types": "live_pentest,code",
	}}})
	result := syncNow(t, service, "strix")
	if result.Error != "" || result.Pages != 3 || result.Accepted != 2 || !result.Snapshot {
		t.Fatalf("first sync = %+v (requests %v)", result, requests)
	}

	mu.Lock()
	serveV2 = false
	mu.Unlock()
	if result = syncNow(t, service, "strix"); result.Resolved != 1 {
		t.Fatalf("second sync = %+v", result)
	}
	for _, observation := range store.ObservationsFor("strix") {
		if observation.SourceRecordID == "v-2" && observation.Resolution != ResolutionAbsentFromSnapshot {
			t.Fatalf("v-2 should be resolved as absent: %+v", observation)
		}
		if observation.SourceRecordID == "v-1" && observation.ResolvedAt != nil {
			t.Fatalf("v-1 should stay open: %+v", observation)
		}
	}
}

func TestStrixPullerFailureDoesNotResolve(t *testing.T) {
	var calls int
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		current := calls
		mu.Unlock()
		if current > 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = fmt.Fprint(w, `{"items":[{"id":"v-1","scan_id":"s","title":"IDOR","severity":"high","finding_type":"live_pentest"}],"meta":{"has_next":false}}`)
	}))
	defer server.Close()
	service, store := newTestService(t, StrixPuller{Options: loopbackHTTP})
	mustCreateProfile(t, service, ProfileInput{SourceID: "strix", Pull: &PullInput{Kind: PullKindStrix, Config: map[string]string{ // #nosec G101 -- test credential references, not secret values.
		"api_token": "env:resolved-t", "base_url": server.URL, "finding_types": "live_pentest",
	}}})
	if result := syncNow(t, service, "strix"); result.Error != "" {
		t.Fatalf("first sync = %+v", result)
	}
	result := syncNow(t, service, "strix")
	if result.Status != ProfileStatusFailed || !strings.Contains(result.Error, "403") {
		t.Fatalf("failed sync = %+v", result)
	}
	if strings.Contains(result.Error, "token") {
		t.Fatalf("error leaks credential material: %q", result.Error)
	}
	if store.ObservationsFor("strix")[0].ResolvedAt != nil {
		t.Fatal("a failed sync must not resolve observations")
	}
}

func TestStrixPullerWithoutPageInfoIsNotASnapshot(t *testing.T) {
	var mu sync.Mutex
	body := `{"items":[{"id":"v-1","scan_id":"s","title":"A","finding_type":"live_pentest"},{"id":"v-2","scan_id":"s","title":"B","finding_type":"live_pentest"}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_, _ = fmt.Fprint(w, body)
	}))
	defer server.Close()
	service, store := newTestService(t, StrixPuller{Options: loopbackHTTP})
	mustCreateProfile(t, service, ProfileInput{SourceID: "strix", Pull: &PullInput{Kind: PullKindStrix, Config: map[string]string{ // #nosec G101 -- test credential references, not secret values.
		"api_token": "env:resolved-t", "base_url": server.URL, "finding_types": "live_pentest",
	}}})
	if result := syncNow(t, service, "strix"); result.Accepted != 2 || result.Snapshot || result.Pages != 1 {
		t.Fatalf("first sync = %+v", result)
	}
	mu.Lock()
	body = `{"items":[{"id":"v-1","scan_id":"s","title":"A","finding_type":"live_pentest"}],"meta":{"page":1}}`
	mu.Unlock()
	if result := syncNow(t, service, "strix"); result.Resolved != 0 || result.Snapshot {
		t.Fatalf("a page without has_next or total_pages must not resolve: %+v", result)
	}
	for _, observation := range store.ObservationsFor("strix") {
		if observation.ResolvedAt != nil {
			t.Fatalf("observation %s was resolved", observation.SourceRecordID)
		}
	}
}

func TestStrixPageInfo(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		page        int
		next, known bool
	}{
		{name: "has_next", body: `{"meta":{"has_next":true}}`, page: 1, next: true, known: true},
		{name: "total pages above ten", body: `{"meta":{"total_pages":12}}`, page: 11, next: true, known: true},
		{name: "last of total pages", body: `{"meta":{"total_pages":2}}`, page: 2, next: false, known: true},
		{name: "no meta", body: `{"items":[]}`, page: 1},
		{name: "meta without paging", body: `{"meta":{"page":1}}`, page: 1},
		{name: "not json", body: `nope`, page: 1},
	}
	for _, tc := range cases {
		next, known := strixPageInfo([]byte(tc.body), tc.page)
		if next != tc.next || known != tc.known {
			t.Errorf("%s: strixPageInfo() = %v, %v; want %v, %v", tc.name, next, known, tc.next, tc.known)
		}
	}
}

func TestStrixPullerPinsAPIHost(t *testing.T) {
	config := func(baseURL string) map[string]string {
		out := map[string]string{"api_token": "env:x"} // #nosec G101 -- test credential reference.
		if baseURL != "" {
			out["base_url"] = baseURL
		}
		return out
	}
	if err := (StrixPuller{}).ValidateConfig(config("")); err != nil {
		t.Fatalf("default base_url rejected: %v", err)
	}
	if err := (StrixPuller{}).ValidateConfig(config("https://app.strix.ai/api/v2")); err != nil {
		t.Fatalf("default host rejected: %v", err)
	}
	if err := (StrixPuller{}).ValidateConfig(config("https://collector.attacker.example/api/v1")); err == nil {
		t.Fatal("ValidateConfig accepted a base_url outside the Strix host allowlist")
	}
	if err := (StrixPuller{AllowedHosts: []string{"strix.internal.example.com"}}).ValidateConfig(config("https://strix.internal.example.com/api/v1")); err != nil {
		t.Fatalf("operator-allowed host rejected: %v", err)
	}
}

func TestUpdateProfileDestinationChangeDropsStoredSecret(t *testing.T) {
	service, store := newTestService(t, HTTPPuller{}, StrixPuller{})
	ctx := context.Background()
	mustCreateProfile(t, service, ProfileInput{SourceID: "api", Format: ptr(FormatStrix), Pull: &PullInput{Kind: PullKindHTTP, Config: map[string]string{ // #nosec G101 -- test credential references, not secret values.
		"url": "https://scanner.example.com/findings", "token": "env:resolved-k", "auth_header": "X-Api-Key",
	}}})
	view, err := service.UpdateProfile(ctx, "tenant-a", "api", "a", ProfileInput{Pull: &PullInput{Config: map[string]string{"max_pages": "5"}}})
	if err != nil || len(view.PullSecretKeys) != 1 {
		t.Fatalf("unrelated change should keep the token: %+v, %v", view, err)
	}
	view, err = service.UpdateProfile(ctx, "tenant-a", "api", "a", ProfileInput{Pull: &PullInput{Config: map[string]string{"url": "https://collector.attacker.example/steal"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(view.PullSecretKeys) != 0 {
		t.Fatalf("changing url kept the stored token: %+v", view)
	}
	profile, _ := store.GetVulnerabilityProfile(ctx, "tenant-a", "api")
	if strings.Contains(profile.PullConfigJSON, "env:resolved-k") {
		t.Fatalf("stored config still holds the token reference: %s", profile.PullConfigJSON)
	}
	view, err = service.UpdateProfile(ctx, "tenant-a", "api", "a", ProfileInput{Pull: &PullInput{Config: map[string]string{ // #nosec G101 -- test credential reference.
		"auth_header": "Authorization", "token": "env:resolved-k2",
	}}})
	if err != nil || len(view.PullSecretKeys) != 1 {
		t.Fatalf("a destination change that resupplies the token should keep it: %+v, %v", view, err)
	}

	mustCreateProfile(t, service, ProfileInput{SourceID: "strix", Pull: &PullInput{Kind: PullKindStrix, Config: map[string]string{"api_token": "env:resolved-t"}}}) // #nosec G101 -- test credential reference.
	_, err = service.UpdateProfile(ctx, "tenant-a", "strix", "a", ProfileInput{Pull: &PullInput{Config: map[string]string{"base_url": "https://app.strix.ai/api/v2"}}})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("changing base_url without the token error = %v", err)
	}
	if _, err := service.UpdateProfile(ctx, "tenant-a", "strix", "a", ProfileInput{Pull: &PullInput{Config: map[string]string{ // #nosec G101 -- test credential reference.
		"base_url": "https://app.strix.ai/api/v2", "api_token": "env:resolved-t2",
	}}}); err != nil {
		t.Fatalf("changing base_url with the token error = %v", err)
	}
}

func TestHTTPPullerFollowsNextURLAndSendsAuth(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "k-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("page") == "2" {
			_, _ = fmt.Fprint(w, `{"findings":[{"id":"b","title":"Second","severity":"low"}],"next":null}`)
			return
		}
		_, _ = fmt.Fprintf(w, `{"findings":[{"id":"a","title":"First","severity":"high"}],"next":"%s/findings?page=2"}`, server.URL)
	}))
	defer server.Close()
	mapping := &Mapping{RecordsPath: "findings", Fields: map[string]FieldRule{
		FieldSourceRecordID: {Paths: []string{"id"}}, FieldTitle: {Paths: []string{"title"}}, FieldSeverity: {Paths: []string{"severity"}},
	}}
	service, store := newTestService(t, HTTPPuller{Options: loopbackHTTP})
	mustCreateProfile(t, service, ProfileInput{SourceID: "internal-api", Format: ptr(FormatGeneric), Mapping: mapping, Pull: &PullInput{Kind: PullKindHTTP, Config: map[string]string{ // #nosec G101 -- test credential references, not secret values.
		"url": server.URL + "/findings?page=1", "token": "env:resolved-k-1", "auth_header": "X-Api-Key", "auth_scheme": "none",
		"next_url_path": "next", "full_snapshot": "true",
	}}})
	result := syncNow(t, service, "internal-api")
	if result.Error != "" || result.Pages != 2 || result.Accepted != 2 || !result.Snapshot {
		t.Fatalf("sync = %+v", result)
	}
	if len(store.ObservationsFor("internal-api")) != 2 {
		t.Fatal("expected two observations")
	}
}

func TestHTTPPullerMissingNextFieldIsNotASnapshot(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"findings":[{"id":"a","title":"First"}]}`)
	}))
	defer server.Close()
	puller := HTTPPuller{Options: loopbackHTTP}
	outcome, err := puller.Pull(context.Background(), PullRequest{Config: map[string]string{"url": server.URL, "next_url_path": "next", "full_snapshot": "true"}}, func(PullPage) error { return nil })
	if err != nil || outcome.Snapshot {
		t.Fatalf("a page without its next field must not be a snapshot: %+v, %v", outcome, err)
	}
}

func TestHTTPPullerQuarantinedPageDoesNotResolve(t *testing.T) {
	var mu sync.Mutex
	body := `{"findings":[{"id":"a","title":"First"},{"id":"b","title":"Second"}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_, _ = fmt.Fprint(w, body)
	}))
	defer server.Close()
	mapping := &Mapping{RecordsPath: "findings", Fields: map[string]FieldRule{FieldSourceRecordID: {Paths: []string{"id"}}, FieldTitle: {Paths: []string{"title"}}}}
	service, store := newTestService(t, HTTPPuller{Options: loopbackHTTP})
	mustCreateProfile(t, service, ProfileInput{SourceID: "snap-api", Format: ptr(FormatGeneric), Mapping: mapping, Pull: &PullInput{Kind: PullKindHTTP, Config: map[string]string{
		"url": server.URL, "full_snapshot": "true",
	}}})
	if result := syncNow(t, service, "snap-api"); result.Accepted != 2 || !result.Snapshot {
		t.Fatalf("first sync = %+v", result)
	}
	mu.Lock()
	body = `{"findings":[{"id":"a","title":"First"},{"id":"c"}]}`
	mu.Unlock()
	result := syncNow(t, service, "snap-api")
	if result.Quarantined != 1 || result.Resolved != 0 || result.Snapshot {
		t.Fatalf("a partly quarantined snapshot must not resolve: %+v", result)
	}
	for _, observation := range store.ObservationsFor("snap-api") {
		if observation.ResolvedAt != nil {
			t.Fatalf("observation %s was resolved", observation.SourceRecordID)
		}
	}
}

func TestHTTPPullerHoldsOnePageUntilMappingIsActive(t *testing.T) {
	var mu sync.Mutex
	fetched := 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fetched++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("page") == "2" {
			_, _ = fmt.Fprint(w, `{"results":[{"key":"b","headline":"Two","sev":"high"}],"next":null}`)
			return
		}
		_, _ = fmt.Fprintf(w, `{"results":[{"key":"a","headline":"One","sev":"low"}],"next":"%s/?page=2"}`, server.URL)
	}))
	defer server.Close()
	service, store := newTestService(t, HTTPPuller{Options: loopbackHTTP})
	mustCreateProfile(t, service, ProfileInput{SourceID: "unmapped", Format: ptr(FormatGeneric), Pull: &PullInput{Kind: PullKindHTTP, Config: map[string]string{
		"url": server.URL + "/?page=1", "next_url_path": "next",
	}}})
	ctx := context.Background()
	for run := 1; run <= 2; run++ {
		result := syncNow(t, service, "unmapped")
		if result.Pages != 1 || result.Status != ProfileStatusPendingMapping || result.Error != "" {
			t.Fatalf("run %d = %+v", run, result)
		}
	}
	mu.Lock()
	if fetched != 2 {
		t.Fatalf("fetched %d pages, want only the first page of each run", fetched)
	}
	mu.Unlock()
	held, err := service.ListBatches(ctx, "tenant-a", "unmapped", BatchPendingMapping, 10)
	if err != nil || len(held) != 1 {
		t.Fatalf("an unchanged page should be held once: %+v, %v", held, err)
	}
	profile, _ := store.GetVulnerabilityProfile(ctx, "tenant-a", "unmapped")
	if profile.NextPullAt == nil || profile.LastIngestAt == nil || profile.NextPullAt.Sub(*profile.LastIngestAt) < pendingMappingBackoff-time.Minute {
		t.Fatalf("pending profile should back off: next %v last %v", profile.NextPullAt, profile.LastIngestAt)
	}
}

func TestHTTPPullerRejectsUnsafeConfig(t *testing.T) {
	puller := HTTPPuller{}
	cases := []map[string]string{
		{"url": "http://example.com/x"},
		{"url": "https://169.254.169.254/latest"},
		{"url": "https://user:pass@example.com/"}, // #nosec G101 -- rejected-URL fixture, not a credential.
		{"url": "https://example.com/", "unknown": "x"},
		{"url": "https://example.com/", "auth_header": "Bad Header"},
		{"url": "https://example.com/", "cursor_path": "next"},
		{"url": "https://example.com/findings?api_key=abc"},
		{"url": "https://example.com/findings?status=open&token=abc"},
		{"url": "https://example.com/findings?access_token=abc"},
	}
	for _, config := range cases {
		if err := puller.ValidateConfig(config); err == nil {
			t.Errorf("ValidateConfig(%v) accepted unsafe config", config)
		}
	}
	for _, valid := range []string{"https://scanner.example.com/api/findings?status=open", "https://scanner.example.com/api/findings?page_token=abc&nextToken=x"} {
		if err := puller.ValidateConfig(map[string]string{"url": valid}); err != nil {
			t.Fatalf("valid config %q rejected: %v", valid, err)
		}
	}
}

func TestHTTPPullerNextURLMustStayOnOrigin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"items":[{"id":"a","title":"First"}],"next":"https://evil.example.net/steal"}`)
	}))
	defer server.Close()
	puller := HTTPPuller{Options: loopbackHTTP}
	_, err := puller.Pull(context.Background(), PullRequest{Config: map[string]string{"url": server.URL, "next_url_path": "next"}}, func(PullPage) error { return nil })
	if !errors.Is(err, ErrUnsafePageURL) {
		t.Fatalf("cross-origin next url error = %v", err)
	}
}

type fakeS3 struct {
	mu       sync.Mutex
	objects  map[string]string
	order    []string
	errors   map[string]error
	owners   []string
	settings []S3Settings
}

func (f *fakeS3) client(_ context.Context, settings S3Settings) (S3API, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.settings = append(f.settings, settings)
	return f, nil
}

func (f *fakeS3) ListObjectsV2(_ context.Context, input *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.owners = append(f.owners, awssdk.ToString(input.ExpectedBucketOwner))
	out := &s3.ListObjectsV2Output{IsTruncated: awssdk.Bool(false)}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for index, key := range f.order {
		if !strings.HasPrefix(key, awssdk.ToString(input.Prefix)) || (input.StartAfter != nil && key <= *input.StartAfter) {
			continue
		}
		modified := base.Add(time.Duration(index) * time.Hour)
		out.Contents = append(out.Contents, s3types.Object{Key: awssdk.String(key), Size: awssdk.Int64(int64(len(f.objects[key]))), ETag: awssdk.String(`"` + key + `"`), LastModified: &modified})
	}
	return out, nil
}

func (f *fakeS3) GetObject(_ context.Context, input *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.owners = append(f.owners, awssdk.ToString(input.ExpectedBucketOwner))
	if err := f.errors[awssdk.ToString(input.Key)]; err != nil {
		return nil, err
	}
	body := f.objects[awssdk.ToString(input.Key)]
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader([]byte(body))), ContentLength: awssdk.Int64(int64(len(body)))}, nil
}

func (f *fakeS3) add(key string, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = body
	f.order = append(f.order, key)
}

func ambientS3(bucket *fakeS3) S3Puller {
	return S3Puller{AllowAmbientCredentials: true, NewClient: bucket.client}
}

func TestS3PullerIncrementalAdvancesCursor(t *testing.T) {
	bucket := &fakeS3{objects: map[string]string{
		"exports/001.ndjson": `{"id":"x1","scan_id":"s","title":"A","severity":"high","finding_type":"code"}`,
		"exports/002.json":   `{"items":[{"id":"x2","scan_id":"s","title":"B","severity":"low","finding_type":"code"}]}`,
	}, order: []string{"exports/001.ndjson", "exports/002.json"}}
	service, store := newTestService(t, ambientS3(bucket))
	config := map[string]string{"bucket": "vuln-exports", "prefix": "exports/"}
	mustCreateProfile(t, service, ProfileInput{SourceID: "s3-drop", Pull: &PullInput{Kind: PullKindS3, Config: config}})
	ctx := context.Background()
	result := syncNow(t, service, "s3-drop")
	if result.Error != "" || result.Accepted != 2 || result.Snapshot {
		t.Fatalf("first sync = %+v", result)
	}
	profile, _ := store.GetVulnerabilityProfile(ctx, "tenant-a", "s3-drop")
	if key := decodeS3Cursor(config, profile.PullCursor); key != "exports/002.json" {
		t.Fatalf("cursor = %q (%q)", key, profile.PullCursor)
	}
	bucket.add("exports/003.json", `{"items":[{"id":"x3","scan_id":"s","title":"C","severity":"medium","finding_type":"code"}]}`)
	if result = syncNow(t, service, "s3-drop"); result.Pages != 1 || result.Accepted != 1 {
		t.Fatalf("second sync = %+v", result)
	}
	if len(store.ObservationsFor("s3-drop")) != 3 {
		t.Fatal("expected three observations")
	}
}

func TestS3PullerStopsAtFailedIngest(t *testing.T) {
	bucket := &fakeS3{objects: map[string]string{
		"x/001.json": `{"items":[{"id":"a","scan_id":"s","title":"A","finding_type":"code"}]}`,
		"x/002.json": `{"items":[`,
		"x/003.json": `{"items":[{"id":"c","scan_id":"s","title":"C","finding_type":"code"}]}`,
	}, order: []string{"x/001.json", "x/002.json", "x/003.json"}}
	service, store := newTestService(t, ambientS3(bucket))
	config := map[string]string{"bucket": "vuln-exports", "prefix": "x/"}
	mustCreateProfile(t, service, ProfileInput{SourceID: "s3-bad", Pull: &PullInput{Kind: PullKindS3, Config: config}})
	result := syncNow(t, service, "s3-bad")
	if result.Status != ProfileStatusFailed {
		t.Fatalf("sync = %+v", result)
	}
	profile, _ := store.GetVulnerabilityProfile(context.Background(), "tenant-a", "s3-bad")
	if key := decodeS3Cursor(config, profile.PullCursor); key != "x/001.json" {
		t.Fatalf("cursor must stay before the object whose ingest failed, got %q", key)
	}
	if len(store.ObservationsFor("s3-bad")) != 1 {
		t.Fatal("objects after the failed one must not be ingested in this run")
	}
}

func TestS3PullerSkipsPermanentlyUnreadableObjects(t *testing.T) {
	denied := &awshttp.ResponseError{ResponseError: &smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusForbidden}},
		Err:      errors.New("AccessDenied"),
	}}
	bucket := &fakeS3{objects: map[string]string{
		"x/001.json":    `{"items":[{"id":"a","scan_id":"s","title":"A","finding_type":"code"}]}`,
		"x/002.json.gz": "not gzip at all",
		"x/003.json":    "   \n ",
		"x/004.json":    `{"items":[]}`,
		"x/005.json":    `{"items":[{"id":"e","scan_id":"s","title":"E","finding_type":"code"}]}`,
	}, order: []string{"x/001.json", "x/002.json.gz", "x/003.json", "x/004.json", "x/005.json"}, errors: map[string]error{"x/004.json": denied}}
	service, store := newTestService(t, ambientS3(bucket))
	config := map[string]string{"bucket": "vuln-exports", "prefix": "x/"}
	mustCreateProfile(t, service, ProfileInput{SourceID: "s3-skip", Pull: &PullInput{Kind: PullKindS3, Config: config}})
	result := syncNow(t, service, "s3-skip")
	if result.Status != ProfileStatusHealthy || result.Skipped != 3 || result.Accepted != 2 {
		t.Fatalf("sync = %+v", result)
	}
	profile, _ := store.GetVulnerabilityProfile(context.Background(), "tenant-a", "s3-skip")
	if key := decodeS3Cursor(config, profile.PullCursor); key != "x/005.json" {
		t.Fatalf("cursor = %q, want past the unreadable objects", key)
	}
	if !strings.Contains(profile.LastError, "skipped 3") {
		t.Fatalf("last_error should summarize skipped objects: %q", profile.LastError)
	}
}

func TestS3CursorIsScopedToBucketPrefixAndMode(t *testing.T) {
	bucket := &fakeS3{objects: map[string]string{
		"a/1.json": `{"items":[{"id":"a1","scan_id":"s","title":"A","finding_type":"code"}]}`,
		"b/1.json": `{"items":[{"id":"b1","scan_id":"s","title":"B","finding_type":"code"}]}`,
	}, order: []string{"a/1.json", "b/1.json"}}
	service, store := newTestService(t, ambientS3(bucket))
	ctx := context.Background()
	mustCreateProfile(t, service, ProfileInput{SourceID: "scoped", Pull: &PullInput{Kind: PullKindS3, Config: map[string]string{"bucket": "vuln-exports", "prefix": "b/"}}})
	syncNow(t, service, "scoped")
	if _, err := service.UpdateProfile(ctx, "tenant-a", "scoped", "a", ProfileInput{Pull: &PullInput{Config: map[string]string{"prefix": "a/"}}}); err != nil {
		t.Fatal(err)
	}
	// "a/1.json" sorts before the old cursor "b/1.json"; it is read only if
	// the old cursor is ignored for the new prefix.
	if result := syncNow(t, service, "scoped"); result.Accepted != 1 {
		t.Fatalf("sync of the new prefix = %+v", result)
	}
	profile, _ := store.GetVulnerabilityProfile(ctx, "tenant-a", "scoped")
	if key := decodeS3Cursor(map[string]string{"bucket": "vuln-exports", "prefix": "a/"}, profile.PullCursor); key != "a/1.json" {
		t.Fatalf("cursor after the prefix change = %q", profile.PullCursor)
	}

	stored := encodeS3Cursor(map[string]string{"bucket": "vuln-exports", "prefix": "b/"}, "b/9.json")
	for _, config := range []map[string]string{
		{"bucket": "other-bucket", "prefix": "b/"},
		{"bucket": "vuln-exports", "prefix": "a/"},
		{"bucket": "vuln-exports", "prefix": "b/", "mode": s3ModeLatestSnapshot},
	} {
		if key := decodeS3Cursor(config, stored); key != "" {
			t.Errorf("cursor applied to %v: %q", config, key)
		}
	}
	if key := decodeS3Cursor(map[string]string{"bucket": "vuln-exports", "prefix": "b/", "mode": s3ModeIncremental}, stored); key != "b/9.json" {
		t.Errorf("matching cursor = %q", key)
	}
	if key := decodeS3Cursor(map[string]string{"bucket": "vuln-exports"}, "b/9.json"); key != "" {
		t.Errorf("unscoped cursor applied: %q", key)
	}
}

func TestS3PullerLatestSnapshotSkipsResolutionOnReplay(t *testing.T) {
	bucket := &fakeS3{objects: map[string]string{
		"snap/1.json": `{"items":[{"id":"a","scan_id":"s","title":"A","finding_type":"code"},{"id":"b","scan_id":"s","title":"B","finding_type":"code"}]}`,
	}, order: []string{"snap/1.json"}}
	service, store := newTestService(t, ambientS3(bucket))
	mustCreateProfile(t, service, ProfileInput{SourceID: "snap", Pull: &PullInput{Kind: PullKindS3, Config: map[string]string{"bucket": "vuln-exports", "prefix": "snap/", "mode": "latest_snapshot"}}})
	if result := syncNow(t, service, "snap"); result.Accepted != 2 || !result.Snapshot {
		t.Fatalf("first sync = %+v", result)
	}
	if result := syncNow(t, service, "snap"); result.Resolved != 0 || result.Snapshot {
		t.Fatalf("unchanged snapshot replay must not resolve: %+v", result)
	}
	bucket.add("snap/2.json", `{"items":[{"id":"a","scan_id":"s","title":"A","finding_type":"code"}]}`)
	if result := syncNow(t, service, "snap"); result.Resolved != 1 {
		t.Fatalf("new snapshot sync = %+v", result)
	}
	for _, observation := range store.ObservationsFor("snap") {
		if (observation.SourceRecordID == "b") != (observation.ResolvedAt != nil) {
			t.Fatalf("observation %s resolution = %v", observation.SourceRecordID, observation.ResolvedAt)
		}
	}
}

func TestS3PullerValidatesConfig(t *testing.T) {
	cases := []map[string]string{
		{"bucket": "Bad_Bucket"},
		{"bucket": "ok-bucket", "prefix": "../x"},
		{"bucket": "ok-bucket", "prefix": "exports/*"},
		{"bucket": "ok-bucket", "role_arn": "arn:aws:iam::123:user/x"},
		{"bucket": "ok-bucket", "mode": "everything"},
	}
	for _, config := range cases {
		if err := (S3Puller{}).ValidateConfig(config); err == nil {
			t.Errorf("ValidateConfig(%v) accepted invalid config", config)
		}
	}
}

func TestS3PullerRequiresAllowlistedSource(t *testing.T) {
	if err := (S3Puller{}).ValidateConfig(map[string]string{"bucket": "ok-bucket"}); err == nil {
		t.Fatal("ValidateConfig accepted a profile without role_arn")
	}
	role := "arn:aws:iam::123456789012:role/vuln-export-reader"
	for _, tc := range []struct {
		name      string
		allowlist string
		bucket    string
		prefix    string
		accepted  bool
	}{
		{name: "unlisted", bucket: "vuln-exports", prefix: "scanner/"},
		{name: "inventory role allowlist format", allowlist: "tenant-a=" + role, bucket: "vuln-exports", prefix: "scanner/"},
		{name: "other tenant", allowlist: "tenant-b=" + role + "|vuln-exports", bucket: "vuln-exports", prefix: "scanner/"},
		{name: "other bucket", allowlist: "tenant-a=" + role + "|vuln-exports", bucket: "payroll-exports", prefix: "scanner/"},
		{name: "outside prefix", allowlist: "tenant-a=" + role + "|vuln-exports/scanner/", bucket: "vuln-exports", prefix: "other/"},
		{name: "whole bucket", allowlist: "tenant-a=" + role + "|vuln-exports", bucket: "vuln-exports", prefix: "scanner/", accepted: true},
		{name: "within prefix", allowlist: "tenant-b=" + role + "|x, tenant-a=" + role + "|vuln-exports/scanner/", bucket: "vuln-exports", prefix: "scanner/team-a/", accepted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bucket := &fakeS3{objects: map[string]string{}}
			puller := S3Puller{NewClient: bucket.client, Sources: func() string { return tc.allowlist }}
			_, err := puller.Pull(context.Background(), PullRequest{TenantID: "tenant-a", ProfileID: "Scanner Drop", Config: map[string]string{
				"bucket": tc.bucket, "prefix": tc.prefix, "role_arn": role,
			}}, func(PullPage) error { return nil })
			if (err == nil) != tc.accepted {
				t.Fatalf("Pull() error = %v; accepted want %v", err, tc.accepted)
			}
			if !tc.accepted {
				if len(bucket.settings) != 0 {
					t.Fatal("a rejected source must not build an S3 client")
				}
				return
			}
			settings := bucket.settings[0]
			wantResource := `"arn:aws:s3:::` + tc.bucket + "/" + tc.prefix + `*"`
			if !strings.Contains(settings.SessionPolicy, wantResource) || !strings.Contains(settings.SessionPolicy, `"s3:prefix":"`+tc.prefix+`*"`) || strings.Contains(settings.SessionPolicy, "PutObject") {
				t.Fatalf("session policy = %s", settings.SessionPolicy)
			}
			if settings.SessionName != "cerebro-vp-tenant-a-Scanner-Drop" {
				t.Fatalf("session name = %q", settings.SessionName)
			}
			for _, owner := range bucket.owners {
				if owner != "123456789012" {
					t.Fatalf("expected bucket owner = %q", owner)
				}
			}
		})
	}
	if name := s3SessionName(strings.Repeat("t", 80), "p"); len(name) != maxS3SessionName {
		t.Fatalf("session name length = %d", len(name))
	}
}

func TestRunDuePullsClaimsAndReschedules(t *testing.T) {
	bucket := &fakeS3{objects: map[string]string{"a.json": `{"items":[{"id":"a","scan_id":"s","title":"A","finding_type":"code"}]}`}, order: []string{"a.json"}}
	service, store := newTestService(t, ambientS3(bucket))
	mustCreateProfile(t, service, ProfileInput{SourceID: "due", Pull: &PullInput{Kind: PullKindS3, Config: map[string]string{"bucket": "vuln-exports"}, IntervalSeconds: 600}})
	results, err := service.RunDuePulls(context.Background(), "worker-1")
	if err != nil || len(results) != 1 || results[0].Accepted != 1 {
		t.Fatalf("RunDuePulls() = %+v, %v", results, err)
	}
	profile, _ := store.GetVulnerabilityProfile(context.Background(), "tenant-a", "due")
	if profile.NextPullAt == nil || profile.ClaimOwner != "" {
		t.Fatalf("profile not rescheduled: %+v", profile)
	}
	results, _ = service.RunDuePulls(context.Background(), "worker-1")
	if len(results) != 0 {
		t.Fatalf("profile ran again before its interval: %+v", results)
	}
}

func TestSyncProfileQueuesInsteadOfRunning(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	var deadline time.Time
	puller := stubPuller{kind: "stub", pull: func(ctx context.Context, _ PullRequest, _ func(PullPage) error) (PullOutcome, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		deadline, _ = ctx.Deadline()
		return PullOutcome{}, nil
	}}
	service, store := newTestService(t, puller)
	ctx := context.Background()
	mustCreateProfile(t, service, ProfileInput{SourceID: "queued", Pull: &PullInput{Kind: "stub"}})
	if _, err := service.RunDuePulls(ctx, "worker-1"); err != nil {
		t.Fatal(err)
	}
	queued, err := service.SyncProfile(ctx, "tenant-a", "queued", "alice@example.com")
	if err != nil || queued.Status != PullStatusQueued || queued.QueuedAt == nil {
		t.Fatalf("SyncProfile() = %+v, %v", queued, err)
	}
	mu.Lock()
	if calls != 1 {
		t.Fatalf("SyncProfile ran the pull inline (%d calls)", calls)
	}
	if deadline.IsZero() || time.Until(deadline) > claimTTL {
		t.Fatalf("pull run deadline %v must be set and shorter than the claim TTL", deadline)
	}
	mu.Unlock()
	profile, _ := store.GetVulnerabilityProfile(ctx, "tenant-a", "queued")
	if profile.NextPullAt == nil || profile.NextPullAt.After(*queued.QueuedAt) {
		t.Fatalf("profile not marked due: %+v", profile.NextPullAt)
	}

	claimed, err := store.ClaimDueVulnerabilityProfiles(ctx, queued.QueuedAt.Add(time.Second), "other-replica", claimTTL, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim = %+v, %v", claimed, err)
	}
	if _, err := service.SyncProfile(ctx, "tenant-a", "queued", "alice@example.com"); !errors.Is(err, ErrConflict) {
		t.Fatalf("SyncProfile during a running pull error = %v, want conflict", err)
	}
}

func TestRunDuePullsRecoversPanicsAndReleasesClaimsOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	puller := stubPuller{kind: "stub", pull: func(runCtx context.Context, request PullRequest, _ func(PullPage) error) (PullOutcome, error) {
		switch request.ProfileID {
		case "boom":
			panic("puller bug")
		case "shutdown":
			cancel()
			<-runCtx.Done()
			return PullOutcome{}, runCtx.Err()
		}
		return PullOutcome{}, nil
	}}
	service, store := newTestService(t, puller)
	mustCreateProfile(t, service, ProfileInput{SourceID: "boom", Pull: &PullInput{Kind: "stub"}})
	mustCreateProfile(t, service, ProfileInput{SourceID: "fine", Pull: &PullInput{Kind: "stub"}})
	results, err := service.RunDuePulls(context.Background(), "worker-1")
	if err != nil || len(results) != 2 {
		t.Fatalf("RunDuePulls() = %+v, %v", results, err)
	}
	for _, result := range results {
		switch result.ProfileID {
		case "boom":
			if result.Status != ProfileStatusFailed || !strings.Contains(result.Error, "panicked") {
				t.Fatalf("panicking pull = %+v", result)
			}
		case "fine":
			if result.Status != ProfileStatusHealthy {
				t.Fatalf("healthy pull = %+v", result)
			}
		}
	}
	boom, _ := store.GetVulnerabilityProfile(context.Background(), "tenant-a", "boom")
	if boom.LastStatus != ProfileStatusFailed || boom.ClaimOwner != "" {
		t.Fatalf("panicking profile = %+v", boom)
	}

	mustCreateProfile(t, service, ProfileInput{SourceID: "shutdown", Pull: &PullInput{Kind: "stub"}})
	if _, err := service.RunDuePulls(ctx, "worker-1"); err != nil {
		t.Fatalf("RunDuePulls() during shutdown error = %v", err)
	}
	profile, _ := store.GetVulnerabilityProfile(context.Background(), "tenant-a", "shutdown")
	if profile.ClaimOwner != "" || profile.ClaimExpiresAt != nil {
		t.Fatalf("claim not released on shutdown: %+v", profile)
	}
	if profile.LastStatus != ProfileStatusFailed || profile.NextPullAt == nil || profile.LastIngestAt == nil || profile.NextPullAt.Sub(*profile.LastIngestAt) > time.Minute {
		t.Fatalf("cancelled run should be recorded and due again soon: status %q next %v last %v", profile.LastStatus, profile.NextPullAt, profile.LastIngestAt)
	}
}

func TestPullSnapshotMassResolutionNeedsConfirmation(t *testing.T) {
	ids := make([]string, 0, 30)
	for index := range 30 {
		ids = append(ids, fmt.Sprintf("r%02d", index))
	}
	var mu sync.Mutex
	current := ids
	puller := stubPuller{kind: "stub", pull: func(_ context.Context, _ PullRequest, emit func(PullPage) error) (PullOutcome, error) {
		mu.Lock()
		payload := nativePayload(current...)
		mu.Unlock()
		if err := emit(PullPage{Payload: []byte(payload), ContentType: "application/json"}); err != nil {
			return PullOutcome{}, err
		}
		return PullOutcome{Snapshot: true}, nil
	}}
	service, store := newTestService(t, puller)
	mustCreateProfile(t, service, ProfileInput{SourceID: "guarded", Pull: &PullInput{Kind: "stub"}})
	if result := syncNow(t, service, "guarded"); result.Accepted != 30 || !result.Snapshot {
		t.Fatalf("seed pull = %+v", result)
	}
	mu.Lock()
	current = ids[:1]
	mu.Unlock()
	result := syncNow(t, service, "guarded")
	if result.Resolved != 0 || !strings.Contains(strings.Join(result.Problems, " "), "withheld") {
		t.Fatalf("pull dropping 29 of 30 = %+v; want resolution withheld", result)
	}
	profile, _ := store.GetVulnerabilityProfile(context.Background(), "tenant-a", "guarded")
	if !strings.HasPrefix(profile.LastError, snapshotWithheldPrefix) {
		t.Fatalf("withheld resolution should be visible on the profile: %q", profile.LastError)
	}
	if result := syncNow(t, service, "guarded"); result.Resolved != 29 {
		t.Fatalf("confirming pull = %+v; want 29 resolved", result)
	}
}
