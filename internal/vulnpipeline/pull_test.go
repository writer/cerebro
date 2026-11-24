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
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/writer/cerebro/internal/sourceconfig"
)

var loopbackHTTP = HTTPOptions{AllowLoopback: true}

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
	ctx := context.Background()
	mustCreateProfile(t, service, ProfileInput{SourceID: "strix", Pull: &PullInput{Kind: PullKindStrix, Config: map[string]string{ // #nosec G101 -- test credential references, not secret values.
		"api_token": "env:resolved-token-123", "base_url": server.URL + "/api/v1", "finding_types": "live_pentest,code",
	}}})
	result, err := service.SyncProfile(ctx, "tenant-a", "strix", "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if result.Error != "" || result.Pages != 3 || result.Accepted != 2 || !result.Snapshot {
		t.Fatalf("first sync = %+v (requests %v)", result, requests)
	}

	mu.Lock()
	serveV2 = false
	mu.Unlock()
	result, err = service.SyncProfile(ctx, "tenant-a", "strix", "alice@example.com")
	if err != nil || result.Resolved != 1 {
		t.Fatalf("second sync = %+v, %v", result, err)
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
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls > 1 {
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
	ctx := context.Background()
	if result, _ := service.SyncProfile(ctx, "tenant-a", "strix", "a"); result.Error != "" {
		t.Fatalf("first sync = %+v", result)
	}
	result, err := service.SyncProfile(ctx, "tenant-a", "strix", "a")
	if err != nil || result.Status != ProfileStatusFailed || !strings.Contains(result.Error, "403") {
		t.Fatalf("failed sync = %+v, %v", result, err)
	}
	if strings.Contains(result.Error, "token") {
		t.Fatalf("error leaks credential material: %q", result.Error)
	}
	if store.ObservationsFor("strix")[0].ResolvedAt != nil {
		t.Fatal("a failed sync must not resolve observations")
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
	result, err := service.SyncProfile(context.Background(), "tenant-a", "internal-api", "a")
	if err != nil || result.Error != "" || result.Pages != 2 || result.Accepted != 2 || !result.Snapshot {
		t.Fatalf("sync = %+v, %v", result, err)
	}
	if len(store.ObservationsFor("internal-api")) != 2 {
		t.Fatal("expected two observations")
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
	}
	for _, config := range cases {
		if err := puller.ValidateConfig(config); err == nil {
			t.Errorf("ValidateConfig(%v) accepted unsafe config", config)
		}
	}
	if err := puller.ValidateConfig(map[string]string{"url": "https://scanner.example.com/api/findings?status=open"}); err != nil {
		t.Fatalf("valid config rejected: %v", err)
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
	objects map[string]string
	order   []string
}

func (f *fakeS3) ListObjectsV2(_ context.Context, input *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
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
	body := f.objects[awssdk.ToString(input.Key)]
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader([]byte(body))), ContentLength: awssdk.Int64(int64(len(body)))}, nil
}

func TestS3PullerIncrementalAdvancesCursor(t *testing.T) {
	bucket := &fakeS3{objects: map[string]string{
		"exports/001.ndjson": `{"id":"x1","scan_id":"s","title":"A","severity":"high","finding_type":"code"}`,
		"exports/002.json":   `{"items":[{"id":"x2","scan_id":"s","title":"B","severity":"low","finding_type":"code"}]}`,
	}, order: []string{"exports/001.ndjson", "exports/002.json"}}
	puller := S3Puller{AllowAmbientCredentials: true, NewClient: func(context.Context, S3Settings) (S3API, error) { return bucket, nil }}
	service, store := newTestService(t, puller)
	mustCreateProfile(t, service, ProfileInput{SourceID: "s3-drop", Pull: &PullInput{Kind: PullKindS3, Config: map[string]string{"bucket": "vuln-exports", "prefix": "exports/"}}})
	ctx := context.Background()
	result, err := service.SyncProfile(ctx, "tenant-a", "s3-drop", "a")
	if err != nil || result.Error != "" || result.Accepted != 2 || result.Snapshot {
		t.Fatalf("first sync = %+v, %v", result, err)
	}
	profile, _ := store.GetVulnerabilityProfile(ctx, "tenant-a", "s3-drop")
	if profile.PullCursor != "exports/002.json" {
		t.Fatalf("cursor = %q", profile.PullCursor)
	}
	bucket.objects["exports/003.json"] = `{"items":[{"id":"x3","scan_id":"s","title":"C","severity":"medium","finding_type":"code"}]}`
	bucket.order = append(bucket.order, "exports/003.json")
	result, err = service.SyncProfile(ctx, "tenant-a", "s3-drop", "a")
	if err != nil || result.Pages != 1 || result.Accepted != 1 {
		t.Fatalf("second sync = %+v, %v", result, err)
	}
	if len(store.ObservationsFor("s3-drop")) != 3 {
		t.Fatal("expected three observations")
	}
}

func TestS3PullerLatestSnapshotSkipsResolutionOnReplay(t *testing.T) {
	bucket := &fakeS3{objects: map[string]string{
		"snap/1.json": `{"items":[{"id":"a","scan_id":"s","title":"A","finding_type":"code"},{"id":"b","scan_id":"s","title":"B","finding_type":"code"}]}`,
	}, order: []string{"snap/1.json"}}
	puller := S3Puller{AllowAmbientCredentials: true, NewClient: func(context.Context, S3Settings) (S3API, error) { return bucket, nil }}
	service, store := newTestService(t, puller)
	mustCreateProfile(t, service, ProfileInput{SourceID: "snap", Pull: &PullInput{Kind: PullKindS3, Config: map[string]string{"bucket": "vuln-exports", "prefix": "snap/", "mode": "latest_snapshot"}}})
	ctx := context.Background()
	if result, _ := service.SyncProfile(ctx, "tenant-a", "snap", "a"); result.Accepted != 2 || !result.Snapshot {
		t.Fatalf("first sync = %+v", result)
	}
	if result, _ := service.SyncProfile(ctx, "tenant-a", "snap", "a"); result.Resolved != 0 || result.Snapshot {
		t.Fatalf("unchanged snapshot replay must not resolve: %+v", result)
	}
	bucket.objects["snap/2.json"] = `{"items":[{"id":"a","scan_id":"s","title":"A","finding_type":"code"}]}`
	bucket.order = append(bucket.order, "snap/2.json")
	if result, _ := service.SyncProfile(ctx, "tenant-a", "snap", "a"); result.Resolved != 1 {
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
		{"bucket": "ok-bucket", "role_arn": "arn:aws:iam::123:user/x"},
		{"bucket": "ok-bucket", "mode": "everything"},
	}
	for _, config := range cases {
		if err := (S3Puller{}).ValidateConfig(config); err == nil {
			t.Errorf("ValidateConfig(%v) accepted invalid config", config)
		}
	}
}

func TestS3PullerRequiresTenantBoundRole(t *testing.T) {
	if err := (S3Puller{}).ValidateConfig(map[string]string{"bucket": "ok-bucket"}); err == nil {
		t.Fatal("ValidateConfig accepted a profile without role_arn")
	}
	bucket := &fakeS3{objects: map[string]string{"a.json": `{"items":[{"id":"a","scan_id":"s","title":"A","finding_type":"code"}]}`}, order: []string{"a.json"}}
	role := "arn:aws:iam::123456789012:role/vuln-export-reader"
	puller := S3Puller{NewClient: func(context.Context, S3Settings) (S3API, error) { return bucket, nil }}
	for _, tc := range []struct {
		name      string
		allowlist string
		accepted  bool
	}{
		{name: "unlisted", allowlist: "", accepted: false},
		{name: "other tenant", allowlist: "tenant-b=" + role, accepted: false},
		{name: "bound", allowlist: "tenant-a=" + role, accepted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outcome, err := puller.Pull(context.Background(), PullRequest{TenantID: "tenant-a", ProfileID: "p", Config: map[string]string{
				"bucket": "vuln-exports", "role_arn": role, sourceconfig.AWSAssumeRoleAllowlistKey: tc.allowlist,
			}}, func(PullPage) error { return nil })
			if (err == nil) != tc.accepted {
				t.Fatalf("Pull() = %+v, %v; accepted want %v", outcome, err, tc.accepted)
			}
		})
	}
}

func TestRunDuePullsClaimsAndReschedules(t *testing.T) {
	bucket := &fakeS3{objects: map[string]string{"a.json": `{"items":[{"id":"a","scan_id":"s","title":"A","finding_type":"code"}]}`}, order: []string{"a.json"}}
	service, store := newTestService(t, S3Puller{AllowAmbientCredentials: true, NewClient: func(context.Context, S3Settings) (S3API, error) { return bucket, nil }})
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
