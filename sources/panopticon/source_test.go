package panopticon

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
)

func TestSpecLoadsFromCatalog(t *testing.T) {
	src, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	spec := src.Spec()
	if spec == nil {
		t.Fatal("Spec() returned nil")
	}
	if spec.Id != sourceID {
		t.Fatalf("Spec().Id = %q, want %q", spec.Id, sourceID)
	}
	wantKinds := map[string]bool{kindAlert: false, kindCase: false, kindIOC: false}
	for _, kind := range spec.EmittedKinds {
		if _, ok := wantKinds[kind]; ok {
			wantKinds[kind] = true
		}
	}
	for kind, seen := range wantKinds {
		if !seen {
			t.Errorf("Spec().EmittedKinds missing %q", kind)
		}
	}
}

func TestParseSettings(t *testing.T) {
	tests := []struct {
		name      string
		values    map[string]string
		wantErrIs error
		want      settings
	}{
		{
			name:   "defaults",
			values: map[string]string{"bucket": "writer-panopticon-exports", "prefix": "alerts", "tenant_id": "writer"},
			want:   settings{family: familyAlert, bucket: "writer-panopticon-exports", prefix: "alerts/", region: defaultRegion, tenantID: "writer", perPage: defaultPageSize},
		},
		{
			name:   "case-family-runtime-and-page",
			values: map[string]string{"family": familyCase, "bucket": "writer-panopticon-exports", "prefix": "cases/", "region": "us-west-2", "per_page": "25", "tenant_id": "writer", "runtime_id": "writer-panopticon-cases"},
			want:   settings{family: familyCase, bucket: "writer-panopticon-exports", prefix: "cases/", region: "us-west-2", tenantID: "writer", runtimeID: "writer-panopticon-cases", perPage: 25},
		},
		{
			name:   "runtime-tenant",
			values: map[string]string{"bucket": "writer-panopticon-exports", "prefix": "alerts", sourceconfig.RuntimeTenantIDKey: "writer"},
			want:   settings{family: familyAlert, bucket: "writer-panopticon-exports", prefix: "alerts/", region: defaultRegion, tenantID: "writer", perPage: defaultPageSize},
		},
		{name: "missing-bucket", values: map[string]string{"prefix": "alerts/", "tenant_id": "writer"}, wantErrIs: ErrBucketRequired},
		{name: "missing-prefix", values: map[string]string{"bucket": "writer-panopticon-exports", "tenant_id": "writer"}, wantErrIs: ErrPrefixRequired},
		{name: "missing-tenant", values: map[string]string{"bucket": "writer-panopticon-exports", "prefix": "alerts/"}, wantErrIs: ErrTenantIDRequired},
		{name: "unknown-family", values: map[string]string{"family": "garbage", "bucket": "writer-panopticon-exports", "prefix": "x/", "tenant_id": "writer"}, wantErrIs: ErrUnsupportedFamily},
		{name: "invalid-page-size", values: map[string]string{"bucket": "writer-panopticon-exports", "prefix": "x/", "page_size": "0", "tenant_id": "writer"}, wantErrIs: ErrInvalidPageSize},
		{name: "bucket-with-slash-rejected", values: map[string]string{"bucket": "writer/panopticon", "prefix": "x/", "tenant_id": "writer"}, wantErrIs: ErrInvalidBucket},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSettings(sourcecdk.NewConfig(tc.values))
			if tc.wantErrIs != nil {
				if !errors.Is(err, tc.wantErrIs) {
					t.Fatalf("parseSettings() error = %v, want errors.Is %v", err, tc.wantErrIs)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSettings() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("parseSettings() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestParseSettingsAPIMode(t *testing.T) {
	_, err := parseSettings(sourcecdk.NewConfig(map[string]string{
		"mode":      modeAPI,
		"tenant_id": "writer",
		"base_url":  "http://169.254.169.254",
		"token":     "token",
	}))
	if err == nil {
		t.Fatal("parseSettings() unsafe api base_url error = nil, want non-nil")
	}

	got, err := parseSettingsWithLoopback(sourcecdk.NewConfig(map[string]string{
		"mode":      modeAPI,
		"family":    familyCase,
		"tenant_id": "writer",
		"base_url":  "http://127.0.0.1",
		"token":     "token",
	}), true)
	if err != nil {
		t.Fatalf("parseSettingsWithLoopback() error = %v", err)
	}
	if got.mode != modeAPI || got.apiPath != "/api/cerebro/cases" || got.baseURL != "http://127.0.0.1" {
		t.Fatalf("api settings = %+v, want api mode with default cases path", got)
	}
}

func TestReadAPIModePaginatesAndValidatesEvents(t *testing.T) {
	fixed := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cerebro/alerts" {
			http.NotFound(w, r)
			return
		}
		requests++
		if got := r.Header.Get("Authorization"); got != "Bearer api-token" {
			t.Fatalf("Authorization = %q, want bearer token", got)
		}
		if got := r.URL.Query().Get("tenant_id"); got != "writer" {
			t.Fatalf("tenant_id = %q, want writer", got)
		}
		if got := r.URL.Query().Get("family"); got != familyAlert {
			t.Fatalf("family = %q, want %q", got, familyAlert)
		}
		if got := r.URL.Query().Get("limit"); got != "1" {
			t.Fatalf("limit = %q, want 1", got)
		}
		switch r.URL.Query().Get("cursor") {
		case "":
			_ = json.NewEncoder(w).Encode(panopticonAPIResponse{
				Records:    []panopticonRecord{validAlert("alert-1", fixed)},
				NextCursor: "page-2",
				Watermark:  fixed.Format(time.RFC3339Nano),
			})
		case "page-2":
			_ = json.NewEncoder(w).Encode(panopticonAPIResponse{
				Records:   []panopticonRecord{validAlert("alert-2", fixed.Add(time.Minute))},
				Watermark: fixed.Add(time.Minute).Format(time.RFC3339Nano),
			})
		default:
			t.Fatalf("unexpected cursor %q", r.URL.Query().Get("cursor"))
		}
	}))
	defer server.Close()

	src := newTestSource(t, nil)
	src.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"mode":      modeAPI,
		"family":    familyAlert,
		"tenant_id": "writer",
		"base_url":  server.URL,
		"token":     "api-token",
		"per_page":  "1",
	})

	first, err := src.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if got := eventIDs(first.Events); len(got) != 1 || got[0] != "alert-1" || first.NextCursor == nil {
		t.Fatalf("first events/cursor = %v/%v, want alert-1 and cursor", got, first.NextCursor)
	}
	firstCursor := decodeAPICursor(first.NextCursor)
	if firstCursor.Source != cursorSourceAPI || firstCursor.Cursor != "page-2" {
		t.Fatalf("first cursor = %+v, want api cursor page-2", firstCursor)
	}

	second, err := src.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if got := eventIDs(second.Events); len(got) != 1 || got[0] != "alert-2" || second.NextCursor != nil {
		t.Fatalf("second events/cursor = %v/%v, want alert-2 without cursor", got, second.NextCursor)
	}
	if second.Checkpoint == nil || second.Checkpoint.GetWatermark().AsTime() != fixed.Add(time.Minute) {
		t.Fatalf("second checkpoint = %+v, want watermark", second.Checkpoint)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
}

func TestReadAPIModeRejectsCrossTenantEvents(t *testing.T) {
	fixed := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(panopticonAPIResponse{
			Records: []panopticonRecord{withTenant(validAlert("alert-1", fixed), "other")},
		})
	}))
	defer server.Close()

	src := newTestSource(t, nil)
	src.allowLoopbackBaseURL = true
	_, err := src.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"mode":      modeAPI,
		"tenant_id": "writer",
		"base_url":  server.URL,
		"token":     "api-token",
	}), nil)
	if err == nil || !errorContains(err, "does not match runtime tenant") {
		t.Fatalf("Read() error = %v, want cross-tenant rejection", err)
	}
}

func TestReadPlainAndGzipArchivesForAllFamilies(t *testing.T) {
	src := newTestSource(t, nil)
	fixed := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	client := newFakeS3([]fakeObject{
		{key: "alerts/2026/06/08/plain.ndjson", records: []panopticonRecord{validAlert("alert-1", fixed)}},
		{key: "alerts/2026/06/08/compressed.ndjson.gz", records: []panopticonRecord{validAlert("alert-2", fixed.Add(time.Minute))}, gzip: true},
		{key: "cases/2026/06/08/plain.ndjson", records: []panopticonRecord{validCase("case-1", fixed)}},
		{key: "cases/2026/06/08/compressed.ndjson.gz", records: []panopticonRecord{validCase("case-2", fixed.Add(time.Minute))}, gzip: true},
		{key: "iocs/2026/06/08/plain.ndjson", records: []panopticonRecord{validIOC("ioc-1", fixed)}},
		{key: "iocs/2026/06/08/compressed.ndjson.gz", records: []panopticonRecord{validIOC("ioc-2", fixed.Add(time.Minute))}, gzip: true},
	})
	src.newClient = func(context.Context, settings) (s3API, error) { return client, nil }

	for _, tc := range []struct {
		family string
		prefix string
		kind   string
		ids    []string
	}{
		{familyAlert, "alerts/", kindAlert, []string{"alert-2", "alert-1"}},
		{familyCase, "cases/", kindCase, []string{"case-2", "case-1"}},
		{familyIOC, "iocs/", kindIOC, []string{"ioc-2", "ioc-1"}},
	} {
		t.Run(tc.family, func(t *testing.T) {
			pull, err := src.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"family": tc.family, "bucket": "writer-panopticon-exports", "prefix": tc.prefix, "tenant_id": "writer"}), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if got := eventIDs(pull.Events); strings.Join(got, ",") != strings.Join(tc.ids, ",") {
				t.Fatalf("event ids = %v, want %v", got, tc.ids)
			}
			for _, ev := range pull.Events {
				if ev.GetSourceId() != sourceID || ev.GetKind() != tc.kind || ev.GetTenantId() != "writer" {
					t.Fatalf("event scope = source %q kind %q tenant %q", ev.GetSourceId(), ev.GetKind(), ev.GetTenantId())
				}
				if err := sourcecdk.ValidateEventEnvelopeWithContracts(ev, sourcecdkEventContracts()); err != nil {
					t.Fatalf("ValidateEventEnvelopeWithContracts() error = %v", err)
				}
			}
		})
	}
}

func TestReadPanopticonGeneratedArchivesForAllFamilies(t *testing.T) {
	manifest := generateCrossRepoPanopticonArchives(t)
	objects := make([]fakeObject, 0, len(manifest.Archives))
	for _, archive := range manifest.Archives {
		raw, err := os.ReadFile(archive.Path)
		if err != nil {
			t.Fatalf("read generated archive %s: %v", archive.Path, err)
		}
		objects = append(objects, fakeObject{key: archive.Key, rawBody: raw})
	}
	src := newTestSource(t, newFakeS3(objects))

	for _, tc := range []struct {
		family string
		prefix string
		kind   string
	}{
		{familyAlert, "exports/alerts/", kindAlert},
		{familyCase, "exports/cases/", kindCase},
		{familyIOC, "exports/iocs/", kindIOC},
	} {
		t.Run(tc.family, func(t *testing.T) {
			pull, err := src.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"family": tc.family, "bucket": "panopticon-cross-repo-contract", "prefix": tc.prefix, "tenant_id": "writer"}), nil)
			if err != nil {
				t.Fatalf("Read(generated Panopticon %s archives) error = %v", tc.family, err)
			}
			if len(pull.Events) != 2 {
				t.Fatalf("generated Panopticon %s events = %d, want 2 (.ndjson and .ndjson.gz)", tc.family, len(pull.Events))
			}
			for _, ev := range pull.Events {
				if ev.GetTenantId() != "writer" || ev.GetSourceId() != sourceID || ev.GetKind() != tc.kind {
					t.Fatalf("generated event scope = tenant %q source %q kind %q", ev.GetTenantId(), ev.GetSourceId(), ev.GetKind())
				}
				if err := sourcecdk.ValidateEventEnvelopeWithContracts(ev, sourcecdkEventContracts()); err != nil {
					t.Fatalf("generated event failed source contract validation: %v", err)
				}
				payloadText := string(ev.GetPayload())
				for _, forbidden := range []string{"DO-NOT-EXPORT-CONTENTS", "DO-NOT-EXPORT-BYTES", "DO-NOT-EXPORT-INLINE", "DO-NOT-EXPORT-RAW"} {
					if strings.Contains(payloadText, forbidden) {
						t.Fatalf("generated event payload included inline evidence marker %q", forbidden)
					}
				}
				if tc.family == familyCase && !strings.Contains(payloadText, "evidencecas://cases/42/evidence/triage.tar") {
					t.Fatalf("generated case payload did not preserve EvidenceCAS pointer: %s", payloadText)
				}
			}
		})
	}
}

func TestReadScopesObjectsAndRecords(t *testing.T) {
	fixed := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	client := newFakeS3([]fakeObject{
		{key: "alerts/", rawBody: []byte{}},
		{key: "alerts/ignored.txt", rawBody: []byte(`ignored`)},
		{key: "alerts/tmp/upload.tmp", rawBody: []byte(`ignored`)},
		{key: "alerts/batch.ndjson", records: []panopticonRecord{
			withTenant(validAlert("other-tenant", fixed), "other"),
			withRuntime(validAlert("other-runtime", fixed), "writer-panopticon-cases"),
			withRuntime(validAlert("accepted", fixed), "writer-panopticon-alerts"),
		}},
		{key: "cases/not-listed.ndjson", records: []panopticonRecord{validCase("case-should-not-read", fixed)}},
	})
	src := newTestSource(t, client)
	pull, err := src.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"family": familyAlert, "bucket": "writer-panopticon-exports", "prefix": "alerts/", "tenant_id": "writer", "runtime_id": "writer-panopticon-alerts"}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if got := eventIDs(pull.Events); len(got) != 1 || got[0] != "accepted" {
		t.Fatalf("events = %v, want [accepted]", got)
	}
	if client.getCalls["alerts/ignored.txt"] != 0 || client.getCalls["alerts/tmp/upload.tmp"] != 0 || client.getCalls["cases/not-listed.ndjson"] != 0 {
		t.Fatalf("unsupported or out-of-prefix objects were read: %#v", client.getCalls)
	}
}

func TestReadRejectsInvalidEnvelopesAndFamilyContracts(t *testing.T) {
	fixed := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		record panopticonRecord
		want   string
	}{
		{"wrong-source", withSource(validAlert("alert-1", fixed), "other"), "source_id"},
		{"unsupported-kind", withKind(validAlert("alert-1", fixed), kindCase, schemaRefCase), "kind"},
		{"schema-mismatch", withKind(validAlert("alert-1", fixed), kindAlert, "panopticon/alert/v2"), "schema_ref"},
		{"missing-tenant", withTenant(validAlert("alert-1", fixed), ""), "tenant_id"},
		{"blank-tenant", withTenant(validAlert("alert-1", fixed), "  "), "tenant_id"},
		{"missing-title", withoutPayloadField(validAlert("alert-1", fixed), "title"), "title"},
		{"empty-required-attribute", withAttribute(validAlert("alert-1", fixed), "severity", ""), "severity"},
		{"mismatched-attribute-payload", withAttribute(validAlert("alert-1", fixed), "status", "closed"), "does not match"},
		{"missing-payload", panopticonRecord{ID: "alert-1", TenantID: "writer", SourceID: sourceID, Kind: kindAlert, OccurredAt: fixed, SchemaRef: schemaRefAlert, Attributes: map[string]string{"alert_id": "a-1", "severity": "high", "status": "open"}}, "payload"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := newTestSource(t, newFakeS3([]fakeObject{{key: "alerts/bad.ndjson", records: []panopticonRecord{tc.record}}}))
			_, err := src.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"family": familyAlert, "bucket": "writer-panopticon-exports", "prefix": "alerts/", "tenant_id": "writer"}), nil)
			if err == nil || !errorContains(err, tc.want) {
				t.Fatalf("Read() error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestReadRejectsPayloadSynthesizedRequiredAttributesForAllFamilies(t *testing.T) {
	fixed := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		family    string
		prefix    string
		record    panopticonRecord
		missing   string
		wantError string
	}{
		{name: "alert", family: familyAlert, prefix: "alerts/", record: validAlert("alert-1", fixed), missing: "severity", wantError: "severity"},
		{name: "case", family: familyCase, prefix: "cases/", record: validCase("case-1", fixed), missing: "status", wantError: "status"},
		{name: "ioc", family: familyIOC, prefix: "iocs/", record: validIOC("ioc-1", fixed), missing: "value", wantError: "value"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			record := withoutAttribute(tc.record, tc.missing)
			src := newTestSource(t, newFakeS3([]fakeObject{{key: tc.prefix + "bad.ndjson", records: []panopticonRecord{record}}}))
			_, err := src.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"family": tc.family, "bucket": "writer-panopticon-exports", "prefix": tc.prefix, "tenant_id": "writer"}), nil)
			if err == nil || !errorContains(err, tc.wantError) {
				t.Fatalf("Read() error = %v, want containing %q", err, tc.wantError)
			}
		})
	}
}

func TestFamilyValidationFailureDoesNotAdvanceCheckpoint(t *testing.T) {
	fixed := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	client := newFakeS3([]fakeObject{
		{key: "alerts/001-good.ndjson", records: []panopticonRecord{validAlert("good", fixed)}},
		{key: "alerts/002-bad.ndjson", records: []panopticonRecord{withoutAttribute(validAlert("bad", fixed.Add(time.Minute)), "status")}},
	})
	src := newTestSource(t, client)
	cfg := sourcecdk.NewConfig(map[string]string{"family": familyAlert, "bucket": "writer-panopticon-exports", "prefix": "alerts/", "tenant_id": "writer"})

	pull, err := src.Read(context.Background(), cfg, nil)
	if err == nil || !errorContains(err, "status") {
		t.Fatalf("Read() error = %v, want required status failure", err)
	}
	if len(pull.Events) != 0 || pull.Checkpoint != nil || pull.NextCursor != nil {
		t.Fatalf("failed pull advanced state: events=%d checkpoint=%v next=%v", len(pull.Events), pull.Checkpoint, pull.NextCursor)
	}

	retry, err := src.Read(context.Background(), cfg, nil)
	if err == nil || !errorContains(err, "status") {
		t.Fatalf("Read(retry) error = %v, want same required status failure", err)
	}
	if len(retry.Events) != 0 || retry.Checkpoint != nil || retry.NextCursor != nil {
		t.Fatalf("failed retry advanced state: events=%d checkpoint=%v next=%v", len(retry.Events), retry.Checkpoint, retry.NextCursor)
	}
}

func TestReadRejectsMalformedArchivesDeterministically(t *testing.T) {
	badJSON := newFakeS3([]fakeObject{{key: "alerts/bad-json.ndjson", rawBody: []byte("{not json}\n")}})
	src := newTestSource(t, badJSON)
	cfg := sourcecdk.NewConfig(map[string]string{"family": familyAlert, "bucket": "writer-panopticon-exports", "prefix": "alerts/", "tenant_id": "writer"})
	for i := 0; i < 2; i++ {
		_, err := src.Read(context.Background(), cfg, nil)
		if err == nil || !errorContains(err, "decode line 1") {
			t.Fatalf("Read() retry %d error = %v, want decode line 1", i, err)
		}
	}
	if badJSON.getCalls["alerts/bad-json.ndjson"] != 2 {
		t.Fatalf("retry get calls = %d, want 2", badJSON.getCalls["alerts/bad-json.ndjson"])
	}

	badGzip := newFakeS3([]fakeObject{{key: "alerts/bad-gzip.ndjson.gz", rawBody: []byte("not gzip")}})
	src = newTestSource(t, badGzip)
	_, err := src.Read(context.Background(), cfg, nil)
	if err == nil || !errorContains(err, "gunzip") {
		t.Fatalf("Read() invalid gzip error = %v, want gunzip", err)
	}
}

func TestReadEnforcesRawAndGzipDecompressedObjectSizeLimits(t *testing.T) {
	rawTooLarge := newFakeS3([]fakeObject{{key: "alerts/too-large.ndjson", rawBody: bytes.Repeat([]byte{'x'}, maxObjectBytes+1)}})
	src := newTestSource(t, rawTooLarge)
	cfg := sourcecdk.NewConfig(map[string]string{"family": familyAlert, "bucket": "writer-panopticon-exports", "prefix": "alerts/", "tenant_id": "writer"})
	_, err := src.Read(context.Background(), cfg, nil)
	if err == nil || !errorContains(err, "object exceeds") {
		t.Fatalf("Read() oversized raw object error = %v, want object exceeds", err)
	}

	compressed := &bytes.Buffer{}
	gz := gzip.NewWriter(compressed)
	if _, err := gz.Write(bytes.Repeat([]byte{'a'}, 128)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	_, err = readArchiveRecords(bytes.NewReader(compressed.Bytes()), "oversized.ndjson.gz", 64)
	if !errors.Is(err, ErrDecompressedObjectTooLarge) {
		t.Fatalf("readArchiveRecords() decompressed size error = %v, want ErrDecompressedObjectTooLarge", err)
	}
}

func TestReadRejectsNonStringAttributesAndOversizedLines(t *testing.T) {
	nonString := newFakeS3([]fakeObject{{key: "alerts/non-string.ndjson", rawBody: []byte(`{"id":"alert-1","tenant_id":"writer","source_id":"panopticon","kind":"panopticon.alert","occurred_at":"2026-06-08T12:00:00Z","schema_ref":"panopticon/alert/v1","payload":{"alert_id":"a-1","severity":"high","status":"open","title":"Alert"},"attributes":{"alert_id":"a-1","severity":"high","status":42}}` + "\n")}})
	src := newTestSource(t, nonString)
	cfg := sourcecdk.NewConfig(map[string]string{"family": familyAlert, "bucket": "writer-panopticon-exports", "prefix": "alerts/", "tenant_id": "writer"})
	_, err := src.Read(context.Background(), cfg, nil)
	if err == nil || !errorContains(err, "cannot unmarshal") {
		t.Fatalf("Read() non-string attributes error = %v, want cannot unmarshal", err)
	}

	_, err = readArchiveRecords(bytes.NewReader(append(bytes.Repeat([]byte{'a'}, maxLineBytes+1), '\n')), "oversized.ndjson", int64(maxLineBytes+2))
	if err == nil || !errorContains(err, "token too long") {
		t.Fatalf("readArchiveRecords() oversized line error = %v, want token too long", err)
	}
}

func TestReadCursorSafetyAcrossPaginationAndPartialArchive(t *testing.T) {
	fixed := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	records := make([]panopticonRecord, 0, maxEventsPerPull+1)
	for i := 0; i < maxEventsPerPull+1; i++ {
		records = append(records, validAlert(fmt.Sprintf("alert-%04d", i), fixed.Add(time.Duration(i)*time.Second)))
	}
	client := newFakeS3([]fakeObject{
		{key: "alerts/001.ndjson", records: []panopticonRecord{validAlert("first-page", fixed)}},
		{key: "alerts/002.ndjson", records: records},
		{key: "alerts/003.ndjson", records: []panopticonRecord{validAlert("final-page", fixed)}},
	})
	src := newTestSource(t, client)
	cfg := sourcecdk.NewConfig(map[string]string{"family": familyAlert, "bucket": "writer-panopticon-exports", "prefix": "alerts/", "tenant_id": "writer", "page_size": "1"})

	first, err := src.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if got := eventIDs(first.Events); len(got) != 1 || got[0] != "first-page" || first.NextCursor == nil {
		t.Fatalf("first events/cursor = %v/%v, want first-page with cursor", got, first.NextCursor)
	}

	second, err := src.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != maxEventsPerPull || second.NextCursor == nil {
		t.Fatalf("second events/cursor = %d/%v, want max events with partial cursor", len(second.Events), second.NextCursor)
	}
	secondCursor := mustDecodePanopticonCursor(t, second.NextCursor.GetOpaque())
	if secondCursor.LastKey == "alerts/002.ndjson" || secondCursor.PartialKey != "alerts/002.ndjson" || secondCursor.RecordOffset != maxEventsPerPull {
		t.Fatalf("second cursor = %+v, want partial archive at offset %d", secondCursor, maxEventsPerPull)
	}

	third, err := src.Read(context.Background(), cfg, second.NextCursor)
	if err != nil {
		t.Fatalf("Read(third) error = %v", err)
	}
	if got := eventIDs(third.Events); len(got) != 1 || got[0] != "alert-1000" {
		t.Fatalf("third events = %v, want remaining partial record only", got)
	}
	if third.NextCursor == nil {
		t.Fatal("third NextCursor = nil, want cursor for remaining S3 page")
	}

	fourth, err := src.Read(context.Background(), cfg, third.NextCursor)
	if err != nil {
		t.Fatalf("Read(fourth) error = %v", err)
	}
	if got := eventIDs(fourth.Events); len(got) != 1 || got[0] != "final-page" || fourth.NextCursor != nil {
		t.Fatalf("fourth events/cursor = %v/%v, want final-page without cursor", got, fourth.NextCursor)
	}
}

func TestMalformedArchiveDoesNotAdvanceCheckpointPastPriorCursor(t *testing.T) {
	fixed := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	client := newFakeS3([]fakeObject{
		{key: "alerts/001-good.ndjson", records: []panopticonRecord{validAlert("good", fixed)}},
		{key: "alerts/002-bad.ndjson", rawBody: []byte("{bad json}\n")},
	})
	src := newTestSource(t, client)
	cfg := sourcecdk.NewConfig(map[string]string{"family": familyAlert, "bucket": "writer-panopticon-exports", "prefix": "alerts/", "tenant_id": "writer"})

	first, err := src.Read(context.Background(), cfg, nil)
	if err == nil || !errorContains(err, "decode line 1") {
		t.Fatalf("Read(first) error = %v, want deterministic malformed JSON failure", err)
	}
	if first.Checkpoint != nil || first.NextCursor != nil || len(first.Events) != 0 {
		t.Fatalf("failed pull advanced state: events=%d checkpoint=%v next=%v", len(first.Events), first.Checkpoint, first.NextCursor)
	}

	cursor := &cerebrov1.SourceCursor{Opaque: encodeCursor(panopticonCursor{LastKey: "alerts/001-good.ndjson"})}
	retry, err := src.Read(context.Background(), cfg, cursor)
	if err == nil || !errorContains(err, "decode line 1") {
		t.Fatalf("Read(retry) error = %v, want same malformed JSON failure", err)
	}
	if retry.Checkpoint != nil || retry.NextCursor != nil || len(retry.Events) != 0 {
		t.Fatalf("failed retry advanced state: events=%d checkpoint=%v next=%v", len(retry.Events), retry.Checkpoint, retry.NextCursor)
	}
}

func newTestSource(t *testing.T, client *fakeS3) *Source {
	t.Helper()
	src, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if client != nil {
		src.newClient = func(context.Context, settings) (s3API, error) { return client, nil }
	}
	return src
}

func errorContains(err error, want string) bool {
	return strings.Contains(fmt.Sprint(err), want)
}

type crossRepoPanopticonArchiveManifest struct {
	Archives []struct {
		Family string `json:"family"`
		Gzip   bool   `json:"gzip"`
		Key    string `json:"key"`
		Path   string `json:"path"`
	} `json:"archives"`
}

func generateCrossRepoPanopticonArchives(t *testing.T) crossRepoPanopticonArchiveManifest {
	t.Helper()
	panopticonRepo := os.Getenv("PANOPTICON_REPO")
	if panopticonRepo == "" {
		panopticonRepo = filepath.Clean("../../../panopticon")
	}
	script := filepath.Join(panopticonRepo, "scripts", "generate_cerebro_contract_archives.py")
	// #nosec G703 -- test-only optional local cross-repo fixture path.
	if _, err := os.Stat(script); err != nil {
		t.Skipf("Panopticon cross-repo archive generator not available at %s: %v", script, err)
	}
	outputDir := t.TempDir()
	// #nosec G204 G702 -- test-only optional local cross-repo fixture generator.
	cmd := exec.Command("python3", script, "--output-dir", outputDir)
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generate Panopticon cross-repo archives: %v\n%s", err, out)
	}
	manifestPath := filepath.Join(outputDir, "manifest.json")
	// #nosec G304 -- manifest is read from this test's temporary output directory.
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read generated Panopticon manifest: %v", err)
	}
	var manifest crossRepoPanopticonArchiveManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("decode generated Panopticon manifest: %v", err)
	}
	return manifest
}

func validAlert(id string, occurredAt time.Time) panopticonRecord {
	alertID := strings.TrimPrefix(id, "alert-")
	return panopticonRecord{ID: id, TenantID: "writer", SourceID: sourceID, Kind: kindAlert, OccurredAt: occurredAt, SchemaRef: schemaRefAlert, Attributes: map[string]string{"alert_id": alertID, "severity": "high", "status": "open"}, Payload: map[string]interface{}{"alert_id": alertID, "severity": "high", "status": "open", "title": "Suspicious activity"}}
}

func validCase(id string, occurredAt time.Time) panopticonRecord {
	caseID := strings.TrimPrefix(id, "case-")
	return panopticonRecord{ID: id, TenantID: "writer", SourceID: sourceID, Kind: kindCase, OccurredAt: occurredAt, SchemaRef: schemaRefCase, Attributes: map[string]string{"case_id": caseID, "status": "investigating"}, Payload: map[string]interface{}{"case_id": caseID, "status": "investigating", "title": "Incident case", "evidence": []interface{}{map[string]interface{}{"evidence_cas": "cas://object/abc", "sha256": "abc"}}}}
}

func validIOC(id string, occurredAt time.Time) panopticonRecord {
	iocID := strings.TrimPrefix(id, "ioc-")
	return panopticonRecord{ID: id, TenantID: "writer", SourceID: sourceID, Kind: kindIOC, OccurredAt: occurredAt, SchemaRef: schemaRefIOC, Attributes: map[string]string{"ioc_id": iocID, "ioc_type": "domain", "value": "evil.example"}, Payload: map[string]interface{}{"ioc_id": iocID, "ioc_type": "domain", "value": "evil.example"}}
}

func withTenant(rec panopticonRecord, tenant string) panopticonRecord {
	rec.TenantID = tenant
	return rec
}
func withSource(rec panopticonRecord, source string) panopticonRecord {
	rec.SourceID = source
	return rec
}
func withKind(rec panopticonRecord, kind, schemaRef string) panopticonRecord {
	rec.Kind = kind
	rec.SchemaRef = schemaRef
	return rec
}
func withRuntime(rec panopticonRecord, runtimeID string) panopticonRecord {
	rec.Attributes["runtime_id"] = runtimeID
	return rec
}
func withAttribute(rec panopticonRecord, key, value string) panopticonRecord {
	rec.Attributes[key] = value
	return rec
}
func withoutPayloadField(rec panopticonRecord, key string) panopticonRecord {
	delete(rec.Payload, key)
	return rec
}
func withoutAttribute(rec panopticonRecord, key string) panopticonRecord {
	delete(rec.Attributes, key)
	return rec
}

func eventIDs(events []*cerebrov1.EventEnvelope) []string {
	ids := make([]string, 0, len(events))
	for _, ev := range events {
		ids = append(ids, ev.GetId())
	}
	return ids
}

type fakeObject struct {
	key     string
	records []panopticonRecord
	gzip    bool
	rawBody []byte
}

func (o fakeObject) body() (io.ReadCloser, error) {
	if o.rawBody != nil {
		return io.NopCloser(bytes.NewReader(o.rawBody)), nil
	}
	buf := &bytes.Buffer{}
	for _, rec := range o.records {
		raw, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		buf.Write(raw)
		buf.WriteByte('\n')
	}
	if o.gzip {
		compressed := &bytes.Buffer{}
		gz := gzip.NewWriter(compressed)
		if _, err := gz.Write(buf.Bytes()); err != nil {
			return nil, err
		}
		if err := gz.Close(); err != nil {
			return nil, err
		}
		return io.NopCloser(compressed), nil
	}
	return io.NopCloser(buf), nil
}

type fakeS3 struct {
	objects  map[string]fakeObject
	keys     []string
	getCalls map[string]int
}

func newFakeS3(objects []fakeObject) *fakeS3 {
	m := make(map[string]fakeObject, len(objects))
	keys := make([]string, 0, len(objects))
	for _, obj := range objects {
		m[obj.key] = obj
		keys = append(keys, obj.key)
	}
	sort.Strings(keys)
	return &fakeS3{objects: m, keys: keys, getCalls: map[string]int{}}
}

func (f *fakeS3) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	prefix := awssdk.ToString(in.Prefix)
	startAfter := awssdk.ToString(in.StartAfter)
	maxKeys := int32(1000)
	if in.MaxKeys != nil {
		maxKeys = *in.MaxKeys
	}
	out := &s3.ListObjectsV2Output{}
	matched := int32(0)
	for _, key := range f.keys {
		if !strings.HasPrefix(key, prefix) || (startAfter != "" && key <= startAfter) {
			continue
		}
		matched++
		if matched > maxKeys {
			out.IsTruncated = awssdk.Bool(true)
			break
		}
		out.Contents = append(out.Contents, s3types.Object{Key: awssdk.String(key)})
	}
	return out, nil
}

func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	key := awssdk.ToString(in.Key)
	f.getCalls[key]++
	obj, ok := f.objects[key]
	if !ok {
		return nil, errors.New("not found: " + key)
	}
	body, err := obj.body()
	if err != nil {
		return nil, err
	}
	return &s3.GetObjectOutput{Body: body}, nil
}

func mustDecodePanopticonCursor(t *testing.T, opaque string) panopticonCursor {
	t.Helper()
	cursor := decodeCursor(&cerebrov1.SourceCursor{Opaque: opaque})
	if cursor.Source != cursorSource {
		t.Fatalf("cursor source = %q, want %q (opaque %q)", cursor.Source, cursorSource, opaque)
	}
	return cursor
}
