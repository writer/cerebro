package aurelius

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	if spec.Id != "aurelius" {
		t.Fatalf("Spec().Id = %q, want %q", spec.Id, "aurelius")
	}
	wantKinds := map[string]bool{
		kindVerdict: false, kindFinding: false, kindImageScan: false,
		kindCatalogPromotion: false, kindPolicyException: false,
	}
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
			name: "defaults",
			values: map[string]string{
				"bucket":    "writer-aurelius-telemetry",
				"prefix":    "verdicts",
				"tenant_id": "writer",
			},
			want: settings{
				family: familyVerdict, bucket: "writer-aurelius-telemetry",
				prefix: "verdicts/", region: defaultRegion, tenantID: "writer",
				perPage: defaultPageSize,
			},
		},
		{
			name: "explicit-family-and-page",
			values: map[string]string{
				"family":    familyFinding,
				"bucket":    "writer-aurelius-telemetry",
				"prefix":    "findings/",
				"region":    "us-west-2",
				"per_page":  "250",
				"tenant_id": "writer",
			},
			want: settings{
				family: familyFinding, bucket: "writer-aurelius-telemetry",
				prefix: "findings/", region: "us-west-2", tenantID: "writer",
				perPage: 250,
			},
		},
		{
			name: "per-page",
			values: map[string]string{
				"bucket":    "writer-aurelius-telemetry",
				"prefix":    "verdicts/",
				"per_page":  "25",
				"tenant_id": "writer",
			},
			want: settings{
				family: familyVerdict, bucket: "writer-aurelius-telemetry",
				prefix: "verdicts/", region: defaultRegion, tenantID: "writer",
				perPage: 25,
			},
		},
		{
			name: "runtime-tenant",
			values: map[string]string{
				"bucket":                        "writer-aurelius-telemetry",
				"prefix":                        "verdicts",
				sourceconfig.RuntimeTenantIDKey: "writer",
			},
			want: settings{
				family: familyVerdict, bucket: "writer-aurelius-telemetry",
				prefix: "verdicts/", region: defaultRegion, tenantID: "writer",
				perPage: defaultPageSize,
			},
		},
		{
			name: "assume-role",
			values: map[string]string{
				"bucket":                               "writer-aurelius-telemetry",
				"prefix":                               "verdicts/",
				"tenant_id":                            "writer",
				"role_arn":                             "arn:aws:iam::502497380968:role/cerebro-aurelius-source-dev",
				"external_id":                          "external-1",
				sourceconfig.AWSAssumeRoleAllowlistKey: "writer=arn:aws:iam::502497380968:role/cerebro-aurelius-source-dev",
			},
			want: settings{
				family: familyVerdict, bucket: "writer-aurelius-telemetry",
				prefix: "verdicts/", region: defaultRegion, tenantID: "writer",
				roleARN:        "arn:aws:iam::502497380968:role/cerebro-aurelius-source-dev",
				externalID:     "external-1",
				assumeRoleARNs: "writer=arn:aws:iam::502497380968:role/cerebro-aurelius-source-dev",
				perPage:        defaultPageSize,
			},
		},
		{
			name:      "missing-bucket",
			values:    map[string]string{"prefix": "verdicts/", "tenant_id": "writer"},
			wantErrIs: ErrBucketRequired,
		},
		{
			name:      "missing-prefix",
			values:    map[string]string{"bucket": "writer-aurelius-telemetry", "tenant_id": "writer"},
			wantErrIs: ErrPrefixRequired,
		},
		{
			name: "missing-tenant",
			values: map[string]string{
				"bucket": "writer-aurelius-telemetry",
				"prefix": "x/",
			},
			wantErrIs: ErrTenantIDRequired,
		},
		{
			name: "unknown-family",
			values: map[string]string{
				"family":    "garbage",
				"bucket":    "writer-aurelius-telemetry",
				"prefix":    "x/",
				"tenant_id": "writer",
			},
			wantErrIs: ErrUnsupportedFamily,
		},
		{
			name: "invalid-page-size",
			values: map[string]string{
				"bucket":    "writer-aurelius-telemetry",
				"prefix":    "x/",
				"per_page":  "0",
				"tenant_id": "writer",
			},
			wantErrIs: ErrInvalidPageSize,
		},
		{
			name: "page-size-clamped",
			values: map[string]string{
				"bucket":    "writer-aurelius-telemetry",
				"prefix":    "x/",
				"per_page":  "999999",
				"tenant_id": "writer",
			},
			want: settings{
				family: familyVerdict, bucket: "writer-aurelius-telemetry",
				prefix: "x/", region: defaultRegion, tenantID: "writer",
				perPage: maxPageSize,
			},
		},
		{
			name: "bucket-with-slash-rejected",
			values: map[string]string{
				"bucket":    "writer/aurelius",
				"prefix":    "x/",
				"tenant_id": "writer",
			},
			wantErrIs: ErrInvalidBucket,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSettings(sourcecdk.NewConfig(tc.values))
			if tc.wantErrIs != nil {
				if err == nil {
					t.Fatalf("parseSettings() error = nil, want %v", tc.wantErrIs)
				}
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

func TestReadEmitsEventsAndCompletesFinalPage(t *testing.T) {
	src, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	fixed := time.Date(2026, 5, 22, 14, 30, 0, 0, time.UTC)
	objects := []fakeObject{
		{
			key: "verdicts/2026/05/22/13/batch-001.ndjson",
			records: []aureliusRecord{
				{
					EventID:    "01HX0001-verdict-a",
					OccurredAt: fixed,
					TenantID:   "writer",
					Attributes: map[string]string{
						"image_digest": "sha256:c6b86af5b3d4",
						"verdict":      "warn",
					},
					Payload: map[string]interface{}{
						"image_digest":      "sha256:c6b86af5b3d4",
						"verdict":           "warn",
						"blocking_findings": float64(0),
						"excepted_findings": float64(13),
					},
				},
			},
		},
		{
			key: "verdicts/2026/05/22/14/batch-002.ndjson.gz",
			records: []aureliusRecord{
				{
					EventID:    "01HX0002-verdict-b",
					OccurredAt: fixed.Add(time.Hour),
					Attributes: map[string]string{
						"image_digest": "sha256:abcdef",
						"verdict":      "pass",
					},
					Payload: map[string]interface{}{
						"image_digest":      "sha256:abcdef",
						"verdict":           "pass",
						"blocking_findings": float64(0),
						"excepted_findings": float64(0),
					},
				},
			},
			gzip: true,
		},
	}
	client := newFakeS3(objects)
	src.newClient = func(context.Context, settings) (s3API, error) { return client, nil }

	cfg := sourcecdk.NewConfig(map[string]string{
		"family":    familyVerdict,
		"bucket":    "writer-aurelius-telemetry",
		"prefix":    "verdicts/",
		"tenant_id": "writer",
	})

	pull, err := src.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("Read() events = %d, want 2", len(pull.Events))
	}
	for _, ev := range pull.Events {
		if ev.GetKind() != kindVerdict {
			t.Errorf("event kind = %q, want %q", ev.GetKind(), kindVerdict)
		}
		if ev.GetSchemaRef() != schemaRefVerdict {
			t.Errorf("event schema_ref = %q, want %q", ev.GetSchemaRef(), schemaRefVerdict)
		}
		if ev.GetSourceId() != "aurelius" {
			t.Errorf("event source_id = %q, want aurelius", ev.GetSourceId())
		}
		if ev.GetTenantId() == "" {
			t.Errorf("event tenant_id empty")
		}
		if err := sourcecdk.ValidateEventEnvelope(ev); err != nil {
			t.Errorf("ValidateEventEnvelope = %v", err)
		}
	}
	if pull.NextCursor != nil {
		t.Fatalf("NextCursor = %#v, want nil on final page", pull.NextCursor)
	}
	if pull.Checkpoint == nil {
		t.Fatal("Checkpoint = nil, want non-nil")
	}
	checkpoint := mustDecodeAureliusCursor(t, pull.Checkpoint.GetCursorOpaque())
	if checkpoint.LastKey != "verdicts/2026/05/22/14/batch-002.ndjson.gz" {
		t.Fatalf("Checkpoint cursor last_key = %q, want %q",
			checkpoint.LastKey, "verdicts/2026/05/22/14/batch-002.ndjson.gz")
	}
	if !checkpoint.ResumableCheckpoint {
		t.Fatal("Checkpoint cursor is not resumable")
	}
	wantWatermark := fixed.Add(time.Hour)
	if !pull.Checkpoint.Watermark.AsTime().Equal(wantWatermark) {
		t.Fatalf("Checkpoint.Watermark = %v, want %v",
			pull.Checkpoint.Watermark.AsTime(), wantWatermark)
	}
}

func TestReadSkipsRecordsFromOtherTenants(t *testing.T) {
	src, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	fixed := time.Date(2026, 5, 22, 14, 30, 0, 0, time.UTC)
	client := newFakeS3([]fakeObject{{
		key: "verdicts/batch-001.ndjson",
		records: []aureliusRecord{
			{
				EventID:    "01HX-other-tenant",
				OccurredAt: fixed,
				TenantID:   "other",
				Attributes: map[string]string{"image_digest": "sha256:other", "verdict": "pass"},
				Payload:    map[string]interface{}{"image_digest": "sha256:other", "verdict": "pass"},
			},
			{
				EventID:    "01HX-writer-tenant",
				OccurredAt: fixed.Add(time.Minute),
				TenantID:   "writer",
				Attributes: map[string]string{"image_digest": "sha256:writer", "verdict": "warn"},
				Payload:    map[string]interface{}{"image_digest": "sha256:writer", "verdict": "warn"},
			},
		},
	}})
	src.newClient = func(context.Context, settings) (s3API, error) { return client, nil }

	pull, err := src.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"family":    familyVerdict,
		"bucket":    "writer-aurelius-telemetry",
		"prefix":    "verdicts/",
		"tenant_id": "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("Read() events = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].GetId(); got != "01HX-writer-tenant" {
		t.Fatalf("event id = %q, want writer tenant record", got)
	}
	if got := pull.Events[0].GetTenantId(); got != "writer" {
		t.Fatalf("event tenant_id = %q, want writer", got)
	}
}

func TestReadCheckpointsWhenOnlyOtherTenantRecordsAreSkipped(t *testing.T) {
	src, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	fixed := time.Date(2026, 5, 22, 14, 30, 0, 0, time.UTC)
	const key = "verdicts/batch-foreign.ndjson"
	client := newFakeS3([]fakeObject{{
		key: key,
		records: []aureliusRecord{{
			EventID:    "01HX-other-tenant",
			OccurredAt: fixed,
			TenantID:   "other",
			Attributes: map[string]string{"image_digest": "sha256:other", "verdict": "pass"},
			Payload:    map[string]interface{}{"image_digest": "sha256:other", "verdict": "pass"},
		}},
	}})
	src.newClient = func(context.Context, settings) (s3API, error) { return client, nil }

	pull, err := src.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"family":    familyVerdict,
		"bucket":    "writer-aurelius-telemetry",
		"prefix":    "verdicts/",
		"tenant_id": "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("Read() events = %d, want 0", len(pull.Events))
	}
	if pull.Checkpoint == nil {
		t.Fatal("Checkpoint = nil, want progress checkpoint after skipped object")
	}
	checkpoint := mustDecodeAureliusCursor(t, pull.Checkpoint.GetCursorOpaque())
	if checkpoint.LastKey != key {
		t.Fatalf("checkpoint last_key = %q, want %q", checkpoint.LastKey, key)
	}
}

func TestReadReturnsCursorWhenS3PageIsTruncated(t *testing.T) {
	src, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	fixed := time.Date(2026, 5, 22, 14, 30, 0, 0, time.UTC)
	objects := []fakeObject{
		{
			key: "verdicts/2026/05/22/14/batch-001.ndjson",
			records: []aureliusRecord{{
				EventID:    "01HX0001-verdict-a",
				OccurredAt: fixed,
				Attributes: map[string]string{
					"image_digest": "sha256:c6b86af5b3d4",
					"verdict":      "warn",
				},
				Payload: map[string]interface{}{
					"image_digest":      "sha256:c6b86af5b3d4",
					"verdict":           "warn",
					"blocking_findings": float64(0),
					"excepted_findings": float64(13),
				},
			}},
		},
		{
			key: "verdicts/2026/05/22/14/batch-002.ndjson",
			records: []aureliusRecord{{
				EventID:    "01HX0002-verdict-b",
				OccurredAt: fixed.Add(time.Hour),
				Attributes: map[string]string{
					"image_digest": "sha256:abcdef",
					"verdict":      "pass",
				},
				Payload: map[string]interface{}{
					"image_digest":      "sha256:abcdef",
					"verdict":           "pass",
					"blocking_findings": float64(0),
					"excepted_findings": float64(0),
				},
			}},
		},
	}
	client := newFakeS3(objects)
	src.newClient = func(context.Context, settings) (s3API, error) { return client, nil }

	cfg := sourcecdk.NewConfig(map[string]string{
		"family":    familyVerdict,
		"bucket":    "writer-aurelius-telemetry",
		"prefix":    "verdicts/",
		"per_page":  "1",
		"tenant_id": "writer",
	})

	first, err := src.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("first events = %d, want 1", len(first.Events))
	}
	if first.NextCursor == nil {
		t.Fatal("first NextCursor = nil, want cursor for truncated S3 page")
	}
	firstCursor := mustDecodeAureliusCursor(t, first.NextCursor.GetOpaque())
	if firstCursor.LastKey != "verdicts/2026/05/22/14/batch-001.ndjson" {
		t.Fatalf("first cursor last_key = %q, want first batch", firstCursor.LastKey)
	}

	second, err := src.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("second events = %d, want 1", len(second.Events))
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil on final page", second.NextCursor)
	}
}

func TestReadResumesFromCursor(t *testing.T) {
	src, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	fixed := time.Date(2026, 5, 22, 14, 30, 0, 0, time.UTC)
	objects := []fakeObject{
		{
			key: "findings/2026/05/22/12/batch-001.ndjson",
			records: []aureliusRecord{
				{
					EventID:    "01HX0010-finding-a",
					OccurredAt: fixed,
					Attributes: map[string]string{
						"image_digest": "sha256:aaa",
						"severity":     "high",
					},
					Payload: map[string]interface{}{
						"image_digest": "sha256:aaa",
						"cve_id":       "CVE-2026-1111",
						"severity":     "high",
						"package":      "openssl",
					},
				},
			},
		},
		{
			key: "findings/2026/05/22/13/batch-002.ndjson",
			records: []aureliusRecord{
				{
					EventID:    "01HX0011-finding-b",
					OccurredAt: fixed.Add(time.Hour),
					Attributes: map[string]string{
						"image_digest": "sha256:bbb",
						"severity":     "medium",
					},
					Payload: map[string]interface{}{
						"image_digest": "sha256:bbb",
						"cve_id":       "CVE-2026-2222",
						"severity":     "medium",
						"package":      "zlib",
					},
				},
			},
		},
	}
	client := newFakeS3(objects)
	src.newClient = func(context.Context, settings) (s3API, error) { return client, nil }

	cfg := sourcecdk.NewConfig(map[string]string{
		"family":    familyFinding,
		"bucket":    "writer-aurelius-telemetry",
		"prefix":    "findings/",
		"tenant_id": "writer",
	})
	cursor := &cerebrov1.SourceCursor{Opaque: "findings/2026/05/22/12/batch-001.ndjson"}
	pull, err := src.Read(context.Background(), cfg, cursor)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("Read() events = %d, want 1", len(pull.Events))
	}
	if pull.Events[0].GetId() != "01HX0011-finding-b" {
		t.Errorf("event id = %q, want %q", pull.Events[0].GetId(), "01HX0011-finding-b")
	}
}

func TestReadDoesNotAdvancePastPartiallyProcessedArchive(t *testing.T) {
	if maxEventsPerPull > 1000 {
		t.Fatalf("maxEventsPerPull = %d, want <= 1000 to keep graph ingest batches below the orchestrator phase timeout", maxEventsPerPull)
	}
	src, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	fixed := time.Date(2026, 5, 22, 14, 30, 0, 0, time.UTC)
	const key = "findings/2026/05/22/14/batch-001.ndjson"
	records := make([]aureliusRecord, 0, maxEventsPerPull+1)
	for i := 0; i < maxEventsPerPull+1; i++ {
		records = append(records, aureliusRecord{
			EventID:    fmt.Sprintf("01HX-finding-%05d", i),
			OccurredAt: fixed.Add(time.Duration(i) * time.Second),
			Attributes: map[string]string{
				"image_digest": "sha256:aaa",
				"severity":     "high",
			},
			Payload: map[string]interface{}{
				"image_digest": "sha256:aaa",
				"cve_id":       "CVE-2026-1111",
				"severity":     "high",
				"package":      "openssl",
			},
		})
	}
	client := newFakeS3([]fakeObject{{key: key, records: records}})
	src.newClient = func(context.Context, settings) (s3API, error) { return client, nil }

	cfg := sourcecdk.NewConfig(map[string]string{
		"family":    familyFinding,
		"bucket":    "writer-aurelius-telemetry",
		"prefix":    "findings/",
		"tenant_id": "writer",
	})

	first, err := src.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != maxEventsPerPull {
		t.Fatalf("first events = %d, want %d", len(first.Events), maxEventsPerPull)
	}
	if first.NextCursor == nil {
		t.Fatal("first NextCursor = nil, want partial archive cursor")
	}
	firstCursor := mustDecodeAureliusCursor(t, first.NextCursor.GetOpaque())
	if firstCursor.LastKey == key {
		t.Fatalf("first cursor advanced last_key to partially processed archive %q", key)
	}
	if firstCursor.PartialKey != key {
		t.Fatalf("first cursor partial_key = %q, want %q", firstCursor.PartialKey, key)
	}
	if firstCursor.RecordOffset != maxEventsPerPull {
		t.Fatalf("first cursor record_offset = %d, want %d", firstCursor.RecordOffset, maxEventsPerPull)
	}

	second, err := src.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("second events = %d, want 1", len(second.Events))
	}
	if got := second.Events[0].GetId(); got != fmt.Sprintf("01HX-finding-%05d", maxEventsPerPull) {
		t.Fatalf("second event id = %q, want final record", got)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil after archive is complete", second.NextCursor)
	}
	checkpoint := mustDecodeAureliusCursor(t, second.Checkpoint.GetCursorOpaque())
	if checkpoint.LastKey != key || checkpoint.PartialKey != "" {
		t.Fatalf("second checkpoint cursor = %+v, want completed key %q", checkpoint, key)
	}
}

func TestReadCompletesEmptyFinalPageAfterCursor(t *testing.T) {
	src, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	client := newFakeS3(nil)
	src.newClient = func(context.Context, settings) (s3API, error) { return client, nil }

	cfg := sourcecdk.NewConfig(map[string]string{
		"family":    familyFinding,
		"bucket":    "writer-aurelius-telemetry",
		"prefix":    "findings/",
		"tenant_id": "writer",
	})
	cursor := &cerebrov1.SourceCursor{Opaque: "findings/2026/05/22/14/batch-001.ndjson"}
	pull, err := src.Read(context.Background(), cfg, cursor)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("events = %d, want 0", len(pull.Events))
	}
	if pull.NextCursor != nil {
		t.Fatalf("NextCursor = %#v, want nil on empty final page", pull.NextCursor)
	}
	if pull.Checkpoint == nil {
		t.Fatal("Checkpoint = nil, want resumable checkpoint for existing cursor")
	}
	checkpoint := mustDecodeAureliusCursor(t, pull.Checkpoint.GetCursorOpaque())
	if checkpoint.LastKey != cursor.GetOpaque() {
		t.Fatalf("checkpoint last_key = %q, want %q", checkpoint.LastKey, cursor.GetOpaque())
	}
}

func TestReadPreservesCheckpointWatermarkOnEmptyFollowup(t *testing.T) {
	src, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	client := newFakeS3(nil)
	src.newClient = func(context.Context, settings) (s3API, error) { return client, nil }

	watermark := time.Date(2026, 5, 22, 14, 30, 0, 0, time.UTC)
	cfg := sourcecdk.NewConfig(map[string]string{
		"family":    familyFinding,
		"bucket":    "writer-aurelius-telemetry",
		"prefix":    "findings/",
		"tenant_id": "writer",
	})
	cursor := &cerebrov1.SourceCursor{Opaque: encodeCursor(aureliusCursor{
		LastKey:   "findings/2026/05/22/14/batch-001.ndjson",
		Watermark: watermark.Format(time.RFC3339Nano),
	})}
	pull, err := src.Read(context.Background(), cfg, cursor)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if pull.Checkpoint == nil {
		t.Fatal("Checkpoint = nil, want preserved checkpoint")
	}
	if got := pull.Checkpoint.GetWatermark().AsTime(); !got.Equal(watermark) {
		t.Fatalf("checkpoint watermark = %v, want %v", got, watermark)
	}
	checkpoint := mustDecodeAureliusCursor(t, pull.Checkpoint.GetCursorOpaque())
	if checkpoint.Watermark != watermark.Format(time.RFC3339Nano) {
		t.Fatalf("cursor watermark = %q, want %q", checkpoint.Watermark, watermark.Format(time.RFC3339Nano))
	}
}

func TestReadKeepsCheckpointWatermarkMonotonic(t *testing.T) {
	src, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	priorWatermark := time.Date(2026, 5, 22, 15, 30, 0, 0, time.UTC)
	olderEventTime := priorWatermark.Add(-time.Hour)
	const key = "findings/2026/05/22/16/backfill.ndjson"
	client := newFakeS3([]fakeObject{{
		key: key,
		records: []aureliusRecord{{
			EventID:    "01HX-backfill",
			OccurredAt: olderEventTime,
			Attributes: map[string]string{
				"image_digest": "sha256:aaa",
				"severity":     "high",
			},
			Payload: map[string]interface{}{
				"cve_id":  "CVE-2026-1111",
				"package": "openssl",
			},
		}},
	}})
	src.newClient = func(context.Context, settings) (s3API, error) { return client, nil }

	cfg := sourcecdk.NewConfig(map[string]string{
		"family":    familyFinding,
		"bucket":    "writer-aurelius-telemetry",
		"prefix":    "findings/",
		"tenant_id": "writer",
	})
	cursor := &cerebrov1.SourceCursor{Opaque: encodeCursor(aureliusCursor{
		LastKey:   "findings/2026/05/22/15/batch.ndjson",
		Watermark: priorWatermark.Format(time.RFC3339Nano),
	})}
	pull, err := src.Read(context.Background(), cfg, cursor)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	if got := pull.Checkpoint.GetWatermark().AsTime(); !got.Equal(priorWatermark) {
		t.Fatalf("checkpoint watermark = %v, want prior %v", got, priorWatermark)
	}
	checkpoint := mustDecodeAureliusCursor(t, pull.Checkpoint.GetCursorOpaque())
	if checkpoint.Watermark != priorWatermark.Format(time.RFC3339Nano) {
		t.Fatalf("cursor watermark = %q, want %q", checkpoint.Watermark, priorWatermark.Format(time.RFC3339Nano))
	}
}

func TestBuildEventPromotesFindingPayloadVulnerabilityAttributes(t *testing.T) {
	event, err := buildEvent(settings{tenantID: "writer"}, aureliusRecord{
		EventID:    "01HX0010-finding-a",
		OccurredAt: time.Date(2026, 5, 22, 14, 30, 0, 0, time.UTC),
		Attributes: map[string]string{
			"image_digest": "sha256:aaa",
			"severity":     "high",
		},
		Payload: map[string]interface{}{
			"image_digest": "sha256:aaa",
			"cve_id":       "CVE-2026-1111",
			"severity":     "high",
			"package":      "openssl",
		},
	}, kindFinding, schemaRefFinding)
	if err != nil {
		t.Fatalf("buildEvent() error = %v", err)
	}
	if got := event.GetAttributes()["cve_id"]; got != "CVE-2026-1111" {
		t.Fatalf("cve_id attribute = %q, want CVE-2026-1111", got)
	}
	if got := event.GetAttributes()["package"]; got != "openssl" {
		t.Fatalf("package attribute = %q, want openssl", got)
	}
}

func TestBuildEventPromotesContractAttributesFromPayload(t *testing.T) {
	catalogBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	catalog, err := sourcecdk.LoadSourceCatalog(catalogBytes)
	if err != nil {
		t.Fatalf("LoadSourceCatalog() error = %v", err)
	}
	fixed := time.Date(2026, 5, 22, 14, 30, 0, 0, time.UTC)
	tests := []struct {
		name      string
		kind      string
		schemaRef string
		payload   map[string]interface{}
	}{
		{
			name:      "verdict",
			kind:      kindVerdict,
			schemaRef: schemaRefVerdict,
			payload: map[string]interface{}{
				"image_digest":      "sha256:verdict",
				"verdict":           "warn",
				"blocking_findings": float64(1),
				"excepted_findings": float64(0),
			},
		},
		{
			name:      "image-scan",
			kind:      kindImageScan,
			schemaRef: schemaRefImageScan,
			payload: map[string]interface{}{
				"image_digest": "sha256:image",
				"registry":     "us-docker.pkg.dev",
				"completed_at": fixed.Format(time.RFC3339),
			},
		},
		{
			name:      "catalog-promotion",
			kind:      kindCatalogPromotion,
			schemaRef: schemaRefCatalogPromotion,
			payload: map[string]interface{}{
				"track":        "stable",
				"image_digest": "sha256:promoted",
				"promoted_by":  "release-bot",
			},
		},
		{
			name:      "policy-exception",
			kind:      kindPolicyException,
			schemaRef: schemaRefPolicyException,
			payload: map[string]interface{}{
				"cve_id":     "CVE-2026-1111",
				"status":     "active",
				"expires_at": fixed.Add(time.Hour).Format(time.RFC3339),
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			event, err := buildEvent(settings{tenantID: "writer"}, aureliusRecord{
				EventID:    "01HX-" + tc.name,
				OccurredAt: fixed,
				Payload:    tc.payload,
			}, tc.kind, tc.schemaRef)
			if err != nil {
				t.Fatalf("buildEvent() error = %v", err)
			}
			if err := sourcecdk.ValidateEventEnvelopeWithContracts(event, catalog.EventContracts); err != nil {
				t.Fatalf("ValidateEventEnvelopeWithContracts() error = %v", err)
			}
		})
	}
}

func TestReadArchiveRejectsOverLimitDecompressedGzip(t *testing.T) {
	record := aureliusRecord{
		EventID:    "01HX0001-verdict-a",
		OccurredAt: time.Date(2026, 5, 22, 14, 30, 0, 0, time.UTC),
		Attributes: map[string]string{"image_digest": "sha256:aaa"},
		Payload:    map[string]interface{}{"verdict": "pass"},
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	raw = append(raw, '\n')

	compressed := &bytes.Buffer{}
	gz := gzip.NewWriter(compressed)
	for i := 0; i < 3; i++ {
		if _, err := gz.Write(raw); err != nil {
			t.Fatalf("gzip.Write() error = %v", err)
		}
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip.Close() error = %v", err)
	}

	_, err = readArchiveRecords(bytes.NewReader(compressed.Bytes()), "batch.ndjson.gz", int64(len(raw))*2)
	if err == nil {
		t.Fatal("readArchiveRecords() error = nil, want decompressed limit error")
	}
	if !errors.Is(err, ErrDecompressedObjectTooLarge) {
		t.Fatalf("readArchiveRecords() error = %v, want errors.Is ErrDecompressedObjectTooLarge", err)
	}
}

func TestCheckSurfacesS3Errors(t *testing.T) {
	src, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	src.newClient = func(context.Context, settings) (s3API, error) {
		return &erroringS3{err: errors.New("access denied")}, nil
	}
	cfg := sourcecdk.NewConfig(map[string]string{
		"family":    familyImageScan,
		"bucket":    "writer-aurelius-telemetry",
		"prefix":    "image_scans/",
		"tenant_id": "writer",
	})
	if err := src.Check(context.Background(), cfg); err == nil {
		t.Fatal("Check() error = nil, want s3 error")
	}
}

func TestDiscoverReturnsStableURN(t *testing.T) {
	src, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{
		"family":    familyPolicyException,
		"bucket":    "writer-aurelius-telemetry",
		"prefix":    "policy_exceptions/",
		"tenant_id": "writer",
	})
	urns, err := src.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(urns) != 1 {
		t.Fatalf("Discover() urns = %d, want 1", len(urns))
	}
	want := "urn:cerebro:aurelius:policy_exception:"
	if !strings.HasPrefix(string(urns[0]), want) {
		t.Errorf("urn = %q, want prefix %q", urns[0], want)
	}
}

type fakeObject struct {
	key     string
	records []aureliusRecord
	gzip    bool
}

func (o fakeObject) body() (io.ReadCloser, error) {
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
	objects map[string]fakeObject
	keys    []string
}

func newFakeS3(objects []fakeObject) *fakeS3 {
	m := make(map[string]fakeObject, len(objects))
	keys := make([]string, 0, len(objects))
	for _, obj := range objects {
		m[obj.key] = obj
		keys = append(keys, obj.key)
	}
	sort.Strings(keys)
	return &fakeS3{objects: m, keys: keys}
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
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if startAfter != "" && key <= startAfter {
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

type erroringS3 struct{ err error }

func (e *erroringS3) ListObjectsV2(context.Context, *s3.ListObjectsV2Input, ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	return nil, e.err
}

func (e *erroringS3) GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return nil, e.err
}

func mustDecodeAureliusCursor(t *testing.T, opaque string) aureliusCursor {
	t.Helper()
	cursor := decodeCursor(&cerebrov1.SourceCursor{Opaque: opaque})
	if cursor.Source != cursorSource {
		t.Fatalf("cursor source = %q, want %q (opaque %q)", cursor.Source, cursorSource, opaque)
	}
	return cursor
}
