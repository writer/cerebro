package cerebro

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/sources/internal/s3ndjson"
)

func TestSourceSpec(t *testing.T) {
	src, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if src.Spec().Id != sourceID || src.Spec().Name != "Cerebro" {
		t.Fatalf("Spec() = %#v", src.Spec())
	}
}

func TestParseSettings(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/cerebro-access-export"
	tests := []struct {
		name      string
		values    map[string]string
		wantErrIs error
		want      settings
	}{
		{
			name:   "defaults",
			values: map[string]string{"bucket": "example-cerebro-access-logs", "prefix": "access", "tenant_id": "writer"},
			want:   settings{family: familyAccess, bucket: "example-cerebro-access-logs", prefix: "access/", region: defaultRegion, tenantID: "writer", perPage: defaultPerPage},
		},
		{
			name: "runtime-tenant-role-and-page",
			values: map[string]string{
				"bucket": "example-cerebro-access-logs", "prefix": "access/", "region": "us-west-2", "per_page": "25", "role_arn": roleARN, "external_id": "external",
				sourceconfig.RuntimeTenantIDKey: "writer", sourceconfig.AWSAssumeRoleAllowlistKey: "writer=" + roleARN,
			},
			want: settings{family: familyAccess, bucket: "example-cerebro-access-logs", prefix: "access/", region: "us-west-2", tenantID: "writer", roleARN: roleARN, externalID: "external", assumeRoleARNs: "writer=" + roleARN, perPage: 25},
		},
		{name: "missing-bucket", values: map[string]string{"prefix": "access", "tenant_id": "writer"}, wantErrIs: ErrBucketRequired},
		{name: "missing-prefix", values: map[string]string{"bucket": "example-cerebro-access-logs", "tenant_id": "writer"}, wantErrIs: ErrPrefixRequired},
		{name: "missing-tenant", values: map[string]string{"bucket": "example-cerebro-access-logs", "prefix": "access"}, wantErrIs: ErrTenantRequired},
		{name: "invalid-page-size", values: map[string]string{"bucket": "example-cerebro-access-logs", "prefix": "access", "tenant_id": "writer", "page_size": "0"}, wantErrIs: ErrInvalidPageSize},
		{name: "role-not-allowlisted", values: map[string]string{"bucket": "example-cerebro-access-logs", "prefix": "access", "tenant_id": "writer", "role_arn": roleARN}, wantErrIs: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSettings(sourcecdk.NewConfig(tc.values))
			if tc.name == "role-not-allowlisted" {
				if !errors.Is(err, ErrRoleNotAllowed) {
					t.Fatalf("parseSettings() error = %v, want role allowlist error", err)
				}
				return
			}
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

func TestReadAccessTelemetryArchives(t *testing.T) {
	src, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	client := newFakeS3([]fakeObject{
		{key: "access/2026-06-09.ndjson", records: []map[string]any{
			accessTelemetry("audit-request-1", "writer", "allowed", "GET /sources", "ci@example.com"),
		}},
		{key: "access/2026-06-10.ndjson.gz", gzip: true, records: []map[string]any{
			accessTelemetry("audit-request-2", "writer", "denied", "POST /source-runtimes/{runtimeID}/sync", "ops@example.com"),
		}},
	})
	src.newClient = func(context.Context, settings) (s3ndjson.API, error) { return client, nil }
	pull, err := src.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"bucket": "example-cerebro-access-logs", "prefix": "access/", "tenant_id": "writer"}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("events = %d, want 2", len(pull.Events))
	}
	for _, event := range pull.Events {
		if event.GetSourceId() != sourceID || event.GetKind() != kindAccess || event.GetSchemaRef() != schemaAccess {
			t.Fatalf("event scope = source %q kind %q schema %q", event.GetSourceId(), event.GetKind(), event.GetSchemaRef())
		}
		if err := sourcecdk.ValidateEventEnvelope(event); err != nil {
			t.Fatalf("ValidateEventEnvelope() error = %v", err)
		}
	}
	if pull.Events[0].GetAttributes()["actor_user"] != "ci@example.com" || pull.Events[0].GetAttributes()["source_ip"] != "198.51.100.7" {
		t.Fatalf("first event attrs = %#v", pull.Events[0].GetAttributes())
	}
	if pull.Events[0].GetAttributes()["credential_id"] != "cred-audit-request-1" || pull.Events[0].GetAttributes()["scopes"] != "cerebro.cosmo.security.read,cerebro.findings.write" {
		t.Fatalf("first event access attrs = %#v", pull.Events[0].GetAttributes())
	}
	if pull.Events[1].GetAttributes()["outcome_result"] != "denied" || pull.Events[1].GetAttributes()["sensitive_action"] != "true" {
		t.Fatalf("second event attrs = %#v", pull.Events[1].GetAttributes())
	}
}

func TestReadDerivesTenantMismatchForCrossTenantRequest(t *testing.T) {
	src, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	record := accessTelemetry("audit-request-mismatch", "writer", "allowed", "GET /sources", "ci@example.com")
	record["requested_tenant_id"] = "tenant-b"
	delete(record, "tenant_mismatch")
	src.newClient = func(context.Context, settings) (s3ndjson.API, error) {
		return newFakeS3([]fakeObject{{key: "access/mismatch.ndjson", records: []map[string]any{record}}}), nil
	}
	pull, err := src.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"bucket": "example-cerebro-access-logs", "prefix": "access/", "tenant_id": "writer"}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].GetAttributes()["tenant_mismatch"]; got != "true" {
		t.Fatalf("tenant_mismatch = %q, want true (derived from requested_tenant_id != effective_tenant_id)", got)
	}
}

func TestReadPreservesContractMandatoryAttributes(t *testing.T) {
	src, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	src.newClient = func(context.Context, settings) (s3ndjson.API, error) {
		return newFakeS3([]fakeObject{{key: "access/contract.ndjson", records: []map[string]any{accessTelemetry("audit-request-contract", "writer", "allowed", "GET /sources", "ci@example.com")}}}), nil
	}
	pull, err := src.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"bucket": "example-cerebro-access-logs", "prefix": "access/", "tenant_id": "writer"}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].GetAttributes()
	for _, required := range []string{"event_type", "outcome_result", "route", "method"} {
		if strings.TrimSpace(attrs[required]) == "" {
			t.Fatalf("contract-mandatory attribute %q missing, attrs = %#v", required, attrs)
		}
	}
}

func TestReadRejectsOutsideTenantTelemetry(t *testing.T) {
	src, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	src.newClient = func(context.Context, settings) (s3ndjson.API, error) {
		return newFakeS3([]fakeObject{{key: "access/outside.ndjson", records: []map[string]any{accessTelemetry("audit-request-3", "other", "allowed", "GET /sources", "ci@example.com")}}}), nil
	}
	_, err = src.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"bucket": "example-cerebro-access-logs", "prefix": "access/", "tenant_id": "writer"}), nil)
	if !errors.Is(err, ErrTenantScope) {
		t.Fatalf("Read() error = %v, want tenant rejection", err)
	}
}

type fakeObject struct {
	key     string
	records []map[string]any
	gzip    bool
}

type fakeS3 struct {
	objects []fakeObject
}

func newFakeS3(objects []fakeObject) *fakeS3 {
	return &fakeS3{objects: objects}
}

func (f *fakeS3) ListObjectsV2(_ context.Context, input *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	prefix := awssdk.ToString(input.Prefix)
	out := &s3.ListObjectsV2Output{}
	for _, object := range f.objects {
		if strings.HasPrefix(object.key, prefix) {
			out.Contents = append(out.Contents, s3types.Object{Key: awssdk.String(object.key)})
		}
	}
	return out, nil
}

func (f *fakeS3) GetObject(_ context.Context, input *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	key := awssdk.ToString(input.Key)
	for _, object := range f.objects {
		if object.key != key {
			continue
		}
		body := encodeRecords(object.records)
		if object.gzip {
			var zipped bytes.Buffer
			gz := gzip.NewWriter(&zipped)
			_, _ = gz.Write(body)
			_ = gz.Close()
			body = zipped.Bytes()
		}
		return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(body))}, nil
	}
	return nil, errors.New("not found")
}

func encodeRecords(records []map[string]any) []byte {
	var buf bytes.Buffer
	for _, record := range records {
		_ = json.NewEncoder(&buf).Encode(record)
	}
	return buf.Bytes()
}

func accessTelemetry(requestID string, tenantID string, outcome string, route string, principal string) map[string]any {
	return map[string]any{
		"kind":                  "event",
		"name":                  "cerebro.api.access",
		"ts":                    time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
		"outcome":               outcome,
		"status":                200,
		"status_code":           200,
		"effective_status_code": 200,
		"method":                strings.Fields(route)[0],
		"route":                 route,
		"operation_family":      "source",
		"operation_type":        "read",
		"tenant_id":             tenantID,
		"effective_tenant_id":   tenantID,
		"requested_tenant_id":   tenantID,
		"principal":             principal,
		"auth_mode":             "api_key",
		"client_id":             "client-" + requestID,
		"client_ip":             "198.51.100.7",
		"credential_id":         "cred-" + requestID,
		"request_id":            requestID,
		"required_scopes":       []any{"cerebro.cosmo.security.read"},
		"scopes":                []any{"cerebro.cosmo.security.read", "cerebro.findings.write"},
		"sensitive_action":      strings.HasPrefix(route, "POST"),
	}
}
