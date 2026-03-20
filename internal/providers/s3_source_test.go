package providers

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func TestS3SourceProviderName(t *testing.T) {
	t.Parallel()
	p := NewS3SourceProvider("sentinelone")
	if p.Name() != "s3-sentinelone" {
		t.Fatalf("Name() = %q, want s3-sentinelone", p.Name())
	}
}

func TestS3SourceProviderConfigureRequiresBucket(t *testing.T) {
	t.Parallel()
	p := NewS3SourceProvider("kolide")
	err := p.Configure(context.Background(), map[string]interface{}{})
	if err == nil || !strings.Contains(err.Error(), "bucket required") {
		t.Fatalf("expected bucket validation error, got: %v", err)
	}
}

func TestS3SourceProviderSchemaTableNames(t *testing.T) {
	t.Parallel()
	p := NewS3SourceProvider("sentinelone")
	schema := p.Schema()
	if len(schema) != 2 {
		t.Fatalf("expected 2 tables, got %d", len(schema))
	}
	if schema[0].Name != "s3_sentinelone_objects" {
		t.Fatalf("objects table = %q, want s3_sentinelone_objects", schema[0].Name)
	}
	if schema[1].Name != "s3_sentinelone_records" {
		t.Fatalf("records table = %q, want s3_sentinelone_records", schema[1].Name)
	}
}

func TestS3SourceProviderSyncMultiplePrefixes(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 5, 3, 0, 0, 0, time.UTC)

	fake := &fakeS3Client{
		listByPrefix: map[string]*s3.ListObjectsV2Output{
			"alerts/": {Contents: []types.Object{
				{Key: aws.String("alerts/event1.jsonl"), ETag: aws.String("\"e1\""), Size: aws.Int64(10), LastModified: aws.Time(now)},
			}},
			"threats/": {Contents: []types.Object{
				{Key: aws.String("threats/event2.jsonl"), ETag: aws.String("\"e2\""), Size: aws.Int64(10), LastModified: aws.Time(now)},
			}},
		},
		getBodyFn: map[string]func() *s3.GetObjectOutput{
			"alerts/event1.jsonl": func() *s3.GetObjectOutput {
				return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader("{\"type\":\"alert\"}\n"))}
			},
			"threats/event2.jsonl": func() *s3.GetObjectOutput {
				return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader("{\"type\":\"threat\"}\n"))}
			},
		},
	}

	p := NewS3SourceProvider("sentinelone")
	p.bucket = "s1-bucket"
	p.prefixes = []string{"alerts/", "threats/"}
	p.client = fake

	result, err := p.Sync(context.Background(), SyncOptions{FullSync: true})
	if err != nil {
		t.Fatalf("sync failed: %v", err)
	}

	rowsByTable := make(map[string]int64)
	for _, table := range result.Tables {
		rowsByTable[table.Name] = table.Rows
	}

	if rowsByTable["s3_sentinelone_objects"] != 2 {
		t.Fatalf("objects rows = %d, want 2", rowsByTable["s3_sentinelone_objects"])
	}
	if rowsByTable["s3_sentinelone_records"] != 2 {
		t.Fatalf("records rows = %d, want 2", rowsByTable["s3_sentinelone_records"])
	}
}

func TestS3SourceProviderSyncRespectsGlobalMaxObjectsAcrossPrefixes(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 5, 3, 0, 0, 0, time.UTC)

	fake := &fakeS3Client{
		listByPrefix: map[string]*s3.ListObjectsV2Output{
			"alerts/": {Contents: []types.Object{
				{Key: aws.String("alerts/event1.jsonl"), ETag: aws.String("\"e1\""), Size: aws.Int64(10), LastModified: aws.Time(now)},
			}},
			"threats/": {Contents: []types.Object{
				{Key: aws.String("threats/event2.jsonl"), ETag: aws.String("\"e2\""), Size: aws.Int64(10), LastModified: aws.Time(now)},
			}},
		},
		getBodyFn: map[string]func() *s3.GetObjectOutput{
			"alerts/event1.jsonl": func() *s3.GetObjectOutput {
				return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader("{\"type\":\"alert\"}\n"))}
			},
			"threats/event2.jsonl": func() *s3.GetObjectOutput {
				return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader("{\"type\":\"threat\"}\n"))}
			},
		},
	}

	p := NewS3SourceProvider("sentinelone")
	p.bucket = "s1-bucket"
	p.prefixes = []string{"alerts/", "threats/"}
	p.maxObjects = 1
	p.client = fake

	result, err := p.Sync(context.Background(), SyncOptions{FullSync: true})
	if err != nil {
		t.Fatalf("sync failed: %v", err)
	}

	rowsByTable := make(map[string]int64)
	for _, table := range result.Tables {
		rowsByTable[table.Name] = table.Rows
	}

	if rowsByTable["s3_sentinelone_objects"] != 1 {
		t.Fatalf("objects rows = %d, want 1", rowsByTable["s3_sentinelone_objects"])
	}
	if rowsByTable["s3_sentinelone_records"] != 1 {
		t.Fatalf("records rows = %d, want 1", rowsByTable["s3_sentinelone_records"])
	}
}

func TestS3SourceProviderSyncNoPrefix(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 5, 3, 0, 0, 0, time.UTC)
	fake := &fakeS3Client{
		listByPrefix: map[string]*s3.ListObjectsV2Output{
			"": {Contents: []types.Object{
				{Key: aws.String("data.json"), ETag: aws.String("\"e1\""), Size: aws.Int64(10), LastModified: aws.Time(now)},
			}},
		},
		getBodyFn: map[string]func() *s3.GetObjectOutput{
			"data.json": func() *s3.GetObjectOutput {
				return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader("[{\"id\":1},{\"id\":2}]"))}
			},
		},
	}

	p := NewS3SourceProvider("kolide")
	p.bucket = "kolide-bucket"
	p.client = fake

	result, err := p.Sync(context.Background(), SyncOptions{FullSync: true})
	if err != nil {
		t.Fatalf("sync failed: %v", err)
	}

	rowsByTable := make(map[string]int64)
	for _, table := range result.Tables {
		rowsByTable[table.Name] = table.Rows
	}

	if rowsByTable["s3_kolide_objects"] != 1 {
		t.Fatalf("objects rows = %d, want 1", rowsByTable["s3_kolide_objects"])
	}
	if rowsByTable["s3_kolide_records"] != 2 {
		t.Fatalf("records rows = %d, want 2", rowsByTable["s3_kolide_records"])
	}
}

func TestS3SourceProviderSyncIncludesSourceColumn(t *testing.T) {
	t.Parallel()

	p := NewS3SourceProvider("kolide")

	schema := p.Schema()
	for _, table := range schema {
		hasSourceColumn := false
		for _, col := range table.Columns {
			if col.Name == "source" {
				hasSourceColumn = true
				break
			}
		}
		if !hasSourceColumn {
			t.Fatalf("%s schema missing 'source' column", table.Name)
		}
	}
}

func TestS3SourceProviderTableFilter(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 5, 3, 0, 0, 0, time.UTC)
	fake := &fakeS3Client{
		listByPrefix: map[string]*s3.ListObjectsV2Output{
			"": {Contents: []types.Object{
				{Key: aws.String("log.jsonl"), ETag: aws.String("\"e1\""), Size: aws.Int64(10), LastModified: aws.Time(now)},
			}},
		},
		getBodyFn: map[string]func() *s3.GetObjectOutput{
			"log.jsonl": func() *s3.GetObjectOutput {
				return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader("{\"event\":\"test\"}\n"))}
			},
		},
	}

	p := NewS3SourceProvider("sentinelone")
	p.bucket = "s1-bucket"
	p.client = fake

	result, err := p.Sync(context.Background(), SyncOptions{Tables: []string{"s3_sentinelone_objects"}})
	if err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	if len(result.Tables) != 1 {
		t.Fatalf("expected 1 table, got %d", len(result.Tables))
	}
	if result.Tables[0].Name != "s3_sentinelone_objects" {
		t.Fatalf("expected s3_sentinelone_objects, got %s", result.Tables[0].Name)
	}
}

func TestS3SourceProviderRoleARNConfig(t *testing.T) {
	t.Parallel()

	p := NewS3SourceProvider("crossaccount")
	p.bucket = "remote-bucket"
	p.client = &fakeS3Client{}

	cfg := map[string]interface{}{
		"bucket":      "remote-bucket",
		"role_arn":    "arn:aws:iam::999999999999:role/cerebro-read",
		"external_id": "ext-abc-123",
		"prefixes":    []string{"data/", "logs/"},
	}
	if err := p.BaseProvider.Configure(context.Background(), cfg); err != nil {
		t.Fatalf("base configure: %v", err)
	}

	p.roleARN = strings.TrimSpace(p.GetConfigString("role_arn"))
	p.externalID = strings.TrimSpace(p.GetConfigString("external_id"))
	p.prefixes = parseS3SourcePrefixes(p.GetConfig("prefixes"))

	if p.roleARN != "arn:aws:iam::999999999999:role/cerebro-read" {
		t.Fatalf("roleARN = %q, want arn:aws:iam::999999999999:role/cerebro-read", p.roleARN)
	}
	if p.externalID != "ext-abc-123" {
		t.Fatalf("externalID = %q, want ext-abc-123", p.externalID)
	}
	if len(p.prefixes) != 2 || p.prefixes[0] != "data/" || p.prefixes[1] != "logs/" {
		t.Fatalf("prefixes = %v, want [data/ logs/]", p.prefixes)
	}
}

func TestParseS3Sources(t *testing.T) {
	t.Parallel()

	envs := map[string]string{
		"S3_SOURCES":                        "sentinelone,kolide",
		"S3_SOURCE_SENTINELONE_BUCKET":      "s1-logs",
		"S3_SOURCE_SENTINELONE_PREFIXES":    "alerts/,threats/",
		"S3_SOURCE_SENTINELONE_REGION":      "us-west-2",
		"S3_SOURCE_SENTINELONE_ROLE_ARN":    "arn:aws:iam::123456789:role/s1-read",
		"S3_SOURCE_SENTINELONE_EXTERNAL_ID": "ext123",
		"S3_SOURCE_KOLIDE_BUCKET":           "kolide-exports",
		"S3_SOURCE_KOLIDE_PREFIXES":         "devices/",
		"AWS_REGION":                        "us-east-1",
	}
	getEnv := func(key, fallback string) string {
		if v, ok := envs[key]; ok {
			return v
		}
		return fallback
	}
	getEnvInt := func(key string, fallback int) int {
		return fallback
	}

	sources := ParseS3Sources(getEnv, getEnvInt)
	if len(sources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(sources))
	}

	s1 := sources[0]
	if s1.Name != "sentinelone" {
		t.Fatalf("source 0 name = %q, want sentinelone", s1.Name)
	}
	if s1.Bucket != "s1-logs" {
		t.Fatalf("source 0 bucket = %q, want s1-logs", s1.Bucket)
	}
	if len(s1.Prefixes) != 2 || s1.Prefixes[0] != "alerts/" || s1.Prefixes[1] != "threats/" {
		t.Fatalf("source 0 prefixes = %v, want [alerts/ threats/]", s1.Prefixes)
	}
	if s1.Region != "us-west-2" {
		t.Fatalf("source 0 region = %q, want us-west-2", s1.Region)
	}
	if s1.RoleARN != "arn:aws:iam::123456789:role/s1-read" {
		t.Fatalf("source 0 role_arn = %q", s1.RoleARN)
	}
	if s1.ExternalID != "ext123" {
		t.Fatalf("source 0 external_id = %q, want ext123", s1.ExternalID)
	}
	if s1.MaxRecordsPerObject != defaultS3InputMaxRecordsPerObject {
		t.Fatalf("source 0 max_records_per_object = %d, want %d", s1.MaxRecordsPerObject, defaultS3InputMaxRecordsPerObject)
	}

	k := sources[1]
	if k.Name != "kolide" {
		t.Fatalf("source 1 name = %q, want kolide", k.Name)
	}
	if k.Bucket != "kolide-exports" {
		t.Fatalf("source 1 bucket = %q, want kolide-exports", k.Bucket)
	}
	if len(k.Prefixes) != 1 || k.Prefixes[0] != "devices/" {
		t.Fatalf("source 1 prefixes = %v, want [devices/]", k.Prefixes)
	}
	if k.Region != "us-east-1" {
		t.Fatalf("source 1 region = %q, want us-east-1 (default)", k.Region)
	}
}

func TestParseS3SourcesEmpty(t *testing.T) {
	t.Parallel()

	getEnv := func(key, fallback string) string { return fallback }
	getEnvInt := func(key string, fallback int) int { return fallback }

	sources := ParseS3Sources(getEnv, getEnvInt)
	if len(sources) != 0 {
		t.Fatalf("expected 0 sources, got %d", len(sources))
	}
}

func TestParseS3SourcesSkipsMissingBucket(t *testing.T) {
	t.Parallel()

	envs := map[string]string{
		"S3_SOURCES":             "ghost,valid",
		"S3_SOURCE_VALID_BUCKET": "valid-bucket",
	}
	getEnv := func(key, fallback string) string {
		if v, ok := envs[key]; ok {
			return v
		}
		return fallback
	}
	getEnvInt := func(key string, fallback int) int { return fallback }

	sources := ParseS3Sources(getEnv, getEnvInt)
	if len(sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(sources))
	}
	if sources[0].Name != "valid" {
		t.Fatalf("source name = %q, want valid", sources[0].Name)
	}
}

func TestParseS3SourcePrefixes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input interface{}
		want  []string
	}{
		{"nil", nil, nil},
		{"empty string", "", nil},
		{"comma-separated string", "alerts/,threats/", []string{"alerts/", "threats/"}},
		{"string slice", []string{"a/", "b/"}, []string{"a/", "b/"}},
		{"interface slice", []interface{}{"x/", "y/"}, []string{"x/", "y/"}},
		{"single prefix", "logs/", []string{"logs/"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseS3SourcePrefixes(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("parseS3SourcePrefixes(%v) = %v, want %v", tc.input, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("parseS3SourcePrefixes(%v)[%d] = %q, want %q", tc.input, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestParseS3SourcesMaxRecordsPerObject(t *testing.T) {
	t.Parallel()

	envs := map[string]string{
		"S3_SOURCES":                                "bigfiles",
		"S3_SOURCE_BIGFILES_BUCKET":                 "big-bucket",
		"S3_SOURCE_BIGFILES_MAX_RECORDS_PER_OBJECT": "50000",
	}
	getEnv := func(key, fallback string) string {
		if v, ok := envs[key]; ok {
			return v
		}
		return fallback
	}
	getEnvInt := func(key string, fallback int) int {
		if v, ok := envs[key]; ok {
			var n int
			if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
				return n
			}
		}
		return fallback
	}

	sources := ParseS3Sources(getEnv, getEnvInt)
	if len(sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(sources))
	}
	if sources[0].MaxRecordsPerObject != 50000 {
		t.Fatalf("max_records_per_object = %d, want 50000", sources[0].MaxRecordsPerObject)
	}
}
