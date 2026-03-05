package providers

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type fakeS3Client struct {
	listOutputs []*s3.ListObjectsV2Output
	listErr     error
	listCalls   int
	getOutputs  map[string]*s3.GetObjectOutput
	getErrors   map[string]error
	headErr     error
}

func (f *fakeS3Client) ListObjectsV2(_ context.Context, _ *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listCalls >= len(f.listOutputs) {
		return &s3.ListObjectsV2Output{}, nil
	}
	output := f.listOutputs[f.listCalls]
	f.listCalls++
	return output, nil
}

func (f *fakeS3Client) GetObject(_ context.Context, input *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	key := aws.ToString(input.Key)
	if err, ok := f.getErrors[key]; ok && err != nil {
		return nil, err
	}
	output, ok := f.getOutputs[key]
	if !ok {
		return nil, io.EOF
	}
	return output, nil
}

func (f *fakeS3Client) HeadBucket(_ context.Context, _ *s3.HeadBucketInput, _ ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	if f.headErr != nil {
		return nil, f.headErr
	}
	return &s3.HeadBucketOutput{}, nil
}

func TestS3ProviderConfigureRequiresBucket(t *testing.T) {
	t.Parallel()

	provider := NewS3Provider()
	err := provider.Configure(context.Background(), map[string]interface{}{})
	if err == nil || !strings.Contains(err.Error(), "s3 bucket required") {
		t.Fatalf("expected bucket validation error, got: %v", err)
	}
}

func TestS3ProviderSyncParsesJSONLAndCSV(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 5, 3, 0, 0, 0, time.UTC)
	fake := &fakeS3Client{
		listOutputs: []*s3.ListObjectsV2Output{{
			Contents: []types.Object{
				{Key: aws.String("logs/events.jsonl"), ETag: aws.String("\"etag-jsonl\""), Size: aws.Int64(32), LastModified: aws.Time(now)},
				{Key: aws.String("logs/users.csv"), ETag: aws.String("\"etag-csv\""), Size: aws.Int64(64), LastModified: aws.Time(now.Add(-time.Minute))},
			},
		}},
		getOutputs: map[string]*s3.GetObjectOutput{
			"logs/events.jsonl": {Body: io.NopCloser(strings.NewReader("{\"event\":\"login\"}\n{\"event\":\"logout\"}\n"))},
			"logs/users.csv":    {Body: io.NopCloser(strings.NewReader("id,name\n1,Alice\n2,Bob\n"))},
		},
	}

	provider := NewS3Provider()
	provider.bucket = "input-bucket"
	provider.client = fake

	result, err := provider.Sync(context.Background(), SyncOptions{FullSync: true})
	if err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected parse errors: %v", result.Errors)
	}

	rowsByTable := make(map[string]int64)
	for _, table := range result.Tables {
		rowsByTable[table.Name] = table.Rows
	}

	if rowsByTable["s3_input_objects"] != 2 {
		t.Fatalf("s3_input_objects rows = %d, want 2", rowsByTable["s3_input_objects"])
	}
	if rowsByTable["s3_input_records"] != 4 {
		t.Fatalf("s3_input_records rows = %d, want 4", rowsByTable["s3_input_records"])
	}
}

func TestS3ProviderSyncSupportsGzipJSONL(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 5, 3, 0, 0, 0, time.UTC)
	fake := &fakeS3Client{
		listOutputs: []*s3.ListObjectsV2Output{{
			Contents: []types.Object{
				{Key: aws.String("logs/events.jsonl.gz"), ETag: aws.String("\"etag-gz\""), Size: aws.Int64(20), LastModified: aws.Time(now)},
			},
		}},
		getOutputs: map[string]*s3.GetObjectOutput{
			"logs/events.jsonl.gz": {
				Body: io.NopCloser(bytes.NewReader(gzipBytes(t, "{\"event\":\"password_reset\"}\n"))),
			},
		},
	}

	provider := NewS3Provider()
	provider.bucket = "input-bucket"
	provider.client = fake

	result, err := provider.Sync(context.Background(), SyncOptions{FullSync: true})
	if err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected parse errors: %v", result.Errors)
	}

	rowsByTable := make(map[string]int64)
	for _, table := range result.Tables {
		rowsByTable[table.Name] = table.Rows
	}

	if rowsByTable["s3_input_objects"] != 1 {
		t.Fatalf("s3_input_objects rows = %d, want 1", rowsByTable["s3_input_objects"])
	}
	if rowsByTable["s3_input_records"] != 1 {
		t.Fatalf("s3_input_records rows = %d, want 1", rowsByTable["s3_input_records"])
	}
}

func TestParseS3JSONLinesCapturesLineErrors(t *testing.T) {
	t.Parallel()

	records, parseErrors, err := parseS3JSONLines(strings.NewReader("{\"event\":\"ok\"}\n{bad-json}\n"), 10)
	if err != nil {
		t.Fatalf("parseS3JSONLines returned error: %v", err)
	}
	if parseErrors != 1 {
		t.Fatalf("parseErrors = %d, want 1", parseErrors)
	}
	if len(records) != 2 {
		t.Fatalf("record count = %d, want 2", len(records))
	}
	if records[1].ParseError == "" {
		t.Fatalf("expected second record parse_error to be set")
	}
}

func TestS3ProviderSyncRespectsTableFilter(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 5, 3, 0, 0, 0, time.UTC)
	fake := &fakeS3Client{
		listOutputs: []*s3.ListObjectsV2Output{{
			Contents: []types.Object{
				{Key: aws.String("logs/events.jsonl"), ETag: aws.String("\"etag-jsonl\""), Size: aws.Int64(32), LastModified: aws.Time(now)},
			},
		}},
		getOutputs: map[string]*s3.GetObjectOutput{
			"logs/events.jsonl": {Body: io.NopCloser(strings.NewReader("{\"event\":\"login\"}\n"))},
		},
	}

	provider := NewS3Provider()
	provider.bucket = "input-bucket"
	provider.client = fake

	result, err := provider.Sync(context.Background(), SyncOptions{FullSync: true, Tables: []string{"s3_input_objects"}})
	if err != nil {
		t.Fatalf("sync failed: %v", err)
	}

	if len(result.Tables) != 1 {
		t.Fatalf("expected exactly one table result, got %d", len(result.Tables))
	}
	if result.Tables[0].Name != "s3_input_objects" {
		t.Fatalf("expected s3_input_objects table, got %s", result.Tables[0].Name)
	}
}

func gzipBytes(t *testing.T, value string) []byte {
	t.Helper()

	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write([]byte(value)); err != nil {
		t.Fatalf("write gzip payload: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close gzip payload: %v", err)
	}

	return buffer.Bytes()
}
