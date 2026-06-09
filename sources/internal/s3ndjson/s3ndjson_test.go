package s3ndjson

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
)

func TestReadPartialCursorAdvancesCompletedKeyAndSkipsLogicalRecords(t *testing.T) {
	lines := make([]string, 0, MaxEventsPerPull+2)
	for i := 0; i < MaxEventsPerPull+1; i++ {
		if i == 500 {
			lines = append(lines, "")
		}
		lines = append(lines, fmt.Sprintf(`{"id":"b-%04d"}`, i))
	}
	client := &fakeS3{
		objects: map[string]string{
			"access/a.ndjson": `{"id":"a"}` + "\n",
			"access/b.ndjson": strings.Join(lines, "\n") + "\n",
		},
	}
	settings := Settings{
		Source:           "test/s3-ndjson/v1",
		Bucket:           "example",
		Prefix:           "access/",
		PerPage:          100,
		MarshalRawRecord: testEvent,
	}

	first, err := Read(context.Background(), client, settings, nil)
	if err != nil {
		t.Fatalf("first Read() error = %v", err)
	}
	if len(first.Events) != MaxEventsPerPull+1 {
		t.Fatalf("first events = %d, want %d", len(first.Events), MaxEventsPerPull+1)
	}
	if first.Events[0].GetId() != "a" || first.Events[len(first.Events)-1].GetId() != "b-0999" {
		t.Fatalf("first event bounds = %q..%q", first.Events[0].GetId(), first.Events[len(first.Events)-1].GetId())
	}
	cursor := decodeCursor(first.NextCursor, settings.Source)
	if cursor.LastKey != "access/a.ndjson" || cursor.PartialKey != "access/b.ndjson" || cursor.RecordOffset != MaxEventsPerPull {
		t.Fatalf("first cursor = %+v, want completed a and partial b at offset %d", cursor, MaxEventsPerPull)
	}

	second, err := Read(context.Background(), client, settings, first.NextCursor)
	if err != nil {
		t.Fatalf("second Read() error = %v", err)
	}
	if len(client.startAfter) != 2 || client.startAfter[1] != "access/a.ndjson" {
		t.Fatalf("second listing StartAfter = %v, want access/a.ndjson", client.startAfter)
	}
	if len(second.Events) != 1 || second.Events[0].GetId() != "b-1000" {
		t.Fatalf("second events = %v, want only b-1000", eventIDs(second.Events))
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil after completing partial object", second.NextCursor)
	}
}

type fakeS3 struct {
	objects    map[string]string
	startAfter []string
}

func (f *fakeS3) ListObjectsV2(_ context.Context, input *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	prefix := awssdk.ToString(input.Prefix)
	startAfter := awssdk.ToString(input.StartAfter)
	f.startAfter = append(f.startAfter, startAfter)
	keys := make([]string, 0, len(f.objects))
	for key := range f.objects {
		if strings.HasPrefix(key, prefix) && key > startAfter {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	contents := make([]s3types.Object, 0, len(keys))
	for _, key := range keys {
		contents = append(contents, s3types.Object{Key: awssdk.String(key)})
	}
	return &s3.ListObjectsV2Output{Contents: contents}, nil
}

func (f *fakeS3) GetObject(_ context.Context, input *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	body, ok := f.objects[awssdk.ToString(input.Key)]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader([]byte(body)))}, nil
}

func testEvent(raw json.RawMessage) (*primitives.Event, error) {
	var payload struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	return &cerebrov1.EventEnvelope{Id: payload.ID}, nil
}

func eventIDs(events []*primitives.Event) []string {
	ids := make([]string, 0, len(events))
	for _, event := range events {
		ids = append(ids, event.GetId())
	}
	return ids
}
