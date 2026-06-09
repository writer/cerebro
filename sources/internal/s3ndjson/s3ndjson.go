package s3ndjson

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"google.golang.org/protobuf/encoding/protojson"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

const (
	MaxObjectBytes   = 64 << 20
	MaxLineBytes     = 1 << 20
	MaxEventsPerPull = 1000
)

var ErrDecompressedObjectTooLarge = errors.New("decompressed object exceeds limit")

type API interface {
	ListObjectsV2(context.Context, *s3.ListObjectsV2Input, ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

type Settings struct {
	Source           string
	Bucket           string
	Prefix           string
	Region           string
	RoleARN          string
	ExternalID       string
	SessionName      string
	PerPage          int32
	MarshalRawRecord func(json.RawMessage) (*primitives.Event, error)
}

type Cursor struct {
	Source              string `json:"source,omitempty"`
	ResumableCheckpoint bool   `json:"resumable_checkpoint,omitempty"`
	LastKey             string `json:"last_key,omitempty"`
	PartialKey          string `json:"partial_key,omitempty"`
	RecordOffset        int    `json:"record_offset,omitempty"`
}

func NewClient(ctx context.Context, st Settings) (API, error) {
	region := strings.TrimSpace(st.Region)
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	if st.RoleARN != "" {
		provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), st.RoleARN, func(options *stscreds.AssumeRoleOptions) {
			options.RoleSessionName = firstNonEmpty(st.SessionName, "cerebro-s3ndjson-source")
			if st.ExternalID != "" {
				options.ExternalID = awssdk.String(st.ExternalID)
			}
		})
		cfg.Credentials = awssdk.NewCredentialsCache(provider)
	}
	return s3.NewFromConfig(cfg), nil
}

func Check(ctx context.Context, client API, st Settings) error {
	_, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: awssdk.String(st.Bucket), Prefix: awssdk.String(st.Prefix), MaxKeys: awssdk.Int32(1)})
	return err
}

func Discover(urn string) ([]sourcecdk.URN, error) {
	parsed, err := sourcecdk.ParseURN(urn)
	if err != nil {
		return nil, err
	}
	return []sourcecdk.URN{parsed}, nil
}

func Read(ctx context.Context, client API, st Settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	state := decodeCursor(cursor, st.Source)
	out, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:     awssdk.String(st.Bucket),
		Prefix:     awssdk.String(st.Prefix),
		StartAfter: tokenPtr(state.LastKey),
		MaxKeys:    awssdk.Int32(st.PerPage),
	})
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	events := []*primitives.Event{}
	completedLastKey := state.LastKey
	for _, object := range out.Contents {
		key := awssdk.ToString(object.Key)
		if key == "" {
			continue
		}
		if strings.HasSuffix(key, "/") {
			completedLastKey = key
			continue
		}
		offset := 0
		if key == state.PartialKey {
			offset = state.RecordOffset
		}
		next, nextOffset, complete, err := readObject(ctx, client, st, key, offset)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, next...)
		if !complete {
			state.LastKey = completedLastKey
			state.PartialKey = key
			state.RecordOffset = nextOffset
			return sourcecdk.Pull{Events: events, NextCursor: encodeCursor(state, st.Source), Checkpoint: checkpoint(state)}, nil
		}
		state.PartialKey = ""
		state.RecordOffset = 0
		completedLastKey = key
		if len(events) >= MaxEventsPerPull {
			state.LastKey = completedLastKey
			return sourcecdk.Pull{Events: events, NextCursor: encodeCursor(state, st.Source), Checkpoint: checkpoint(state)}, nil
		}
	}
	if awssdk.ToBool(out.IsTruncated) {
		state.LastKey = completedLastKey
		return sourcecdk.Pull{Events: events, NextCursor: encodeCursor(state, st.Source), Checkpoint: checkpoint(state)}, nil
	}
	state.LastKey = completedLastKey
	return sourcecdk.Pull{Events: events, Checkpoint: checkpoint(state)}, nil
}

func readObject(ctx context.Context, client API, st Settings, key string, skip int) ([]*primitives.Event, int, bool, error) {
	out, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: awssdk.String(st.Bucket), Key: awssdk.String(key)})
	if err != nil {
		return nil, 0, false, err
	}
	defer func() { _ = out.Body.Close() }()
	reader, err := objectReader(key, io.LimitReader(out.Body, MaxObjectBytes+1))
	if err != nil {
		return nil, 0, false, err
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), MaxLineBytes)
	events := []*primitives.Event{}
	line := 0
	recordsSeen := 0
	for scanner.Scan() {
		line++
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		if recordsSeen < skip {
			recordsSeen++
			continue
		}
		event, err := decodeEvent(raw, st.MarshalRawRecord)
		if err != nil {
			return nil, recordsSeen, false, fmt.Errorf("decode %s line %d: %w", key, line, err)
		}
		recordsSeen++
		events = append(events, event)
		if len(events) >= MaxEventsPerPull {
			return events, recordsSeen, false, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, recordsSeen, false, err
	}
	return events, recordsSeen, true, nil
}

func objectReader(key string, reader io.Reader) (io.Reader, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxObjectBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxObjectBytes {
		return nil, ErrDecompressedObjectTooLarge
	}
	if strings.HasSuffix(strings.ToLower(key), ".gz") {
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		data, err = io.ReadAll(io.LimitReader(gz, MaxObjectBytes+1))
		if err != nil {
			_ = gz.Close()
			return nil, err
		}
		if err := gz.Close(); err != nil {
			return nil, err
		}
		if len(data) > MaxObjectBytes {
			return nil, ErrDecompressedObjectTooLarge
		}
	}
	return bytes.NewReader(data), nil
}

func decodeEvent(raw json.RawMessage, marshal func(json.RawMessage) (*primitives.Event, error)) (*primitives.Event, error) {
	if marshal != nil {
		return marshal(raw)
	}
	event := &cerebrov1.EventEnvelope{}
	if err := protojson.Unmarshal(raw, event); err != nil {
		return nil, err
	}
	return event, nil
}

func decodeCursor(cursor *cerebrov1.SourceCursor, source string) Cursor {
	if cursor == nil || strings.TrimSpace(cursor.GetOpaque()) == "" {
		return Cursor{Source: source}
	}
	var decoded Cursor
	if err := json.Unmarshal([]byte(cursor.GetOpaque()), &decoded); err != nil || decoded.Source != source {
		return Cursor{Source: source}
	}
	return decoded
}

func encodeCursor(cursor Cursor, source string) *cerebrov1.SourceCursor {
	cursor.Source = source
	cursor.ResumableCheckpoint = true
	data, _ := json.Marshal(cursor)
	return &cerebrov1.SourceCursor{Opaque: string(data)}
}

func checkpoint(cursor Cursor) *cerebrov1.SourceCheckpoint {
	data, _ := json.Marshal(cursor)
	return &cerebrov1.SourceCheckpoint{CursorOpaque: string(data)}
}

func tokenPtr(value string) *string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return awssdk.String(value)
}

func SafeS3Bucket(value string) bool {
	if len(value) < 3 || len(value) > 63 || strings.Contains(value, "..") {
		return false
	}
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' {
			continue
		}
		return false
	}
	return true
}

func SafeS3Prefix(value string) bool {
	if strings.TrimSpace(value) == "" || len(value) > 1024 {
		return false
	}
	_, err := url.ParseRequestURI("/" + value)
	return err == nil
}

func PositivePageSize(raw string, def int32, max int32) (int32, error) {
	if strings.TrimSpace(raw) == "" {
		return def, nil
	}
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 32)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("invalid page_size")
	}
	if int32(value) > max { // #nosec G109 G115 -- ParseInt bitSize 32 bounds value before conversion.
		return max, nil
	}
	return int32(value), nil // #nosec G109 G115 -- ParseInt bitSize 32 bounds value before conversion.
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
