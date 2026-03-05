package providers

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	defaultS3InputRegion              = "us-east-1"
	defaultS3InputFormat              = "auto"
	defaultS3InputMaxObjects          = 200
	defaultS3InputMaxRecordsPerObject = 10000
	s3ScannerBufferSize               = 64 * 1024
	s3ScannerMaxTokenSize             = 4 * 1024 * 1024
)

type s3API interface {
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
}

type s3ObjectMeta struct {
	Key          string
	ETag         string
	SizeBytes    int64
	LastModified time.Time
}

type s3ParsedRecord struct {
	Data       map[string]interface{}
	RawText    string
	ParseError string
}

type s3ParseOutput struct {
	Format      string
	Records     []s3ParsedRecord
	ParseErrors int
}

// S3Provider ingests and parses files from S3 for scheduled input processing.
type S3Provider struct {
	*BaseProvider
	bucket              string
	prefix              string
	region              string
	format              string
	maxObjects          int
	maxRecordsPerObject int
	client              s3API
}

func NewS3Provider() *S3Provider {
	return &S3Provider{
		BaseProvider:        NewBaseProvider("s3", ProviderTypeCloud),
		region:              defaultS3InputRegion,
		format:              defaultS3InputFormat,
		maxObjects:          defaultS3InputMaxObjects,
		maxRecordsPerObject: defaultS3InputMaxRecordsPerObject,
	}
}

func (p *S3Provider) Configure(ctx context.Context, cfgMap map[string]interface{}) error {
	if err := p.BaseProvider.Configure(ctx, cfgMap); err != nil {
		return err
	}

	p.bucket = strings.TrimSpace(p.GetConfigString("bucket"))
	if p.bucket == "" {
		return fmt.Errorf("s3 bucket required")
	}

	p.prefix = strings.TrimSpace(p.GetConfigString("prefix"))
	if region := strings.TrimSpace(p.GetConfigString("region")); region != "" {
		p.region = region
	}

	if format := strings.TrimSpace(p.GetConfigString("format")); format != "" {
		normalized, err := normalizeS3InputFormat(format)
		if err != nil {
			return err
		}
		p.format = normalized
	}

	if rawMax := p.GetConfig("max_objects"); rawMax != nil {
		if maxObjects, ok := intFromConfig(rawMax); ok {
			if maxObjects < 1 {
				maxObjects = 1
			}
			p.maxObjects = maxObjects
		}
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(p.region))
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}
	p.client = s3.NewFromConfig(cfg)

	return nil
}

func (p *S3Provider) Test(ctx context.Context) error {
	if p.client == nil {
		return fmt.Errorf("s3 client not configured")
	}
	_, err := p.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(p.bucket)})
	return err
}

func (p *S3Provider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "s3_input_objects",
			Description: "S3 objects fetched and parsed by the S3 input provider",
			Columns: []ColumnSchema{
				{Name: "bucket", Type: "string", Required: true},
				{Name: "object_key", Type: "string", Required: true},
				{Name: "object_etag", Type: "string", Required: true},
				{Name: "size_bytes", Type: "integer"},
				{Name: "last_modified", Type: "timestamp"},
				{Name: "parse_format", Type: "string"},
				{Name: "records_parsed", Type: "integer"},
				{Name: "parse_error", Type: "string"},
			},
			PrimaryKey: []string{"bucket", "object_key", "object_etag"},
		},
		{
			Name:        "s3_input_records",
			Description: "Parsed records extracted from S3 objects",
			Columns: []ColumnSchema{
				{Name: "bucket", Type: "string", Required: true},
				{Name: "object_key", Type: "string", Required: true},
				{Name: "object_etag", Type: "string", Required: true},
				{Name: "object_last_modified", Type: "timestamp"},
				{Name: "record_index", Type: "integer", Required: true},
				{Name: "record", Type: "object"},
				{Name: "raw_text", Type: "string"},
				{Name: "parse_error", Type: "string"},
			},
			PrimaryKey: []string{"bucket", "object_key", "object_etag", "record_index"},
		},
	}
}

func (p *S3Provider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{Provider: p.Name(), StartedAt: start}

	if p.client == nil {
		return result, fmt.Errorf("s3 client not configured")
	}

	syncObjects := tableRequested(opts.Tables, "s3_input_objects")
	syncRecords := tableRequested(opts.Tables, "s3_input_records")
	if len(opts.Tables) > 0 && !syncObjects && !syncRecords {
		return result, fmt.Errorf("no matching S3 tables in filter: %s", strings.Join(opts.Tables, ", "))
	}

	objects, err := p.listObjects(ctx)
	if err != nil {
		return result, fmt.Errorf("list s3 objects: %w", err)
	}

	objectRows := make([]map[string]interface{}, 0, len(objects))
	recordRows := make([]map[string]interface{}, 0)

	for _, object := range objects {
		parsed, parseErr := p.parseObject(ctx, object)

		objectRow := map[string]interface{}{
			"bucket":         p.bucket,
			"object_key":     object.Key,
			"object_etag":    object.ETag,
			"size_bytes":     object.SizeBytes,
			"last_modified":  object.LastModified,
			"parse_format":   parsed.Format,
			"records_parsed": len(parsed.Records),
		}

		if parseErr != nil {
			objectRow["parse_error"] = parseErr.Error()
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", object.Key, parseErr))
			objectRows = append(objectRows, objectRow)
			continue
		}

		if parsed.ParseErrors > 0 {
			parseSummary := fmt.Sprintf("%d record(s) failed to parse", parsed.ParseErrors)
			objectRow["parse_error"] = parseSummary
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", object.Key, parseSummary))
		}

		objectRows = append(objectRows, objectRow)

		for idx, record := range parsed.Records {
			recordRow := map[string]interface{}{
				"bucket":               p.bucket,
				"object_key":           object.Key,
				"object_etag":          object.ETag,
				"object_last_modified": object.LastModified,
				"record_index":         idx,
			}
			if record.Data != nil {
				recordRow["record"] = record.Data
			}
			if record.RawText != "" {
				recordRow["raw_text"] = record.RawText
			}
			if record.ParseError != "" {
				recordRow["parse_error"] = record.ParseError
			}
			recordRows = append(recordRows, recordRow)
		}
	}

	if syncObjects {
		table, err := p.syncS3Table(ctx, "s3_input_objects", objectRows)
		if err != nil {
			return result, err
		}
		result.Tables = append(result.Tables, *table)
		result.TotalRows += table.Rows
	}

	if syncRecords {
		table, err := p.syncS3Table(ctx, "s3_input_records", recordRows)
		if err != nil {
			return result, err
		}
		result.Tables = append(result.Tables, *table)
		result.TotalRows += table.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (p *S3Provider) syncS3Table(ctx context.Context, tableName string, rows []map[string]interface{}) (*TableResult, error) {
	schema, ok := schemaByName(p.Schema(), tableName)
	if !ok {
		return &TableResult{Name: tableName}, fmt.Errorf("schema not found: %s", tableName)
	}

	return p.syncTable(ctx, schema, rows)
}

func (p *S3Provider) listObjects(ctx context.Context) ([]s3ObjectMeta, error) {
	objects := make([]s3ObjectMeta, 0)
	input := &s3.ListObjectsV2Input{Bucket: aws.String(p.bucket)}
	if p.prefix != "" {
		input.Prefix = aws.String(p.prefix)
	}

	for len(objects) < p.maxObjects {
		output, err := p.client.ListObjectsV2(ctx, input)
		if err != nil {
			return nil, err
		}

		for _, object := range output.Contents {
			key := strings.TrimSpace(aws.ToString(object.Key))
			if key == "" {
				continue
			}

			etag := strings.Trim(aws.ToString(object.ETag), "\"")
			if etag == "" {
				lastModified := aws.ToTime(object.LastModified).UTC()
				etag = fmt.Sprintf("fallback-%d-%d", aws.ToInt64(object.Size), lastModified.UnixNano())
			}

			objects = append(objects, s3ObjectMeta{
				Key:          key,
				ETag:         etag,
				SizeBytes:    aws.ToInt64(object.Size),
				LastModified: aws.ToTime(object.LastModified).UTC(),
			})

			if len(objects) >= p.maxObjects {
				break
			}
		}

		if len(objects) >= p.maxObjects || !aws.ToBool(output.IsTruncated) {
			break
		}

		if strings.TrimSpace(aws.ToString(output.NextContinuationToken)) == "" {
			break
		}
		input.ContinuationToken = output.NextContinuationToken
	}

	sort.Slice(objects, func(i, j int) bool {
		if objects[i].LastModified.Equal(objects[j].LastModified) {
			return objects[i].Key < objects[j].Key
		}
		return objects[i].LastModified.After(objects[j].LastModified)
	})

	return objects, nil
}

func (p *S3Provider) parseObject(ctx context.Context, object s3ObjectMeta) (s3ParseOutput, error) {
	output, err := p.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(object.Key),
	})
	if err != nil {
		return s3ParseOutput{}, err
	}
	defer func() { _ = output.Body.Close() }()

	reader := io.Reader(output.Body)
	if shouldGunzip(object.Key, aws.ToString(output.ContentEncoding)) {
		gzipReader, err := gzip.NewReader(output.Body)
		if err != nil {
			return s3ParseOutput{}, fmt.Errorf("open gzip stream: %w", err)
		}
		defer func() { _ = gzipReader.Close() }()
		reader = gzipReader
	}

	format := p.resolveFormat(object.Key)
	records, parseErrors, err := parseS3Records(reader, format, p.maxRecordsPerObject)
	if err != nil {
		return s3ParseOutput{Format: format}, err
	}

	return s3ParseOutput{
		Format:      format,
		Records:     records,
		ParseErrors: parseErrors,
	}, nil
}

func normalizeS3InputFormat(raw string) (string, error) {
	format := strings.ToLower(strings.TrimSpace(raw))
	switch format {
	case "", "auto", "json", "jsonl", "csv", "text":
		if format == "" {
			return defaultS3InputFormat, nil
		}
		return format, nil
	default:
		return "", fmt.Errorf("unsupported s3 input format %q (allowed: auto, json, jsonl, csv, text)", raw)
	}
}

func intFromConfig(value interface{}) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int32:
		return int(typed), true
	case int64:
		return int(typed), true
	case float64:
		return int(typed), true
	case float32:
		return int(typed), true
	case json.Number:
		v, err := typed.Int64()
		if err != nil {
			return 0, false
		}
		return int(v), true
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return 0, false
		}
		v, err := strconv.Atoi(trimmed)
		if err != nil {
			return 0, false
		}
		return v, true
	default:
		return 0, false
	}
}

func tableRequested(selected []string, tableName string) bool {
	if len(selected) == 0 {
		return true
	}
	for _, table := range selected {
		if strings.EqualFold(strings.TrimSpace(table), tableName) {
			return true
		}
	}
	return false
}

func shouldGunzip(key, contentEncoding string) bool {
	if strings.HasSuffix(strings.ToLower(strings.TrimSpace(key)), ".gz") {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(contentEncoding), "gzip")
}

func (p *S3Provider) resolveFormat(key string) string {
	if p.format != "" && p.format != "auto" {
		return p.format
	}

	name := strings.ToLower(strings.TrimSpace(key))
	name = strings.TrimSuffix(name, ".gz")

	switch {
	case strings.HasSuffix(name, ".jsonl"), strings.HasSuffix(name, ".ndjson"):
		return "jsonl"
	case strings.HasSuffix(name, ".json"):
		return "json"
	case strings.HasSuffix(name, ".csv"):
		return "csv"
	default:
		return "text"
	}
}

func parseS3Records(reader io.Reader, format string, maxRecords int) ([]s3ParsedRecord, int, error) {
	if maxRecords < 1 {
		maxRecords = defaultS3InputMaxRecordsPerObject
	}

	switch format {
	case "json":
		return parseS3JSON(reader, maxRecords)
	case "jsonl":
		return parseS3JSONLines(reader, maxRecords)
	case "csv":
		return parseS3CSV(reader, maxRecords)
	case "text":
		return parseS3Text(reader, maxRecords)
	default:
		return nil, 0, fmt.Errorf("unsupported parse format %q", format)
	}
}

func parseS3JSON(reader io.Reader, maxRecords int) ([]s3ParsedRecord, int, error) {
	decoder := json.NewDecoder(reader)
	decoder.UseNumber()

	var payload interface{}
	if err := decoder.Decode(&payload); err != nil {
		return nil, 0, err
	}

	records := make([]s3ParsedRecord, 0)
	appendValue := func(value interface{}) {
		if len(records) >= maxRecords {
			return
		}
		records = append(records, s3ParsedRecord{Data: toRecordMap(value)})
	}

	switch typed := payload.(type) {
	case []interface{}:
		for _, item := range typed {
			appendValue(item)
			if len(records) >= maxRecords {
				break
			}
		}
	default:
		appendValue(typed)
	}

	return records, 0, nil
}

func parseS3JSONLines(reader io.Reader, maxRecords int) ([]s3ParsedRecord, int, error) {
	scanner := bufio.NewScanner(reader)
	buffer := make([]byte, s3ScannerBufferSize)
	scanner.Buffer(buffer, s3ScannerMaxTokenSize)

	records := make([]s3ParsedRecord, 0)
	parseErrors := 0

	for scanner.Scan() {
		if len(records) >= maxRecords {
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		decoder := json.NewDecoder(strings.NewReader(line))
		decoder.UseNumber()

		var payload interface{}
		if err := decoder.Decode(&payload); err != nil {
			parseErrors++
			records = append(records, s3ParsedRecord{RawText: line, ParseError: err.Error()})
			continue
		}

		records = append(records, s3ParsedRecord{Data: toRecordMap(payload), RawText: line})
	}

	if err := scanner.Err(); err != nil {
		return nil, parseErrors, err
	}

	return records, parseErrors, nil
}

func parseS3CSV(reader io.Reader, maxRecords int) ([]s3ParsedRecord, int, error) {
	csvReader := csv.NewReader(reader)
	csvReader.FieldsPerRecord = -1

	headers, err := csvReader.Read()
	if err != nil {
		if err == io.EOF {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	headers = normalizeCSVHeaders(headers)

	records := make([]s3ParsedRecord, 0)
	for len(records) < maxRecords {
		row, err := csvReader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, 0, err
		}

		mapped := make(map[string]interface{}, len(headers))
		for i, header := range headers {
			if i < len(row) {
				mapped[header] = row[i]
			} else {
				mapped[header] = ""
			}
		}
		records = append(records, s3ParsedRecord{Data: mapped})
	}

	return records, 0, nil
}

func parseS3Text(reader io.Reader, maxRecords int) ([]s3ParsedRecord, int, error) {
	scanner := bufio.NewScanner(reader)
	buffer := make([]byte, s3ScannerBufferSize)
	scanner.Buffer(buffer, s3ScannerMaxTokenSize)

	records := make([]s3ParsedRecord, 0)
	for scanner.Scan() {
		if len(records) >= maxRecords {
			break
		}
		line := scanner.Text()
		records = append(records, s3ParsedRecord{
			Data:    map[string]interface{}{"line": line},
			RawText: line,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, 0, err
	}

	return records, 0, nil
}

func normalizeCSVHeaders(headers []string) []string {
	result := make([]string, 0, len(headers))
	seen := make(map[string]int, len(headers))

	for i, header := range headers {
		normalized := strings.TrimSpace(header)
		if normalized == "" {
			normalized = fmt.Sprintf("column_%d", i+1)
		}

		if count, ok := seen[normalized]; ok {
			count++
			seen[normalized] = count
			normalized = fmt.Sprintf("%s_%d", normalized, count)
		} else {
			seen[normalized] = 1
		}

		result = append(result, normalized)
	}

	return result
}

func toRecordMap(value interface{}) map[string]interface{} {
	if value == nil {
		return map[string]interface{}{}
	}
	if typed, ok := value.(map[string]interface{}); ok {
		return typed
	}
	return map[string]interface{}{"value": value}
}
