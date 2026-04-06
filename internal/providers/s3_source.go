package providers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// S3SourceProvider ingests files from a named S3 source with support for
// multiple prefixes and cross-account IAM role assumption.
type S3SourceProvider struct {
	*BaseProvider
	sourceName          string
	bucket              string
	prefixes            []string
	region              string
	format              string
	roleARN             string
	externalID          string
	maxObjects          int
	maxRecordsPerObject int
	client              s3API
}

func NewS3SourceProvider(sourceName string) *S3SourceProvider {
	normalized := strings.ToLower(strings.TrimSpace(sourceName))
	return &S3SourceProvider{
		BaseProvider:        NewBaseProvider("s3-"+normalized, ProviderTypeCloud),
		sourceName:          normalized,
		region:              defaultS3InputRegion,
		format:              defaultS3InputFormat,
		maxObjects:          defaultS3InputMaxObjects,
		maxRecordsPerObject: defaultS3InputMaxRecordsPerObject,
	}
}

func (p *S3SourceProvider) Configure(ctx context.Context, cfgMap map[string]interface{}) error {
	if err := p.BaseProvider.Configure(ctx, cfgMap); err != nil {
		return err
	}

	p.bucket = strings.TrimSpace(p.GetConfigString("bucket"))
	if p.bucket == "" {
		return fmt.Errorf("s3 source %q: bucket required", p.sourceName)
	}

	p.prefixes = parseS3SourcePrefixes(p.GetConfig("prefixes"))
	if prefix := strings.TrimSpace(p.GetConfigString("prefix")); prefix != "" && len(p.prefixes) == 0 {
		p.prefixes = []string{prefix}
	}

	if region := strings.TrimSpace(p.GetConfigString("region")); region != "" {
		p.region = region
	}
	if format := strings.TrimSpace(p.GetConfigString("format")); format != "" {
		normalized, err := normalizeS3InputFormat(format)
		if err != nil {
			return fmt.Errorf("s3 source %q: %w", p.sourceName, err)
		}
		p.format = normalized
	}
	if rawMax := p.GetConfig("max_objects"); rawMax != nil {
		if maxObjects, ok := intFromConfig(rawMax); ok && maxObjects >= 1 {
			p.maxObjects = maxObjects
		}
	}
	if rawMax := p.GetConfig("max_records_per_object"); rawMax != nil {
		if maxRec, ok := intFromConfig(rawMax); ok && maxRec >= 1 {
			p.maxRecordsPerObject = maxRec
		}
	}

	p.roleARN = strings.TrimSpace(p.GetConfigString("role_arn"))
	p.externalID = strings.TrimSpace(p.GetConfigString("external_id"))

	client, err := p.buildS3Client(ctx)
	if err != nil {
		return fmt.Errorf("s3 source %q: %w", p.sourceName, err)
	}
	p.client = client

	return nil
}

func (p *S3SourceProvider) buildS3Client(ctx context.Context) (s3API, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(p.region))
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	if p.roleARN != "" {
		stsClient := sts.NewFromConfig(cfg)
		provider := stscreds.NewAssumeRoleProvider(stsClient, p.roleARN, func(opts *stscreds.AssumeRoleOptions) {
			opts.RoleSessionName = fmt.Sprintf("cerebro-s3-%s", p.sourceName)
			if p.externalID != "" {
				opts.ExternalID = aws.String(p.externalID)
			}
		})
		cfg.Credentials = aws.NewCredentialsCache(provider)
	}

	return s3.NewFromConfig(cfg), nil
}

func (p *S3SourceProvider) Test(ctx context.Context) error {
	if p.client == nil {
		return fmt.Errorf("s3 source %q: client not configured", p.sourceName)
	}
	_, err := p.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(p.bucket)})
	return err
}

func (p *S3SourceProvider) objectsTableName() string {
	return fmt.Sprintf("s3_%s_objects", p.sourceName)
}

func (p *S3SourceProvider) recordsTableName() string {
	return fmt.Sprintf("s3_%s_records", p.sourceName)
}

func (p *S3SourceProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        p.objectsTableName(),
			Description: fmt.Sprintf("S3 objects from the %s source", p.sourceName),
			Columns: []ColumnSchema{
				{Name: "source", Type: "string", Required: true},
				{Name: "bucket", Type: "string", Required: true},
				{Name: "object_key", Type: "string", Required: true},
				{Name: "object_etag", Type: "string", Required: true},
				{Name: "size_bytes", Type: "integer"},
				{Name: "last_modified", Type: "timestamp"},
				{Name: "parse_format", Type: "string"},
				{Name: "records_parsed", Type: "integer"},
				{Name: "parse_error", Type: "string"},
			},
			PrimaryKey: []string{"source", "bucket", "object_key", "object_etag"},
		},
		{
			Name:        p.recordsTableName(),
			Description: fmt.Sprintf("Parsed records from the %s source", p.sourceName),
			Columns: []ColumnSchema{
				{Name: "source", Type: "string", Required: true},
				{Name: "bucket", Type: "string", Required: true},
				{Name: "object_key", Type: "string", Required: true},
				{Name: "object_etag", Type: "string", Required: true},
				{Name: "object_last_modified", Type: "timestamp"},
				{Name: "record_index", Type: "integer", Required: true},
				{Name: "record", Type: "object"},
				{Name: "raw_text", Type: "string"},
				{Name: "parse_error", Type: "string"},
			},
			PrimaryKey: []string{"source", "bucket", "object_key", "object_etag", "record_index"},
		},
	}
}

func (p *S3SourceProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{Provider: p.Name(), StartedAt: start}

	if p.client == nil {
		return result, fmt.Errorf("s3 source %q: client not configured", p.sourceName)
	}

	objTable := p.objectsTableName()
	recTable := p.recordsTableName()
	syncObjects := tableRequested(opts.Tables, objTable)
	syncRecords := tableRequested(opts.Tables, recTable)
	if len(opts.Tables) > 0 && !syncObjects && !syncRecords {
		return result, fmt.Errorf("no matching tables in filter: %s", strings.Join(opts.Tables, ", "))
	}

	prefixes := p.prefixes
	if len(prefixes) == 0 {
		prefixes = []string{""}
	}

	objectRows := make([]map[string]interface{}, 0)
	recordRows := make([]map[string]interface{}, 0)
	processedObjects := 0
	seen := make(map[string]struct{})

	for _, prefix := range prefixes {
		remaining := p.maxObjects - processedObjects
		if remaining <= 0 {
			break
		}

		objects, err := p.listObjectsWithPrefix(ctx, prefix, remaining, seen)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("prefix %q: %v", prefix, err))
			continue
		}

		processedObjects += len(objects)

		for _, object := range objects {
			parsed, parseErr := p.parseObject(ctx, object)

			objectRow := map[string]interface{}{
				"source":         p.sourceName,
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
				summary := fmt.Sprintf("%d record(s) failed to parse", parsed.ParseErrors)
				objectRow["parse_error"] = summary
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", object.Key, summary))
			}

			objectRows = append(objectRows, objectRow)

			for idx, record := range parsed.Records {
				recordRow := map[string]interface{}{
					"source":               p.sourceName,
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
	}

	if syncObjects {
		table, err := p.syncSourceTable(ctx, objTable, objectRows)
		if err != nil {
			return result, err
		}
		result.Tables = append(result.Tables, *table)
		result.TotalRows += table.Rows
	}

	if syncRecords {
		table, err := p.syncSourceTable(ctx, recTable, recordRows)
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

func (p *S3SourceProvider) syncSourceTable(ctx context.Context, tableName string, rows []map[string]interface{}) (*TableResult, error) {
	schema, ok := schemaByName(p.Schema(), tableName)
	if !ok {
		return &TableResult{Name: tableName}, fmt.Errorf("schema not found: %s", tableName)
	}
	return p.syncTable(ctx, schema, rows)
}

func (p *S3SourceProvider) listObjectsWithPrefix(ctx context.Context, prefix string, maxObjects int, seen map[string]struct{}) ([]s3ObjectMeta, error) {
	objects := make([]s3ObjectMeta, 0)
	localSeen := make(map[string]struct{})
	if maxObjects < 1 {
		return objects, nil
	}
	input := &s3.ListObjectsV2Input{Bucket: aws.String(p.bucket)}
	if prefix != "" {
		input.Prefix = aws.String(prefix)
	}

	for len(objects) < maxObjects {
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

			dedupKey := key + "\x00" + etag
			if _, dup := seen[dedupKey]; dup {
				continue
			}
			if _, dup := localSeen[dedupKey]; dup {
				continue
			}
			localSeen[dedupKey] = struct{}{}

			objects = append(objects, s3ObjectMeta{
				Key:          key,
				ETag:         etag,
				SizeBytes:    aws.ToInt64(object.Size),
				LastModified: aws.ToTime(object.LastModified).UTC(),
			})

			if len(objects) >= maxObjects {
				break
			}
		}

		if len(objects) >= maxObjects || !aws.ToBool(output.IsTruncated) {
			break
		}

		if strings.TrimSpace(aws.ToString(output.NextContinuationToken)) == "" {
			break
		}
		input.ContinuationToken = output.NextContinuationToken
	}

	for dedupKey := range localSeen {
		seen[dedupKey] = struct{}{}
	}
	return objects, nil
}

func (p *S3SourceProvider) parseObject(ctx context.Context, object s3ObjectMeta) (s3ParseOutput, error) {
	output, err := p.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(object.Key),
	})
	if err != nil {
		return s3ParseOutput{}, err
	}
	defer func() { _ = output.Body.Close() }()

	reader, cleanup, err := maybeGunzipReader(output.Body, object.Key, aws.ToString(output.ContentEncoding))
	if err != nil {
		return s3ParseOutput{}, err
	}
	if cleanup != nil {
		defer cleanup()
	}

	format := resolveS3Format(p.format, object.Key)
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

func parseS3SourcePrefixes(value interface{}) []string {
	if value == nil {
		return nil
	}
	switch typed := value.(type) {
	case []string:
		out := make([]string, 0, len(typed))
		for _, s := range typed {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				out = append(out, trimmed)
			}
		}
		return out
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if s, ok := item.(string); ok {
				if trimmed := strings.TrimSpace(s); trimmed != "" {
					out = append(out, trimmed)
				}
			}
		}
		return out
	case string:
		if trimmed := strings.TrimSpace(typed); trimmed != "" {
			var out []string
			for _, p := range strings.Split(trimmed, ",") {
				if t := strings.TrimSpace(p); t != "" {
					out = append(out, t)
				}
			}
			return out
		}
	}
	return nil
}

// S3SourceConfig holds the configuration for a single named S3 source.
type S3SourceConfig struct {
	Name                string
	Bucket              string
	Prefixes            []string
	Region              string
	Format              string
	RoleARN             string
	ExternalID          string
	MaxObjects          int
	MaxRecordsPerObject int
}

// ParseS3Sources parses the S3_SOURCES env var and per-source config into a list of source configs.
func ParseS3Sources(getEnv func(string, string) string, getEnvInt func(string, int) int) []S3SourceConfig {
	raw := strings.TrimSpace(getEnv("S3_SOURCES", ""))
	if raw == "" {
		return nil
	}

	var sources []S3SourceConfig
	for _, name := range strings.Split(raw, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		upper := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
		prefix := "S3_SOURCE_" + upper + "_"

		bucket := strings.TrimSpace(getEnv(prefix+"BUCKET", ""))
		if bucket == "" {
			continue
		}

		var prefixes []string
		if raw := strings.TrimSpace(getEnv(prefix+"PREFIXES", "")); raw != "" {
			for _, p := range strings.Split(raw, ",") {
				if trimmed := strings.TrimSpace(p); trimmed != "" {
					prefixes = append(prefixes, trimmed)
				}
			}
		}

		sources = append(sources, S3SourceConfig{
			Name:                name,
			Bucket:              bucket,
			Prefixes:            prefixes,
			Region:              getEnv(prefix+"REGION", getEnv("AWS_REGION", "us-east-1")),
			Format:              getEnv(prefix+"FORMAT", "auto"),
			RoleARN:             getEnv(prefix+"ROLE_ARN", ""),
			ExternalID:          getEnv(prefix+"EXTERNAL_ID", ""),
			MaxObjects:          getEnvInt(prefix+"MAX_OBJECTS", 200),
			MaxRecordsPerObject: getEnvInt(prefix+"MAX_RECORDS_PER_OBJECT", defaultS3InputMaxRecordsPerObject),
		})
	}

	return sources
}
