package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodbstreams"
	dynamodbstreamstypes "github.com/aws/aws-sdk-go-v2/service/dynamodbstreams/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsDynamoDBTable struct {
	Table             dynamodbtypes.TableDescription
	Tags              map[string]string
	ContinuousBackups *dynamodbtypes.ContinuousBackupsDescription
	TimeToLive        *dynamodbtypes.TimeToLiveDescription
}

type awsDynamoDBBackup = dynamodbtypes.BackupSummary

type awsDynamoDBStream struct {
	Stream dynamodbstreamstypes.StreamDescription
}

func listDynamoDBTables(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsDynamoDBTable, string, error) {
	out, err := clients.dynamodb.ListTables(ctx, &dynamodb.ListTablesInput{
		ExclusiveStartTableName: stringPtr(cursor),
		Limit:                   awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsDynamoDBTable, 0, len(out.TableNames))
	for _, tableName := range out.TableNames {
		tableName = strings.TrimSpace(tableName)
		if tableName == "" {
			continue
		}
		describe, err := clients.dynamodb.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: awssdk.String(tableName)})
		if err != nil {
			return nil, "", fmt.Errorf("describe dynamodb table %q: %w", tableName, err)
		}
		if describe.Table == nil {
			continue
		}
		record := awsDynamoDBTable{Table: *describe.Table}
		arn := awssdk.ToString(describe.Table.TableArn)
		if arn != "" {
			tags, err := listAllDynamoDBTags(ctx, clients, arn)
			if err != nil {
				return nil, "", fmt.Errorf("list dynamodb table tags %q: %w", arn, err)
			}
			record.Tags = tags
		}
		if backups, err := clients.dynamodb.DescribeContinuousBackups(ctx, &dynamodb.DescribeContinuousBackupsInput{TableName: awssdk.String(tableName)}); err == nil {
			record.ContinuousBackups = backups.ContinuousBackupsDescription
		} else if !optionalAWSError(err, "ResourceNotFoundException", "TableNotFoundException", "ContinuousBackupsUnavailableException") {
			return nil, "", fmt.Errorf("describe dynamodb continuous backups %q: %w", tableName, err)
		}
		if ttl, err := clients.dynamodb.DescribeTimeToLive(ctx, &dynamodb.DescribeTimeToLiveInput{TableName: awssdk.String(tableName)}); err == nil {
			record.TimeToLive = ttl.TimeToLiveDescription
		} else if !optionalAWSError(err, "ResourceNotFoundException", "TableNotFoundException") {
			return nil, "", fmt.Errorf("describe dynamodb ttl %q: %w", tableName, err)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.LastEvaluatedTableName), nil
}

func listDynamoDBBackups(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsDynamoDBBackup, string, error) {
	out, err := clients.dynamodb.ListBackups(ctx, &dynamodb.ListBackupsInput{
		BackupType:              dynamodbtypes.BackupTypeFilterAll,
		ExclusiveStartBackupArn: stringPtr(cursor),
		Limit:                   awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
	})
	if err != nil {
		return nil, "", err
	}
	return out.BackupSummaries, awssdk.ToString(out.LastEvaluatedBackupArn), nil
}

func listDynamoDBStreams(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsDynamoDBStream, string, error) {
	out, err := clients.dynamodbStreams.ListStreams(ctx, &dynamodbstreams.ListStreamsInput{
		ExclusiveStartStreamArn: stringPtr(cursor),
		Limit:                   awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsDynamoDBStream, 0, len(out.Streams))
	for _, stream := range out.Streams {
		arn := awssdk.ToString(stream.StreamArn)
		if arn == "" {
			continue
		}
		describe, err := clients.dynamodbStreams.DescribeStream(ctx, &dynamodbstreams.DescribeStreamInput{
			StreamArn: awssdk.String(arn),
		})
		if err != nil {
			return nil, "", fmt.Errorf("describe dynamodb stream %q: %w", arn, err)
		}
		if describe.StreamDescription != nil {
			records = append(records, awsDynamoDBStream{Stream: *describe.StreamDescription})
		}
	}
	return records, awssdk.ToString(out.LastEvaluatedStreamArn), nil
}

func dynamoDBTableEvent(settings settings, record awsDynamoDBTable) (*primitives.Event, error) {
	table := record.Table
	arn := awssdk.ToString(table.TableArn)
	name := awssdk.ToString(table.TableName)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyDynamoDBTable, firstNonEmpty(arn, awssdk.ToString(table.TableId), name), name, "dynamodb_table", record.Tags)
	attributes["arn"] = arn
	attributes["table_arn"] = arn
	attributes["table_id"] = awssdk.ToString(table.TableId)
	attributes["table_name"] = name
	attributes["state"] = string(table.TableStatus)
	attributes["billing_mode"] = dynamoDBBillingMode(table)
	attributes["table_class"] = dynamoDBTableClass(table)
	attributes["item_count"] = int64AttrString(table.ItemCount)
	attributes["size_bytes"] = int64AttrString(table.TableSizeBytes)
	attributes["deletion_protection"] = boolString(awssdk.ToBool(table.DeletionProtectionEnabled))
	attributes["stream_enabled"] = boolString(table.StreamSpecification != nil && awssdk.ToBool(table.StreamSpecification.StreamEnabled))
	attributes["latest_stream_arn"] = awssdk.ToString(table.LatestStreamArn)
	attributes["latest_stream_label"] = awssdk.ToString(table.LatestStreamLabel)
	attributes["encryption"] = boolString(table.SSEDescription != nil && table.SSEDescription.Status == dynamodbtypes.SSEStatusEnabled)
	attributes["gsi_count"] = strconv.Itoa(len(table.GlobalSecondaryIndexes))
	attributes["lsi_count"] = strconv.Itoa(len(table.LocalSecondaryIndexes))
	attributes["replica_count"] = strconv.Itoa(len(table.Replicas))
	if table.SSEDescription != nil {
		attributes["sse_status"] = string(table.SSEDescription.Status)
		attributes["sse_type"] = string(table.SSEDescription.SSEType)
		attributes["kms_key_id"] = awssdk.ToString(table.SSEDescription.KMSMasterKeyArn)
	}
	if record.ContinuousBackups != nil {
		attributes["continuous_backups"] = string(record.ContinuousBackups.ContinuousBackupsStatus)
		if pitr := record.ContinuousBackups.PointInTimeRecoveryDescription; pitr != nil {
			attributes["point_in_time_recovery"] = string(pitr.PointInTimeRecoveryStatus)
			attributes["pitr_recovery_days"] = int32AttrString(pitr.RecoveryPeriodInDays)
		}
	}
	if record.TimeToLive != nil {
		attributes["ttl_status"] = string(record.TimeToLive.TimeToLiveStatus)
		attributes["ttl_attribute"] = awssdk.ToString(record.TimeToLive.AttributeName)
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "table": table, "continuous_backups": record.ContinuousBackups, "time_to_live": record.TimeToLive, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-dynamodb-table-"+firstNonEmpty(arn, name), "aws.dynamodb_table", "aws/dynamodb_table/v1", payload, attributes, firstTime(table.CreationDateTime))
}

func dynamoDBBackupEvent(settings settings, backup awsDynamoDBBackup) (*primitives.Event, error) {
	arn := awssdk.ToString(backup.BackupArn)
	name := awssdk.ToString(backup.BackupName)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyDynamoDBBackup, firstNonEmpty(arn, name), name, "dynamodb_backup", nil)
	attributes["arn"] = arn
	attributes["backup_arn"] = arn
	attributes["backup_name"] = name
	attributes["backup_type"] = string(backup.BackupType)
	attributes["state"] = string(backup.BackupStatus)
	attributes["size_bytes"] = int64AttrString(backup.BackupSizeBytes)
	attributes["table_arn"] = awssdk.ToString(backup.TableArn)
	attributes["table_id"] = awssdk.ToString(backup.TableId)
	attributes["table_name"] = awssdk.ToString(backup.TableName)
	addTimeAttribute(attributes, "expires_at", backup.BackupExpiryDateTime)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "backup": backup})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-dynamodb-backup-"+firstNonEmpty(arn, name), "aws.dynamodb_backup", "aws/dynamodb_backup/v1", payload, attributes, firstTime(backup.BackupCreationDateTime))
}

func dynamoDBStreamEvent(settings settings, record awsDynamoDBStream) (*primitives.Event, error) {
	stream := record.Stream
	arn := awssdk.ToString(stream.StreamArn)
	label := awssdk.ToString(stream.StreamLabel)
	tableName := awssdk.ToString(stream.TableName)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyDynamoDBStream, firstNonEmpty(arn, label), firstNonEmpty(label, tableName), "dynamodb_stream", nil)
	attributes["arn"] = arn
	attributes["stream_arn"] = arn
	attributes["stream_label"] = label
	attributes["table_name"] = tableName
	attributes["state"] = string(stream.StreamStatus)
	attributes["view_type"] = string(stream.StreamViewType)
	attributes["shard_count"] = strconv.Itoa(len(stream.Shards))
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "stream": stream})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-dynamodb-stream-"+firstNonEmpty(arn, label), "aws.dynamodb_stream", "aws/dynamodb_stream/v1", payload, attributes, firstTime(stream.CreationRequestDateTime))
}

func listAllDynamoDBTags(ctx context.Context, clients awsClients, arn string) (map[string]string, error) {
	tags := map[string]string{}
	var token *string
	for {
		out, err := clients.dynamodb.ListTagsOfResource(ctx, &dynamodb.ListTagsOfResourceInput{ResourceArn: awssdk.String(arn), NextToken: token})
		if err != nil {
			if optionalAWSError(err, "ResourceNotFoundException", "TableNotFoundException") {
				return tags, nil
			}
			return nil, err
		}
		for key, value := range dynamoDBTagMap(out.Tags) {
			tags[key] = value
		}
		token = out.NextToken
		if awssdk.ToString(token) == "" {
			return tags, nil
		}
	}
}

func dynamoDBTagMap(tags []dynamodbtypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func dynamoDBBillingMode(table dynamodbtypes.TableDescription) string {
	if table.BillingModeSummary != nil {
		return string(table.BillingModeSummary.BillingMode)
	}
	if table.ProvisionedThroughput != nil {
		return string(dynamodbtypes.BillingModeProvisioned)
	}
	return ""
}

func dynamoDBTableClass(table dynamodbtypes.TableDescription) string {
	if table.TableClassSummary == nil {
		return ""
	}
	return string(table.TableClassSummary.TableClass)
}
