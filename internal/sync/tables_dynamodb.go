package sync

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func (e *SyncEngine) dynamoDBTableTable() TableSpec {
	return TableSpec{
		Name:    "aws_dynamodb_tables",
		Columns: []string{"arn", "account_id", "region", "table_name", "name", "table_status", "creation_date_time", "item_count", "table_size_bytes", "billing_mode", "read_capacity_units", "write_capacity_units", "key_schema", "attribute_definitions", "global_secondary_indexes", "local_secondary_indexes", "stream_enabled", "stream_view_type", "latest_stream_arn", "sse_description", "deletion_protection_enabled", "table_class", "tags"},
		Fetch:   e.fetchDynamoDBTables,
	}
}

func (e *SyncEngine) fetchDynamoDBTables(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := dynamodb.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	// List all tables
	var tableNames []string
	paginator := dynamodb.NewListTablesPaginator(client, &dynamodb.ListTablesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		tableNames = append(tableNames, page.TableNames...)
	}

	rows := make([]map[string]interface{}, 0, len(tableNames))
	for _, tableName := range tableNames {
		// Describe each table
		desc, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{
			TableName: aws.String(tableName),
		})
		if err != nil {
			continue
		}

		table := desc.Table
		arn := aws.ToString(table.TableArn)

		row := map[string]interface{}{
			"_cq_id":                      arn,
			"arn":                         arn,
			"account_id":                  accountID,
			"region":                      region,
			"table_name":                  tableName,
			"name":                        tableName,
			"table_status":                string(table.TableStatus),
			"creation_date_time":          table.CreationDateTime,
			"item_count":                  table.ItemCount,
			"table_size_bytes":            table.TableSizeBytes,
			"key_schema":                  table.KeySchema,
			"attribute_definitions":       table.AttributeDefinitions,
			"global_secondary_indexes":    table.GlobalSecondaryIndexes,
			"local_secondary_indexes":     table.LocalSecondaryIndexes,
			"deletion_protection_enabled": table.DeletionProtectionEnabled,
		}

		if table.TableClassSummary != nil {
			row["table_class"] = string(table.TableClassSummary.TableClass)
		}

		if table.BillingModeSummary != nil {
			row["billing_mode"] = string(table.BillingModeSummary.BillingMode)
		}

		if table.ProvisionedThroughput != nil {
			row["read_capacity_units"] = table.ProvisionedThroughput.ReadCapacityUnits
			row["write_capacity_units"] = table.ProvisionedThroughput.WriteCapacityUnits
		}

		if table.StreamSpecification != nil {
			row["stream_enabled"] = aws.ToBool(table.StreamSpecification.StreamEnabled)
			row["stream_view_type"] = string(table.StreamSpecification.StreamViewType)
		}
		row["latest_stream_arn"] = aws.ToString(table.LatestStreamArn)

		if table.SSEDescription != nil {
			row["sse_description"] = map[string]interface{}{
				"status":      string(table.SSEDescription.Status),
				"sse_type":    string(table.SSEDescription.SSEType),
				"kms_key_arn": aws.ToString(table.SSEDescription.KMSMasterKeyArn),
			}
		}

		// Get tags
		tagsOut, err := client.ListTagsOfResource(ctx, &dynamodb.ListTagsOfResourceInput{
			ResourceArn: aws.String(arn),
		})
		if err == nil && tagsOut.Tags != nil {
			row["tags"] = tagsOut.Tags
		}

		rows = append(rows, row)
	}
	return rows, nil
}
