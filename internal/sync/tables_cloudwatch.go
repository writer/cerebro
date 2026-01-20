package sync

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

func (e *SyncEngine) cloudwatchLogGroupTable() TableSpec {
	return TableSpec{
		Name:    "aws_cloudwatch_log_groups",
		Columns: []string{"arn", "account_id", "region", "log_group_name", "name", "creation_time", "retention_in_days", "metric_filter_count", "stored_bytes", "kms_key_id", "data_protection_status", "log_group_class", "tags"},
		Fetch:   e.fetchCloudWatchLogGroups,
	}
}

func (e *SyncEngine) fetchCloudWatchLogGroups(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := cloudwatchlogs.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(client, &cloudwatchlogs.DescribeLogGroupsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe log groups: %w", err)
		}

		for _, lg := range page.LogGroups {
			arn := aws.ToString(lg.Arn)
			name := aws.ToString(lg.LogGroupName)

			row := map[string]interface{}{
				"_cq_id":                 arn,
				"arn":                    arn,
				"account_id":             accountID,
				"region":                 region,
				"log_group_name":         name,
				"name":                   name,
				"creation_time":          lg.CreationTime,
				"metric_filter_count":    lg.MetricFilterCount,
				"stored_bytes":           lg.StoredBytes,
				"kms_key_id":             aws.ToString(lg.KmsKeyId),
				"data_protection_status": string(lg.DataProtectionStatus),
				"log_group_class":        string(lg.LogGroupClass),
			}

			if lg.RetentionInDays != nil {
				row["retention_in_days"] = *lg.RetentionInDays
			}

			// Get tags
			tagsOut, err := client.ListTagsForResource(ctx, &cloudwatchlogs.ListTagsForResourceInput{
				ResourceArn: lg.Arn,
			})
			if err == nil && tagsOut.Tags != nil {
				row["tags"] = tagsOut.Tags
			}

			rows = append(rows, row)
		}
	}

	return rows, nil
}
