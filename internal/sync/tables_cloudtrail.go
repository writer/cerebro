package sync

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
)

func (e *SyncEngine) cloudtrailTrailTable() TableSpec {
	return TableSpec{
		Name:    "aws_cloudtrail_trails",
		Columns: []string{"arn", "account_id", "region", "name", "s3_bucket_name", "s3_key_prefix", "sns_topic_name", "sns_topic_arn", "include_global_service_events", "is_multi_region_trail", "home_region", "trail_arn", "log_file_validation_enabled", "cloud_watch_logs_log_group_arn", "cloud_watch_logs_role_arn", "kms_key_id", "has_custom_event_selectors", "has_insight_selectors", "is_organization_trail", "is_logging", "latest_delivery_time", "latest_delivery_error", "tags"},
		Fetch:   e.fetchCloudTrailTrails,
	}
}

func (e *SyncEngine) fetchCloudTrailTrails(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := cloudtrail.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	// List trails
	listOut, err := client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(listOut.TrailList))
	for _, trail := range listOut.TrailList {
		// Only process trails in their home region to avoid duplicates
		if aws.ToString(trail.HomeRegion) != region {
			continue
		}

		arn := aws.ToString(trail.TrailARN)
		snsTopicARN := aws.ToString(trail.SnsTopicARN)
		snsTopicName := ""
		if snsTopicARN != "" {
			parts := strings.Split(snsTopicARN, ":")
			snsTopicName = parts[len(parts)-1]
		}

		row := map[string]interface{}{
			"_cq_id":                         arn,
			"arn":                            arn,
			"trail_arn":                      arn,
			"account_id":                     accountID,
			"region":                         region,
			"name":                           aws.ToString(trail.Name),
			"s3_bucket_name":                 aws.ToString(trail.S3BucketName),
			"s3_key_prefix":                  aws.ToString(trail.S3KeyPrefix),
			"sns_topic_name":                 snsTopicName,
			"sns_topic_arn":                  snsTopicARN,
			"include_global_service_events":  aws.ToBool(trail.IncludeGlobalServiceEvents),
			"is_multi_region_trail":          aws.ToBool(trail.IsMultiRegionTrail),
			"home_region":                    aws.ToString(trail.HomeRegion),
			"log_file_validation_enabled":    aws.ToBool(trail.LogFileValidationEnabled),
			"cloud_watch_logs_log_group_arn": aws.ToString(trail.CloudWatchLogsLogGroupArn),
			"cloud_watch_logs_role_arn":      aws.ToString(trail.CloudWatchLogsRoleArn),
			"kms_key_id":                     aws.ToString(trail.KmsKeyId),
			"has_custom_event_selectors":     aws.ToBool(trail.HasCustomEventSelectors),
			"has_insight_selectors":          aws.ToBool(trail.HasInsightSelectors),
			"is_organization_trail":          aws.ToBool(trail.IsOrganizationTrail),
		}

		// Get trail status
		status, err := client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
			Name: trail.TrailARN,
		})
		if err == nil {
			row["is_logging"] = aws.ToBool(status.IsLogging)
			row["latest_delivery_time"] = status.LatestDeliveryTime
			row["latest_delivery_error"] = aws.ToString(status.LatestDeliveryError)
		}

		// Get tags
		tags, err := client.ListTags(ctx, &cloudtrail.ListTagsInput{
			ResourceIdList: []string{arn},
		})
		if err == nil && len(tags.ResourceTagList) > 0 {
			row["tags"] = tags.ResourceTagList[0].TagsList
		}

		rows = append(rows, row)
	}
	return rows, nil
}
