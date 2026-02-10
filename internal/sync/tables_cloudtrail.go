package sync

import (
	"context"
	"sort"
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

func (e *SyncEngine) cloudtrailEventSelectorTable() TableSpec {
	return TableSpec{
		Name: "aws_cloudtrail_event_selectors",
		Columns: []string{
			"arn", "trail_arn", "trail_name", "account_id", "region",
			"event_selectors", "advanced_event_selectors", "read_write_types",
			"include_management_events", "exclude_management_event_sources",
			"has_management_events", "has_data_events", "data_resources",
		},
		Fetch: e.fetchCloudTrailEventSelectors,
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

func (e *SyncEngine) fetchCloudTrailEventSelectors(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := cloudtrail.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	listOut, err := client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	for _, trail := range listOut.TrailList {
		if aws.ToString(trail.HomeRegion) != region {
			continue
		}

		trailArn := aws.ToString(trail.TrailARN)
		trailName := aws.ToString(trail.Name)

		selectors, err := client.GetEventSelectors(ctx, &cloudtrail.GetEventSelectorsInput{
			TrailName: trail.TrailARN,
		})
		if err != nil {
			e.logger.Warn("failed to get cloudtrail event selectors", "trail", trailArn, "error", err)
			continue
		}

		readWriteSet := make(map[string]struct{})
		includeManagement := make([]bool, 0, len(selectors.EventSelectors))
		var excludeManagementSources []string
		var dataResources []interface{}
		hasManagement := false
		hasData := false

		for _, selector := range selectors.EventSelectors {
			if selector.ReadWriteType != "" {
				readWriteSet[string(selector.ReadWriteType)] = struct{}{}
			}
			if selector.IncludeManagementEvents != nil {
				includeManagement = append(includeManagement, *selector.IncludeManagementEvents)
				if *selector.IncludeManagementEvents {
					hasManagement = true
				}
			}
			if len(selector.ExcludeManagementEventSources) > 0 {
				excludeManagementSources = append(excludeManagementSources, selector.ExcludeManagementEventSources...)
			}
			if len(selector.DataResources) > 0 {
				hasData = true
				for _, resource := range selector.DataResources {
					dataResources = append(dataResources, resource)
				}
			}
		}

		if len(selectors.AdvancedEventSelectors) > 0 {
			hasData = true
		}

		readWriteTypes := make([]string, 0, len(readWriteSet))
		for value := range readWriteSet {
			readWriteTypes = append(readWriteTypes, value)
		}
		sort.Strings(readWriteTypes)
		sort.Strings(excludeManagementSources)

		row := map[string]interface{}{
			"_cq_id":                           trailArn,
			"arn":                              trailArn,
			"trail_arn":                        trailArn,
			"trail_name":                       trailName,
			"account_id":                       accountID,
			"region":                           region,
			"event_selectors":                  selectors.EventSelectors,
			"advanced_event_selectors":         selectors.AdvancedEventSelectors,
			"read_write_types":                 readWriteTypes,
			"include_management_events":        includeManagement,
			"exclude_management_event_sources": excludeManagementSources,
			"has_management_events":            hasManagement,
			"has_data_events":                  hasData,
		}

		if len(dataResources) > 0 {
			row["data_resources"] = dataResources
		}

		rows = append(rows, row)
	}

	return rows, nil
}
