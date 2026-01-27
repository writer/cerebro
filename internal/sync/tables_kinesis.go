package sync

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
)

// Kinesis Streams table
func (e *SyncEngine) kinesisStreamTable() TableSpec {
	return TableSpec{
		Name: "aws_kinesis_streams",
		Columns: []string{
			"_cq_hash", "arn", "name", "account_id", "region",
			"encryption_type", "enhanced_monitoring", "has_more_shards",
			"key_id", "open_shard_count", "retention_period_hours",
			"stream_creation_timestamp", "stream_mode_details", "stream_status",
			"tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := kinesis.NewFromConfig(cfg, func(o *kinesis.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := kinesis.NewListStreamsPaginator(client, &kinesis.ListStreamsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, summary := range page.StreamSummaries {
					streamName := aws.ToString(summary.StreamName)

					// Get full stream details
					detail, err := client.DescribeStreamSummary(ctx, &kinesis.DescribeStreamSummaryInput{
						StreamName: aws.String(streamName),
					})
					if err != nil {
						continue
					}
					stream := detail.StreamDescriptionSummary

					// Get tags
					tagsOut, _ := client.ListTagsForStream(ctx, &kinesis.ListTagsForStreamInput{
						StreamName: aws.String(streamName),
					})
					tags := map[string]string{}
					if tagsOut != nil {
						for _, t := range tagsOut.Tags {
							if t.Key != nil && t.Value != nil {
								tags[*t.Key] = *t.Value
							}
						}
					}
					tagsJSON, _ := json.Marshal(tags)
					monitoringJSON, _ := json.Marshal(stream.EnhancedMonitoring)
					modeJSON, _ := json.Marshal(stream.StreamModeDetails)

					row := map[string]interface{}{
						"arn":                       aws.ToString(stream.StreamARN),
						"name":                      aws.ToString(stream.StreamName),
						"account_id":                accountID,
						"region":                    region,
						"encryption_type":           string(stream.EncryptionType),
						"enhanced_monitoring":       string(monitoringJSON),
						"has_more_shards":           false,
						"key_id":                    aws.ToString(stream.KeyId),
						"open_shard_count":          stream.OpenShardCount,
						"retention_period_hours":    stream.RetentionPeriodHours,
						"stream_creation_timestamp": timeToString(stream.StreamCreationTimestamp),
						"stream_mode_details":       string(modeJSON),
						"stream_status":             string(stream.StreamStatus),
						"tags":                      string(tagsJSON),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Firehose Delivery Streams table
func (e *SyncEngine) firehoseDeliveryStreamTable() TableSpec {
	return TableSpec{
		Name: "aws_firehose_delivery_streams",
		Columns: []string{
			"_cq_hash", "arn", "name", "account_id", "region",
			"create_timestamp", "delivery_stream_encryption_configuration",
			"delivery_stream_status", "delivery_stream_type",
			"failure_description", "has_more_destinations",
			"last_update_timestamp", "source", "version_id",
			"destinations", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := firehose.NewFromConfig(cfg, func(o *firehose.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			var exclusiveStartName *string
			for {
				out, err := client.ListDeliveryStreams(ctx, &firehose.ListDeliveryStreamsInput{
					ExclusiveStartDeliveryStreamName: exclusiveStartName,
				})
				if err != nil {
					return nil, err
				}

				for _, name := range out.DeliveryStreamNames {
					// Get full stream details
					detail, err := client.DescribeDeliveryStream(ctx, &firehose.DescribeDeliveryStreamInput{
						DeliveryStreamName: aws.String(name),
					})
					if err != nil {
						continue
					}
					stream := detail.DeliveryStreamDescription

					// Get tags
					tagsOut, _ := client.ListTagsForDeliveryStream(ctx, &firehose.ListTagsForDeliveryStreamInput{
						DeliveryStreamName: aws.String(name),
					})
					tags := map[string]string{}
					if tagsOut != nil {
						for _, t := range tagsOut.Tags {
							if t.Key != nil && t.Value != nil {
								tags[*t.Key] = *t.Value
							}
						}
					}
					tagsJSON, _ := json.Marshal(tags)
					encryptionJSON, _ := json.Marshal(stream.DeliveryStreamEncryptionConfiguration)
					failureJSON, _ := json.Marshal(stream.FailureDescription)
					sourceJSON, _ := json.Marshal(stream.Source)
					destinationsJSON, _ := json.Marshal(stream.Destinations)

					row := map[string]interface{}{
						"arn":              aws.ToString(stream.DeliveryStreamARN),
						"name":             aws.ToString(stream.DeliveryStreamName),
						"account_id":       accountID,
						"region":           region,
						"create_timestamp": timeToString(stream.CreateTimestamp),
						"delivery_stream_encryption_configuration": string(encryptionJSON),
						"delivery_stream_status":                   string(stream.DeliveryStreamStatus),
						"delivery_stream_type":                     string(stream.DeliveryStreamType),
						"failure_description":                      string(failureJSON),
						"has_more_destinations":                    stream.HasMoreDestinations,
						"last_update_timestamp":                    timeToString(stream.LastUpdateTimestamp),
						"source":                                   string(sourceJSON),
						"version_id":                               aws.ToString(stream.VersionId),
						"destinations":                             string(destinationsJSON),
						"tags":                                     string(tagsJSON),
					}
					results = append(results, row)
				}

				if out.HasMoreDeliveryStreams == nil || !*out.HasMoreDeliveryStreams {
					break
				}
				if len(out.DeliveryStreamNames) > 0 {
					exclusiveStartName = aws.String(out.DeliveryStreamNames[len(out.DeliveryStreamNames)-1])
				}
			}
			return results, nil
		},
	}
}
