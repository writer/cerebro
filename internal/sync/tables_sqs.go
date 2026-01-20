package sync

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

func (e *SyncEngine) sqsQueueTable() TableSpec {
	return TableSpec{
		Name:    "aws_sqs_queues",
		Columns: []string{"arn", "account_id", "region", "url", "name", "visibility_timeout", "maximum_message_size", "message_retention_period", "delay_seconds", "receive_message_wait_time_seconds", "policy", "redrive_policy", "fifo_queue", "content_based_deduplication", "kms_master_key_id", "kms_data_key_reuse_period_seconds", "sqs_managed_sse_enabled", "dead_letter_target_arn", "max_receive_count", "approximate_number_of_messages", "approximate_number_of_messages_delayed", "approximate_number_of_messages_not_visible", "created_timestamp", "last_modified_timestamp", "tags"},
		Fetch:   e.fetchSQSQueues,
	}
}

func (e *SyncEngine) fetchSQSQueues(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := sqs.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	// List all queues
	listOut, err := client.ListQueues(ctx, &sqs.ListQueuesInput{})
	if err != nil {
		return nil, fmt.Errorf("list queues: %w", err)
	}

	rows := make([]map[string]interface{}, 0, len(listOut.QueueUrls))

	for _, queueURL := range listOut.QueueUrls {
		// Get queue attributes
		attrs, err := client.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
			QueueUrl:       aws.String(queueURL),
			AttributeNames: []types.QueueAttributeName{types.QueueAttributeNameAll},
		})
		if err != nil {
			e.logger.Warn("failed to get queue attributes", "queue", queueURL, "error", err)
			continue
		}

		arn := attrs.Attributes["QueueArn"]

		// Extract queue name from URL
		name := ""
		if parts := splitArn(queueURL); len(parts) > 0 {
			name = parts[len(parts)-1]
		}

		row := map[string]interface{}{
			"_cq_id":                                 arn,
			"arn":                                    arn,
			"account_id":                             accountID,
			"region":                                 region,
			"url":                                    queueURL,
			"name":                                   name,
			"visibility_timeout":                     attrs.Attributes["VisibilityTimeout"],
			"maximum_message_size":                   attrs.Attributes["MaximumMessageSize"],
			"message_retention_period":               attrs.Attributes["MessageRetentionPeriod"],
			"delay_seconds":                          attrs.Attributes["DelaySeconds"],
			"receive_message_wait_time_seconds":      attrs.Attributes["ReceiveMessageWaitTimeSeconds"],
			"approximate_number_of_messages":         attrs.Attributes["ApproximateNumberOfMessages"],
			"approximate_number_of_messages_delayed": attrs.Attributes["ApproximateNumberOfMessagesDelayed"],
			"approximate_number_of_messages_not_visible": attrs.Attributes["ApproximateNumberOfMessagesNotVisible"],
			"created_timestamp":                          attrs.Attributes["CreatedTimestamp"],
			"last_modified_timestamp":                    attrs.Attributes["LastModifiedTimestamp"],
			"sqs_managed_sse_enabled":                    attrs.Attributes["SqsManagedSseEnabled"] == "true",
			"fifo_queue":                                 attrs.Attributes["FifoQueue"] == "true",
			"content_based_deduplication":                attrs.Attributes["ContentBasedDeduplication"] == "true",
		}

		// Only add KMS fields if they have values
		if kmsKey := attrs.Attributes["KmsMasterKeyId"]; kmsKey != "" {
			row["kms_master_key_id"] = kmsKey
		}
		if kmsReuse := attrs.Attributes["KmsDataKeyReusePeriodSeconds"]; kmsReuse != "" {
			row["kms_data_key_reuse_period_seconds"] = kmsReuse
		}

		// Parse policy as JSON
		if policy := attrs.Attributes["Policy"]; policy != "" {
			var policyObj interface{}
			if json.Unmarshal([]byte(policy), &policyObj) == nil {
				row["policy"] = policyObj
			}
		}

		// Parse redrive policy
		if redrivePolicy := attrs.Attributes["RedrivePolicy"]; redrivePolicy != "" {
			var rpObj map[string]interface{}
			if json.Unmarshal([]byte(redrivePolicy), &rpObj) == nil {
				row["redrive_policy"] = rpObj
				if dlArn, ok := rpObj["deadLetterTargetArn"].(string); ok {
					row["dead_letter_target_arn"] = dlArn
				}
				if maxReceive, ok := rpObj["maxReceiveCount"].(float64); ok {
					row["max_receive_count"] = int(maxReceive)
				}
			}
		}

		// Get tags
		tagsOut, err := client.ListQueueTags(ctx, &sqs.ListQueueTagsInput{
			QueueUrl: aws.String(queueURL),
		})
		if err == nil && tagsOut.Tags != nil {
			row["tags"] = tagsOut.Tags
		}

		rows = append(rows, row)
	}

	return rows, nil
}
