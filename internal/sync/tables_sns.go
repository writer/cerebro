package sync

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
)

func (e *SyncEngine) snsTopicTable() TableSpec {
	return TableSpec{
		Name:    "aws_sns_topics",
		Columns: []string{"arn", "account_id", "region", "topic_arn", "name", "display_name", "owner", "subscriptions_confirmed", "subscriptions_pending", "subscriptions_deleted", "policy", "delivery_policy", "effective_delivery_policy", "kms_master_key_id", "tags"},
		Fetch:   e.fetchSNSTopics,
	}
}

func (e *SyncEngine) snsSubscriptionTable() TableSpec {
	return TableSpec{
		Name: "aws_sns_subscriptions",
		Columns: []string{
			"arn", "account_id", "region", "subscription_arn", "topic_arn",
			"protocol", "endpoint", "owner", "pending_confirmation",
			"confirmation_was_authenticated", "raw_message_delivery",
			"delivery_policy", "filter_policy", "redrive_policy",
		},
		Fetch: e.fetchSNSSubscriptions,
	}
}

func (e *SyncEngine) fetchSNSTopics(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := sns.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	paginator := sns.NewListTopicsPaginator(client, &sns.ListTopicsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, topic := range page.Topics {
			topicArn := aws.ToString(topic.TopicArn)

			// Get topic attributes
			attrs, err := client.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{
				TopicArn: topic.TopicArn,
			})
			if err != nil {
				continue
			}

			// Get topic name from ARN
			name := ""
			if len(topicArn) > 0 {
				parts := splitArn(topicArn)
				if len(parts) > 0 {
					name = parts[len(parts)-1]
				}
			}

			row := map[string]interface{}{
				"_cq_id":     topicArn,
				"arn":        topicArn,
				"topic_arn":  topicArn,
				"account_id": accountID,
				"region":     region,
				"name":       name,
			}

			if attrs.Attributes != nil {
				row["display_name"] = attrs.Attributes["DisplayName"]
				row["owner"] = attrs.Attributes["Owner"]
				row["subscriptions_confirmed"] = attrs.Attributes["SubscriptionsConfirmed"]
				row["subscriptions_pending"] = attrs.Attributes["SubscriptionsPending"]
				row["subscriptions_deleted"] = attrs.Attributes["SubscriptionsDeleted"]
				row["kms_master_key_id"] = attrs.Attributes["KmsMasterKeyId"]

				// Parse policies as JSON to store as VARIANT
				if policy := attrs.Attributes["Policy"]; policy != "" {
					var policyObj interface{}
					if json.Unmarshal([]byte(policy), &policyObj) == nil {
						row["policy"] = policyObj
					}
				}
				if deliveryPolicy := attrs.Attributes["DeliveryPolicy"]; deliveryPolicy != "" {
					var dpObj interface{}
					if json.Unmarshal([]byte(deliveryPolicy), &dpObj) == nil {
						row["delivery_policy"] = dpObj
					}
				}
				if effectiveDP := attrs.Attributes["EffectiveDeliveryPolicy"]; effectiveDP != "" {
					var edpObj interface{}
					if json.Unmarshal([]byte(effectiveDP), &edpObj) == nil {
						row["effective_delivery_policy"] = edpObj
					}
				}
			}

			// Get tags
			tags, err := client.ListTagsForResource(ctx, &sns.ListTagsForResourceInput{
				ResourceArn: topic.TopicArn,
			})
			if err == nil && tags.Tags != nil {
				row["tags"] = tags.Tags
			}

			rows = append(rows, row)
		}
	}
	return rows, nil
}

func (e *SyncEngine) fetchSNSSubscriptions(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := sns.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	paginator := sns.NewListSubscriptionsPaginator(client, &sns.ListSubscriptionsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, sub := range page.Subscriptions {
			subscriptionArn := aws.ToString(sub.SubscriptionArn)
			topicArn := aws.ToString(sub.TopicArn)
			protocol := aws.ToString(sub.Protocol)
			endpoint := aws.ToString(sub.Endpoint)

			rowID := subscriptionArn
			if rowID == "" || rowID == "PendingConfirmation" {
				rowID = topicArn + ":" + protocol + ":" + endpoint
			}

			row := map[string]interface{}{
				"_cq_id":           rowID,
				"arn":              subscriptionArn,
				"subscription_arn": subscriptionArn,
				"topic_arn":        topicArn,
				"protocol":         protocol,
				"endpoint":         endpoint,
				"account_id":       accountID,
				"region":           region,
			}

			if subscriptionArn == "PendingConfirmation" {
				row["pending_confirmation"] = true
			}

			if subscriptionArn != "" && subscriptionArn != "PendingConfirmation" {
				attrs, err := client.GetSubscriptionAttributes(ctx, &sns.GetSubscriptionAttributesInput{
					SubscriptionArn: aws.String(subscriptionArn),
				})
				if err == nil && attrs.Attributes != nil {
					row["owner"] = attrs.Attributes["Owner"]
					row["pending_confirmation"] = attrs.Attributes["PendingConfirmation"] == "true"
					row["confirmation_was_authenticated"] = attrs.Attributes["ConfirmationWasAuthenticated"] == "true"
					row["raw_message_delivery"] = attrs.Attributes["RawMessageDelivery"] == "true"

					if deliveryPolicy := attrs.Attributes["DeliveryPolicy"]; deliveryPolicy != "" {
						var policyObj interface{}
						if json.Unmarshal([]byte(deliveryPolicy), &policyObj) == nil {
							row["delivery_policy"] = policyObj
						}
					}
					if filterPolicy := attrs.Attributes["FilterPolicy"]; filterPolicy != "" {
						var policyObj interface{}
						if json.Unmarshal([]byte(filterPolicy), &policyObj) == nil {
							row["filter_policy"] = policyObj
						}
					}
					if redrivePolicy := attrs.Attributes["RedrivePolicy"]; redrivePolicy != "" {
						var policyObj interface{}
						if json.Unmarshal([]byte(redrivePolicy), &policyObj) == nil {
							row["redrive_policy"] = policyObj
						}
					}
				}
			}

			rows = append(rows, row)
		}
	}

	return rows, nil
}

func splitArn(arn string) []string {
	var parts []string
	current := ""
	for _, c := range arn {
		if c == ':' || c == '/' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
