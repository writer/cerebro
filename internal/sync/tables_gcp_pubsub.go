package sync

import (
	"context"
	"fmt"
	"strings"

	"cloud.google.com/go/iam/apiv1/iampb"
	pubsubadmin "cloud.google.com/go/pubsub/apiv1"
	"cloud.google.com/go/pubsub/v2/apiv1/pubsubpb"
	"google.golang.org/api/iterator"
)

func (e *GCPSyncEngine) gcpPubSubTopicTable() GCPTableSpec {
	return GCPTableSpec{
		Name:    "gcp_pubsub_topics",
		Columns: []string{"project_id", "name", "labels", "kms_key_name", "schema_settings", "message_retention_duration", "message_storage_policy", "iam_policy", "subscriptions"},
		Fetch:   e.fetchGCPPubSubTopics,
	}
}

func (e *GCPSyncEngine) fetchGCPPubSubTopics(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	adminClient, err := pubsubadmin.NewPublisherClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create pubsub admin client: %w", err)
	}
	defer func() { _ = adminClient.Close() }()

	subAdminClient, err := pubsubadmin.NewSubscriberClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create pubsub subscriber admin client: %w", err)
	}
	defer func() { _ = subAdminClient.Close() }()

	rows := make([]map[string]interface{}, 0, 100)

	req := &pubsubpb.ListTopicsRequest{
		Project: fmt.Sprintf("projects/%s", projectID),
	}
	it := adminClient.ListTopics(ctx, req)
	for {
		topic, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list topics: %w", err)
		}

		topicID := extractPubSubResourceID(topic.Name)
		fullName := topic.Name

		row := map[string]interface{}{
			"_cq_id":     fullName,
			"project_id": projectID,
			"name":       topicID,
			"labels":     topic.Labels,
		}

		if topic.KmsKeyName != "" {
			row["kms_key_name"] = topic.KmsKeyName
		}

		if topic.SchemaSettings != nil {
			row["schema_settings"] = map[string]interface{}{
				"schema":            topic.SchemaSettings.Schema,
				"encoding":          topic.SchemaSettings.Encoding.String(),
				"first_revision_id": topic.SchemaSettings.FirstRevisionId,
				"last_revision_id":  topic.SchemaSettings.LastRevisionId,
			}
		}

		if topic.MessageStoragePolicy != nil && len(topic.MessageStoragePolicy.AllowedPersistenceRegions) > 0 {
			row["message_storage_policy"] = map[string]interface{}{
				"allowed_persistence_regions": topic.MessageStoragePolicy.AllowedPersistenceRegions,
			}
		}

		if topic.MessageRetentionDuration != nil {
			row["message_retention_duration"] = topic.MessageRetentionDuration.AsDuration().String()
		}

		iamReq := &iampb.GetIamPolicyRequest{
			Resource: fullName,
		}
		policy, err := adminClient.GetIamPolicy(ctx, iamReq)
		if err == nil && policy != nil {
			var bindings []map[string]interface{}
			for _, b := range policy.GetBindings() {
				bindings = append(bindings, map[string]interface{}{
					"role":    b.GetRole(),
					"members": b.GetMembers(),
				})
			}
			row["iam_policy"] = map[string]interface{}{
				"bindings": bindings,
				"version":  policy.GetVersion(),
			}
		}

		var subs []string
		subReq := &pubsubpb.ListSubscriptionsRequest{
			Project: fmt.Sprintf("projects/%s", projectID),
		}
		subIt := subAdminClient.ListSubscriptions(ctx, subReq)
		for {
			sub, err := subIt.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				break
			}
			if sub.Topic == fullName {
				subs = append(subs, extractPubSubResourceID(sub.Name))
			}
		}
		row["subscriptions"] = subs

		rows = append(rows, row)
	}

	return rows, nil
}

func extractPubSubResourceID(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}
