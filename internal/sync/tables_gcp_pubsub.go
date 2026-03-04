package sync

import (
	"context"
	"errors"
	"fmt"
	"path"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	pubsub "cloud.google.com/go/pubsub/v2"
	pubsubadmin "cloud.google.com/go/pubsub/v2/apiv1"
	pubsubpb "cloud.google.com/go/pubsub/v2/apiv1/pubsubpb"
	"google.golang.org/api/iterator"
)

type pubsubTopicIterator interface {
	Next() (*pubsubpb.Topic, error)
}

type pubsubStringIterator interface {
	Next() (string, error)
}

type pubsubTopicAdminClient interface {
	ListTopics(ctx context.Context, req *pubsubpb.ListTopicsRequest) pubsubTopicIterator
	GetIamPolicy(ctx context.Context, req *iampb.GetIamPolicyRequest) (*iampb.Policy, error)
	ListTopicSubscriptions(ctx context.Context, req *pubsubpb.ListTopicSubscriptionsRequest) pubsubStringIterator
}

type pubsubTopicAdminWrapper struct {
	client *pubsubadmin.TopicAdminClient
}

func (w pubsubTopicAdminWrapper) ListTopics(ctx context.Context, req *pubsubpb.ListTopicsRequest) pubsubTopicIterator {
	return w.client.ListTopics(ctx, req)
}

func (w pubsubTopicAdminWrapper) GetIamPolicy(ctx context.Context, req *iampb.GetIamPolicyRequest) (*iampb.Policy, error) {
	return w.client.GetIamPolicy(ctx, req)
}

func (w pubsubTopicAdminWrapper) ListTopicSubscriptions(ctx context.Context, req *pubsubpb.ListTopicSubscriptionsRequest) pubsubStringIterator {
	return w.client.ListTopicSubscriptions(ctx, req)
}

func (e *GCPSyncEngine) gcpPubSubTopicTable() GCPTableSpec {
	return GCPTableSpec{
		Name:    "gcp_pubsub_topics",
		Columns: []string{"project_id", "name", "labels", "kms_key_name", "schema_settings", "message_retention_duration", "message_storage_policy", "iam_policy", "subscriptions"},
		Fetch:   e.fetchGCPPubSubTopics,
	}
}

func (e *GCPSyncEngine) fetchGCPPubSubTopics(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	client, err := pubsub.NewClient(ctx, projectID, gcpClientOptionsFromContext(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("create pubsub client: %w", err)
	}
	defer func() { _ = client.Close() }()

	return fetchGCPPubSubTopicsWithAdmin(ctx, projectID, pubsubTopicAdminWrapper{client: client.TopicAdminClient})
}

func fetchGCPPubSubTopicsWithAdmin(ctx context.Context, projectID string, adminClient pubsubTopicAdminClient) ([]map[string]interface{}, error) {

	rows := make([]map[string]interface{}, 0, 100)

	it := adminClient.ListTopics(ctx, &pubsubpb.ListTopicsRequest{
		Project: fmt.Sprintf("projects/%s", projectID),
	})
	for {
		topic, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list topics: %w", err)
		}

		topicID := path.Base(topic.Name)
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

		// Schema settings
		if topic.SchemaSettings != nil {
			row["schema_settings"] = map[string]interface{}{
				"schema":            topic.SchemaSettings.Schema,
				"encoding":          topic.SchemaSettings.Encoding.String(),
				"first_revision_id": topic.SchemaSettings.FirstRevisionId,
				"last_revision_id":  topic.SchemaSettings.LastRevisionId,
			}
		}

		// Message storage policy
		if topic.MessageStoragePolicy != nil && len(topic.MessageStoragePolicy.AllowedPersistenceRegions) > 0 {
			row["message_storage_policy"] = map[string]interface{}{
				"allowed_persistence_regions": topic.MessageStoragePolicy.AllowedPersistenceRegions,
			}
		}

		if topic.MessageRetentionDuration != nil {
			row["message_retention_duration"] = topic.MessageRetentionDuration.AsDuration().String()
		}

		// Get IAM policy
		policy, err := adminClient.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
			Resource: topic.Name,
		})
		if err == nil {
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

		// Get subscriptions for this topic
		var subs []string
		subIt := adminClient.ListTopicSubscriptions(ctx, &pubsubpb.ListTopicSubscriptionsRequest{
			Topic: topic.Name,
		})
		for {
			subscription, err := subIt.Next()
			if errors.Is(err, iterator.Done) {
				break
			}
			if err != nil {
				break
			}
			subs = append(subs, path.Base(subscription))
		}
		row["subscriptions"] = subs

		rows = append(rows, row)
	}

	return rows, nil
}
