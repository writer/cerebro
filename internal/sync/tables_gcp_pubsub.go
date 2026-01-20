package sync

import (
	"context"
	"fmt"

	"cloud.google.com/go/pubsub"
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
	client, err := pubsub.NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("create pubsub client: %w", err)
	}
	defer client.Close()

	var rows []map[string]interface{}

	it := client.Topics(ctx)
	for {
		topic, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list topics: %w", err)
		}

		// Get topic config
		config, err := topic.Config(ctx)
		if err != nil {
			continue
		}

		topicID := topic.ID()
		fullName := fmt.Sprintf("projects/%s/topics/%s", projectID, topicID)

		row := map[string]interface{}{
			"_cq_id":     fullName,
			"project_id": projectID,
			"name":       topicID,
			"labels":     config.Labels,
		}

		if config.KMSKeyName != "" {
			row["kms_key_name"] = config.KMSKeyName
		}

		// Schema settings
		if config.SchemaSettings != nil {
			row["schema_settings"] = map[string]interface{}{
				"schema":            config.SchemaSettings.Schema,
				"encoding":          string(config.SchemaSettings.Encoding),
				"first_revision_id": config.SchemaSettings.FirstRevisionID,
				"last_revision_id":  config.SchemaSettings.LastRevisionID,
			}
		}

		// Message storage policy
		if len(config.MessageStoragePolicy.AllowedPersistenceRegions) > 0 {
			row["message_storage_policy"] = map[string]interface{}{
				"allowed_persistence_regions": config.MessageStoragePolicy.AllowedPersistenceRegions,
			}
		}

		// Get IAM policy
		policy, err := topic.IAM().Policy(ctx)
		if err == nil {
			var bindings []map[string]interface{}
			for _, b := range policy.InternalProto.GetBindings() {
				bindings = append(bindings, map[string]interface{}{
					"role":    b.GetRole(),
					"members": b.GetMembers(),
				})
			}
			row["iam_policy"] = map[string]interface{}{
				"bindings": bindings,
				"version":  policy.InternalProto.GetVersion(),
			}
		}

		// Get subscriptions for this topic
		var subs []string
		subIt := topic.Subscriptions(ctx)
		for {
			sub, err := subIt.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				break
			}
			subs = append(subs, sub.ID())
		}
		row["subscriptions"] = subs

		rows = append(rows, row)
	}

	return rows, nil
}
