package sync

import (
	"context"
	"fmt"
	"testing"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	pubsubpb "cloud.google.com/go/pubsub/v2/apiv1/pubsubpb"
	"google.golang.org/api/iterator"
)

type fakeTopicIterator struct {
	topics []*pubsubpb.Topic
	index  int
}

func (f *fakeTopicIterator) Next() (*pubsubpb.Topic, error) {
	if f.index >= len(f.topics) {
		return nil, iterator.Done
	}
	topic := f.topics[f.index]
	f.index++
	return topic, nil
}

type fakeStringIterator struct {
	values []string
	index  int
}

func (f *fakeStringIterator) Next() (string, error) {
	if f.index >= len(f.values) {
		return "", iterator.Done
	}
	value := f.values[f.index]
	f.index++
	return value, nil
}

type fakePubSubAdminClient struct {
	topics          []*pubsubpb.Topic
	policies        map[string]*iampb.Policy
	subscriptions   map[string][]string
	project         string
	requestedTopics []string
}

func (f *fakePubSubAdminClient) ListTopics(ctx context.Context, req *pubsubpb.ListTopicsRequest) pubsubTopicIterator {
	f.project = req.Project
	return &fakeTopicIterator{topics: f.topics}
}

func (f *fakePubSubAdminClient) GetIamPolicy(ctx context.Context, req *iampb.GetIamPolicyRequest) (*iampb.Policy, error) {
	policy, ok := f.policies[req.Resource]
	if !ok {
		return nil, fmt.Errorf("policy not found")
	}
	return policy, nil
}

func (f *fakePubSubAdminClient) ListTopicSubscriptions(ctx context.Context, req *pubsubpb.ListTopicSubscriptionsRequest) pubsubStringIterator {
	f.requestedTopics = append(f.requestedTopics, req.Topic)
	return &fakeStringIterator{values: f.subscriptions[req.Topic]}
}

func TestFetchGCPPubSubTopicsWithAdmin(t *testing.T) {
	policy := &iampb.Policy{
		Version: 1,
		Bindings: []*iampb.Binding{
			{
				Role:    "roles/pubsub.viewer",
				Members: []string{"user:me@example.com"},
			},
		},
	}

	topic := &pubsubpb.Topic{
		Name:       "projects/my-project/topics/topic-a",
		Labels:     map[string]string{"env": "prod"},
		KmsKeyName: "projects/my-project/locations/us/keyRings/ring/cryptoKeys/key",
		SchemaSettings: &pubsubpb.SchemaSettings{
			Schema:          "projects/my-project/schemas/schema-a",
			Encoding:        pubsubpb.Encoding_JSON,
			FirstRevisionId: "1",
			LastRevisionId:  "2",
		},
		MessageStoragePolicy: &pubsubpb.MessageStoragePolicy{
			AllowedPersistenceRegions: []string{"us-east1"},
		},
	}

	admin := &fakePubSubAdminClient{
		topics: []*pubsubpb.Topic{topic},
		policies: map[string]*iampb.Policy{
			topic.Name: policy,
		},
		subscriptions: map[string][]string{
			topic.Name: {"projects/my-project/subscriptions/sub-a"},
		},
	}

	rows, err := fetchGCPPubSubTopicsWithAdmin(context.Background(), "my-project", admin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if admin.project != "projects/my-project" {
		t.Fatalf("unexpected project request: %s", admin.project)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}

	row := rows[0]
	if row["name"] != "topic-a" {
		t.Fatalf("unexpected name: %v", row["name"])
	}
	if row["kms_key_name"] != topic.KmsKeyName {
		t.Fatalf("unexpected kms key: %v", row["kms_key_name"])
	}

	schema, ok := row["schema_settings"].(map[string]interface{})
	if !ok || schema["encoding"] != "JSON" {
		t.Fatalf("unexpected schema settings: %v", row["schema_settings"])
	}

	storage, ok := row["message_storage_policy"].(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected storage policy: %v", row["message_storage_policy"])
	}
	if regions, ok := storage["allowed_persistence_regions"].([]string); !ok || len(regions) != 1 || regions[0] != "us-east1" {
		t.Fatalf("unexpected persistence regions: %v", storage["allowed_persistence_regions"])
	}

	policyRow, ok := row["iam_policy"].(map[string]interface{})
	if !ok || policyRow["version"] != int32(1) {
		t.Fatalf("unexpected iam policy: %v", row["iam_policy"])
	}

	subs, ok := row["subscriptions"].([]string)
	if !ok || len(subs) != 1 || subs[0] != "sub-a" {
		t.Fatalf("unexpected subscriptions: %v", row["subscriptions"])
	}
}
