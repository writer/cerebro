package sync

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"cloud.google.com/go/iam"
	"cloud.google.com/go/logging/logadmin"
	"cloud.google.com/go/pubsub" //nolint:staticcheck // Pub/Sub IAM handle not available in v2 client
	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

func (e *GCPSyncEngine) gcpLoggingSinkTable() GCPTableSpec {
	return GCPTableSpec{
		Name:    "gcp_logging_sinks",
		Columns: []string{"project_id", "name", "destination", "filter", "writer_identity", "include_children", "destination_iam_permissions_public"},
		Fetch:   e.fetchGCPLoggingSinks,
	}
}

func (e *GCPSyncEngine) gcpLoggingProjectSinkTable() GCPTableSpec {
	return GCPTableSpec{
		Name:    "gcp_logging_project_sinks",
		Columns: []string{"project_id", "id", "sink_count", "disabled"},
		Fetch:   e.fetchGCPLoggingProjectSinks,
	}
}

func (e *GCPSyncEngine) fetchGCPLoggingSinks(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	client, err := logadmin.NewClient(ctx, projectID, gcpClientOptionsFromContext(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("create logging client: %w", err)
	}
	defer func() { _ = client.Close() }()

	storageClient, _ := storage.NewClient(ctx, gcpClientOptionsFromContext(ctx)...)
	if storageClient != nil {
		defer func() { _ = storageClient.Close() }()
	}

	pubsubClients := map[string]*pubsub.Client{}
	defer func() {
		for _, ps := range pubsubClients {
			_ = ps.Close()
		}
	}()

	rows := make([]map[string]interface{}, 0, 20)
	it := client.Sinks(ctx)
	for {
		sink, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list sinks: %w", err)
		}

		row := map[string]interface{}{
			"_cq_id":           fmt.Sprintf("%s/%s", projectID, sink.ID),
			"project_id":       projectID,
			"name":             sink.ID,
			"destination":      sink.Destination,
			"filter":           sink.Filter,
			"writer_identity":  sink.WriterIdentity,
			"include_children": sink.IncludeChildren,
		}

		if public, ok := isPublicSinkDestination(ctx, sink.Destination, storageClient, pubsubClients); ok {
			row["destination_iam_permissions_public"] = public
		}

		rows = append(rows, row)
	}

	return rows, nil
}

func (e *GCPSyncEngine) fetchGCPLoggingProjectSinks(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	client, err := logadmin.NewClient(ctx, projectID, gcpClientOptionsFromContext(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("create logging client: %w", err)
	}
	defer func() { _ = client.Close() }()

	count := 0
	it := client.Sinks(ctx)
	for {
		_, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list sinks: %w", err)
		}
		count++
	}

	row := map[string]interface{}{
		"_cq_id":     fmt.Sprintf("%s/logging-sinks", projectID),
		"project_id": projectID,
		"id":         fmt.Sprintf("%s/logging-sinks", projectID),
		"sink_count": count,
		"disabled":   count == 0,
	}

	return []map[string]interface{}{row}, nil
}

func isPublicSinkDestination(ctx context.Context, destination string, storageClient *storage.Client, pubsubClients map[string]*pubsub.Client) (bool, bool) {
	if strings.HasPrefix(destination, "storage.googleapis.com/") {
		if storageClient == nil {
			return false, false
		}
		bucketName := strings.TrimPrefix(destination, "storage.googleapis.com/")
		policy, err := storageClient.Bucket(bucketName).IAM().V3().Policy(ctx)
		if err != nil {
			return false, false
		}
		return policyHasPublicMembers(policy), true
	}

	if strings.HasPrefix(destination, "pubsub.googleapis.com/") {
		resource := strings.TrimPrefix(destination, "pubsub.googleapis.com/")
		parts := strings.Split(resource, "/")
		if len(parts) < 4 {
			return false, false
		}
		if parts[0] != "projects" || parts[2] != "topics" {
			return false, false
		}

		destProject := parts[1]
		topicID := parts[3]
		client := pubsubClients[destProject]
		if client == nil {
			ps, err := pubsub.NewClient(ctx, destProject, gcpClientOptionsFromContext(ctx)...)
			if err != nil {
				return false, false
			}
			pubsubClients[destProject] = ps
			client = ps
		}

		policy, err := client.Topic(topicID).IAM().V3().Policy(ctx)
		if err != nil {
			return false, false
		}
		return policyHasPublicMembers(policy), true
	}

	return false, false
}

func policyHasPublicMembers(policy *iam.Policy3) bool {
	if policy == nil {
		return false
	}
	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			if member == iam.AllUsers || member == iam.AllAuthenticatedUsers {
				return true
			}
		}
	}
	return false
}
