package sync

import (
	"context"
	"errors"
	"fmt"

	functions "cloud.google.com/go/functions/apiv2"
	"cloud.google.com/go/functions/apiv2/functionspb"
	"google.golang.org/api/iterator"
)

func (e *GCPSyncEngine) gcpCloudFunctionTable() GCPTableSpec {
	return GCPTableSpec{
		Name:    "gcp_cloudfunctions_functions",
		Columns: []string{"project_id", "name", "location", "description", "state", "build_config", "service_config", "event_trigger", "update_time", "labels", "environment", "url", "kms_key_name"},
		Fetch:   e.fetchGCPCloudFunctions,
	}
}

func (e *GCPSyncEngine) fetchGCPCloudFunctions(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	client, err := functions.NewFunctionClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create functions client: %w", err)
	}
	defer func() { _ = client.Close() }()

	rows := make([]map[string]interface{}, 0, 100)

	// List functions across all locations
	req := &functionspb.ListFunctionsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectID),
	}

	it := client.ListFunctions(ctx, req)
	for {
		fn, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list functions: %w", err)
		}

		row := map[string]interface{}{
			"_cq_id":       fn.Name,
			"project_id":   projectID,
			"name":         fn.Name,
			"description":  fn.Description,
			"state":        fn.State.String(),
			"environment":  fn.Environment.String(),
			"url":          fn.Url,
			"kms_key_name": fn.KmsKeyName,
			"labels":       fn.Labels,
		}

		// Extract location from name
		// Format: projects/{project}/locations/{location}/functions/{function}
		if parts := splitArn(fn.Name); len(parts) >= 4 {
			for i, p := range parts {
				if p == "locations" && i+1 < len(parts) {
					row["location"] = parts[i+1]
					break
				}
			}
		}

		if fn.UpdateTime != nil {
			row["update_time"] = fn.UpdateTime.AsTime()
		}

		// Build config
		if fn.BuildConfig != nil {
			buildConfig := map[string]interface{}{
				"build":             fn.BuildConfig.Build,
				"runtime":           fn.BuildConfig.Runtime,
				"entry_point":       fn.BuildConfig.EntryPoint,
				"docker_repository": fn.BuildConfig.DockerRepository,
				"service_account":   fn.BuildConfig.ServiceAccount,
			}

			if fn.BuildConfig.Source != nil {
				if fn.BuildConfig.Source.GetStorageSource() != nil {
					ss := fn.BuildConfig.Source.GetStorageSource()
					buildConfig["source_storage"] = map[string]interface{}{
						"bucket":     ss.Bucket,
						"object":     ss.Object,
						"generation": ss.Generation,
					}
				}
				if fn.BuildConfig.Source.GetRepoSource() != nil {
					rs := fn.BuildConfig.Source.GetRepoSource()
					buildConfig["source_repo"] = map[string]interface{}{
						"project_id": rs.ProjectId,
						"repo_name":  rs.RepoName,
						"branch":     rs.GetBranchName(),
						"tag":        rs.GetTagName(),
						"commit":     rs.GetCommitSha(),
						"dir":        rs.Dir,
					}
				}
			}

			row["build_config"] = buildConfig
		}

		// Service config
		if fn.ServiceConfig != nil {
			serviceConfig := map[string]interface{}{
				"service":                          fn.ServiceConfig.Service,
				"timeout_seconds":                  fn.ServiceConfig.TimeoutSeconds,
				"available_memory":                 fn.ServiceConfig.AvailableMemory,
				"available_cpu":                    fn.ServiceConfig.AvailableCpu,
				"max_instance_count":               fn.ServiceConfig.MaxInstanceCount,
				"min_instance_count":               fn.ServiceConfig.MinInstanceCount,
				"max_instance_request_concurrency": fn.ServiceConfig.MaxInstanceRequestConcurrency,
				"vpc_connector":                    fn.ServiceConfig.VpcConnector,
				"vpc_connector_egress_settings":    fn.ServiceConfig.VpcConnectorEgressSettings.String(),
				"ingress_settings":                 fn.ServiceConfig.IngressSettings.String(),
				"uri":                              fn.ServiceConfig.Uri,
				"service_account_email":            fn.ServiceConfig.ServiceAccountEmail,
				"all_traffic_on_latest_revision":   fn.ServiceConfig.AllTrafficOnLatestRevision,
			}

			if len(fn.ServiceConfig.SecretEnvironmentVariables) > 0 {
				var secrets []map[string]interface{}
				for _, s := range fn.ServiceConfig.SecretEnvironmentVariables {
					secrets = append(secrets, map[string]interface{}{
						"key":        s.Key,
						"project_id": s.ProjectId,
						"secret":     s.Secret,
						"version":    s.Version,
					})
				}
				serviceConfig["secret_environment_variables"] = secrets
			}

			row["service_config"] = serviceConfig
		}

		// Event trigger
		if fn.EventTrigger != nil {
			eventTrigger := map[string]interface{}{
				"trigger":               fn.EventTrigger.Trigger,
				"trigger_region":        fn.EventTrigger.TriggerRegion,
				"event_type":            fn.EventTrigger.EventType,
				"pubsub_topic":          fn.EventTrigger.PubsubTopic,
				"service_account_email": fn.EventTrigger.ServiceAccountEmail,
				"retry_policy":          fn.EventTrigger.RetryPolicy.String(),
				"channel":               fn.EventTrigger.Channel,
			}

			if len(fn.EventTrigger.EventFilters) > 0 {
				var filters []map[string]interface{}
				for _, f := range fn.EventTrigger.EventFilters {
					filters = append(filters, map[string]interface{}{
						"attribute": f.Attribute,
						"value":     f.Value,
						"operator":  f.Operator,
					})
				}
				eventTrigger["event_filters"] = filters
			}

			row["event_trigger"] = eventTrigger
		}

		rows = append(rows, row)
	}

	return rows, nil
}
