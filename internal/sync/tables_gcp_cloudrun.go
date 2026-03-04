package sync

import (
	"context"
	"errors"
	"fmt"
	"strings"

	run "cloud.google.com/go/run/apiv2"
	"cloud.google.com/go/run/apiv2/runpb"
	"google.golang.org/api/iterator"
)

func (e *GCPSyncEngine) gcpCloudRunServiceTable() GCPTableSpec {
	return GCPTableSpec{
		Name: "gcp_cloudrun_services",
		Columns: []string{
			"project_id", "name", "uid", "location", "description", "generation",
			"labels", "annotations", "creator", "last_modifier", "client", "client_version",
			"ingress", "launch_stage", "template", "traffic", "observed_generation",
			"terminal_condition", "conditions", "latest_ready_revision", "latest_created_revision",
			"traffic_statuses", "uri", "custom_audiences", "satisfies_pzs", "reconciling",
			"etag", "create_time", "update_time", "delete_time", "expire_time",
		},
		Fetch: e.fetchGCPCloudRunServices,
	}
}

func (e *GCPSyncEngine) gcpCloudRunRevisionTable() GCPTableSpec {
	return GCPTableSpec{
		Name: "gcp_cloudrun_revisions",
		Columns: []string{
			"project_id", "name", "uid", "location", "service", "generation",
			"labels", "annotations", "creator", "launch_stage",
			"service_account", "containers", "volumes", "execution_environment",
			"encryption_key", "max_instance_request_concurrency", "scaling",
			"timeout", "vpc_access", "observed_generation", "conditions",
			"log_uri", "etag", "create_time", "update_time", "delete_time", "expire_time",
		},
		Fetch: e.fetchGCPCloudRunRevisions,
	}
}

func (e *GCPSyncEngine) fetchGCPCloudRunServices(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	client, err := run.NewServicesClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create cloud run services client: %w", err)
	}
	defer func() { _ = client.Close() }()

	rows := make([]map[string]interface{}, 0, 100)

	// List services across all locations
	req := &runpb.ListServicesRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectID),
	}

	it := client.ListServices(ctx, req)
	for {
		svc, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list cloud run services: %w", err)
		}

		row := map[string]interface{}{
			"_cq_id":                  svc.Name,
			"project_id":              projectID,
			"name":                    svc.Name,
			"uid":                     svc.Uid,
			"description":             svc.Description,
			"generation":              svc.Generation,
			"labels":                  svc.Labels,
			"annotations":             svc.Annotations,
			"creator":                 svc.Creator,
			"last_modifier":           svc.LastModifier,
			"client":                  svc.Client,
			"client_version":          svc.ClientVersion,
			"ingress":                 svc.Ingress.String(),
			"launch_stage":            svc.LaunchStage.String(),
			"observed_generation":     svc.ObservedGeneration,
			"latest_ready_revision":   svc.LatestReadyRevision,
			"latest_created_revision": svc.LatestCreatedRevision,
			"uri":                     svc.Uri,
			"custom_audiences":        svc.CustomAudiences,
			"satisfies_pzs":           svc.SatisfiesPzs,
			"reconciling":             svc.Reconciling,
			"etag":                    svc.Etag,
		}

		// Extract location from name
		if loc := extractLocation(svc.Name); loc != "" {
			row["location"] = loc
		}

		if svc.CreateTime != nil {
			row["create_time"] = svc.CreateTime.AsTime()
		}
		if svc.UpdateTime != nil {
			row["update_time"] = svc.UpdateTime.AsTime()
		}
		if svc.DeleteTime != nil {
			row["delete_time"] = svc.DeleteTime.AsTime()
		}
		if svc.ExpireTime != nil {
			row["expire_time"] = svc.ExpireTime.AsTime()
		}

		// Terminal condition
		if svc.TerminalCondition != nil {
			tc := map[string]interface{}{
				"type":     svc.TerminalCondition.Type,
				"state":    svc.TerminalCondition.State.String(),
				"message":  svc.TerminalCondition.Message,
				"severity": svc.TerminalCondition.Severity.String(),
			}
			if svc.TerminalCondition.LastTransitionTime != nil {
				tc["last_transition_time"] = svc.TerminalCondition.LastTransitionTime.AsTime()
			}
			if r := svc.TerminalCondition.GetReason(); r != 0 {
				tc["reason"] = r.String()
			}
			if r := svc.TerminalCondition.GetRevisionReason(); r != 0 {
				tc["revision_reason"] = r.String()
			}
			if r := svc.TerminalCondition.GetExecutionReason(); r != 0 {
				tc["execution_reason"] = r.String()
			}
			row["terminal_condition"] = tc
		}

		// Conditions
		if len(svc.Conditions) > 0 {
			var conditions []map[string]interface{}
			for _, c := range svc.Conditions {
				conditions = append(conditions, map[string]interface{}{
					"type":     c.Type,
					"state":    c.State.String(),
					"message":  c.Message,
					"severity": c.Severity.String(),
				})
			}
			row["conditions"] = conditions
		}

		// Template
		if svc.Template != nil {
			template := map[string]interface{}{
				"revision":              svc.Template.Revision,
				"service_account":       svc.Template.ServiceAccount,
				"execution_environment": svc.Template.ExecutionEnvironment.String(),
				"encryption_key":        svc.Template.EncryptionKey,
				"session_affinity":      svc.Template.SessionAffinity,
			}

			if svc.Template.Scaling != nil {
				template["scaling"] = map[string]interface{}{
					"min_instance_count": svc.Template.Scaling.MinInstanceCount,
					"max_instance_count": svc.Template.Scaling.MaxInstanceCount,
				}
			}

			if len(svc.Template.Containers) > 0 {
				var containers []map[string]interface{}
				for _, c := range svc.Template.Containers {
					container := map[string]interface{}{
						"name":        c.Name,
						"image":       c.Image,
						"command":     c.Command,
						"args":        c.Args,
						"working_dir": c.WorkingDir,
					}
					if c.Resources != nil {
						container["resources"] = map[string]interface{}{
							"limits":            c.Resources.Limits,
							"cpu_idle":          c.Resources.CpuIdle,
							"startup_cpu_boost": c.Resources.StartupCpuBoost,
						}
					}
					containers = append(containers, container)
				}
				template["containers"] = containers
			}

			row["template"] = template
		}

		// Traffic
		if len(svc.Traffic) > 0 {
			var traffic []map[string]interface{}
			for _, t := range svc.Traffic {
				traffic = append(traffic, map[string]interface{}{
					"type":     t.Type.String(),
					"revision": t.Revision,
					"percent":  t.Percent,
					"tag":      t.Tag,
				})
			}
			row["traffic"] = traffic
		}

		// Traffic statuses
		if len(svc.TrafficStatuses) > 0 {
			var statuses []map[string]interface{}
			for _, ts := range svc.TrafficStatuses {
				statuses = append(statuses, map[string]interface{}{
					"type":     ts.Type.String(),
					"revision": ts.Revision,
					"percent":  ts.Percent,
					"tag":      ts.Tag,
					"uri":      ts.Uri,
				})
			}
			row["traffic_statuses"] = statuses
		}

		rows = append(rows, row)
	}

	return rows, nil
}

func (e *GCPSyncEngine) fetchGCPCloudRunRevisions(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	client, err := run.NewRevisionsClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create cloud run revisions client: %w", err)
	}
	defer func() { _ = client.Close() }()

	rows := make([]map[string]interface{}, 0, 200)

	// List revisions across all locations and services
	req := &runpb.ListRevisionsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-/services/-", projectID),
	}

	it := client.ListRevisions(ctx, req)
	for {
		rev, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list cloud run revisions: %w", err)
		}

		row := map[string]interface{}{
			"_cq_id":                           rev.Name,
			"project_id":                       projectID,
			"name":                             rev.Name,
			"uid":                              rev.Uid,
			"generation":                       rev.Generation,
			"labels":                           rev.Labels,
			"annotations":                      rev.Annotations,
			"creator":                          rev.Creator,
			"launch_stage":                     rev.LaunchStage.String(),
			"service_account":                  rev.ServiceAccount,
			"execution_environment":            rev.ExecutionEnvironment.String(),
			"encryption_key":                   rev.EncryptionKey,
			"max_instance_request_concurrency": rev.MaxInstanceRequestConcurrency,
			"observed_generation":              rev.ObservedGeneration,
			"log_uri":                          rev.LogUri,
			"etag":                             rev.Etag,
		}

		// Extract location and service from name
		// Format: projects/{project}/locations/{location}/services/{service}/revisions/{revision}
		if loc := extractLocation(rev.Name); loc != "" {
			row["location"] = loc
		}
		if svc := extractService(rev.Name); svc != "" {
			row["service"] = svc
		}

		if rev.CreateTime != nil {
			row["create_time"] = rev.CreateTime.AsTime()
		}
		if rev.UpdateTime != nil {
			row["update_time"] = rev.UpdateTime.AsTime()
		}
		if rev.DeleteTime != nil {
			row["delete_time"] = rev.DeleteTime.AsTime()
		}
		if rev.ExpireTime != nil {
			row["expire_time"] = rev.ExpireTime.AsTime()
		}
		if rev.Timeout != nil {
			row["timeout"] = rev.Timeout.AsDuration().String()
		}

		// Scaling
		if rev.Scaling != nil {
			row["scaling"] = map[string]interface{}{
				"min_instance_count": rev.Scaling.MinInstanceCount,
				"max_instance_count": rev.Scaling.MaxInstanceCount,
			}
		}

		// VPC Access
		if rev.VpcAccess != nil {
			row["vpc_access"] = map[string]interface{}{
				"connector":          rev.VpcAccess.Connector,
				"egress":             rev.VpcAccess.Egress.String(),
				"network_interfaces": rev.VpcAccess.NetworkInterfaces,
			}
		}

		// Conditions
		if len(rev.Conditions) > 0 {
			var conditions []map[string]interface{}
			for _, c := range rev.Conditions {
				conditions = append(conditions, map[string]interface{}{
					"type":     c.Type,
					"state":    c.State.String(),
					"message":  c.Message,
					"severity": c.Severity.String(),
				})
			}
			row["conditions"] = conditions
		}

		// Containers
		if len(rev.Containers) > 0 {
			var containers []map[string]interface{}
			for _, c := range rev.Containers {
				container := map[string]interface{}{
					"name":        c.Name,
					"image":       c.Image,
					"command":     c.Command,
					"args":        c.Args,
					"working_dir": c.WorkingDir,
				}
				if c.Resources != nil {
					container["resources"] = map[string]interface{}{
						"limits":            c.Resources.Limits,
						"cpu_idle":          c.Resources.CpuIdle,
						"startup_cpu_boost": c.Resources.StartupCpuBoost,
					}
				}
				if len(c.Ports) > 0 {
					var ports []map[string]interface{}
					for _, p := range c.Ports {
						ports = append(ports, map[string]interface{}{
							"name":           p.Name,
							"container_port": p.ContainerPort,
						})
					}
					container["ports"] = ports
				}
				containers = append(containers, container)
			}
			row["containers"] = containers
		}

		// Volumes
		if len(rev.Volumes) > 0 {
			var volumes []map[string]interface{}
			for _, v := range rev.Volumes {
				volumes = append(volumes, map[string]interface{}{
					"name": v.Name,
				})
			}
			row["volumes"] = volumes
		}

		rows = append(rows, row)
	}

	return rows, nil
}

// extractLocation extracts location from a resource name
// Format: projects/{project}/locations/{location}/...
func extractLocation(name string) string {
	parts := strings.Split(name, "/")
	for i, p := range parts {
		if p == "locations" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// extractService extracts service name from a revision name
// Format: projects/{project}/locations/{location}/services/{service}/revisions/{revision}
func extractService(name string) string {
	parts := strings.Split(name, "/")
	for i, p := range parts {
		if p == "services" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
