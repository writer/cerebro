package agents

import (
	"context"
	"encoding/json"
	"fmt"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	iam "cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	"cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

// gcpInspect executes read-only GCP commands to verify infrastructure state
func (st *SecurityTools) gcpInspect(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Service string          `json:"service"`
		Action  string          `json:"action"`
		Project string          `json:"project"` // Required for most calls
		Params  json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", err
	}

	// Use provided project or fall back to default if configured in environment
	// But GCP SDK doesn't automatically imply project for all calls, so it's best to require it or error.
	if params.Project == "" {
		return "", fmt.Errorf("project ID is required for GCP inspection")
	}

	switch params.Service {
	case "storage":
		return st.handleGCPStorage(ctx, params.Project, params.Action, params.Params)
	case "compute":
		return st.handleGCPCompute(ctx, params.Project, params.Action, params.Params)
	case "iam":
		return st.handleGCPIAM(ctx, params.Project, params.Action, params.Params)
	case "resourcemanager":
		return st.handleGCPResourceManager(ctx, params.Action, params.Params)
	default:
		return "", fmt.Errorf("unsupported service: %s", params.Service)
	}
}

func (st *SecurityTools) handleGCPStorage(ctx context.Context, projectID, action string, args json.RawMessage) (string, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return "", err
	}
	defer client.Close()

	switch action {
	case "list-buckets":
		it := client.Buckets(ctx, projectID)
		var buckets []string
		for {
			b, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return "", err
			}
			buckets = append(buckets, b.Name)
		}
		return toJSON(buckets)
	case "list-objects":
		var input struct {
			Bucket string `json:"bucket"`
		}
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		it := client.Bucket(input.Bucket).Objects(ctx, nil)
		var objects []string
		for {
			o, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return "", err
			}
			objects = append(objects, o.Name)
		}
		return toJSON(objects)
	default:
		return "", fmt.Errorf("unsupported storage action: %s", action)
	}
}

func (st *SecurityTools) handleGCPCompute(ctx context.Context, projectID, action string, args json.RawMessage) (string, error) {
	// Compute API requires region/zone usually
	switch action {
	case "list-instances":
		client, err := compute.NewInstancesRESTClient(ctx)
		if err != nil {
			return "", err
		}
		defer client.Close()

		var input struct {
			Zone string `json:"zone"`
		}
		// If zone not provided, we might need to use AggregatedList
		_ = json.Unmarshal(args, &input) // Optional

		if input.Zone != "" {
			req := &computepb.ListInstancesRequest{
				Project: projectID,
				Zone:    input.Zone,
			}
			it := client.List(ctx, req)
			var instances []string
			for {
				i, err := it.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					return "", err
				}
				instances = append(instances, *i.Name)
			}
			return toJSON(instances)
		} else {
			// Aggregated List
			req := &computepb.AggregatedListInstancesRequest{
				Project: projectID,
			}
			it := client.AggregatedList(ctx, req)
			var instances []string
			for {
				pair, err := it.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					return "", err
				}
				for _, i := range pair.Value.Instances {
					instances = append(instances, *i.Name)
				}
			}
			return toJSON(instances)
		}

	default:
		return "", fmt.Errorf("unsupported compute action: %s", action)
	}
}

func (st *SecurityTools) handleGCPIAM(ctx context.Context, projectID, action string, _ json.RawMessage) (string, error) {
	client, err := iam.NewIamClient(ctx)
	if err != nil {
		return "", err
	}
	defer client.Close()

	switch action {
	case "list-service-accounts":
		req := &adminpb.ListServiceAccountsRequest{
			Name: fmt.Sprintf("projects/%s", projectID),
		}
		it := client.ListServiceAccounts(ctx, req)
		var sas []string
		for {
			sa, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return "", err
			}
			sas = append(sas, sa.Email)
		}
		return toJSON(sas)
	default:
		return "", fmt.Errorf("unsupported iam action: %s", action)
	}
}

func (st *SecurityTools) handleGCPResourceManager(ctx context.Context, action string, _ json.RawMessage) (string, error) {
	client, err := resourcemanager.NewProjectsClient(ctx)
	if err != nil {
		return "", err
	}
	defer client.Close()

	switch action {
	case "list-projects":
		// This might require organization permissions or just list what's visible
		req := &resourcemanagerpb.SearchProjectsRequest{}
		it := client.SearchProjects(ctx, req)
		var projects []string
		for {
			p, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return "", err
			}
			projects = append(projects, p.ProjectId)
		}
		return toJSON(projects)
	default:
		return "", fmt.Errorf("unsupported resourcemanager action: %s", action)
	}
}
