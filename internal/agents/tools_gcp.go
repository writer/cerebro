package agents

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	cloudiam "cloud.google.com/go/iam"
	iam "cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	iampb "cloud.google.com/go/iam/apiv1/iampb"
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	"cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

var gcpSupportedServices = []string{"storage", "compute", "iam", "resourcemanager"}

var gcpStorageSupportedActions = []string{
	"list-buckets",
	"list-objects",
	"get-bucket-attrs",
	"get-bucket-iam",
}

var gcpComputeSupportedActions = []string{
	"list-instances",
	"get-instance",
}

var gcpIAMSupportedActions = []string{
	"list-service-accounts",
}

var gcpResourceManagerSupportedActions = []string{
	"list-projects",
	"get-project",
	"get-project-iam",
}

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
		return "", UnsupportedServiceError("gcp", params.Service, gcpSupportedServices)
	}
}

func (st *SecurityTools) handleGCPStorage(ctx context.Context, projectID, action string, args json.RawMessage) (string, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = client.Close() }()

	switch action {
	case "list-buckets":
		it := client.Buckets(ctx, projectID)
		var buckets []string
		for {
			b, err := it.Next()
			if errors.Is(err, iterator.Done) {
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
			if errors.Is(err, iterator.Done) {
				break
			}
			if err != nil {
				return "", err
			}
			objects = append(objects, o.Name)
		}
		return toJSON(objects)
	case "get-bucket-attrs":
		var input struct {
			Bucket string `json:"bucket"`
		}
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		attrs, err := client.Bucket(input.Bucket).Attrs(ctx)
		if err != nil {
			return "", err
		}
		return toJSON(bucketAttrsToMap(attrs))
	case "get-bucket-iam":
		var input struct {
			Bucket string `json:"bucket"`
		}
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		policy, err := client.Bucket(input.Bucket).IAM().Policy(ctx)
		if err != nil {
			return "", err
		}
		return toJSON(iamPolicyToMap(policy))
	default:
		return "", UnsupportedActionError("storage", action, gcpStorageSupportedActions)
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
		defer func() { _ = client.Close() }()

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
				if errors.Is(err, iterator.Done) {
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
				if errors.Is(err, iterator.Done) {
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
	case "get-instance":
		client, err := compute.NewInstancesRESTClient(ctx)
		if err != nil {
			return "", err
		}
		defer func() { _ = client.Close() }()

		var input struct {
			Zone     string `json:"zone"`
			Instance string `json:"instance"`
		}
		if unmarshalErr := json.Unmarshal(args, &input); unmarshalErr != nil {
			return "", unmarshalErr
		}
		if input.Zone == "" || input.Instance == "" {
			return "", fmt.Errorf("zone and instance are required")
		}

		req := &computepb.GetInstanceRequest{
			Project:  projectID,
			Zone:     input.Zone,
			Instance: input.Instance,
		}
		instance, err := client.Get(ctx, req)
		if err != nil {
			return "", err
		}
		return toJSON(instanceSummary(instance))
	default:
		return "", UnsupportedActionError("compute", action, gcpComputeSupportedActions)
	}
}

func (st *SecurityTools) handleGCPIAM(ctx context.Context, projectID, action string, _ json.RawMessage) (string, error) {
	client, err := iam.NewIamClient(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = client.Close() }()

	switch action {
	case "list-service-accounts":
		req := &adminpb.ListServiceAccountsRequest{
			Name: fmt.Sprintf("projects/%s", projectID),
		}
		it := client.ListServiceAccounts(ctx, req)
		var sas []string
		for {
			sa, err := it.Next()
			if errors.Is(err, iterator.Done) {
				break
			}
			if err != nil {
				return "", err
			}
			sas = append(sas, sa.Email)
		}
		return toJSON(sas)
	default:
		return "", UnsupportedActionError("iam", action, gcpIAMSupportedActions)
	}
}

func (st *SecurityTools) handleGCPResourceManager(ctx context.Context, action string, args json.RawMessage) (string, error) {
	client, err := resourcemanager.NewProjectsClient(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = client.Close() }()

	switch action {
	case "list-projects":
		// This might require organization permissions or just list what's visible
		req := &resourcemanagerpb.SearchProjectsRequest{}
		it := client.SearchProjects(ctx, req)
		var projects []string
		for {
			p, err := it.Next()
			if errors.Is(err, iterator.Done) {
				break
			}
			if err != nil {
				return "", err
			}
			projects = append(projects, p.ProjectId)
		}
		return toJSON(projects)
	case "get-project":
		var input struct {
			Project string `json:"project"`
		}
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		if input.Project == "" {
			return "", fmt.Errorf("project is required")
		}
		req := &resourcemanagerpb.GetProjectRequest{
			Name: fmt.Sprintf("projects/%s", input.Project),
		}
		project, err := client.GetProject(ctx, req)
		if err != nil {
			return "", err
		}
		return toJSON(projectSummary(project))
	case "get-project-iam":
		var input struct {
			Project string `json:"project"`
		}
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		if input.Project == "" {
			return "", fmt.Errorf("project is required")
		}
		req := &iampb.GetIamPolicyRequest{
			Resource: fmt.Sprintf("projects/%s", input.Project),
		}
		policy, err := client.GetIamPolicy(ctx, req)
		if err != nil {
			return "", err
		}
		return toJSON(iamPolicyProtoToMap(policy))
	default:
		return "", UnsupportedActionError("resourcemanager", action, gcpResourceManagerSupportedActions)
	}
}

func bucketAttrsToMap(attrs *storage.BucketAttrs) map[string]interface{} {
	if attrs == nil {
		return nil
	}

	acl := make([]map[string]string, 0, len(attrs.ACL))
	for _, rule := range attrs.ACL {
		acl = append(acl, map[string]string{
			"entity": string(rule.Entity),
			"role":   string(rule.Role),
		})
	}

	return map[string]interface{}{
		"name":                        attrs.Name,
		"location":                    attrs.Location,
		"storage_class":               attrs.StorageClass,
		"public_access_prevention":    fmt.Sprintf("%v", attrs.PublicAccessPrevention),
		"uniform_bucket_level_access": attrs.UniformBucketLevelAccess.Enabled,
		"versioning_enabled":          attrs.VersioningEnabled,
		"labels":                      attrs.Labels,
		"logging":                     attrs.Logging,
		"acl":                         acl,
	}
}

func iamPolicyToMap(policy *cloudiam.Policy) map[string]interface{} {
	if policy == nil || policy.InternalProto == nil {
		return nil
	}
	return iamPolicyProtoToMap(policy.InternalProto)
}

func iamPolicyProtoToMap(policy *iampb.Policy) map[string]interface{} {
	if policy == nil {
		return nil
	}
	bindings := make([]map[string]interface{}, 0, len(policy.Bindings))
	for _, binding := range policy.Bindings {
		entry := map[string]interface{}{
			"role":    binding.Role,
			"members": binding.Members,
		}
		if binding.Condition != nil {
			entry["condition"] = map[string]interface{}{
				"title":       binding.Condition.Title,
				"description": binding.Condition.Description,
				"expression":  binding.Condition.Expression,
			}
		}
		bindings = append(bindings, entry)
	}

	etag := ""
	if len(policy.Etag) > 0 {
		etag = base64.StdEncoding.EncodeToString(policy.Etag)
	}

	return map[string]interface{}{
		"version":  policy.Version,
		"etag":     etag,
		"bindings": bindings,
	}
}

func instanceSummary(instance *computepb.Instance) map[string]interface{} {
	if instance == nil {
		return nil
	}

	return map[string]interface{}{
		"name":         instance.GetName(),
		"id":           instance.GetId(),
		"status":       instance.GetStatus(),
		"zone":         instance.GetZone(),
		"machine_type": instance.GetMachineType(),
		"labels":       instance.GetLabels(),
	}
}

func projectSummary(project *resourcemanagerpb.Project) map[string]interface{} {
	if project == nil {
		return nil
	}

	createTime := ""
	if project.CreateTime != nil {
		createTime = project.CreateTime.AsTime().Format("2006-01-02T15:04:05Z")
	}

	return map[string]interface{}{
		"project_id":   project.ProjectId,
		"display_name": project.DisplayName,
		"state":        project.State.String(),
		"create_time":  createTime,
	}
}
