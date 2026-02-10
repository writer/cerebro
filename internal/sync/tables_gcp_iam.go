package sync

import (
	"context"
	"fmt"

	admin "cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	"cloud.google.com/go/iam/apiv1/iampb"
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	"google.golang.org/api/iterator"
	exprpb "google.golang.org/genproto/googleapis/type/expr"
)

func (e *GCPSyncEngine) gcpIAMServiceAccountTable() GCPTableSpec {
	return GCPTableSpec{
		Name:    "gcp_iam_service_accounts",
		Columns: []string{"project_id", "name", "email", "unique_id", "display_name", "description", "oauth2_client_id", "disabled", "keys"},
		Fetch:   e.fetchGCPIAMServiceAccounts,
	}
}

func (e *GCPSyncEngine) gcpIAMPolicyTable() GCPTableSpec {
	return GCPTableSpec{
		Name:    "gcp_iam_policies",
		Columns: []string{"project_id", "version", "etag", "bindings"},
		Fetch:   e.fetchGCPIAMPolicies,
	}
}

func (e *GCPSyncEngine) fetchGCPIAMServiceAccounts(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	client, err := admin.NewIamClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create IAM client: %w", err)
	}
	defer func() { _ = client.Close() }()

	rows := make([]map[string]interface{}, 0, 100)

	req := &adminpb.ListServiceAccountsRequest{
		Name: fmt.Sprintf("projects/%s", projectID),
	}

	it := client.ListServiceAccounts(ctx, req)
	for {
		sa, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list service accounts: %w", err)
		}

		row := map[string]interface{}{
			"_cq_id":           sa.Name,
			"project_id":       projectID,
			"name":             sa.Name,
			"email":            sa.Email,
			"unique_id":        sa.UniqueId,
			"display_name":     sa.DisplayName,
			"description":      sa.Description,
			"oauth2_client_id": sa.Oauth2ClientId,
			"disabled":         sa.Disabled,
		}

		// Get service account keys
		keysReq := &adminpb.ListServiceAccountKeysRequest{
			Name: sa.Name,
		}
		keysResp, err := client.ListServiceAccountKeys(ctx, keysReq)
		if err == nil && keysResp != nil {
			var keys []map[string]interface{}
			for _, key := range keysResp.Keys {
				keyInfo := map[string]interface{}{
					"name":          key.Name,
					"key_algorithm": key.KeyAlgorithm.String(),
					"key_origin":    key.KeyOrigin.String(),
					"key_type":      key.KeyType.String(),
					"valid_after":   key.ValidAfterTime.AsTime(),
					"valid_before":  key.ValidBeforeTime.AsTime(),
					"disabled":      key.Disabled,
				}
				keys = append(keys, keyInfo)
			}
			row["keys"] = keys
		}

		rows = append(rows, row)
	}

	return rows, nil
}

func (e *GCPSyncEngine) fetchGCPIAMPolicies(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	client, err := resourcemanager.NewProjectsClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create resource manager client: %w", err)
	}
	defer func() { _ = client.Close() }()

	policy, err := client.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
		Resource: fmt.Sprintf("projects/%s", projectID),
	})
	if err != nil {
		return nil, fmt.Errorf("get iam policy: %w", err)
	}

	var bindings []map[string]interface{}
	for _, binding := range policy.Bindings {
		bindings = append(bindings, map[string]interface{}{
			"role":      binding.Role,
			"members":   binding.Members,
			"condition": serializePolicyCondition(binding.Condition),
		})
	}

	row := map[string]interface{}{
		"_cq_id":     fmt.Sprintf("%s/iam-policy", projectID),
		"project_id": projectID,
		"version":    policy.Version,
		"etag":       string(policy.Etag),
		"bindings":   bindings,
	}

	return []map[string]interface{}{row}, nil
}

func serializePolicyCondition(condition *exprpb.Expr) map[string]interface{} {
	if condition == nil {
		return nil
	}
	return map[string]interface{}{
		"title":       condition.Title,
		"description": condition.Description,
		"expression":  condition.Expression,
		"location":    condition.Location,
	}
}
