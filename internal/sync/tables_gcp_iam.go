package sync

import (
	"context"
	"fmt"

	admin "cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	"google.golang.org/api/iterator"
)

func (e *GCPSyncEngine) gcpIAMServiceAccountTable() GCPTableSpec {
	return GCPTableSpec{
		Name:    "gcp_iam_service_accounts",
		Columns: []string{"project_id", "name", "email", "unique_id", "display_name", "description", "oauth2_client_id", "disabled", "keys"},
		Fetch:   e.fetchGCPIAMServiceAccounts,
	}
}

func (e *GCPSyncEngine) fetchGCPIAMServiceAccounts(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	client, err := admin.NewIamClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create IAM client: %w", err)
	}
	defer client.Close()

	var rows []map[string]interface{}

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
					"name":            key.Name,
					"key_algorithm":   key.KeyAlgorithm.String(),
					"key_origin":      key.KeyOrigin.String(),
					"key_type":        key.KeyType.String(),
					"valid_after":     key.ValidAfterTime.AsTime(),
					"valid_before":    key.ValidBeforeTime.AsTime(),
					"disabled":        key.Disabled,
				}
				keys = append(keys, keyInfo)
			}
			row["keys"] = keys
		}

		rows = append(rows, row)
	}

	return rows, nil
}
