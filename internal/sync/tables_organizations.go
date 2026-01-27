package sync

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	organizations_types "github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

// Organizations Accounts table
func (e *SyncEngine) organizationsAccountTable() TableSpec {
	return TableSpec{
		Name: "aws_organizations_accounts",
		Columns: []string{
			"_cq_hash", "arn", "id", "account_id", "name", "email",
			"joined_method", "joined_timestamp", "status",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := organizations.NewFromConfig(cfg)
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := organizations.NewListAccountsPaginator(client, &organizations.ListAccountsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, account := range page.Accounts {
					row := map[string]interface{}{
						"arn":              aws.ToString(account.Arn),
						"id":               aws.ToString(account.Id),
						"account_id":       accountID,
						"name":             aws.ToString(account.Name),
						"email":            aws.ToString(account.Email),
						"joined_method":    string(account.JoinedMethod),
						"joined_timestamp": timeToString(account.JoinedTimestamp),
						"status":           string(account.Status),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Organizations Organization table
func (e *SyncEngine) organizationsOrganizationTable() TableSpec {
	return TableSpec{
		Name: "aws_organizations_organization",
		Columns: []string{
			"_cq_hash", "arn", "id", "account_id", "feature_set",
			"master_account_arn", "master_account_email", "master_account_id",
			"available_policy_types",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := organizations.NewFromConfig(cfg)
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			out, err := client.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
			if err != nil {
				return nil, err
			}

			org := out.Organization
			policyTypesJSON, _ := json.Marshal(org.AvailablePolicyTypes)

			row := map[string]interface{}{
				"arn":                    aws.ToString(org.Arn),
				"id":                     aws.ToString(org.Id),
				"account_id":             accountID,
				"feature_set":            string(org.FeatureSet),
				"master_account_arn":     aws.ToString(org.MasterAccountArn),
				"master_account_email":   aws.ToString(org.MasterAccountEmail),
				"master_account_id":      aws.ToString(org.MasterAccountId),
				"available_policy_types": string(policyTypesJSON),
			}
			results = append(results, row)

			return results, nil
		},
	}
}

// Organizations Policies table
func (e *SyncEngine) organizationsPolicyTable() TableSpec {
	return TableSpec{
		Name: "aws_organizations_policies",
		Columns: []string{
			"_cq_hash", "arn", "id", "account_id", "name",
			"description", "type", "aws_managed", "content",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := organizations.NewFromConfig(cfg)
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			policyTypes := []organizations_types.PolicyType{
				organizations_types.PolicyTypeServiceControlPolicy,
				organizations_types.PolicyTypeTagPolicy,
				organizations_types.PolicyTypeBackupPolicy,
				organizations_types.PolicyTypeAiservicesOptOutPolicy,
			}

			for _, policyType := range policyTypes {
				paginator := organizations.NewListPoliciesPaginator(client, &organizations.ListPoliciesInput{
					Filter: policyType,
				})
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil {
						break // Move to next policy type
					}

					for _, policy := range page.Policies {
						// Get policy content
						detail, _ := client.DescribePolicy(ctx, &organizations.DescribePolicyInput{
							PolicyId: policy.Id,
						})

						content := ""
						if detail != nil && detail.Policy != nil {
							content = aws.ToString(detail.Policy.Content)
						}

						row := map[string]interface{}{
							"arn":         aws.ToString(policy.Arn),
							"id":          aws.ToString(policy.Id),
							"account_id":  accountID,
							"name":        aws.ToString(policy.Name),
							"description": aws.ToString(policy.Description),
							"type":        string(policy.Type),
							"aws_managed": policy.AwsManaged,
							"content":     content,
						}
						results = append(results, row)
					}
				}
			}
			return results, nil
		},
	}
}

// Organizations OUs table
func (e *SyncEngine) organizationsOUTable() TableSpec {
	return TableSpec{
		Name: "aws_organizations_organizational_units",
		Columns: []string{
			"_cq_hash", "arn", "id", "account_id", "name", "parent_id",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := organizations.NewFromConfig(cfg)
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			// First get roots
			rootsOut, err := client.ListRoots(ctx, &organizations.ListRootsInput{})
			if err != nil {
				return nil, err
			}

			// Recursively get OUs
			var getOUs func(parentID string)
			getOUs = func(parentID string) {
				paginator := organizations.NewListOrganizationalUnitsForParentPaginator(client, &organizations.ListOrganizationalUnitsForParentInput{
					ParentId: aws.String(parentID),
				})
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil {
						break
					}

					for _, ou := range page.OrganizationalUnits {
						row := map[string]interface{}{
							"arn":        aws.ToString(ou.Arn),
							"id":         aws.ToString(ou.Id),
							"account_id": accountID,
							"name":       aws.ToString(ou.Name),
							"parent_id":  parentID,
						}
						results = append(results, row)

						// Recurse into child OUs
						getOUs(aws.ToString(ou.Id))
					}
				}
			}

			// Start from each root
			for _, root := range rootsOut.Roots {
				getOUs(aws.ToString(root.Id))
			}

			return results, nil
		},
	}
}
