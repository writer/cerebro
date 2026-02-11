package sync

import (
	"context"
	"encoding/json"
	"errors"

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
					return e.handleOrganizationsError("aws_organizations_accounts", err, results)
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
				return e.handleOrganizationsError("aws_organizations_organization", err, results)
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

// Organizations Roots table
func (e *SyncEngine) organizationsRootsTable() TableSpec {
	return TableSpec{
		Name: "aws_organizations_roots",
		Columns: []string{
			"_cq_hash", "arn", "id", "account_id", "name", "policy_types",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := organizations.NewFromConfig(cfg)
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := organizations.NewListRootsPaginator(client, &organizations.ListRootsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return e.handleOrganizationsError("aws_organizations_roots", err, results)
				}

				for _, root := range page.Roots {
					policyTypesJSON, _ := json.Marshal(root.PolicyTypes)
					row := map[string]interface{}{
						"arn":          aws.ToString(root.Arn),
						"id":           aws.ToString(root.Id),
						"account_id":   accountID,
						"name":         aws.ToString(root.Name),
						"policy_types": string(policyTypesJSON),
					}
					results = append(results, row)
				}
			}

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
						if isOrganizationsAccessDenied(err) {
							return e.handleOrganizationsError("aws_organizations_policies", err, results)
						}
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

// Organizations Policy Targets table
func (e *SyncEngine) organizationsPolicyTargetsTable() TableSpec {
	return TableSpec{
		Name: "aws_organizations_policy_targets",
		Columns: []string{
			"_cq_hash", "policy_id", "policy_arn", "policy_name", "policy_type",
			"target_id", "target_arn", "target_name", "target_type", "account_id",
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
						if isOrganizationsAccessDenied(err) {
							return e.handleOrganizationsError("aws_organizations_policy_targets", err, results)
						}
						break
					}

					for _, policy := range page.Policies {
						policyID := aws.ToString(policy.Id)
						if policyID == "" {
							continue
						}

						targetPager := organizations.NewListTargetsForPolicyPaginator(client, &organizations.ListTargetsForPolicyInput{
							PolicyId: policy.Id,
						})
						for targetPager.HasMorePages() {
							targetPage, err := targetPager.NextPage(ctx)
							if err != nil {
								if isOrganizationsAccessDenied(err) {
									return e.handleOrganizationsError("aws_organizations_policy_targets", err, results)
								}
								e.logger.Warn("failed to list policy targets", "policy", policyID, "error", err)
								break
							}

							for _, target := range targetPage.Targets {
								row := map[string]interface{}{
									"policy_id":   policyID,
									"policy_arn":  aws.ToString(policy.Arn),
									"policy_name": aws.ToString(policy.Name),
									"policy_type": string(policy.Type),
									"target_id":   aws.ToString(target.TargetId),
									"target_arn":  aws.ToString(target.Arn),
									"target_name": aws.ToString(target.Name),
									"target_type": string(target.Type),
									"account_id":  accountID,
								}
								results = append(results, row)
							}
						}
					}
				}
			}

			return results, nil
		},
	}
}

// Organizations Delegated Administrators table
func (e *SyncEngine) organizationsDelegatedAdministratorsTable() TableSpec {
	return TableSpec{
		Name: "aws_organizations_delegated_administrators",
		Columns: []string{
			"_cq_hash", "arn", "id", "account_id", "name", "email",
			"joined_method", "joined_timestamp", "delegation_enabled_date",
			"status", "state",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := organizations.NewFromConfig(cfg)
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := organizations.NewListDelegatedAdministratorsPaginator(client, &organizations.ListDelegatedAdministratorsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return e.handleOrganizationsError("aws_organizations_delegated_administrators", err, results)
				}

				for _, admin := range page.DelegatedAdministrators {
					row := map[string]interface{}{
						"arn":                     aws.ToString(admin.Arn),
						"id":                      aws.ToString(admin.Id),
						"account_id":              accountID,
						"name":                    aws.ToString(admin.Name),
						"email":                   aws.ToString(admin.Email),
						"joined_method":           string(admin.JoinedMethod),
						"joined_timestamp":        timeToString(admin.JoinedTimestamp),
						"delegation_enabled_date": timeToString(admin.DelegationEnabledDate),
						"status":                  string(admin.Status),
						"state":                   string(admin.State),
					}
					results = append(results, row)
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
				return e.handleOrganizationsError("aws_organizations_organizational_units", err, results)
			}

			var ouErr error
			// Recursively get OUs
			var getOUs func(parentID string)
			getOUs = func(parentID string) {
				if ouErr != nil {
					return
				}
				paginator := organizations.NewListOrganizationalUnitsForParentPaginator(client, &organizations.ListOrganizationalUnitsForParentInput{
					ParentId: aws.String(parentID),
				})
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil {
						if isOrganizationsAccessDenied(err) {
							ouErr = err
							return
						}
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
						if ouErr != nil {
							return
						}
					}
				}
			}

			// Start from each root
			for _, root := range rootsOut.Roots {
				getOUs(aws.ToString(root.Id))
				if ouErr != nil {
					break
				}
			}

			if ouErr != nil {
				return e.handleOrganizationsError("aws_organizations_organizational_units", ouErr, results)
			}

			return results, nil
		},
	}
}

// Organizations Account Parents table
func (e *SyncEngine) organizationsAccountParentsTable() TableSpec {
	return TableSpec{
		Name: "aws_organizations_account_parents",
		Columns: []string{
			"_cq_hash", "account_id", "child_id", "child_type", "parent_id", "parent_type",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := organizations.NewFromConfig(cfg)
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := organizations.NewListAccountsPaginator(client, &organizations.ListAccountsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return e.handleOrganizationsError("aws_organizations_account_parents", err, results)
				}

				for _, account := range page.Accounts {
					childID := aws.ToString(account.Id)
					if childID == "" {
						continue
					}

					parentsPager := organizations.NewListParentsPaginator(client, &organizations.ListParentsInput{
						ChildId: account.Id,
					})
					for parentsPager.HasMorePages() {
						parentPage, err := parentsPager.NextPage(ctx)
						if err != nil {
							if isOrganizationsAccessDenied(err) {
								return e.handleOrganizationsError("aws_organizations_account_parents", err, results)
							}
							e.logger.Warn("failed to list account parents", "account", childID, "error", err)
							break
						}

						for _, parent := range parentPage.Parents {
							row := map[string]interface{}{
								"account_id":  accountID,
								"child_id":    childID,
								"child_type":  string(organizations_types.ChildTypeAccount),
								"parent_id":   aws.ToString(parent.Id),
								"parent_type": string(parent.Type),
							}
							results = append(results, row)
						}
					}
				}
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) handleOrganizationsError(table string, err error, results []map[string]interface{}) ([]map[string]interface{}, error) {
	if err == nil {
		return results, nil
	}
	if isOrganizationsAccessDenied(err) {
		e.logger.Warn("organizations access denied, skipping table", "table", table, "error", err)
		return results, nil
	}
	return nil, err
}

func isOrganizationsAccessDenied(err error) bool {
	var accessDenied *organizations_types.AccessDeniedException
	if errors.As(err, &accessDenied) {
		return true
	}
	var notInUse *organizations_types.AWSOrganizationsNotInUseException
	return errors.As(err, &notInUse)
}
