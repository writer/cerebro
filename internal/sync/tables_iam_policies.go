package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// IAM Policies
func (e *SyncEngine) iamPolicyTable() TableSpec {
	return TableSpec{
		Name:    "aws_iam_policies",
		Columns: []string{"arn", "account_id", "policy_id", "policy_name", "path", "default_version_id", "attachment_count", "permissions_boundary_usage_count", "is_attachable", "description", "create_date", "update_date", "tags"},
		Fetch:   e.fetchIAMPolicies,
	}
}

func (e *SyncEngine) fetchIAMPolicies(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := iam.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	paginator := iam.NewListPoliciesPaginator(client, &iam.ListPoliciesInput{
		Scope: types.PolicyScopeTypeLocal,
	})

	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, p := range out.Policies {
			policyArn := aws.ToString(p.Arn)
			rows = append(rows, map[string]interface{}{
				"_cq_id":                            policyArn,
				"arn":                               policyArn,
				"account_id":                        accountID,
				"policy_id":                         aws.ToString(p.PolicyId),
				"policy_name":                       aws.ToString(p.PolicyName),
				"path":                              aws.ToString(p.Path),
				"default_version_id":                aws.ToString(p.DefaultVersionId),
				"attachment_count":                  p.AttachmentCount,
				"permissions_boundary_usage_count":  p.PermissionsBoundaryUsageCount,
				"is_attachable":                     p.IsAttachable,
				"description":                       aws.ToString(p.Description),
				"create_date":                       p.CreateDate,
				"update_date":                       p.UpdateDate,
				"tags":                              p.Tags,
			})
		}
	}
	return rows, nil
}

// IAM Groups
func (e *SyncEngine) iamGroupTable() TableSpec {
	return TableSpec{
		Name:    "aws_iam_groups",
		Columns: []string{"arn", "account_id", "group_id", "group_name", "path", "create_date"},
		Fetch:   e.fetchIAMGroups,
	}
}

func (e *SyncEngine) fetchIAMGroups(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := iam.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	paginator := iam.NewListGroupsPaginator(client, &iam.ListGroupsInput{})

	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, g := range out.Groups {
			groupArn := aws.ToString(g.Arn)
			rows = append(rows, map[string]interface{}{
				"_cq_id":      groupArn,
				"arn":         groupArn,
				"account_id":  accountID,
				"group_id":    aws.ToString(g.GroupId),
				"group_name":  aws.ToString(g.GroupName),
				"path":        aws.ToString(g.Path),
				"create_date": g.CreateDate,
			})
		}
	}
	return rows, nil
}

// IAM User Access Keys
func (e *SyncEngine) iamUserAccessKeyTable() TableSpec {
	return TableSpec{
		Name:    "aws_iam_user_access_keys",
		Columns: []string{"arn", "account_id", "user_name", "access_key_id", "status", "create_date", "last_used_date", "last_used_service", "last_used_region"},
		Fetch:   e.fetchIAMUserAccessKeys,
	}
}

func (e *SyncEngine) fetchIAMUserAccessKeys(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := iam.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	// First get all users
	var users []string
	userPaginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for userPaginator.HasMorePages() {
		out, err := userPaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, u := range out.Users {
			users = append(users, aws.ToString(u.UserName))
		}
	}

	var rows []map[string]interface{}
	for _, userName := range users {
		keysOut, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
			UserName: aws.String(userName),
		})
		if err != nil {
			continue
		}

		for _, key := range keysOut.AccessKeyMetadata {
			keyID := aws.ToString(key.AccessKeyId)
			arn := fmt.Sprintf("arn:aws:iam::%s:user/%s/accesskey/%s", accountID, userName, keyID)

			var lastUsedDate *time.Time
			var lastUsedService, lastUsedRegion string

			lastUsedOut, err := client.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{
				AccessKeyId: key.AccessKeyId,
			})
			if err == nil && lastUsedOut.AccessKeyLastUsed != nil {
				lastUsedDate = lastUsedOut.AccessKeyLastUsed.LastUsedDate
				lastUsedService = aws.ToString(lastUsedOut.AccessKeyLastUsed.ServiceName)
				lastUsedRegion = aws.ToString(lastUsedOut.AccessKeyLastUsed.Region)
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":            arn,
				"arn":               arn,
				"account_id":        accountID,
				"user_name":         userName,
				"access_key_id":     keyID,
				"status":            string(key.Status),
				"create_date":       key.CreateDate,
				"last_used_date":    lastUsedDate,
				"last_used_service": lastUsedService,
				"last_used_region":  lastUsedRegion,
			})
		}
	}
	return rows, nil
}

// IAM MFA Devices
func (e *SyncEngine) iamMfaDeviceTable() TableSpec {
	return TableSpec{
		Name:    "aws_iam_mfa_devices",
		Columns: []string{"arn", "account_id", "user_name", "serial_number", "enable_date"},
		Fetch:   e.fetchIAMMfaDevices,
	}
}

func (e *SyncEngine) fetchIAMMfaDevices(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := iam.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	// First get all users
	var users []string
	userPaginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for userPaginator.HasMorePages() {
		out, err := userPaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, u := range out.Users {
			users = append(users, aws.ToString(u.UserName))
		}
	}

	var rows []map[string]interface{}
	for _, userName := range users {
		mfaOut, err := client.ListMFADevices(ctx, &iam.ListMFADevicesInput{
			UserName: aws.String(userName),
		})
		if err != nil {
			continue
		}

		for _, mfa := range mfaOut.MFADevices {
			serialNumber := aws.ToString(mfa.SerialNumber)
			rows = append(rows, map[string]interface{}{
				"_cq_id":        serialNumber,
				"arn":           serialNumber,
				"account_id":    accountID,
				"user_name":     userName,
				"serial_number": serialNumber,
				"enable_date":   mfa.EnableDate,
			})
		}
	}
	return rows, nil
}

// IAM Virtual MFA Devices
func (e *SyncEngine) iamVirtualMfaDeviceTable() TableSpec {
	return TableSpec{
		Name:    "aws_iam_virtual_mfa_devices",
		Columns: []string{"arn", "account_id", "serial_number", "user_name", "user_arn", "enable_date", "tags"},
		Fetch:   e.fetchIAMVirtualMfaDevices,
	}
}

func (e *SyncEngine) fetchIAMVirtualMfaDevices(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := iam.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	paginator := iam.NewListVirtualMFADevicesPaginator(client, &iam.ListVirtualMFADevicesInput{})

	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, mfa := range out.VirtualMFADevices {
			serialNumber := aws.ToString(mfa.SerialNumber)
			var userName, userArn string
			if mfa.User != nil {
				userName = aws.ToString(mfa.User.UserName)
				userArn = aws.ToString(mfa.User.Arn)
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":        serialNumber,
				"arn":           serialNumber,
				"account_id":    accountID,
				"serial_number": serialNumber,
				"user_name":     userName,
				"user_arn":      userArn,
				"enable_date":   mfa.EnableDate,
				"tags":          mfa.Tags,
			})
		}
	}
	return rows, nil
}

// IAM Password Policy
func (e *SyncEngine) iamPasswordPolicyTable() TableSpec {
	return TableSpec{
		Name:    "aws_iam_password_policies",
		Columns: []string{"arn", "account_id", "minimum_password_length", "require_symbols", "require_numbers", "require_uppercase_characters", "require_lowercase_characters", "allow_users_to_change_password", "expire_passwords", "max_password_age", "password_reuse_prevention", "hard_expiry"},
		Fetch:   e.fetchIAMPasswordPolicy,
	}
}

func (e *SyncEngine) fetchIAMPasswordPolicy(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := iam.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	out, err := client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		// No password policy is set - return empty
		return nil, nil
	}

	arn := fmt.Sprintf("arn:aws:iam::%s:account-password-policy", accountID)
	pp := out.PasswordPolicy

	return []map[string]interface{}{
		{
			"_cq_id":                          arn,
			"arn":                             arn,
			"account_id":                      accountID,
			"minimum_password_length":         pp.MinimumPasswordLength,
			"require_symbols":                 pp.RequireSymbols,
			"require_numbers":                 pp.RequireNumbers,
			"require_uppercase_characters":    pp.RequireUppercaseCharacters,
			"require_lowercase_characters":    pp.RequireLowercaseCharacters,
			"allow_users_to_change_password":  pp.AllowUsersToChangePassword,
			"expire_passwords":                pp.ExpirePasswords,
			"max_password_age":                pp.MaxPasswordAge,
			"password_reuse_prevention":       pp.PasswordReusePrevention,
			"hard_expiry":                     pp.HardExpiry,
		},
	}, nil
}

// IAM Account Summary
func (e *SyncEngine) iamAccountSummaryTable() TableSpec {
	return TableSpec{
		Name:    "aws_iam_accounts",
		Columns: []string{"arn", "account_id", "users", "users_quota", "groups", "groups_quota", "roles", "roles_quota", "policies", "policies_quota", "account_mfa_enabled", "account_access_keys_present", "mfa_devices", "mfa_devices_in_use"},
		Fetch:   e.fetchIAMAccountSummary,
	}
}

func (e *SyncEngine) fetchIAMAccountSummary(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := iam.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	out, err := client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, err
	}

	arn := fmt.Sprintf("arn:aws:iam::%s:root", accountID)
	sm := out.SummaryMap

	return []map[string]interface{}{
		{
			"_cq_id":                      arn,
			"arn":                         arn,
			"account_id":                  accountID,
			"users":                       sm["Users"],
			"users_quota":                 sm["UsersQuota"],
			"groups":                      sm["Groups"],
			"groups_quota":                sm["GroupsQuota"],
			"roles":                       sm["Roles"],
			"roles_quota":                 sm["RolesQuota"],
			"policies":                    sm["Policies"],
			"policies_quota":              sm["PoliciesQuota"],
			"account_mfa_enabled":         sm["AccountMFAEnabled"] == 1,
			"account_access_keys_present": sm["AccountAccessKeysPresent"] == 1,
			"mfa_devices":                 sm["MFADevices"],
			"mfa_devices_in_use":          sm["MFADevicesInUse"],
		},
	}, nil
}

// IAM Instance Profiles
func (e *SyncEngine) iamInstanceProfileTable() TableSpec {
	return TableSpec{
		Name:    "aws_iam_instance_profiles",
		Columns: []string{"arn", "account_id", "instance_profile_id", "instance_profile_name", "path", "roles", "create_date", "tags"},
		Fetch:   e.fetchIAMInstanceProfiles,
	}
}

func (e *SyncEngine) fetchIAMInstanceProfiles(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := iam.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	paginator := iam.NewListInstanceProfilesPaginator(client, &iam.ListInstanceProfilesInput{})

	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, ip := range out.InstanceProfiles {
			ipArn := aws.ToString(ip.Arn)

			var roles []map[string]interface{}
			for _, r := range ip.Roles {
				roles = append(roles, map[string]interface{}{
					"arn":       aws.ToString(r.Arn),
					"role_id":   aws.ToString(r.RoleId),
					"role_name": aws.ToString(r.RoleName),
				})
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":                ipArn,
				"arn":                   ipArn,
				"account_id":            accountID,
				"instance_profile_id":   aws.ToString(ip.InstanceProfileId),
				"instance_profile_name": aws.ToString(ip.InstanceProfileName),
				"path":                  aws.ToString(ip.Path),
				"roles":                 roles,
				"create_date":           ip.CreateDate,
				"tags":                  ip.Tags,
			})
		}
	}
	return rows, nil
}

// IAM SAML Providers
func (e *SyncEngine) iamSamlProviderTable() TableSpec {
	return TableSpec{
		Name:    "aws_iam_saml_identity_providers",
		Columns: []string{"arn", "account_id", "saml_metadata_document", "create_date", "valid_until", "tags"},
		Fetch:   e.fetchIAMSamlProviders,
	}
}

func (e *SyncEngine) fetchIAMSamlProviders(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := iam.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	listOut, err := client.ListSAMLProviders(ctx, &iam.ListSAMLProvidersInput{})
	if err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	for _, p := range listOut.SAMLProviderList {
		providerArn := aws.ToString(p.Arn)

		getOut, err := client.GetSAMLProvider(ctx, &iam.GetSAMLProviderInput{
			SAMLProviderArn: p.Arn,
		})
		if err != nil {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"_cq_id":                 providerArn,
			"arn":                    providerArn,
			"account_id":             accountID,
			"saml_metadata_document": aws.ToString(getOut.SAMLMetadataDocument),
			"create_date":            getOut.CreateDate,
			"valid_until":            getOut.ValidUntil,
			"tags":                   getOut.Tags,
		})
	}
	return rows, nil
}

// IAM OpenID Connect Providers
func (e *SyncEngine) iamOidcProviderTable() TableSpec {
	return TableSpec{
		Name:    "aws_iam_openid_connect_identity_providers",
		Columns: []string{"arn", "account_id", "url", "client_id_list", "thumbprint_list", "create_date", "tags"},
		Fetch:   e.fetchIAMOidcProviders,
	}
}

func (e *SyncEngine) fetchIAMOidcProviders(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := iam.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	listOut, err := client.ListOpenIDConnectProviders(ctx, &iam.ListOpenIDConnectProvidersInput{})
	if err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	for _, p := range listOut.OpenIDConnectProviderList {
		providerArn := aws.ToString(p.Arn)

		getOut, err := client.GetOpenIDConnectProvider(ctx, &iam.GetOpenIDConnectProviderInput{
			OpenIDConnectProviderArn: p.Arn,
		})
		if err != nil {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"_cq_id":          providerArn,
			"arn":             providerArn,
			"account_id":      accountID,
			"url":             aws.ToString(getOut.Url),
			"client_id_list":  getOut.ClientIDList,
			"thumbprint_list": getOut.ThumbprintList,
			"create_date":     getOut.CreateDate,
			"tags":            getOut.Tags,
		})
	}
	return rows, nil
}

// IAM Server Certificates
func (e *SyncEngine) iamServerCertificateTable() TableSpec {
	return TableSpec{
		Name:    "aws_iam_server_certificates",
		Columns: []string{"arn", "account_id", "server_certificate_id", "server_certificate_name", "path", "upload_date", "expiration"},
		Fetch:   e.fetchIAMServerCertificates,
	}
}

func (e *SyncEngine) fetchIAMServerCertificates(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := iam.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	paginator := iam.NewListServerCertificatesPaginator(client, &iam.ListServerCertificatesInput{})

	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, cert := range out.ServerCertificateMetadataList {
			certArn := aws.ToString(cert.Arn)
			rows = append(rows, map[string]interface{}{
				"_cq_id":                  certArn,
				"arn":                     certArn,
				"account_id":              accountID,
				"server_certificate_id":   aws.ToString(cert.ServerCertificateId),
				"server_certificate_name": aws.ToString(cert.ServerCertificateName),
				"path":                    aws.ToString(cert.Path),
				"upload_date":             cert.UploadDate,
				"expiration":              cert.Expiration,
			})
		}
	}
	return rows, nil
}

// IAM Role Policies (inline)
func (e *SyncEngine) iamRolePolicyTable() TableSpec {
	return TableSpec{
		Name:    "aws_iam_role_policies",
		Columns: []string{"arn", "account_id", "role_name", "role_arn", "policy_name", "policy_document"},
		Fetch:   e.fetchIAMRolePolicies,
	}
}

func (e *SyncEngine) fetchIAMRolePolicies(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := iam.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	// Get all roles first
	var roles []types.Role
	rolePaginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})
	for rolePaginator.HasMorePages() {
		out, err := rolePaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		roles = append(roles, out.Roles...)
	}

	var rows []map[string]interface{}
	for _, role := range roles {
		roleName := aws.ToString(role.RoleName)
		roleArn := aws.ToString(role.Arn)

		policyPaginator := iam.NewListRolePoliciesPaginator(client, &iam.ListRolePoliciesInput{
			RoleName: role.RoleName,
		})
		for policyPaginator.HasMorePages() {
			out, err := policyPaginator.NextPage(ctx)
			if err != nil {
				break
			}

			for _, policyName := range out.PolicyNames {
				policyOut, err := client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
					RoleName:   role.RoleName,
					PolicyName: aws.String(policyName),
				})
				if err != nil {
					continue
				}

				policyDoc := aws.ToString(policyOut.PolicyDocument)
				if decoded, err := url.QueryUnescape(policyDoc); err == nil {
					policyDoc = decoded
				}

				arn := fmt.Sprintf("%s/policy/%s", roleArn, policyName)
				rows = append(rows, map[string]interface{}{
					"_cq_id":          arn,
					"arn":             arn,
					"account_id":      accountID,
					"role_name":       roleName,
					"role_arn":        roleArn,
					"policy_name":     policyName,
					"policy_document": policyDoc,
				})
			}
		}
	}
	return rows, nil
}

// IAM Role Attached Policies
func (e *SyncEngine) iamRoleAttachedPolicyTable() TableSpec {
	return TableSpec{
		Name:    "aws_iam_role_attached_policies",
		Columns: []string{"arn", "account_id", "role_name", "role_arn", "policy_name", "policy_arn"},
		Fetch:   e.fetchIAMRoleAttachedPolicies,
	}
}

func (e *SyncEngine) fetchIAMRoleAttachedPolicies(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := iam.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	// Get all roles first
	var roles []types.Role
	rolePaginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})
	for rolePaginator.HasMorePages() {
		out, err := rolePaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		roles = append(roles, out.Roles...)
	}

	var rows []map[string]interface{}
	for _, role := range roles {
		roleName := aws.ToString(role.RoleName)
		roleArn := aws.ToString(role.Arn)

		policyPaginator := iam.NewListAttachedRolePoliciesPaginator(client, &iam.ListAttachedRolePoliciesInput{
			RoleName: role.RoleName,
		})
		for policyPaginator.HasMorePages() {
			out, err := policyPaginator.NextPage(ctx)
			if err != nil {
				break
			}

			for _, policy := range out.AttachedPolicies {
				policyArn := aws.ToString(policy.PolicyArn)
				arn := fmt.Sprintf("%s/attached/%s", roleArn, aws.ToString(policy.PolicyName))
				rows = append(rows, map[string]interface{}{
					"_cq_id":      arn,
					"arn":         arn,
					"account_id":  accountID,
					"role_name":   roleName,
					"role_arn":    roleArn,
					"policy_name": aws.ToString(policy.PolicyName),
					"policy_arn":  policyArn,
				})
			}
		}
	}
	return rows, nil
}

// IAM User Policies (inline)
func (e *SyncEngine) iamUserPolicyTable() TableSpec {
	return TableSpec{
		Name:    "aws_iam_user_policies",
		Columns: []string{"arn", "account_id", "user_name", "user_arn", "policy_name", "policy_document"},
		Fetch:   e.fetchIAMUserPolicies,
	}
}

func (e *SyncEngine) fetchIAMUserPolicies(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := iam.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	// Get all users first
	var users []types.User
	userPaginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for userPaginator.HasMorePages() {
		out, err := userPaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		users = append(users, out.Users...)
	}

	var rows []map[string]interface{}
	for _, user := range users {
		userName := aws.ToString(user.UserName)
		userArn := aws.ToString(user.Arn)

		policyPaginator := iam.NewListUserPoliciesPaginator(client, &iam.ListUserPoliciesInput{
			UserName: user.UserName,
		})
		for policyPaginator.HasMorePages() {
			out, err := policyPaginator.NextPage(ctx)
			if err != nil {
				break
			}

			for _, policyName := range out.PolicyNames {
				policyOut, err := client.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
					UserName:   user.UserName,
					PolicyName: aws.String(policyName),
				})
				if err != nil {
					continue
				}

				policyDoc := aws.ToString(policyOut.PolicyDocument)
				if decoded, err := url.QueryUnescape(policyDoc); err == nil {
					policyDoc = decoded
				}

				arn := fmt.Sprintf("%s/policy/%s", userArn, policyName)
				rows = append(rows, map[string]interface{}{
					"_cq_id":          arn,
					"arn":             arn,
					"account_id":      accountID,
					"user_name":       userName,
					"user_arn":        userArn,
					"policy_name":     policyName,
					"policy_document": policyDoc,
				})
			}
		}
	}
	return rows, nil
}

// IAM Group Policies (inline)
func (e *SyncEngine) iamGroupPolicyTable() TableSpec {
	return TableSpec{
		Name:    "aws_iam_group_policies",
		Columns: []string{"arn", "account_id", "group_name", "group_arn", "policy_name", "policy_document"},
		Fetch:   e.fetchIAMGroupPolicies,
	}
}

func (e *SyncEngine) fetchIAMGroupPolicies(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := iam.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	// Get all groups first
	var groups []types.Group
	groupPaginator := iam.NewListGroupsPaginator(client, &iam.ListGroupsInput{})
	for groupPaginator.HasMorePages() {
		out, err := groupPaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		groups = append(groups, out.Groups...)
	}

	var rows []map[string]interface{}
	for _, group := range groups {
		groupName := aws.ToString(group.GroupName)
		groupArn := aws.ToString(group.Arn)

		policyPaginator := iam.NewListGroupPoliciesPaginator(client, &iam.ListGroupPoliciesInput{
			GroupName: group.GroupName,
		})
		for policyPaginator.HasMorePages() {
			out, err := policyPaginator.NextPage(ctx)
			if err != nil {
				break
			}

			for _, policyName := range out.PolicyNames {
				policyOut, err := client.GetGroupPolicy(ctx, &iam.GetGroupPolicyInput{
					GroupName:  group.GroupName,
					PolicyName: aws.String(policyName),
				})
				if err != nil {
					continue
				}

				policyDoc := aws.ToString(policyOut.PolicyDocument)
				if decoded, err := url.QueryUnescape(policyDoc); err == nil {
					policyDoc = decoded
				}

				arn := fmt.Sprintf("%s/policy/%s", groupArn, policyName)
				rows = append(rows, map[string]interface{}{
					"_cq_id":          arn,
					"arn":             arn,
					"account_id":      accountID,
					"group_name":      groupName,
					"group_arn":       groupArn,
					"policy_name":     policyName,
					"policy_document": policyDoc,
				})
			}
		}
	}
	return rows, nil
}

// IAM User Groups
func (e *SyncEngine) iamUserGroupTable() TableSpec {
	return TableSpec{
		Name:    "aws_iam_user_groups",
		Columns: []string{"arn", "account_id", "user_name", "user_arn", "group_name", "group_arn"},
		Fetch:   e.fetchIAMUserGroups,
	}
}

func (e *SyncEngine) fetchIAMUserGroups(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := iam.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	// Get all users first
	var users []types.User
	userPaginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for userPaginator.HasMorePages() {
		out, err := userPaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		users = append(users, out.Users...)
	}

	var rows []map[string]interface{}
	for _, user := range users {
		userName := aws.ToString(user.UserName)
		userArn := aws.ToString(user.Arn)

		groupsOut, err := client.ListGroupsForUser(ctx, &iam.ListGroupsForUserInput{
			UserName: user.UserName,
		})
		if err != nil {
			continue
		}

		for _, group := range groupsOut.Groups {
			groupArn := aws.ToString(group.Arn)
			arn := fmt.Sprintf("%s/group/%s", userArn, aws.ToString(group.GroupName))
			rows = append(rows, map[string]interface{}{
				"_cq_id":     arn,
				"arn":        arn,
				"account_id": accountID,
				"user_name":  userName,
				"user_arn":   userArn,
				"group_name": aws.ToString(group.GroupName),
				"group_arn":  groupArn,
			})
		}
	}
	return rows, nil
}

// Placeholder for compiler
var _ = json.Marshal
var _ types.PolicyScopeType
