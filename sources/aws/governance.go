package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	identitystoretypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	organizationstypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssoadmintypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsOrganizationsAccount struct {
	Account organizationstypes.Account
	ID      string
	OrgID   string
	Parent  organizationstypes.Parent
}

type awsOrganizationsOU struct {
	OU       organizationstypes.OrganizationalUnit
	ID       string
	ParentID string
	RootID   string
}

type awsOrganizationsPolicy struct {
	Policy  organizationstypes.PolicySummary
	ID      string
	Content string
	Targets []organizationstypes.PolicyTargetSummary
}

type awsOrganizationsRoot struct {
	Root organizationstypes.Root
	ID   string
}

type awsSSOInstance struct {
	Instance        ssoadmintypes.InstanceMetadata
	InstanceARN     string
	IdentityStoreID string
}

type awsSSOPermissionSet struct {
	InstanceARN      string
	IdentityStoreID  string
	PermissionSet    ssoadmintypes.PermissionSet
	PermissionSetARN string
}

type awsSSOAccountAssignment struct {
	InstanceARN       string
	IdentityStoreID   string
	AccountID         string
	PermissionSetARN  string
	PermissionSetName string
	PrincipalID       string
	PrincipalType     string
	Assignment        ssoadmintypes.AccountAssignment
}

type awsIdentityStoreUser struct {
	IdentityStoreID string
	User            identitystoretypes.User
	UserID          string
}

type awsIdentityStoreGroup struct {
	IdentityStoreID string
	Group           identitystoretypes.Group
	GroupID         string
}

type awsIdentityStoreGroupMembership struct {
	IdentityStoreID string
	GroupID         string
	MemberID        string
	Membership      identitystoretypes.GroupMembership
}

func listOrganizationsAccounts(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsOrganizationsAccount, string, error) {
	records, err := listAllOrganizationsAccounts(ctx, clients, settings)
	if err != nil {
		return nil, "", err
	}
	return governancePage(records, cursor, limit)
}

func listAllOrganizationsAccounts(ctx context.Context, clients awsClients, settings settings) ([]awsOrganizationsAccount, error) {
	var records []awsOrganizationsAccount
	var next *string
	for {
		output, err := clients.organizations.ListAccounts(ctx, &organizations.ListAccountsInput{
			MaxResults: awssdk.Int32(20),
			NextToken:  next,
		})
		if err != nil && optionalAWSError(err, "AccessDeniedException") && settings.accountID != "" {
			return []awsOrganizationsAccount{{ID: settings.accountID}}, nil
		}
		if err != nil {
			return nil, err
		}
		for _, account := range output.Accounts {
			id := awssdk.ToString(account.Id)
			if id == "" {
				continue
			}
			parent, err := organizationParent(ctx, clients, id)
			if err != nil {
				return nil, fmt.Errorf("list organizations parent for account %q: %w", id, err)
			}
			records = append(records, awsOrganizationsAccount{Account: account, ID: id, OrgID: organizationsIDFromARN(awssdk.ToString(account.Arn)), Parent: parent})
		}
		if awssdk.ToString(output.NextToken) == "" {
			break
		}
		next = output.NextToken
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

func listOrganizationsOUs(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsOrganizationsOU, string, error) {
	var records []awsOrganizationsOU
	roots, err := listOrganizationRoots(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	for _, root := range roots {
		rootID := awssdk.ToString(root.Id)
		if rootID == "" {
			continue
		}
		children, err := listOrganizationOUsForParent(ctx, clients, rootID, rootID)
		if err != nil {
			return nil, "", err
		}
		records = append(records, children...)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return governancePage(records, cursor, limit)
}

func listOrganizationsRoots(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsOrganizationsRoot, string, error) {
	roots, err := listOrganizationRoots(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	records := make([]awsOrganizationsRoot, 0, len(roots))
	for _, root := range roots {
		id := awssdk.ToString(root.Id)
		if id == "" {
			continue
		}
		records = append(records, awsOrganizationsRoot{Root: root, ID: id})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return governancePage(records, cursor, limit)
}

func listOrganizationsPolicies(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsOrganizationsPolicy, string, error) {
	var records []awsOrganizationsPolicy
	for _, policyType := range organizationstypes.PolicyType("").Values() {
		var next *string
		for {
			output, err := clients.organizations.ListPolicies(ctx, &organizations.ListPoliciesInput{
				Filter:     policyType,
				MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 20)),
				NextToken:  next,
			})
			if err != nil {
				if optionalAWSError(err, "PolicyTypeNotEnabledException", "AccessDeniedException") {
					break
				}
				return nil, "", fmt.Errorf("list organizations policies %s: %w", policyType, err)
			}
			for _, policy := range output.Policies {
				id := awssdk.ToString(policy.Id)
				if id == "" {
					continue
				}
				record := awsOrganizationsPolicy{Policy: policy, ID: id}
				detail, err := clients.organizations.DescribePolicy(ctx, &organizations.DescribePolicyInput{PolicyId: awssdk.String(id)})
				if err != nil {
					return nil, "", fmt.Errorf("describe organizations policy %q: %w", id, err)
				}
				if detail.Policy != nil {
					record.Content = awssdk.ToString(detail.Policy.Content)
					if detail.Policy.PolicySummary != nil {
						record.Policy = *detail.Policy.PolicySummary
					}
				}
				targets, err := listOrganizationPolicyTargets(ctx, clients, id)
				if err != nil {
					return nil, "", err
				}
				record.Targets = targets
				records = append(records, record)
			}
			if awssdk.ToString(output.NextToken) == "" {
				break
			}
			next = output.NextToken
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return governancePage(records, cursor, limit)
}

func listSSOInstances(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsSSOInstance, string, error) {
	instances, err := listAllSSOInstances(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	return governancePage(instances, cursor, limit)
}

func listSSOPermissionSets(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsSSOPermissionSet, string, error) {
	records, err := listAllSSOPermissionSets(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	return governancePage(records, cursor, limit)
}

func listAllSSOPermissionSets(ctx context.Context, clients awsClients) ([]awsSSOPermissionSet, error) {
	instances, err := listAllSSOInstances(ctx, clients)
	if err != nil {
		return nil, err
	}
	var records []awsSSOPermissionSet
	for _, instance := range instances {
		var next *string
		for {
			output, err := clients.sso.ListPermissionSets(ctx, &ssoadmin.ListPermissionSetsInput{
				InstanceArn: awssdk.String(instance.InstanceARN),
				MaxResults:  awssdk.Int32(100),
				NextToken:   next,
			})
			if err != nil {
				return nil, fmt.Errorf("list sso permission sets for %q: %w", instance.InstanceARN, err)
			}
			for _, arn := range output.PermissionSets {
				describe, err := clients.sso.DescribePermissionSet(ctx, &ssoadmin.DescribePermissionSetInput{InstanceArn: awssdk.String(instance.InstanceARN), PermissionSetArn: awssdk.String(arn)})
				if err != nil {
					return nil, fmt.Errorf("describe sso permission set %q: %w", arn, err)
				}
				if describe.PermissionSet != nil {
					records = append(records, awsSSOPermissionSet{InstanceARN: instance.InstanceARN, IdentityStoreID: instance.IdentityStoreID, PermissionSet: *describe.PermissionSet, PermissionSetARN: arn})
				}
			}
			if awssdk.ToString(output.NextToken) == "" {
				break
			}
			next = output.NextToken
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].PermissionSetARN < records[j].PermissionSetARN })
	return records, nil
}

func listSSOAccountAssignments(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsSSOAccountAssignment, string, error) {
	instances, err := listAllSSOInstances(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	accounts, err := listAllOrganizationAccountIDs(ctx, clients, settings)
	if err != nil {
		return nil, "", err
	}
	permissionSets, err := listAllSSOPermissionSets(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	permissionByInstance := map[string][]awsSSOPermissionSet{}
	for _, permissionSet := range permissionSets {
		permissionByInstance[permissionSet.InstanceARN] = append(permissionByInstance[permissionSet.InstanceARN], permissionSet)
	}

	var records []awsSSOAccountAssignment
	for _, instance := range instances {
		for _, permissionSet := range permissionByInstance[instance.InstanceARN] {
			for _, accountID := range accounts {
				var next *string
				for {
					output, err := clients.sso.ListAccountAssignments(ctx, &ssoadmin.ListAccountAssignmentsInput{
						AccountId:        awssdk.String(accountID),
						InstanceArn:      awssdk.String(instance.InstanceARN),
						PermissionSetArn: awssdk.String(permissionSet.PermissionSetARN),
						MaxResults:       awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 100)),
						NextToken:        next,
					})
					if err != nil {
						return nil, "", fmt.Errorf("list sso account assignments for %q/%q: %w", accountID, permissionSet.PermissionSetARN, err)
					}
					for _, assignment := range output.AccountAssignments {
						principalID := awssdk.ToString(assignment.PrincipalId)
						if principalID == "" {
							continue
						}
						records = append(records, awsSSOAccountAssignment{
							InstanceARN:       instance.InstanceARN,
							IdentityStoreID:   instance.IdentityStoreID,
							AccountID:         firstNonEmpty(awssdk.ToString(assignment.AccountId), accountID),
							PermissionSetARN:  firstNonEmpty(awssdk.ToString(assignment.PermissionSetArn), permissionSet.PermissionSetARN),
							PermissionSetName: awssdk.ToString(permissionSet.PermissionSet.Name),
							PrincipalID:       principalID,
							PrincipalType:     string(assignment.PrincipalType),
							Assignment:        assignment,
						})
					}
					if awssdk.ToString(output.NextToken) == "" {
						break
					}
					next = output.NextToken
				}
			}
		}
	}
	sort.Slice(records, func(i, j int) bool {
		return strings.Join([]string{records[i].AccountID, records[i].PermissionSetARN, records[i].PrincipalID}, ":") <
			strings.Join([]string{records[j].AccountID, records[j].PermissionSetARN, records[j].PrincipalID}, ":")
	})
	return governancePage(records, cursor, limit)
}

func listIdentityStoreUsers(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsIdentityStoreUser, string, error) {
	storeIDs, err := identityStoreIDs(ctx, clients, settings)
	if err != nil {
		return nil, "", err
	}
	var records []awsIdentityStoreUser
	for _, storeID := range storeIDs {
		var next *string
		for {
			output, err := clients.identityStore.ListUsers(ctx, &identitystore.ListUsersInput{
				IdentityStoreId: awssdk.String(storeID),
				MaxResults:      awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 100)),
				NextToken:       next,
			})
			if err != nil {
				return nil, "", fmt.Errorf("list identity store users for %q: %w", storeID, err)
			}
			for _, user := range output.Users {
				userID := awssdk.ToString(user.UserId)
				if userID != "" {
					records = append(records, awsIdentityStoreUser{IdentityStoreID: storeID, User: user, UserID: userID})
				}
			}
			if awssdk.ToString(output.NextToken) == "" {
				break
			}
			next = output.NextToken
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].UserID < records[j].UserID })
	return governancePage(records, cursor, limit)
}

func listIdentityStoreGroups(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsIdentityStoreGroup, string, error) {
	groups, err := listAllIdentityStoreGroups(ctx, clients, settings)
	if err != nil {
		return nil, "", err
	}
	return governancePage(groups, cursor, limit)
}

func listIdentityStoreGroupMemberships(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsIdentityStoreGroupMembership, string, error) {
	groups, err := listAllIdentityStoreGroups(ctx, clients, settings)
	if err != nil {
		return nil, "", err
	}
	var records []awsIdentityStoreGroupMembership
	for _, group := range groups {
		var next *string
		for {
			output, err := clients.identityStore.ListGroupMemberships(ctx, &identitystore.ListGroupMembershipsInput{
				GroupId:         awssdk.String(group.GroupID),
				IdentityStoreId: awssdk.String(group.IdentityStoreID),
				MaxResults:      awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 100)),
				NextToken:       next,
			})
			if err != nil {
				return nil, "", fmt.Errorf("list identity store group memberships for %q: %w", group.GroupID, err)
			}
			for _, membership := range output.GroupMemberships {
				memberID := identityStoreMembershipUserID(membership.MemberId)
				if memberID == "" {
					continue
				}
				records = append(records, awsIdentityStoreGroupMembership{IdentityStoreID: group.IdentityStoreID, GroupID: firstNonEmpty(awssdk.ToString(membership.GroupId), group.GroupID), MemberID: memberID, Membership: membership})
			}
			if awssdk.ToString(output.NextToken) == "" {
				break
			}
			next = output.NextToken
		}
	}
	return governancePage(records, cursor, limit)
}

func organizationsAccountEvent(settings settings, record awsOrganizationsAccount) (*primitives.Event, error) {
	account := record.Account
	id := record.ID
	arn := firstNonEmpty(awssdk.ToString(account.Arn), organizationsAccountARN(settings, id))
	attributes := commonCloudAssetAttributes(settings, "global", familyOrganizationsAcct, id, firstNonEmpty(awssdk.ToString(account.Name), id), "organizations_account", nil)
	attributes["account_id"] = id
	attributes["account_arn"] = arn
	attributes["account_email"] = awssdk.ToString(account.Email)
	attributes["account_name"] = firstNonEmpty(awssdk.ToString(account.Name), id)
	attributes["arn"] = arn
	attributes["email"] = awssdk.ToString(account.Email)
	attributes["joined_method"] = string(account.JoinedMethod)
	attributes["organization_id"] = record.OrgID
	attributes["parent_id"] = awssdk.ToString(record.Parent.Id)
	attributes["parent_type"] = string(record.Parent.Type)
	attributes["relationship"] = "member_of"
	attributes["state"] = string(account.State)
	attributes["status"] = string(account.Status)
	addTimeAttribute(attributes, "joined_at", account.JoinedTimestamp)
	payload, err := json.Marshal(map[string]any{"account": account, "management_account_id": settings.accountID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-organizations-account-"+id, "aws.organizations_account", "aws/organizations_account/v1", payload, attributes, firstTime(account.JoinedTimestamp))
}

func organizationsOUEvent(settings settings, record awsOrganizationsOU) (*primitives.Event, error) {
	ou := record.OU
	id := record.ID
	arn := awssdk.ToString(ou.Arn)
	attributes := commonCloudAssetAttributes(settings, "global", familyOrganizationsOU, id, firstNonEmpty(awssdk.ToString(ou.Name), id), "organizations_organizational_unit", nil)
	attributes["arn"] = arn
	attributes["ou_arn"] = arn
	attributes["ou_id"] = id
	attributes["ou_name"] = firstNonEmpty(awssdk.ToString(ou.Name), id)
	attributes["organizational_unit_id"] = id
	attributes["parent_id"] = record.ParentID
	attributes["parent_type"] = organizationParentType(record.ParentID, record.RootID)
	attributes["relationship"] = "belongs_to"
	attributes["root_id"] = record.RootID
	payload, err := json.Marshal(map[string]any{"organizational_unit": ou, "management_account_id": settings.accountID, "parent_id": record.ParentID, "root_id": record.RootID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-organizations-ou-"+id, "aws.organizations_organizational_unit", "aws/organizations_organizational_unit/v1", payload, attributes, time.Now().UTC())
}

func organizationsRootEvent(settings settings, record awsOrganizationsRoot) (*primitives.Event, error) {
	root := record.Root
	id := record.ID
	arn := awssdk.ToString(root.Arn)
	attributes := commonCloudAssetAttributes(settings, "global", familyOrganizationsRoot, firstNonEmpty(id, arn), firstNonEmpty(awssdk.ToString(root.Name), id), "organizations_root", nil)
	attributes["arn"] = arn
	attributes["policy_types"] = strings.Join(organizationsRootPolicyTypes(root), ",")
	attributes["root_arn"] = arn
	attributes["root_id"] = id
	attributes["root_name"] = firstNonEmpty(awssdk.ToString(root.Name), id)
	payload, err := json.Marshal(map[string]any{"root": root, "management_account_id": settings.accountID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-organizations-root-"+id, "aws.organizations_root", "aws/organizations_root/v1", payload, attributes, time.Now().UTC())
}

func organizationsPolicyEvent(settings settings, record awsOrganizationsPolicy) (*primitives.Event, error) {
	policy := record.Policy
	id := record.ID
	arn := awssdk.ToString(policy.Arn)
	attributes := commonCloudAssetAttributes(settings, "global", familyOrganizationsPolicy, firstNonEmpty(arn, id), firstNonEmpty(awssdk.ToString(policy.Name), id), "organizations_policy", nil)
	attributes["arn"] = arn
	attributes["aws_managed"] = boolString(policy.AwsManaged)
	attributes["description"] = awssdk.ToString(policy.Description)
	attributes["policy_arn"] = arn
	attributes["policy_content"] = record.Content
	attributes["policy_id"] = id
	attributes["policy_name"] = firstNonEmpty(awssdk.ToString(policy.Name), id)
	attributes["policy_type"] = string(policy.Type)
	attributes["relationship"] = "attached_to"
	attributes["target_account_ids"] = strings.Join(organizationPolicyTargetIDs(record.Targets, organizationstypes.TargetTypeAccount), ",")
	attributes["target_arns"] = strings.Join(organizationPolicyTargetARNs(record.Targets), ",")
	attributes["target_ids"] = strings.Join(organizationPolicyTargetField(record.Targets, func(target organizationstypes.PolicyTargetSummary) string { return awssdk.ToString(target.TargetId) }), ",")
	attributes["target_names"] = strings.Join(organizationPolicyTargetField(record.Targets, func(target organizationstypes.PolicyTargetSummary) string { return awssdk.ToString(target.Name) }), ",")
	attributes["target_organizational_unit_ids"] = strings.Join(organizationPolicyTargetIDs(record.Targets, organizationstypes.TargetTypeOrganizationalUnit), ",")
	attributes["target_root_ids"] = strings.Join(organizationPolicyTargetIDs(record.Targets, organizationstypes.TargetTypeRoot), ",")
	attributes["target_types"] = strings.Join(organizationPolicyTargetField(record.Targets, func(target organizationstypes.PolicyTargetSummary) string { return string(target.Type) }), ",")
	payload, err := json.Marshal(map[string]any{"policy": policy, "targets": record.Targets, "management_account_id": settings.accountID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-organizations-policy-"+id, "aws.organizations_policy", "aws/organizations_policy/v1", payload, attributes, time.Now().UTC())
}

func ssoInstanceEvent(settings settings, record awsSSOInstance) (*primitives.Event, error) {
	instance := record.Instance
	id := firstNonEmpty(record.InstanceARN, record.IdentityStoreID)
	attributes := commonCloudAssetAttributes(settings, settings.region, familySSOInstance, id, firstNonEmpty(awssdk.ToString(instance.Name), id), "sso_instance", nil)
	attributes["arn"] = record.InstanceARN
	attributes["identity_store_id"] = record.IdentityStoreID
	attributes["instance_arn"] = record.InstanceARN
	attributes["owner_account_id"] = awssdk.ToString(instance.OwnerAccountId)
	attributes["status"] = string(instance.Status)
	attributes["status_reason"] = awssdk.ToString(instance.StatusReason)
	addTimeAttribute(attributes, "created_at", instance.CreatedDate)
	payload, err := json.Marshal(map[string]any{"instance": instance, "account_id": settings.accountID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-sso-instance-"+id, "aws.sso_instance", "aws/sso_instance/v1", payload, attributes, firstTime(instance.CreatedDate))
}

func ssoPermissionSetEvent(settings settings, record awsSSOPermissionSet) (*primitives.Event, error) {
	permissionSet := record.PermissionSet
	arn := record.PermissionSetARN
	attributes := commonCloudAssetAttributes(settings, settings.region, familySSOPermissionSet, arn, firstNonEmpty(awssdk.ToString(permissionSet.Name), arn), "sso_permission_set", nil)
	attributes["arn"] = arn
	attributes["description"] = awssdk.ToString(permissionSet.Description)
	attributes["identity_store_id"] = record.IdentityStoreID
	attributes["instance_arn"] = record.InstanceARN
	attributes["permission_set_arn"] = arn
	attributes["permission_set_name"] = awssdk.ToString(permissionSet.Name)
	attributes["relay_state"] = awssdk.ToString(permissionSet.RelayState)
	attributes["session_duration"] = awssdk.ToString(permissionSet.SessionDuration)
	addTimeAttribute(attributes, "created_at", permissionSet.CreatedDate)
	payload, err := json.Marshal(map[string]any{"permission_set": permissionSet, "instance_arn": record.InstanceARN, "identity_store_id": record.IdentityStoreID, "account_id": settings.accountID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-sso-permission-set-"+arn, "aws.sso_permission_set", "aws/sso_permission_set/v1", payload, attributes, firstTime(permissionSet.CreatedDate))
}

func ssoAccountAssignmentEvent(settings settings, record awsSSOAccountAssignment) (*primitives.Event, error) {
	assignmentID := strings.Join([]string{record.AccountID, record.PermissionSetARN, record.PrincipalID}, ":")
	attributes := map[string]string{
		"account_id":          record.AccountID,
		"domain":              settings.accountID,
		"family":              familySSOAssignment,
		"identity_store_id":   record.IdentityStoreID,
		"instance_arn":        record.InstanceARN,
		"permission_set_arn":  record.PermissionSetARN,
		"permission_set_name": record.PermissionSetName,
		"principal_id":        record.PrincipalID,
		"principal_type":      strings.ToLower(record.PrincipalType),
		"resource_id":         record.AccountID,
		"resource_name":       record.AccountID,
		"resource_provider":   "aws",
		"resource_type":       "account",
		"role_id":             record.PermissionSetARN,
		"role_name":           record.PermissionSetName,
		"subject_id":          record.PrincipalID,
		"subject_type":        strings.ToLower(record.PrincipalType),
	}
	payload, err := json.Marshal(map[string]any{"assignment": record.Assignment, "instance_arn": record.InstanceARN, "identity_store_id": record.IdentityStoreID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-sso-account-assignment-"+assignmentID, "aws.sso_account_assignment", "aws/sso_account_assignment/v1", payload, attributes, time.Now().UTC())
}

func identityStoreUserEvent(settings settings, record awsIdentityStoreUser) (*primitives.Event, error) {
	user := record.User
	email := identityStorePrimaryEmail(user.Emails)
	displayName := firstNonEmpty(awssdk.ToString(user.DisplayName), identityStoreFormattedName(user.Name), awssdk.ToString(user.UserName), record.UserID)
	attributes := map[string]string{
		"domain":            settings.accountID,
		"email":             email,
		"family":            familyIdentityStoreUser,
		"identity_store_id": record.IdentityStoreID,
		"login":             awssdk.ToString(user.UserName),
		"name":              displayName,
		"principal_type":    "user",
		"status":            string(user.UserStatus),
		"title":             awssdk.ToString(user.Title),
		"user_id":           record.UserID,
		"user_name":         awssdk.ToString(user.UserName),
		"user_type":         awssdk.ToString(user.UserType),
	}
	addTimeAttribute(attributes, "created_at", user.CreatedAt)
	addTimeAttribute(attributes, "updated_at", user.UpdatedAt)
	payload, err := json.Marshal(map[string]any{"user": user, "account_id": settings.accountID, "identity_store_id": record.IdentityStoreID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-identitystore-user-"+record.UserID, "aws.identitystore_user", "aws/identitystore_user/v1", payload, attributes, firstTime(user.UpdatedAt, user.CreatedAt))
}

func identityStoreGroupEvent(settings settings, record awsIdentityStoreGroup) (*primitives.Event, error) {
	group := record.Group
	attributes := map[string]string{
		"description":       awssdk.ToString(group.Description),
		"domain":            settings.accountID,
		"family":            familyIdentityStoreGroup,
		"group_id":          record.GroupID,
		"group_name":        awssdk.ToString(group.DisplayName),
		"identity_store_id": record.IdentityStoreID,
		"name":              awssdk.ToString(group.DisplayName),
	}
	addTimeAttribute(attributes, "created_at", group.CreatedAt)
	addTimeAttribute(attributes, "updated_at", group.UpdatedAt)
	payload, err := json.Marshal(map[string]any{"group": group, "account_id": settings.accountID, "identity_store_id": record.IdentityStoreID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-identitystore-group-"+record.GroupID, "aws.identitystore_group", "aws/identitystore_group/v1", payload, attributes, firstTime(group.UpdatedAt, group.CreatedAt))
}

func identityStoreGroupMembershipEvent(settings settings, record awsIdentityStoreGroupMembership) (*primitives.Event, error) {
	attributes := map[string]string{
		"domain":            settings.accountID,
		"family":            familyIdentityStoreMember,
		"group_id":          record.GroupID,
		"identity_store_id": record.IdentityStoreID,
		"member_id":         record.MemberID,
		"member_type":       "user",
		"member_user_id":    record.MemberID,
		"membership_id":     awssdk.ToString(record.Membership.MembershipId),
		"principal_type":    "user",
		"relationship":      "member_of",
		"user_id":           record.MemberID,
	}
	addTimeAttribute(attributes, "created_at", record.Membership.CreatedAt)
	addTimeAttribute(attributes, "updated_at", record.Membership.UpdatedAt)
	payload, err := json.Marshal(map[string]any{"membership": record.Membership, "account_id": settings.accountID, "identity_store_id": record.IdentityStoreID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-identitystore-group-membership-"+record.GroupID+"-"+record.MemberID, "aws.identitystore_group_membership", "aws/identitystore_group_membership/v1", payload, attributes, firstTime(record.Membership.UpdatedAt, record.Membership.CreatedAt))
}

func listOrganizationRoots(ctx context.Context, clients awsClients) ([]organizationstypes.Root, error) {
	var roots []organizationstypes.Root
	var next *string
	for {
		output, err := clients.organizations.ListRoots(ctx, &organizations.ListRootsInput{MaxResults: awssdk.Int32(20), NextToken: next})
		if err != nil {
			return nil, err
		}
		roots = append(roots, output.Roots...)
		if awssdk.ToString(output.NextToken) == "" {
			break
		}
		next = output.NextToken
	}
	return roots, nil
}

func organizationParent(ctx context.Context, clients awsClients, childID string) (organizationstypes.Parent, error) {
	if strings.TrimSpace(childID) == "" {
		return organizationstypes.Parent{}, nil
	}
	output, err := clients.organizations.ListParents(ctx, &organizations.ListParentsInput{ChildId: awssdk.String(childID)})
	if err != nil {
		return organizationstypes.Parent{}, err
	}
	if len(output.Parents) == 0 {
		return organizationstypes.Parent{}, nil
	}
	return output.Parents[0], nil
}

func listOrganizationOUsForParent(ctx context.Context, clients awsClients, parentID string, rootID string) ([]awsOrganizationsOU, error) {
	var records []awsOrganizationsOU
	var next *string
	for {
		output, err := clients.organizations.ListOrganizationalUnitsForParent(ctx, &organizations.ListOrganizationalUnitsForParentInput{ParentId: awssdk.String(parentID), MaxResults: awssdk.Int32(20), NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("list organizations OUs for parent %q: %w", parentID, err)
		}
		for _, ou := range output.OrganizationalUnits {
			id := awssdk.ToString(ou.Id)
			if id == "" {
				continue
			}
			records = append(records, awsOrganizationsOU{OU: ou, ID: id, ParentID: parentID, RootID: rootID})
			children, err := listOrganizationOUsForParent(ctx, clients, id, rootID)
			if err != nil {
				return nil, err
			}
			records = append(records, children...)
		}
		if awssdk.ToString(output.NextToken) == "" {
			break
		}
		next = output.NextToken
	}
	return records, nil
}

func listOrganizationPolicyTargets(ctx context.Context, clients awsClients, policyID string) ([]organizationstypes.PolicyTargetSummary, error) {
	var targets []organizationstypes.PolicyTargetSummary
	var next *string
	for {
		output, err := clients.organizations.ListTargetsForPolicy(ctx, &organizations.ListTargetsForPolicyInput{PolicyId: awssdk.String(policyID), MaxResults: awssdk.Int32(20), NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("list targets for organizations policy %q: %w", policyID, err)
		}
		targets = append(targets, output.Targets...)
		if awssdk.ToString(output.NextToken) == "" {
			break
		}
		next = output.NextToken
	}
	return targets, nil
}

func listAllSSOInstances(ctx context.Context, clients awsClients) ([]awsSSOInstance, error) {
	var records []awsSSOInstance
	var next *string
	for {
		output, err := clients.sso.ListInstances(ctx, &ssoadmin.ListInstancesInput{MaxResults: awssdk.Int32(100), NextToken: next})
		if err != nil {
			return nil, err
		}
		for _, instance := range output.Instances {
			instanceARN := awssdk.ToString(instance.InstanceArn)
			identityStoreID := awssdk.ToString(instance.IdentityStoreId)
			if instanceARN == "" && identityStoreID == "" {
				continue
			}
			records = append(records, awsSSOInstance{Instance: instance, InstanceARN: instanceARN, IdentityStoreID: identityStoreID})
		}
		if awssdk.ToString(output.NextToken) == "" {
			break
		}
		next = output.NextToken
	}
	sort.Slice(records, func(i, j int) bool { return records[i].InstanceARN < records[j].InstanceARN })
	return records, nil
}

func listAllOrganizationAccountIDs(ctx context.Context, clients awsClients, settings settings) ([]string, error) {
	var ids []string
	var next *string
	for {
		output, err := clients.organizations.ListAccounts(ctx, &organizations.ListAccountsInput{MaxResults: awssdk.Int32(20), NextToken: next})
		if err != nil {
			return nil, err
		}
		for _, account := range output.Accounts {
			ids = append(ids, awssdk.ToString(account.Id))
		}
		if awssdk.ToString(output.NextToken) == "" {
			break
		}
		next = output.NextToken
	}
	if len(ids) == 0 && settings.accountID != "" {
		ids = append(ids, settings.accountID)
	}
	return cleanStrings(ids), nil
}

func identityStoreIDs(ctx context.Context, clients awsClients, settings settings) ([]string, error) {
	if settings.identityCenter.storeID != "" {
		return []string{settings.identityCenter.storeID}, nil
	}
	instances, err := listAllSSOInstances(ctx, clients)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, instance := range instances {
		ids = append(ids, instance.IdentityStoreID)
	}
	return cleanStrings(ids), nil
}

func listAllIdentityStoreGroups(ctx context.Context, clients awsClients, settings settings) ([]awsIdentityStoreGroup, error) {
	storeIDs, err := identityStoreIDs(ctx, clients, settings)
	if err != nil {
		return nil, err
	}
	var records []awsIdentityStoreGroup
	for _, storeID := range storeIDs {
		var next *string
		for {
			output, err := clients.identityStore.ListGroups(ctx, &identitystore.ListGroupsInput{IdentityStoreId: awssdk.String(storeID), MaxResults: awssdk.Int32(100), NextToken: next})
			if err != nil {
				return nil, fmt.Errorf("list identity store groups for %q: %w", storeID, err)
			}
			for _, group := range output.Groups {
				groupID := awssdk.ToString(group.GroupId)
				if groupID != "" {
					records = append(records, awsIdentityStoreGroup{IdentityStoreID: storeID, Group: group, GroupID: groupID})
				}
			}
			if awssdk.ToString(output.NextToken) == "" {
				break
			}
			next = output.NextToken
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].GroupID < records[j].GroupID })
	return records, nil
}

func governancePage[T any](records []T, cursor string, limit int) ([]T, string, error) {
	start := 0
	cursor = strings.TrimSpace(cursor)
	if cursor != "" {
		parsed, err := strconv.Atoi(cursor)
		if err != nil {
			return nil, "", fmt.Errorf("parse aws governance cursor: %w", err)
		}
		if parsed < 0 || parsed > len(records) {
			return nil, "", fmt.Errorf("aws governance cursor offset %d out of range [0,%d]", parsed, len(records))
		}
		start = parsed
	}
	if limit <= 0 {
		limit = defaultPageSize
	}
	if start >= len(records) {
		return nil, "", nil
	}
	end := start + limit
	if end >= len(records) {
		return records[start:], "", nil
	}
	return records[start:end], strconv.Itoa(end), nil
}

func organizationsIDFromARN(arn string) string {
	parts := strings.Split(strings.TrimSpace(arn), "/")
	if len(parts) >= 2 && strings.HasPrefix(parts[len(parts)-2], "o-") {
		return parts[len(parts)-2]
	}
	return ""
}

func organizationsAccountARN(settings settings, accountID string) string {
	if accountID == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:organizations::%s:account/%s", settings.accountID, accountID)
}

func organizationPolicyTargetIDs(targets []organizationstypes.PolicyTargetSummary, targetType organizationstypes.TargetType) []string {
	var ids []string
	for _, target := range targets {
		if target.Type == targetType {
			ids = append(ids, awssdk.ToString(target.TargetId))
		}
	}
	return cleanStrings(ids)
}

func organizationPolicyTargetARNs(targets []organizationstypes.PolicyTargetSummary) []string {
	return organizationPolicyTargetField(targets, func(target organizationstypes.PolicyTargetSummary) string {
		return awssdk.ToString(target.Arn)
	})
}

func organizationPolicyTargetField(targets []organizationstypes.PolicyTargetSummary, value func(organizationstypes.PolicyTargetSummary) string) []string {
	fields := make([]string, 0, len(targets))
	for _, target := range targets {
		fields = append(fields, strings.TrimSpace(value(target)))
	}
	return fields
}

func organizationsRootPolicyTypes(root organizationstypes.Root) []string {
	values := make([]string, 0, len(root.PolicyTypes))
	for _, policyType := range root.PolicyTypes {
		values = append(values, string(policyType.Type)+":"+string(policyType.Status))
	}
	sort.Strings(values)
	return values
}

func organizationParentType(parentID string, rootID string) string {
	if strings.TrimSpace(parentID) == "" {
		return ""
	}
	if parentID == rootID {
		return string(organizationstypes.ParentTypeRoot)
	}
	return string(organizationstypes.ParentTypeOrganizationalUnit)
}

func identityStorePrimaryEmail(emails []identitystoretypes.Email) string {
	for _, email := range emails {
		if email.Primary && awssdk.ToString(email.Value) != "" {
			return awssdk.ToString(email.Value)
		}
	}
	for _, email := range emails {
		if awssdk.ToString(email.Value) != "" {
			return awssdk.ToString(email.Value)
		}
	}
	return ""
}

func identityStoreFormattedName(name *identitystoretypes.Name) string {
	if name == nil {
		return ""
	}
	return firstNonEmpty(awssdk.ToString(name.Formatted), strings.TrimSpace(strings.Join([]string{awssdk.ToString(name.GivenName), awssdk.ToString(name.FamilyName)}, " ")))
}

func identityStoreMembershipUserID(member identitystoretypes.MemberId) string {
	if user, ok := member.(*identitystoretypes.MemberIdMemberUserId); ok {
		return strings.TrimSpace(user.Value)
	}
	return ""
}
