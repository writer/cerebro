package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	identitystoretypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssoadmintypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"

	"github.com/writer/cerebro/internal/primitives"
)

type identitystoretypesUser = identitystoretypes.User
type identitystoretypesGroup = identitystoretypes.Group

type awsSSOAdminAPI interface {
	ListInstances(context.Context, *ssoadmin.ListInstancesInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error)
	ListPermissionSets(context.Context, *ssoadmin.ListPermissionSetsInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListPermissionSetsOutput, error)
	DescribePermissionSet(context.Context, *ssoadmin.DescribePermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.DescribePermissionSetOutput, error)
	ListAccountsForProvisionedPermissionSet(context.Context, *ssoadmin.ListAccountsForProvisionedPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountsForProvisionedPermissionSetOutput, error)
	ListAccountAssignments(context.Context, *ssoadmin.ListAccountAssignmentsInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountAssignmentsOutput, error)
}

type awsIdentityStoreAPI interface {
	ListUsers(context.Context, *identitystore.ListUsersInput, ...func(*identitystore.Options)) (*identitystore.ListUsersOutput, error)
	ListGroups(context.Context, *identitystore.ListGroupsInput, ...func(*identitystore.Options)) (*identitystore.ListGroupsOutput, error)
	ListGroupMemberships(context.Context, *identitystore.ListGroupMembershipsInput, ...func(*identitystore.Options)) (*identitystore.ListGroupMembershipsOutput, error)
}

type identityCenterPermissionSet struct {
	Instance      ssoadmintypes.InstanceMetadata
	PermissionSet ssoadmintypes.PermissionSet
}

type identityCenterAccountAssignment struct {
	Instance          ssoadmintypes.InstanceMetadata
	Assignment        ssoadmintypes.AccountAssignment
	PermissionSetName string
}

type identityStoreGroupMembership struct {
	Group      identitystoretypes.Group
	Membership identitystoretypes.GroupMembership
}

func listIdentityCenterInstances(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]ssoadmintypes.InstanceMetadata, string, error) {
	if settings.identityCenterInstanceARN != "" {
		return []ssoadmintypes.InstanceMetadata{{
			InstanceArn:     awssdk.String(settings.identityCenterInstanceARN),
			IdentityStoreId: stringPtr(settings.identityStoreID),
			OwnerAccountId:  awssdk.String(settings.accountID),
		}}, "", nil
	}
	out, err := clients.ssoAdmin.ListInstances(ctx, &ssoadmin.ListInstancesInput{NextToken: stringPtr(cursor), MaxResults: int32Ptr(limit)})
	if err != nil {
		return nil, "", err
	}
	return out.Instances, awssdk.ToString(out.NextToken), nil
}

func listIdentityCenterPermissionSets(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]identityCenterPermissionSet, string, error) {
	instances, nextInstances, err := listIdentityCenterInstances(ctx, clients, settings, "", limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]identityCenterPermissionSet, 0)
	for _, instance := range instances {
		instanceARN := awssdk.ToString(instance.InstanceArn)
		if instanceARN == "" {
			continue
		}
		permissionSets, next, err := listIdentityCenterPermissionSetsForInstance(ctx, clients, settings, instance, cursor, limit)
		if err != nil {
			return nil, "", err
		}
		records = append(records, permissionSets...)
		if settings.identityCenterInstanceARN != "" {
			return records, next, nil
		}
	}
	return records, nextInstances, nil
}

func listIdentityCenterPermissionSetsForInstance(ctx context.Context, clients awsClients, settings settings, instance ssoadmintypes.InstanceMetadata, cursor string, limit int) ([]identityCenterPermissionSet, string, error) {
	instanceARN := awssdk.ToString(instance.InstanceArn)
	if settings.permissionSetARN != "" {
		permissionSet, err := describeIdentityCenterPermissionSet(ctx, clients, instanceARN, settings.permissionSetARN)
		if err != nil {
			return nil, "", err
		}
		return []identityCenterPermissionSet{{Instance: instance, PermissionSet: permissionSet}}, "", nil
	}
	out, err := clients.ssoAdmin.ListPermissionSets(ctx, &ssoadmin.ListPermissionSetsInput{
		InstanceArn: awssdk.String(instanceARN),
		MaxResults:  int32Ptr(limit),
		NextToken:   stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]identityCenterPermissionSet, 0, len(out.PermissionSets))
	for _, permissionSetARN := range out.PermissionSets {
		permissionSet, err := describeIdentityCenterPermissionSet(ctx, clients, instanceARN, permissionSetARN)
		if err != nil {
			return nil, "", err
		}
		records = append(records, identityCenterPermissionSet{Instance: instance, PermissionSet: permissionSet})
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func describeIdentityCenterPermissionSet(ctx context.Context, clients awsClients, instanceARN string, permissionSetARN string) (ssoadmintypes.PermissionSet, error) {
	out, err := clients.ssoAdmin.DescribePermissionSet(ctx, &ssoadmin.DescribePermissionSetInput{
		InstanceArn:      awssdk.String(instanceARN),
		PermissionSetArn: awssdk.String(permissionSetARN),
	})
	if err != nil {
		return ssoadmintypes.PermissionSet{}, err
	}
	if out.PermissionSet == nil {
		return ssoadmintypes.PermissionSet{PermissionSetArn: awssdk.String(permissionSetARN)}, nil
	}
	return *out.PermissionSet, nil
}

func listIdentityCenterAccountAssignments(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]identityCenterAccountAssignment, string, error) {
	instances, _, err := listIdentityCenterInstances(ctx, clients, settings, "", limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]identityCenterAccountAssignment, 0)
	for _, instance := range instances {
		permissionSets, _, err := listIdentityCenterPermissionSetsForInstance(ctx, clients, settings, instance, "", limit)
		if err != nil {
			return nil, "", err
		}
		for _, permissionSet := range permissionSets {
			assignmentRecords, next, err := listIdentityCenterAssignmentsForPermissionSet(ctx, clients, settings, instance, permissionSet.PermissionSet, cursor, limit)
			if err != nil {
				return nil, "", err
			}
			records = append(records, assignmentRecords...)
			if settings.identityCenterInstanceARN != "" && settings.permissionSetARN != "" && settings.targetAccountID != "" {
				return records, next, nil
			}
		}
	}
	return records, "", nil
}

func listIdentityCenterAssignmentsForPermissionSet(ctx context.Context, clients awsClients, settings settings, instance ssoadmintypes.InstanceMetadata, permissionSet ssoadmintypes.PermissionSet, cursor string, limit int) ([]identityCenterAccountAssignment, string, error) {
	instanceARN := awssdk.ToString(instance.InstanceArn)
	permissionSetARN := awssdk.ToString(permissionSet.PermissionSetArn)
	accounts := []string{settings.targetAccountID}
	if settings.targetAccountID == "" {
		out, err := clients.ssoAdmin.ListAccountsForProvisionedPermissionSet(ctx, &ssoadmin.ListAccountsForProvisionedPermissionSetInput{
			InstanceArn:      awssdk.String(instanceARN),
			PermissionSetArn: awssdk.String(permissionSetARN),
			MaxResults:       int32Ptr(limit),
		})
		if err != nil {
			return nil, "", err
		}
		accounts = out.AccountIds
	}
	records := make([]identityCenterAccountAssignment, 0)
	for _, accountID := range cleanStrings(accounts) {
		out, err := clients.ssoAdmin.ListAccountAssignments(ctx, &ssoadmin.ListAccountAssignmentsInput{
			AccountId:        awssdk.String(accountID),
			InstanceArn:      awssdk.String(instanceARN),
			PermissionSetArn: awssdk.String(permissionSetARN),
			MaxResults:       int32Ptr(limit),
			NextToken:        stringPtr(cursor),
		})
		if err != nil {
			return nil, "", err
		}
		for _, assignment := range out.AccountAssignments {
			records = append(records, identityCenterAccountAssignment{
				Instance:          instance,
				Assignment:        assignment,
				PermissionSetName: awssdk.ToString(permissionSet.Name),
			})
		}
		if settings.targetAccountID != "" {
			return records, awssdk.ToString(out.NextToken), nil
		}
	}
	return records, "", nil
}

func identityStoreID(ctx context.Context, clients awsClients, settings settings) (string, error) {
	if settings.identityStoreID != "" {
		return settings.identityStoreID, nil
	}
	instances, _, err := listIdentityCenterInstances(ctx, clients, settings, "", 1)
	if err != nil {
		return "", err
	}
	for _, instance := range instances {
		if id := awssdk.ToString(instance.IdentityStoreId); id != "" {
			return id, nil
		}
	}
	return "", fmt.Errorf("aws identity_store_id is required when no IAM Identity Center instance exposes one")
}

func listIdentityStoreUsers(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]identitystoretypes.User, string, error) {
	storeID, err := identityStoreID(ctx, clients, settings)
	if err != nil {
		return nil, "", err
	}
	out, err := clients.identityStore.ListUsers(ctx, &identitystore.ListUsersInput{
		IdentityStoreId: awssdk.String(storeID),
		MaxResults:      int32Ptr(limit),
		NextToken:       stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	return out.Users, awssdk.ToString(out.NextToken), nil
}

func listIdentityStoreGroups(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]identitystoretypes.Group, string, error) {
	storeID, err := identityStoreID(ctx, clients, settings)
	if err != nil {
		return nil, "", err
	}
	out, err := clients.identityStore.ListGroups(ctx, &identitystore.ListGroupsInput{
		IdentityStoreId: awssdk.String(storeID),
		MaxResults:      int32Ptr(limit),
		NextToken:       stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	return out.Groups, awssdk.ToString(out.NextToken), nil
}

func listIdentityStoreGroupMemberships(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]identityStoreGroupMembership, string, error) {
	storeID, err := identityStoreID(ctx, clients, settings)
	if err != nil {
		return nil, "", err
	}
	if settings.groupID != "" {
		out, err := clients.identityStore.ListGroupMemberships(ctx, &identitystore.ListGroupMembershipsInput{
			GroupId:         awssdk.String(settings.groupID),
			IdentityStoreId: awssdk.String(storeID),
			MaxResults:      int32Ptr(limit),
			NextToken:       stringPtr(cursor),
		})
		if err != nil {
			return nil, "", err
		}
		records := make([]identityStoreGroupMembership, 0, len(out.GroupMemberships))
		for _, membership := range out.GroupMemberships {
			records = append(records, identityStoreGroupMembership{Group: identitystoretypes.Group{GroupId: awssdk.String(settings.groupID), IdentityStoreId: awssdk.String(storeID)}, Membership: membership})
		}
		return records, awssdk.ToString(out.NextToken), nil
	}
	groups, nextGroups, err := listIdentityStoreGroups(ctx, clients, settings, cursor, limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]identityStoreGroupMembership, 0)
	for _, group := range groups {
		groupID := awssdk.ToString(group.GroupId)
		if groupID == "" {
			continue
		}
		out, err := clients.identityStore.ListGroupMemberships(ctx, &identitystore.ListGroupMembershipsInput{
			GroupId:         awssdk.String(groupID),
			IdentityStoreId: awssdk.String(storeID),
			MaxResults:      int32Ptr(limit),
		})
		if err != nil {
			return nil, "", err
		}
		for _, membership := range out.GroupMemberships {
			records = append(records, identityStoreGroupMembership{Group: group, Membership: membership})
		}
	}
	return records, nextGroups, nil
}

func identityCenterPermissionSetEvent(settings settings, record identityCenterPermissionSet) (*primitives.Event, error) {
	permissionSet := record.PermissionSet
	instance := record.Instance
	resourceID := firstNonEmpty(awssdk.ToString(permissionSet.PermissionSetArn), awssdk.ToString(permissionSet.Name))
	attributes := map[string]string{
		"account_id":          settings.accountID,
		"description":         awssdk.ToString(permissionSet.Description),
		"domain":              settings.accountID,
		"family":              familyIdentityCenterPermission,
		"identity_store_id":   awssdk.ToString(instance.IdentityStoreId),
		"instance_arn":        awssdk.ToString(instance.InstanceArn),
		"permission_set_arn":  awssdk.ToString(permissionSet.PermissionSetArn),
		"permission_set_name": awssdk.ToString(permissionSet.Name),
		"relay_state":         awssdk.ToString(permissionSet.RelayState),
		"resource_arn":        awssdk.ToString(permissionSet.PermissionSetArn),
		"resource_id":         resourceID,
		"resource_name":       awssdk.ToString(permissionSet.Name),
		"resource_provider":   "aws",
		"resource_type":       "identity_center_permission_set",
		"session_duration":    awssdk.ToString(permissionSet.SessionDuration),
	}
	addTimeAttribute(attributes, "created_at", permissionSet.CreatedDate)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "instance": instance, "permission_set": permissionSet})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-identity-center-permission-set-"+resourceID, "aws.identity_center_permission_set", "aws/identity_center_permission_set/v1", payload, attributes, firstTime(permissionSet.CreatedDate))
}

func identityCenterAccountAssignmentEvent(settings settings, record identityCenterAccountAssignment) (*primitives.Event, error) {
	assignment := record.Assignment
	principalType := strings.ToLower(string(assignment.PrincipalType))
	if principalType == "" {
		principalType = "user"
	}
	permissionSetARN := awssdk.ToString(assignment.PermissionSetArn)
	accountID := awssdk.ToString(assignment.AccountId)
	attributes := map[string]string{
		"account_id":          settings.accountID,
		"domain":              settings.accountID,
		"family":              familyIdentityCenterAssignment,
		"identity_store_id":   awssdk.ToString(record.Instance.IdentityStoreId),
		"instance_arn":        awssdk.ToString(record.Instance.InstanceArn),
		"is_admin":            boolString(containsAny(strings.ToLower(record.PermissionSetName), "admin", "administrator", "power")),
		"path_type":           "identity_center_account_assignment",
		"permission_set_arn":  permissionSetARN,
		"permission_set_name": record.PermissionSetName,
		"principal_id":        awssdk.ToString(assignment.PrincipalId),
		"principal_type":      principalType,
		"relationship":        "assigned_to",
		"role_id":             firstNonEmpty(permissionSetARN, record.PermissionSetName),
		"role_name":           record.PermissionSetName,
		"target_account_id":   accountID,
		"target_id":           accountID,
		"target_name":         accountID,
		"target_type":         "account",
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "instance": record.Instance, "assignment": assignment})
	if err != nil {
		return nil, err
	}
	id := fmt.Sprintf("aws-identity-center-account-assignment-%s-%s-%s", accountID, firstNonEmpty(permissionSetARN, record.PermissionSetName), awssdk.ToString(assignment.PrincipalId))
	return sourceEvent(settings, id, "aws.identity_center_account_assignment", "aws/identity_center_account_assignment/v1", payload, attributes, time.Now().UTC())
}

func identityStoreUserEvent(settings settings, user identitystoretypes.User) (*primitives.Event, error) {
	email := identityStorePrimaryEmail(user.Emails)
	displayName := firstNonEmpty(awssdk.ToString(user.DisplayName), identityStoreFormattedName(user.Name), awssdk.ToString(user.UserName), email)
	attributes := map[string]string{
		"account_id":        settings.accountID,
		"display_name":      displayName,
		"domain":            settings.accountID,
		"email":             email,
		"family":            familyIdentityStoreUser,
		"identity_store_id": awssdk.ToString(user.IdentityStoreId),
		"is_admin":          boolString(containsAny(strings.ToLower(displayName), "admin", "administrator")),
		"login":             awssdk.ToString(user.UserName),
		"principal_type":    "user",
		"status":            string(user.UserStatus),
		"user_id":           firstNonEmpty(awssdk.ToString(user.UserId), awssdk.ToString(user.UserName), email),
		"user_type":         awssdk.ToString(user.UserType),
	}
	addTimeAttribute(attributes, "created_at", user.CreatedAt)
	addTimeAttribute(attributes, "updated_at", user.UpdatedAt)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "user": user})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-identitystore-user-"+firstNonEmpty(awssdk.ToString(user.UserId), awssdk.ToString(user.UserName), email), "aws.identity_store_user", "aws/identity_store_user/v1", payload, attributes, firstTime(user.UpdatedAt, user.CreatedAt))
}

func identityStoreGroupEvent(settings settings, group identitystoretypes.Group) (*primitives.Event, error) {
	attributes := map[string]string{
		"account_id":        settings.accountID,
		"description":       awssdk.ToString(group.Description),
		"domain":            settings.accountID,
		"family":            familyIdentityStoreGroup,
		"group_id":          awssdk.ToString(group.GroupId),
		"group_name":        awssdk.ToString(group.DisplayName),
		"identity_store_id": awssdk.ToString(group.IdentityStoreId),
	}
	addTimeAttribute(attributes, "created_at", group.CreatedAt)
	addTimeAttribute(attributes, "updated_at", group.UpdatedAt)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "group": group})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-identitystore-group-"+firstNonEmpty(awssdk.ToString(group.GroupId), awssdk.ToString(group.DisplayName)), "aws.identity_store_group", "aws/identity_store_group/v1", payload, attributes, firstTime(group.UpdatedAt, group.CreatedAt))
}

func identityStoreGroupMembershipEvent(settings settings, record identityStoreGroupMembership) (*primitives.Event, error) {
	membership := record.Membership
	group := record.Group
	groupID := firstNonEmpty(awssdk.ToString(membership.GroupId), awssdk.ToString(group.GroupId), settings.groupID)
	memberUserID := identityStoreMembershipUserID(membership.MemberId)
	attributes := map[string]string{
		"account_id":        settings.accountID,
		"domain":            settings.accountID,
		"family":            familyIdentityStoreMembership,
		"group_id":          groupID,
		"group_name":        awssdk.ToString(group.DisplayName),
		"identity_store_id": firstNonEmpty(awssdk.ToString(membership.IdentityStoreId), awssdk.ToString(group.IdentityStoreId), settings.identityStoreID),
		"member_id":         memberUserID,
		"member_type":       "user",
		"member_user_id":    memberUserID,
		"membership_id":     awssdk.ToString(membership.MembershipId),
		"role":              "member",
	}
	addTimeAttribute(attributes, "created_at", membership.CreatedAt)
	addTimeAttribute(attributes, "updated_at", membership.UpdatedAt)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "group": group, "membership": membership})
	if err != nil {
		return nil, err
	}
	id := fmt.Sprintf("aws-identitystore-group-membership-%s-%s", groupID, firstNonEmpty(memberUserID, awssdk.ToString(membership.MembershipId)))
	return sourceEvent(settings, id, "aws.identity_store_group_membership", "aws/identity_store_group_membership/v1", payload, attributes, firstTime(membership.UpdatedAt, membership.CreatedAt))
}

func identityStorePrimaryEmail(emails []identitystoretypes.Email) string {
	for _, email := range emails {
		if email.Primary {
			return strings.ToLower(strings.TrimSpace(awssdk.ToString(email.Value)))
		}
	}
	for _, email := range emails {
		if value := strings.ToLower(strings.TrimSpace(awssdk.ToString(email.Value))); value != "" {
			return value
		}
	}
	return ""
}

func identityStoreFormattedName(name *identitystoretypes.Name) string {
	if name == nil {
		return ""
	}
	return firstNonEmpty(awssdk.ToString(name.Formatted), strings.Join(cleanStrings([]string{awssdk.ToString(name.GivenName), awssdk.ToString(name.FamilyName)}), " "))
}

func identityStoreMembershipUserID(member identitystoretypes.MemberId) string {
	switch typed := member.(type) {
	case *identitystoretypes.MemberIdMemberUserId:
		return strings.TrimSpace(typed.Value)
	default:
		return ""
	}
}
