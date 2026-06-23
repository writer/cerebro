package aws

import (
	"context"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func listAccessKeys(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]iamtypes.AccessKeyMetadata, string, error) {
	if strings.TrimSpace(settings.userName) == "" {
		users, next, err := listIAMUsers(ctx, clients, settings, cursor, limit)
		if err != nil {
			return nil, "", err
		}
		keys := make([]iamtypes.AccessKeyMetadata, 0, len(users))
		for _, user := range users {
			userName := awssdk.ToString(user.UserName)
			if userName == "" {
				continue
			}
			out, err := clients.iam.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: awssdk.String(userName)})
			if err != nil {
				return nil, "", err
			}
			for _, key := range out.AccessKeyMetadata {
				if awssdk.ToString(key.UserName) == "" {
					key.UserName = awssdk.String(userName)
				}
				keys = append(keys, key)
			}
		}
		return keys, next, nil
	}
	out, err := clients.iam.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: awssdk.String(settings.userName), Marker: stringPtr(cursor), MaxItems: int32Ptr(limit)})
	if err != nil {
		return nil, "", err
	}
	return out.AccessKeyMetadata, nextMarker(out.IsTruncated, out.Marker), nil
}

func listIAMUsers(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]iamtypes.User, string, error) {
	out, err := clients.iam.ListUsers(ctx, &iam.ListUsersInput{Marker: stringPtr(cursor), MaxItems: int32Ptr(limit)})
	if err != nil {
		return nil, "", err
	}
	return out.Users, nextMarker(out.IsTruncated, out.Marker), nil
}

func listIAMRoles(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]iamtypes.Role, string, error) {
	out, err := clients.iam.ListRoles(ctx, &iam.ListRolesInput{Marker: stringPtr(cursor), MaxItems: int32Ptr(limit)})
	if err != nil {
		return nil, "", err
	}
	return out.Roles, nextMarker(out.IsTruncated, out.Marker), nil
}

func listIAMRoleInventory(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsIAMRole, string, error) {
	roles, next, err := listIAMRoles(ctx, clients, settings, cursor, limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]awsIAMRole, 0, len(roles))
	for _, role := range roles {
		record := awsIAMRole{Role: role}
		roleName := awssdk.ToString(role.RoleName)
		if roleName != "" {
			policies, err := listAttachedRolePolicies(ctx, clients, roleName)
			if err != nil {
				return nil, "", err
			}
			record.AttachedPolicies = policies
		}
		records = append(records, record)
	}
	return records, next, nil
}

func listAttachedRolePolicies(ctx context.Context, clients awsClients, roleName string) ([]iamtypes.AttachedPolicy, error) {
	var policies []iamtypes.AttachedPolicy
	var marker string
	for {
		out, err := clients.iam.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
			RoleName: awssdk.String(roleName),
			Marker:   stringPtr(marker),
			MaxItems: awssdk.Int32(1000),
		})
		if optionalAWSError(err, "NoSuchEntity") {
			return policies, nil
		}
		if err != nil {
			return nil, fmt.Errorf("list attached role policies %q: %w", roleName, err)
		}
		policies = append(policies, out.AttachedPolicies...)
		marker = nextMarker(out.IsTruncated, out.Marker)
		if marker == "" {
			return policies, nil
		}
	}
}

func listIAMRoleTrusts(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]iamRoleTrust, string, error) {
	roles, next, err := listIAMRoles(ctx, clients, settings, cursor, limit)
	if err != nil {
		return nil, "", err
	}
	trusts := make([]iamRoleTrust, 0)
	for _, role := range roles {
		trusts = append(trusts, roleTrusts(role)...)
	}
	return trusts, next, nil
}
