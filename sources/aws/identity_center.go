package aws

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssoadmintypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"

	"github.com/writer/cerebro/internal/primitives"
)

type identityCenterPermissionSet struct {
	Instance      ssoadmintypes.InstanceMetadata
	PermissionSet ssoadmintypes.PermissionSet
}

type identityCenterAccountAssignment struct {
	Instance          ssoadmintypes.InstanceMetadata
	Assignment        ssoadmintypes.AccountAssignment
	PermissionSetName string
}

func listIdentityCenterInstances(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]ssoadmintypes.InstanceMetadata, error) {
	if settings.identityCenter.instanceARN != "" && settings.identityCenter.storeID != "" {
		return []ssoadmintypes.InstanceMetadata{{
			InstanceArn:     awssdk.String(settings.identityCenter.instanceARN),
			IdentityStoreId: stringPtr(settings.identityCenter.storeID),
			OwnerAccountId:  awssdk.String(settings.accountID),
		}}, nil
	}
	out, err := clients.sso.ListInstances(ctx, &ssoadmin.ListInstancesInput{NextToken: stringPtr(cursor), MaxResults: int32Ptr(boundedAWSPageSize(limit, 1, 100))})
	if err != nil {
		return nil, err
	}
	if settings.identityCenter.instanceARN != "" {
		for _, instance := range out.Instances {
			if awssdk.ToString(instance.InstanceArn) == settings.identityCenter.instanceARN {
				return []ssoadmintypes.InstanceMetadata{instance}, nil
			}
		}
		return nil, fmt.Errorf("identity center instance %q not found", settings.identityCenter.instanceARN)
	}
	return out.Instances, nil
}

func listIdentityCenterPermissionSets(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]identityCenterPermissionSet, string, error) {
	page, err := decodeIdentityCenterPermissionSetCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	instances, err := listIdentityCenterInstances(ctx, clients, settings, "", limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]identityCenterPermissionSet, 0)
	started := page.InstanceARN == ""
	for _, instance := range instances {
		instanceARN := awssdk.ToString(instance.InstanceArn)
		if instanceARN == "" {
			continue
		}
		if !started {
			if instanceARN == page.InstanceARN {
				started = true
			} else {
				continue
			}
		}
		token := ""
		if instanceARN == page.InstanceARN {
			token = page.Token
		}
		permissionSets, next, err := listIdentityCenterPermissionSetsForInstance(ctx, clients, settings, instance, token, limit)
		if err != nil {
			return nil, "", err
		}
		records = append(records, permissionSets...)
		if next != "" {
			return records, encodeIdentityCenterPermissionSetCursor(identityCenterPermissionSetCursor{InstanceARN: instanceARN, Token: next}), nil
		}
	}
	return records, "", nil
}

func listIdentityCenterPermissionSetsForInstance(ctx context.Context, clients awsClients, settings settings, instance ssoadmintypes.InstanceMetadata, cursor string, limit int) ([]identityCenterPermissionSet, string, error) {
	instanceARN := awssdk.ToString(instance.InstanceArn)
	if settings.identityCenter.permissionSetARN != "" {
		permissionSet, err := describeIdentityCenterPermissionSet(ctx, clients, instanceARN, settings.identityCenter.permissionSetARN)
		if err != nil {
			return nil, "", err
		}
		return []identityCenterPermissionSet{{Instance: instance, PermissionSet: permissionSet}}, "", nil
	}
	out, err := clients.sso.ListPermissionSets(ctx, &ssoadmin.ListPermissionSetsInput{
		InstanceArn: awssdk.String(instanceARN),
		MaxResults:  int32Ptr(boundedAWSPageSize(limit, 1, 100)),
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
	out, err := clients.sso.DescribePermissionSet(ctx, &ssoadmin.DescribePermissionSetInput{
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
	page, err := decodeIdentityCenterAccountAssignmentCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	instances, err := listIdentityCenterInstances(ctx, clients, settings, "", limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]identityCenterAccountAssignment, 0)
	instanceStarted := page.InstanceARN == ""
	for _, instance := range instances {
		instanceARN := awssdk.ToString(instance.InstanceArn)
		if !instanceStarted {
			if instanceARN == page.InstanceARN {
				instanceStarted = true
			} else {
				continue
			}
		}
		permissionSetToken := ""
		if instanceARN == page.InstanceARN {
			permissionSetToken = page.PermissionSetToken
		}
		for {
			permissionSets, nextPermissionSets, err := listIdentityCenterPermissionSetsForInstance(ctx, clients, settings, instance, permissionSetToken, limit)
			if err != nil {
				return nil, "", err
			}
			permissionSetStarted := page.PermissionSetARN == ""
			for _, permissionSet := range permissionSets {
				permissionSetARN := awssdk.ToString(permissionSet.PermissionSet.PermissionSetArn)
				if !permissionSetStarted {
					if permissionSetARN == page.PermissionSetARN {
						permissionSetStarted = true
					} else {
						continue
					}
				}
				assignmentCursor := identityCenterAccountAssignmentCursor{
					InstanceARN:        instanceARN,
					PermissionSetToken: permissionSetToken,
					PermissionSetARN:   permissionSetARN,
					AccountID:          page.AccountID,
					Token:              page.Token,
				}
				if permissionSetARN != page.PermissionSetARN {
					assignmentCursor.AccountID = ""
					assignmentCursor.Token = ""
				}
				assignmentRecords, next, err := listIdentityCenterAssignmentsForPermissionSet(ctx, clients, settings, instance, permissionSet.PermissionSet, encodeIdentityCenterAccountAssignmentCursor(assignmentCursor), limit)
				if err != nil {
					return nil, "", err
				}
				records = append(records, assignmentRecords...)
				if settings.identityCenter.instanceARN != "" && settings.identityCenter.permissionSetARN != "" && settings.identityCenter.targetAccountID != "" {
					return records, next, nil
				}
				if next != "" {
					return records, next, nil
				}
				page.PermissionSetARN = ""
				page.AccountID = ""
				page.Token = ""
			}
			if nextPermissionSets == "" {
				break
			}
			permissionSetToken = nextPermissionSets
			page.PermissionSetARN = ""
			page.AccountID = ""
			page.Token = ""
		}
	}
	return records, "", nil
}

func listIdentityCenterAssignmentsForPermissionSet(ctx context.Context, clients awsClients, settings settings, instance ssoadmintypes.InstanceMetadata, permissionSet ssoadmintypes.PermissionSet, cursor string, limit int) ([]identityCenterAccountAssignment, string, error) {
	page, err := decodeIdentityCenterAccountAssignmentCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	instanceARN := awssdk.ToString(instance.InstanceArn)
	permissionSetARN := awssdk.ToString(permissionSet.PermissionSetArn)
	accounts := []string{settings.identityCenter.targetAccountID}
	if settings.identityCenter.targetAccountID == "" {
		var err error
		accounts, err = listAllIdentityCenterProvisionedAccounts(ctx, clients, instanceARN, permissionSetARN, limit)
		if err != nil {
			return nil, "", err
		}
	}
	records := make([]identityCenterAccountAssignment, 0)
	accountStarted := page.AccountID == ""
	for _, accountID := range accounts {
		accountID = strings.TrimSpace(accountID)
		if accountID == "" {
			continue
		}
		if !accountStarted {
			if accountID == page.AccountID {
				accountStarted = true
			} else {
				continue
			}
		}
		token := ""
		if accountID == page.AccountID {
			token = page.Token
		}
		out, err := clients.sso.ListAccountAssignments(ctx, &ssoadmin.ListAccountAssignmentsInput{
			AccountId:        awssdk.String(accountID),
			InstanceArn:      awssdk.String(instanceARN),
			PermissionSetArn: awssdk.String(permissionSetARN),
			MaxResults:       int32Ptr(boundedAWSPageSize(limit, 1, 100)),
			NextToken:        stringPtr(token),
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
		if next := awssdk.ToString(out.NextToken); next != "" {
			return records, encodeIdentityCenterAccountAssignmentCursor(identityCenterAccountAssignmentCursor{
				InstanceARN:        instanceARN,
				PermissionSetToken: page.PermissionSetToken,
				PermissionSetARN:   permissionSetARN,
				AccountID:          accountID,
				Token:              next,
			}), nil
		}
		if settings.identityCenter.targetAccountID != "" {
			return records, "", nil
		}
	}
	return records, "", nil
}

func listAllIdentityCenterProvisionedAccounts(ctx context.Context, clients awsClients, instanceARN string, permissionSetARN string, limit int) ([]string, error) {
	var accounts []string
	var next *string
	for {
		out, err := clients.sso.ListAccountsForProvisionedPermissionSet(ctx, &ssoadmin.ListAccountsForProvisionedPermissionSetInput{
			InstanceArn:      awssdk.String(instanceARN),
			PermissionSetArn: awssdk.String(permissionSetARN),
			MaxResults:       awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 100)),
			NextToken:        next,
		})
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, out.AccountIds...)
		if awssdk.ToString(out.NextToken) == "" {
			break
		}
		next = out.NextToken
	}
	return cleanStrings(accounts), nil
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

type identityCenterPermissionSetCursor struct {
	InstanceARN string `json:"instance_arn,omitempty"`
	Token       string `json:"token,omitempty"`
}

type identityCenterAccountAssignmentCursor struct {
	InstanceARN        string `json:"instance_arn,omitempty"`
	PermissionSetToken string `json:"permission_set_token,omitempty"`
	PermissionSetARN   string `json:"permission_set_arn,omitempty"`
	AccountID          string `json:"account_id,omitempty"`
	Token              string `json:"token,omitempty"`
}

func decodeIdentityCenterPermissionSetCursor(raw string) (identityCenterPermissionSetCursor, error) {
	return decodeIdentityCenterCursor[identityCenterPermissionSetCursor](raw)
}

func encodeIdentityCenterPermissionSetCursor(cursor identityCenterPermissionSetCursor) string {
	return encodeIdentityCenterCursor(cursor)
}

func decodeIdentityCenterAccountAssignmentCursor(raw string) (identityCenterAccountAssignmentCursor, error) {
	return decodeIdentityCenterCursor[identityCenterAccountAssignmentCursor](raw)
}

func encodeIdentityCenterAccountAssignmentCursor(cursor identityCenterAccountAssignmentCursor) string {
	return encodeIdentityCenterCursor(cursor)
}

func decodeIdentityCenterCursor[T any](raw string) (T, error) {
	var cursor T
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return cursor, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return cursor, fmt.Errorf("decode identity center cursor: %w", err)
	}
	if err := json.Unmarshal(decoded, &cursor); err != nil {
		return cursor, fmt.Errorf("parse identity center cursor: %w", err)
	}
	return cursor, nil
}

func encodeIdentityCenterCursor(cursor any) string {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}
