package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestProjectAWSIdentityStoreUserGroupAndMembership(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	events := []*cerebrov1.EventEnvelope{
		{
			Id:       "aws-identitystore-user-u-123",
			TenantId: "123456789012",
			SourceId: "aws",
			Kind:     "aws.identitystore_user",
			Attributes: map[string]string{
				"domain":  "123456789012",
				"name":    "Alice Writer",
				"email":   "alice@writer.com",
				"login":   "alice",
				"user_id": "u-123",
			},
		},
		{
			Id:       "aws-identitystore-group-g-admins",
			TenantId: "123456789012",
			SourceId: "aws",
			Kind:     "aws.identitystore_group",
			Attributes: map[string]string{
				"domain":     "123456789012",
				"group_id":   "g-admins",
				"group_name": "Admins",
			},
		},
		{
			Id:       "aws-identitystore-group-membership-g-admins-u-123",
			TenantId: "123456789012",
			SourceId: "aws",
			Kind:     "aws.identitystore_group_membership",
			Attributes: map[string]string{
				"group_id":       "g-admins",
				"group_name":     "Admins",
				"member_type":    "user",
				"member_user_id": "u-123",
				"role":           "member",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.Kind, err)
		}
	}

	userURN := "urn:cerebro:123456789012:aws_user:u-123"
	groupURN := "urn:cerebro:123456789012:aws_group:g-admins"
	assertProjectedLink(t, state, userURN, relationMemberOf, groupURN)
	assertProjectedLink(t, state, userURN, relationHasIdentifier, "urn:cerebro:123456789012:identifier:email:alice@writer.com")
	assertProjectedLink(t, state, userURN, relationBelongsTo, "urn:cerebro:123456789012:cloud_account:123456789012")
}

func TestProjectAWSIdentityCenterPermissionSetAndAssignment(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	permissionSetARN := "arn:aws:sso:::permissionSet/ssoins-123/ps-admin"
	if _, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "aws-identity-center-permission-set-ps-admin",
		TenantId: "123456789012",
		SourceId: "aws",
		Kind:     "aws.identity_center_permission_set",
		Attributes: map[string]string{
			"account_id":          "123456789012",
			"domain":              "123456789012",
			"permission_set_arn":  permissionSetARN,
			"permission_set_name": "AdministratorAccess",
			"resource_arn":        permissionSetARN,
			"resource_id":         permissionSetARN,
			"resource_name":       "AdministratorAccess",
			"resource_provider":   "aws",
			"resource_type":       "identity_center_permission_set",
		},
	}); err != nil {
		t.Fatalf("Project(permission set) error = %v", err)
	}
	if _, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "aws-identity-center-account-assignment-1",
		TenantId: "123456789012",
		SourceId: "aws",
		Kind:     "aws.identity_center_account_assignment",
		Attributes: map[string]string{
			"domain":              "123456789012",
			"path_type":           "identity_center_account_assignment",
			"permission_set_arn":  permissionSetARN,
			"permission_set_name": "AdministratorAccess",
			"principal_id":        "u-123",
			"principal_type":      "user",
			"relationship":        "assigned_to",
			"role_id":             permissionSetARN,
			"role_name":           "AdministratorAccess",
			"target_id":           "123456789012",
			"target_type":         "account",
		},
	}); err != nil {
		t.Fatalf("Project(account assignment) error = %v", err)
	}

	permissionSetURN := "urn:cerebro:123456789012:aws_identity_center_permission_set:" + permissionSetARN
	userURN := "urn:cerebro:123456789012:aws_user:u-123"
	accountURN := "urn:cerebro:123456789012:aws_account:123456789012"
	if entity := state.entities[permissionSetURN]; entity == nil || entity.EntityType != "aws.identity.center.permission.set" {
		t.Fatalf("permission set entity missing or wrong type: %#v", entity)
	}
	assertProjectedLink(t, state, permissionSetURN, relationBelongsTo, "urn:cerebro:123456789012:cloud_account:123456789012")
	assertProjectedLink(t, state, userURN, relationCanAdmin, accountURN)
}
