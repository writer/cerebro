package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestProjectAWSSSOAccountAssignmentLinksPrincipalPermissionSetAndAccount(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	permissionSetARN := "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-admin"
	event := &cerebrov1.EventEnvelope{
		Id:       "assignment-1",
		TenantId: "writer",
		SourceId: "aws",
		Kind:     "aws.sso_account_assignment",
		Attributes: map[string]string{
			"account_id":          "210987654321",
			"domain":              "123456789012",
			"identity_store_id":   "d-1234567890",
			"permission_set_arn":  permissionSetARN,
			"permission_set_name": "AdministratorAccess",
			"principal_id":        "user-1",
			"principal_type":      "user",
		},
	}

	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	principalURN := "urn:cerebro:writer:aws_user:user-1"
	permissionSetURN := "urn:cerebro:writer:aws_sso_permission_set:" + permissionSetARN
	accountURN := "urn:cerebro:writer:cloud_account:210987654321"
	if entity := state.entities[permissionSetURN]; entity == nil || entity.EntityType != "aws.sso.permission.set" {
		t.Fatalf("permission set entity missing or wrong type: %#v", entity)
	}
	assertProjectedLink(t, state, principalURN, relationAssignedTo, permissionSetURN)
	assertProjectedLink(t, state, permissionSetURN, relationCanPerform, accountURN)
	assertProjectedLink(t, state, principalURN, relationCanPerform, accountURN)
}
