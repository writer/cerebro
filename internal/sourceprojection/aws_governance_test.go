package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestProjectAWSAccountContactUpdatesCloudAccountPosture(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	if _, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "aws-account-contact",
		TenantId: "writer",
		SourceId: "aws",
		Kind:     "aws.account_contact",
		Attributes: map[string]string{
			"account_alternate_contact_security_compliant": "true",
			"account_id":                          "123456789012",
			"account_security_contact_configured": "true",
			"resource_id":                         "123456789012",
			"resource_name":                       "123456789012",
			"resource_provider":                   "aws",
			"resource_type":                       "aws_account",
			"security_alternate_contact_complete": "true",
			"security_alternate_contact_present":  "true",
		},
	}); err != nil {
		t.Fatalf("Project(account_contact) error = %v", err)
	}

	accountURN := "urn:cerebro:writer:cloud_account:123456789012"
	entity := state.entities[accountURN]
	if entity == nil {
		t.Fatalf("missing projected account %s", accountURN)
	}
	if entity.EntityType != "cloud.account" {
		t.Fatalf("account entity type = %q, want cloud.account", entity.EntityType)
	}
	if got := entity.Attributes["account_security_contact_configured"]; got != "true" {
		t.Fatalf("account_security_contact_configured = %q, want true", got)
	}
	if got := entity.Attributes["account_alternate_contact_security_compliant"]; got != "true" {
		t.Fatalf("account_alternate_contact_security_compliant = %q, want true", got)
	}
	if unexpected := state.entities["urn:cerebro:writer:aws_aws_account:123456789012"]; unexpected != nil {
		t.Fatalf("unexpected synthetic AWS account resource = %#v", unexpected)
	}
}

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
