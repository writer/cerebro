package sync

import (
	"reflect"
	"testing"

	"cloud.google.com/go/iam/apiv1/iampb"
)

func TestBuildGCPServiceAccountRoleMetadata(t *testing.T) {
	policy := &iampb.Policy{
		Bindings: []*iampb.Binding{
			{
				Role: "roles/viewer",
				Members: []string{
					"serviceAccount:App-SA@proj-1.iam.gserviceaccount.com",
					"user:alice@example.com",
				},
			},
			{
				Role: "roles/owner",
				Members: []string{
					"serviceAccount:app-sa@proj-1.iam.gserviceaccount.com",
				},
			},
			{
				Role: "roles/editor",
				Members: []string{
					"serviceAccount:other-sa@proj-1.iam.gserviceaccount.com",
				},
			},
			{
				Role: "roles/editor",
				Members: []string{
					"serviceAccount:other-sa@proj-1.iam.gserviceaccount.com",
				},
			},
		},
	}

	metadata := buildGCPServiceAccountRoleMetadata(policy)

	if len(metadata) != 2 {
		t.Fatalf("expected metadata for 2 service accounts, got %d", len(metadata))
	}

	appMeta, ok := metadata["app-sa@proj-1.iam.gserviceaccount.com"]
	if !ok {
		t.Fatal("expected metadata for app-sa service account")
	}
	if !reflect.DeepEqual(appMeta.Roles, []string{"roles/owner", "roles/viewer"}) {
		t.Fatalf("unexpected roles for app-sa: %#v", appMeta.Roles)
	}
	if !appMeta.HasAdminRole {
		t.Fatal("expected app-sa to have admin role")
	}
	if !appMeta.HasHighPrivilege {
		t.Fatal("expected app-sa to have high privilege role")
	}

	otherMeta, ok := metadata["other-sa@proj-1.iam.gserviceaccount.com"]
	if !ok {
		t.Fatal("expected metadata for other-sa service account")
	}
	if !reflect.DeepEqual(otherMeta.Roles, []string{"roles/editor"}) {
		t.Fatalf("unexpected roles for other-sa: %#v", otherMeta.Roles)
	}
	if otherMeta.HasAdminRole {
		t.Fatal("expected other-sa not to have admin role")
	}
	if !otherMeta.HasHighPrivilege {
		t.Fatal("expected other-sa to have high privilege role")
	}
}

func TestBuildGCPServiceAccountRoleMetadataNilPolicy(t *testing.T) {
	metadata := buildGCPServiceAccountRoleMetadata(nil)
	if metadata != nil {
		t.Fatalf("expected nil metadata for nil policy, got %#v", metadata)
	}
}
