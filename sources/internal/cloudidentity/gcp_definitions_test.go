package cloudidentitysource

import (
	"context"
	"net/http"
	"testing"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

func TestDefineResolvesPredefinedAndCustomRolesOutsidePrincipalProject(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/roles/storage.objectViewer":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "roles/storage.objectViewer", "includedPermissions": []string{"storage.objects.get", "storage.objects.list"}})
		case "/v1/projects/" + testProjectID + "/roles/customReader":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "projects/" + testProjectID + "/roles/customReader", "includedPermissions": []string{"storage.objects.get"}})
		case "/v1/organizations/" + testOrg + "/roles/customOrgRole":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "organizations/" + testOrg + "/roles/customOrgRole", "includedPermissions": []string{"resourcemanager.projects.get"}})
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}
	reader := testGCPReader(t, handler, nil)

	definitions, err := reader.Define(context.Background(), ci.DefinitionRequest{GCPRoles: []string{
		"roles/storage.objectViewer",
		"projects/" + testProjectID + "/roles/customReader",
		"organizations/" + testOrg + "/roles/customOrgRole",
	}})
	if err != nil {
		t.Fatalf("Define() error = %v", err)
	}
	if !definitions.Complete {
		t.Fatalf("Complete = false, gaps = %+v", definitions.Gaps)
	}
	if len(definitions.Roles) != 3 {
		t.Fatalf("len(Roles) = %d, want 3", len(definitions.Roles))
	}
	if len(definitions.Operations) == 0 {
		t.Fatal("Operations is empty, want the static method-reference table")
	}
	if definitions.Digest != "" {
		t.Fatalf("Digest = %q, want empty: the canonical digest is computed once by MergeDefinitions, not per-reader", definitions.Digest)
	}
	foundVerifiedOperation := false
	for _, op := range definitions.Operations {
		if op.DependenciesComplete {
			foundVerifiedOperation = true
			break
		}
	}
	if !foundVerifiedOperation {
		t.Fatal("no static-reference operation is marked DependenciesComplete, want at least one fully-verified upper-bound mapping")
	}
}

func TestDefineDeletedCustomRoleGrantsNoPermissions(t *testing.T) {
	// R11 live regression: a deleted custom role's roles.get response still
	// carries its original includedPermissions (the documented live
	// response shape:
	// https://docs.cloud.google.com/iam/docs/creating-custom-roles#delete-custom-role),
	// but "any role bindings that refer to the role remain in your allow
	// policies, but they have no effect" per that same contract. Reporting
	// those stale permissions here previously let assessment treat them as
	// live supported excess the principal does not actually have.
	handler := func(w http.ResponseWriter, r *http.Request) {
		writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "roles/legacy.role", "includedPermissions": []string{"legacy.permission"}, "deleted": true})
	}
	reader := testGCPReader(t, handler, nil)

	definitions, err := reader.Define(context.Background(), ci.DefinitionRequest{GCPRoles: []string{"roles/legacy.role"}})
	if err != nil {
		t.Fatalf("Define() error = %v", err)
	}
	if len(definitions.Roles) != 1 || len(definitions.Roles[0].Permissions) != 0 {
		t.Fatalf("Roles = %+v, want the deleted role reported with zero permissions: its bindings have no effect", definitions.Roles)
	}
	if !definitions.Complete {
		t.Fatalf("Complete = false, want true: a resolved-but-deleted role is a known-empty role, not a gap that blocks completeness")
	}
	found := false
	for _, gap := range definitions.Gaps {
		if gap.Code == "gcp_role_deleted" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Gaps = %+v, want an informational gcp_role_deleted gap", definitions.Gaps)
	}
}

func TestDefineDisabledCustomRoleGrantsNoPermissions(t *testing.T) {
	const roleName = "projects/my-project/roles/custom.disabled"
	handler := func(w http.ResponseWriter, r *http.Request) {
		writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": roleName, "includedPermissions": []string{"storage.objects.get", "storage.objects.list"}, "stage": "DISABLED"})
	}
	reader := testGCPReader(t, handler, nil)

	definitions, err := reader.Define(context.Background(), ci.DefinitionRequest{GCPRoles: []string{roleName}})
	if err != nil {
		t.Fatalf("Define() error = %v", err)
	}
	if len(definitions.Roles) != 1 || len(definitions.Roles[0].Permissions) != 0 {
		t.Fatalf("Roles = %+v, want the disabled role reported with zero permissions so its bindings stay inactive", definitions.Roles)
	}
	found := false
	for _, gap := range definitions.Gaps {
		if gap.Code == "gcp_role_disabled" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Gaps = %+v, want gcp_role_disabled", definitions.Gaps)
	}
}

func TestDefineRejectsMalformedRoleIdentifierWithoutGuessing(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("no GCP call should be made for a malformed role identifier, got %s", r.URL.Path)
	}
	reader := testGCPReader(t, handler, nil)

	definitions, err := reader.Define(context.Background(), ci.DefinitionRequest{GCPRoles: []string{"not-a-role-resource-name"}})
	if err != nil {
		t.Fatalf("Define() error = %v", err)
	}
	if definitions.Complete {
		t.Fatal("Complete = true for a malformed role identifier")
	}
	if len(definitions.Roles) != 0 {
		t.Fatalf("Roles = %+v, want none", definitions.Roles)
	}
	if len(definitions.Gaps) != 1 || definitions.Gaps[0].Code != "gcp_role_identifier_invalid" {
		t.Fatalf("Gaps = %+v, want exactly one gcp_role_identifier_invalid", definitions.Gaps)
	}
}

func TestDefineRoleLookupDeniedIsAGapNotAFatalError(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		writeJSONGCP(t, w, http.StatusForbidden, map[string]any{"error": map[string]any{"code": 403, "message": "denied", "status": "PERMISSION_DENIED"}})
	}
	reader := testGCPReader(t, handler, nil)

	definitions, err := reader.Define(context.Background(), ci.DefinitionRequest{GCPRoles: []string{"roles/storage.objectViewer"}})
	if err != nil {
		t.Fatalf("Define() error = %v", err)
	}
	if definitions.Complete {
		t.Fatal("Complete = true despite a denied role lookup")
	}
	found := false
	for _, gap := range definitions.Gaps {
		if gap.Code == "gcp_permission_denied" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Gaps = %+v, want gcp_permission_denied", definitions.Gaps)
	}
}
