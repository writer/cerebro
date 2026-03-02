package cli

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

type authDoctorState struct {
	authDoctorOutput            string
	authDoctorProject           string
	authDoctorProjects          string
	authDoctorProjectsFile      string
	authDoctorOrg               string
	authDoctorMaxProjects       int
	listOrganizationProjectsRef func(context.Context, string) ([]string, error)
}

func snapshotAuthDoctorState() authDoctorState {
	return authDoctorState{
		authDoctorOutput:            authDoctorOutput,
		authDoctorProject:           authDoctorProject,
		authDoctorProjects:          authDoctorProjects,
		authDoctorProjectsFile:      authDoctorProjectsFile,
		authDoctorOrg:               authDoctorOrg,
		authDoctorMaxProjects:       authDoctorMaxProjects,
		listOrganizationProjectsRef: listOrganizationProjectsFn,
	}
}

func restoreAuthDoctorState(state authDoctorState) {
	authDoctorOutput = state.authDoctorOutput
	authDoctorProject = state.authDoctorProject
	authDoctorProjects = state.authDoctorProjects
	authDoctorProjectsFile = state.authDoctorProjectsFile
	authDoctorOrg = state.authDoctorOrg
	authDoctorMaxProjects = state.authDoctorMaxProjects
	listOrganizationProjectsFn = state.listOrganizationProjectsRef
}

func TestValidateAuthDoctorOutput(t *testing.T) {
	state := snapshotAuthDoctorState()
	t.Cleanup(func() { restoreAuthDoctorState(state) })

	authDoctorOutput = "JSON"
	if err := validateAuthDoctorOutput(); err != nil {
		t.Fatalf("unexpected output validation error: %v", err)
	}
	if authDoctorOutput != FormatJSON {
		t.Fatalf("expected normalized output %q, got %q", FormatJSON, authDoctorOutput)
	}

	authDoctorOutput = "invalid"
	if err := validateAuthDoctorOutput(); err == nil {
		t.Fatal("expected invalid output error")
	}
}

func TestResolveAuthDoctorProjects_FromOrgHonorsMax(t *testing.T) {
	state := snapshotAuthDoctorState()
	t.Cleanup(func() { restoreAuthDoctorState(state) })

	authDoctorProject = ""
	authDoctorProjects = ""
	authDoctorProjectsFile = ""
	authDoctorOrg = "1234567890"
	authDoctorMaxProjects = 2

	listOrganizationProjectsFn = func(context.Context, string) ([]string, error) {
		return []string{"proj-a", "proj-b", "proj-c"}, nil
	}

	projects, err := resolveAuthDoctorProjects(context.Background())
	if err != nil {
		t.Fatalf("unexpected project resolution error: %v", err)
	}

	want := []string{"proj-a", "proj-b"}
	if !reflect.DeepEqual(projects, want) {
		t.Fatalf("unexpected projects: got %v want %v", projects, want)
	}
}

func TestAuthDoctorHint_GCPCloudAssetPermission(t *testing.T) {
	hint := authDoctorHint("gcp", "project.my-proj.asset_access", assertErr("permission cloudasset.assets.searchAllResources denied"))
	if !strings.Contains(strings.ToLower(hint), "roles/cloudasset.viewer") {
		t.Fatalf("unexpected hint: %q", hint)
	}
}

type authDoctorError string

func (e authDoctorError) Error() string { return string(e) }

func assertErr(msg string) error {
	return authDoctorError(msg)
}
