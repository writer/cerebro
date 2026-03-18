package sync

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	"cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"google.golang.org/api/iterator"
)

type fakeProjectIterator struct {
	projects []*resourcemanagerpb.Project
	index    int
}

func (f *fakeProjectIterator) Next() (*resourcemanagerpb.Project, error) {
	if f.index >= len(f.projects) {
		return nil, iterator.Done
	}
	project := f.projects[f.index]
	f.index++
	return project, nil
}

type fakeResourceManagerProjectsClient struct {
	projects []*resourcemanagerpb.Project
}

func (f fakeResourceManagerProjectsClient) SearchProjects(ctx context.Context, query string) gcpProjectSearchIterator {
	_ = ctx
	_ = query
	return &fakeProjectIterator{projects: f.projects}
}

func (f fakeResourceManagerProjectsClient) GetIAMPolicy(ctx context.Context, resource string) (*iampb.Policy, error) {
	_ = ctx
	_ = resource
	return &iampb.Policy{}, nil
}

func (f fakeResourceManagerProjectsClient) Close() error { return nil }

type fakeResourceManagerFoldersClient struct {
	folders  map[string]*resourcemanagerpb.Folder
	policies map[string]*iampb.Policy
}

func (f fakeResourceManagerFoldersClient) GetFolder(ctx context.Context, resource string) (*resourcemanagerpb.Folder, error) {
	_ = ctx
	folder, ok := f.folders[resource]
	if !ok {
		return nil, fmt.Errorf("folder not found: %s", resource)
	}
	return folder, nil
}

func (f fakeResourceManagerFoldersClient) GetIAMPolicy(ctx context.Context, resource string) (*iampb.Policy, error) {
	_ = ctx
	if policy, ok := f.policies[resource]; ok {
		return policy, nil
	}
	return nil, fmt.Errorf("policy not found: %s", resource)
}

func (f fakeResourceManagerFoldersClient) Close() error { return nil }

type fakeResourceManagerOrganizationsClient struct {
	orgs     map[string]*resourcemanagerpb.Organization
	policies map[string]*iampb.Policy
}

func (f fakeResourceManagerOrganizationsClient) GetOrganization(ctx context.Context, resource string) (*resourcemanagerpb.Organization, error) {
	_ = ctx
	org, ok := f.orgs[resource]
	if !ok {
		return nil, fmt.Errorf("org not found: %s", resource)
	}
	return org, nil
}

func (f fakeResourceManagerOrganizationsClient) GetIAMPolicy(ctx context.Context, resource string) (*iampb.Policy, error) {
	_ = ctx
	if policy, ok := f.policies[resource]; ok {
		return policy, nil
	}
	return nil, fmt.Errorf("policy not found: %s", resource)
}

func (f fakeResourceManagerOrganizationsClient) Close() error { return nil }

func TestFetchGCPProjectLineageWithClients(t *testing.T) {
	lineage, err := fetchGCPProjectLineageWithClients(
		context.Background(),
		"proj-a",
		fakeResourceManagerProjectsClient{
			projects: []*resourcemanagerpb.Project{{
				Name:        "projects/123456789",
				ProjectId:   "proj-a",
				DisplayName: "Project A",
				Parent:      "folders/456",
			}},
		},
		fakeResourceManagerFoldersClient{
			folders: map[string]*resourcemanagerpb.Folder{
				"folders/456": {Name: "folders/456", Parent: "folders/123", DisplayName: "Engineering"},
				"folders/123": {Name: "folders/123", Parent: "organizations/789", DisplayName: "Platform"},
			},
		},
		fakeResourceManagerOrganizationsClient{
			orgs: map[string]*resourcemanagerpb.Organization{
				"organizations/789": {Name: "organizations/789", DisplayName: "example.com"},
			},
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lineage.Project == nil || lineage.Project.GetProjectId() != "proj-a" {
		t.Fatalf("unexpected project lineage: %#v", lineage)
	}
	if got := len(lineage.Folders); got != 2 {
		t.Fatalf("expected 2 folders, got %d", got)
	}
	if lineage.Folders[0].GetName() != "folders/123" || lineage.Folders[1].GetName() != "folders/456" {
		t.Fatalf("expected root-to-leaf folder order, got %#v", lineage.Folders)
	}
	if lineage.Organization == nil || lineage.Organization.GetName() != "organizations/789" {
		t.Fatalf("unexpected org lineage: %#v", lineage.Organization)
	}
	if got := lineage.ancestorPath(); len(got) != 3 || got[0] != "organizations/789" || got[2] != "folders/456" {
		t.Fatalf("unexpected ancestor path: %#v", got)
	}
	if got := lineage.folderIDs(); len(got) != 2 || got[0] != "123" || got[1] != "456" {
		t.Fatalf("unexpected folder ids: %#v", got)
	}
}

func TestFetchGCPProjectLineageWithClientsReturnsIncompleteError(t *testing.T) {
	lineage, err := fetchGCPProjectLineageWithClients(
		context.Background(),
		"proj-a",
		fakeResourceManagerProjectsClient{
			projects: []*resourcemanagerpb.Project{{
				Name:      "projects/123456789",
				ProjectId: "proj-a",
				Parent:    "folders/456",
			}},
		},
		fakeResourceManagerFoldersClient{
			folders: map[string]*resourcemanagerpb.Folder{},
		},
		fakeResourceManagerOrganizationsClient{},
	)
	incomplete := (*gcpProjectLineageIncompleteError)(nil)
	if !errors.As(err, &incomplete) {
		t.Fatalf("expected incomplete lineage error, got %v", err)
	}
	if lineage == nil || lineage.Project == nil || lineage.Project.GetProjectId() != "proj-a" {
		t.Fatalf("expected partial lineage with project, got %#v", lineage)
	}
	if incomplete.Resource != "folders/456" {
		t.Fatalf("expected missing folder resource, got %#v", incomplete)
	}
}

func TestFetchGCPFolderIAMPoliciesFromLineageKeepsAccessibleAncestors(t *testing.T) {
	lineage := &gcpProjectLineage{
		Project: &resourcemanagerpb.Project{
			Name:      "projects/123456789",
			ProjectId: "proj-a",
			Parent:    "folders/456",
		},
		Folders: []*resourcemanagerpb.Folder{
			{Name: "folders/456", Parent: "folders/123", DisplayName: "Engineering"},
		},
	}
	lineageErr := &gcpProjectLineageIncompleteError{
		ProjectID: "proj-a",
		Resource:  "folders/123",
		Cause:     errors.New("permission denied"),
	}

	rows, err := fetchGCPFolderIAMPoliciesFromLineage(
		context.Background(),
		"proj-a",
		lineage,
		lineageErr,
		fakeResourceManagerFoldersClient{
			policies: map[string]*iampb.Policy{
				"folders/456": {
					Version: 3,
					Etag:    []byte("etag-456"),
					Bindings: []*iampb.Binding{{
						Role:    "roles/viewer",
						Members: []string{"user:alice@example.com"},
					}},
				},
			},
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one accessible folder policy row, got %d", len(rows))
	}
	if rows[0]["resource_name"] != "folders/456" {
		t.Fatalf("unexpected resource name: %#v", rows[0])
	}
	if got, ok := rows[0]["lineage_complete"].(bool); !ok || got {
		t.Fatalf("expected incomplete lineage marker, got %#v", rows[0]["lineage_complete"])
	}
	if got := fmt.Sprint(rows[0]["lineage_error"]); got == "" || got == "<nil>" {
		t.Fatalf("expected lineage error marker, got %#v", rows[0]["lineage_error"])
	}
}

func TestFetchGCPOrganizationIAMPoliciesFromLineageSkipsMissingAncestorWithoutFatalError(t *testing.T) {
	lineage := &gcpProjectLineage{
		Project: &resourcemanagerpb.Project{
			Name:      "projects/123456789",
			ProjectId: "proj-a",
			Parent:    "folders/456",
		},
		Folders: []*resourcemanagerpb.Folder{
			{Name: "folders/456", Parent: "folders/123", DisplayName: "Engineering"},
		},
	}
	lineageErr := &gcpProjectLineageIncompleteError{
		ProjectID: "proj-a",
		Resource:  "folders/123",
		Cause:     errors.New("permission denied"),
	}

	rows, err := fetchGCPOrganizationIAMPoliciesFromLineage(
		context.Background(),
		"proj-a",
		lineage,
		lineageErr,
		fakeResourceManagerOrganizationsClient{},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected no organization rows when ancestor lineage is incomplete, got %d", len(rows))
	}
}
