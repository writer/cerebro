package sync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	"cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"google.golang.org/api/iterator"
)

type gcpProjectSearchIterator interface {
	Next() (*resourcemanagerpb.Project, error)
}

type gcpResourceManagerProjectClient interface {
	SearchProjects(ctx context.Context, query string) gcpProjectSearchIterator
	GetIAMPolicy(ctx context.Context, resource string) (*iampb.Policy, error)
	Close() error
}

type gcpResourceManagerFolderClient interface {
	GetFolder(ctx context.Context, resource string) (*resourcemanagerpb.Folder, error)
	GetIAMPolicy(ctx context.Context, resource string) (*iampb.Policy, error)
	Close() error
}

type gcpResourceManagerOrganizationClient interface {
	GetOrganization(ctx context.Context, resource string) (*resourcemanagerpb.Organization, error)
	GetIAMPolicy(ctx context.Context, resource string) (*iampb.Policy, error)
	Close() error
}

type gcpProjectsClientWrapper struct {
	client *resourcemanager.ProjectsClient
}

func (w gcpProjectsClientWrapper) SearchProjects(ctx context.Context, query string) gcpProjectSearchIterator {
	return w.client.SearchProjects(ctx, &resourcemanagerpb.SearchProjectsRequest{Query: query})
}

func (w gcpProjectsClientWrapper) GetIAMPolicy(ctx context.Context, resource string) (*iampb.Policy, error) {
	return w.client.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{Resource: resource})
}

func (w gcpProjectsClientWrapper) Close() error { return w.client.Close() }

type gcpFoldersClientWrapper struct {
	client *resourcemanager.FoldersClient
}

func (w gcpFoldersClientWrapper) GetFolder(ctx context.Context, resource string) (*resourcemanagerpb.Folder, error) {
	return w.client.GetFolder(ctx, &resourcemanagerpb.GetFolderRequest{Name: resource})
}

func (w gcpFoldersClientWrapper) GetIAMPolicy(ctx context.Context, resource string) (*iampb.Policy, error) {
	return w.client.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{Resource: resource})
}

func (w gcpFoldersClientWrapper) Close() error { return w.client.Close() }

type gcpOrganizationsClientWrapper struct {
	client *resourcemanager.OrganizationsClient
}

func (w gcpOrganizationsClientWrapper) GetOrganization(ctx context.Context, resource string) (*resourcemanagerpb.Organization, error) {
	return w.client.GetOrganization(ctx, &resourcemanagerpb.GetOrganizationRequest{Name: resource})
}

func (w gcpOrganizationsClientWrapper) GetIAMPolicy(ctx context.Context, resource string) (*iampb.Policy, error) {
	return w.client.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{Resource: resource})
}

func (w gcpOrganizationsClientWrapper) Close() error { return w.client.Close() }

type gcpProjectLineage struct {
	Project      *resourcemanagerpb.Project
	Folders      []*resourcemanagerpb.Folder
	Organization *resourcemanagerpb.Organization
}

type gcpProjectLineageIncompleteError struct {
	ProjectID string
	Resource  string
	Cause     error
}

func (e *gcpProjectLineageIncompleteError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("project %s lineage incomplete at %s: %v", e.ProjectID, e.Resource, e.Cause)
}

func (e *gcpProjectLineageIncompleteError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (l *gcpProjectLineage) ancestorPath() []string {
	if l == nil {
		return nil
	}
	path := make([]string, 0, len(l.Folders)+1)
	if l.Organization != nil && strings.TrimSpace(l.Organization.GetName()) != "" {
		path = append(path, strings.TrimSpace(l.Organization.GetName()))
	}
	for _, folder := range l.Folders {
		if folder == nil || strings.TrimSpace(folder.GetName()) == "" {
			continue
		}
		path = append(path, strings.TrimSpace(folder.GetName()))
	}
	return path
}

func (l *gcpProjectLineage) folderIDs() []string {
	if l == nil {
		return nil
	}
	ids := make([]string, 0, len(l.Folders))
	for _, folder := range l.Folders {
		if folder == nil {
			continue
		}
		if id := gcpResourceSegment(folder.GetName(), "folders"); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

func (l *gcpProjectLineage) organizationID() string {
	if l == nil || l.Organization == nil {
		return ""
	}
	return gcpResourceSegment(l.Organization.GetName(), "organizations")
}

func (e *GCPSyncEngine) gcpResourceManagerProjectTable() GCPTableSpec {
	return GCPTableSpec{
		Name: "gcp_resource_manager_projects",
		Columns: []string{
			"project_id",
			"id",
			"resource_name",
			"project_number",
			"display_name",
			"parent",
			"state",
			"labels",
			"organization_id",
			"folder_ids",
			"ancestor_path",
			"lineage_complete",
			"lineage_error",
			"create_time",
			"update_time",
			"etag",
		},
		Fetch: e.fetchGCPResourceManagerProjects,
	}
}

func (e *GCPSyncEngine) gcpResourceManagerFolderTable() GCPTableSpec {
	return GCPTableSpec{
		Name: "gcp_resource_manager_folders",
		Columns: []string{
			"project_id",
			"id",
			"folder_id",
			"resource_name",
			"display_name",
			"parent",
			"state",
			"organization_id",
			"depth",
			"ancestor_path",
			"lineage_complete",
			"lineage_error",
			"create_time",
			"update_time",
			"etag",
		},
		Fetch: e.fetchGCPResourceManagerFolders,
	}
}

func (e *GCPSyncEngine) gcpResourceManagerOrganizationTable() GCPTableSpec {
	return GCPTableSpec{
		Name: "gcp_resource_manager_organizations",
		Columns: []string{
			"project_id",
			"id",
			"organization_id",
			"resource_name",
			"display_name",
			"state",
			"ancestor_path",
			"lineage_complete",
			"lineage_error",
			"create_time",
			"update_time",
			"etag",
		},
		Fetch: e.fetchGCPResourceManagerOrganizations,
	}
}

func (e *GCPSyncEngine) gcpFolderIAMPolicyTable() GCPTableSpec {
	return GCPTableSpec{
		Name: "gcp_folder_iam_policies",
		Columns: []string{
			"project_id",
			"id",
			"folder_id",
			"resource_name",
			"version",
			"etag",
			"bindings",
			"ancestor_path",
			"lineage_complete",
			"lineage_error",
		},
		Fetch: e.fetchGCPFolderIAMPolicies,
	}
}

func (e *GCPSyncEngine) gcpOrganizationIAMPolicyTable() GCPTableSpec {
	return GCPTableSpec{
		Name: "gcp_organization_iam_policies",
		Columns: []string{
			"project_id",
			"id",
			"organization_id",
			"resource_name",
			"version",
			"etag",
			"bindings",
			"ancestor_path",
			"lineage_complete",
			"lineage_error",
		},
		Fetch: e.fetchGCPOrganizationIAMPolicies,
	}
}

func (e *GCPSyncEngine) fetchGCPResourceManagerProjects(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	lineage, err := e.fetchGCPProjectLineage(ctx, projectID)
	incomplete := (*gcpProjectLineageIncompleteError)(nil)
	if err != nil && !errors.As(err, &incomplete) {
		return nil, err
	}
	project := lineage.Project
	if project == nil {
		return nil, fmt.Errorf("project %s not found", projectID)
	}
	lineageComplete, lineageError := gcpLineageStatus(err)

	row := map[string]interface{}{
		"_cq_id":           fmt.Sprintf("%s/%s", projectID, project.GetName()),
		"project_id":       project.GetProjectId(),
		"id":               project.GetName(),
		"resource_name":    project.GetName(),
		"project_number":   gcpResourceSegment(project.GetName(), "projects"),
		"display_name":     firstNonEmpty(project.GetDisplayName(), project.GetProjectId()),
		"parent":           project.GetParent(),
		"state":            project.GetState().String(),
		"labels":           project.GetLabels(),
		"organization_id":  lineage.organizationID(),
		"folder_ids":       lineage.folderIDs(),
		"ancestor_path":    lineage.ancestorPath(),
		"lineage_complete": lineageComplete,
		"lineage_error":    lineageError,
		"etag":             project.GetEtag(),
	}
	if project.GetCreateTime() != nil {
		row["create_time"] = project.GetCreateTime().AsTime()
	}
	if project.GetUpdateTime() != nil {
		row["update_time"] = project.GetUpdateTime().AsTime()
	}

	return []map[string]interface{}{row}, nil
}

func (e *GCPSyncEngine) fetchGCPResourceManagerFolders(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	lineage, err := e.fetchGCPProjectLineage(ctx, projectID)
	incomplete := (*gcpProjectLineageIncompleteError)(nil)
	if err != nil && !errors.As(err, &incomplete) {
		return nil, err
	}
	lineageComplete, lineageError := gcpLineageStatus(err)

	path := lineage.ancestorPath()
	rows := make([]map[string]interface{}, 0, len(lineage.Folders))
	for idx, folder := range lineage.Folders {
		if folder == nil || strings.TrimSpace(folder.GetName()) == "" {
			continue
		}
		row := map[string]interface{}{
			"_cq_id":           fmt.Sprintf("%s/%s", projectID, folder.GetName()),
			"project_id":       projectID,
			"id":               folder.GetName(),
			"folder_id":        gcpResourceSegment(folder.GetName(), "folders"),
			"resource_name":    folder.GetName(),
			"display_name":     firstNonEmpty(folder.GetDisplayName(), folder.GetName()),
			"parent":           folder.GetParent(),
			"state":            folder.GetState().String(),
			"organization_id":  lineage.organizationID(),
			"depth":            idx + 1,
			"ancestor_path":    path,
			"lineage_complete": lineageComplete,
			"lineage_error":    lineageError,
			"etag":             folder.GetEtag(),
		}
		if folder.GetCreateTime() != nil {
			row["create_time"] = folder.GetCreateTime().AsTime()
		}
		if folder.GetUpdateTime() != nil {
			row["update_time"] = folder.GetUpdateTime().AsTime()
		}
		rows = append(rows, row)
	}

	return rows, nil
}

func (e *GCPSyncEngine) fetchGCPResourceManagerOrganizations(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	lineage, err := e.fetchGCPProjectLineage(ctx, projectID)
	incomplete := (*gcpProjectLineageIncompleteError)(nil)
	if err != nil && !errors.As(err, &incomplete) {
		return nil, err
	}
	if lineage.Organization == nil || strings.TrimSpace(lineage.Organization.GetName()) == "" {
		return nil, nil
	}
	lineageComplete, lineageError := gcpLineageStatus(err)

	org := lineage.Organization
	row := map[string]interface{}{
		"_cq_id":           fmt.Sprintf("%s/%s", projectID, org.GetName()),
		"project_id":       projectID,
		"id":               org.GetName(),
		"organization_id":  gcpResourceSegment(org.GetName(), "organizations"),
		"resource_name":    org.GetName(),
		"display_name":     firstNonEmpty(org.GetDisplayName(), org.GetName()),
		"state":            org.GetState().String(),
		"ancestor_path":    lineage.ancestorPath(),
		"lineage_complete": lineageComplete,
		"lineage_error":    lineageError,
		"etag":             org.GetEtag(),
	}
	if org.GetCreateTime() != nil {
		row["create_time"] = org.GetCreateTime().AsTime()
	}
	if org.GetUpdateTime() != nil {
		row["update_time"] = org.GetUpdateTime().AsTime()
	}

	return []map[string]interface{}{row}, nil
}

func (e *GCPSyncEngine) fetchGCPFolderIAMPolicies(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	lineage, lineageErr := e.fetchGCPProjectLineage(ctx, projectID)
	incomplete := (*gcpProjectLineageIncompleteError)(nil)
	if lineageErr != nil && !errors.As(lineageErr, &incomplete) {
		return nil, fmt.Errorf("resolve GCP project lineage for folder IAM policies: %w", lineageErr)
	}

	foldersClient, clientErr := e.newGCPFoldersClient(ctx)
	if clientErr != nil {
		return nil, fmt.Errorf("create folders client: %w", clientErr)
	}
	defer func() { _ = foldersClient.Close() }()

	return fetchGCPFolderIAMPoliciesFromLineage(ctx, projectID, lineage, lineageErr, foldersClient, e.logger)
}

func fetchGCPFolderIAMPoliciesFromLineage(
	ctx context.Context,
	projectID string,
	lineage *gcpProjectLineage,
	lineageErr error,
	foldersClient gcpResourceManagerFolderClient,
	logger *slog.Logger,
) ([]map[string]interface{}, error) {
	if lineage == nil {
		return nil, nil
	}
	lineageComplete, lineageError := gcpLineageStatus(lineageErr)
	rows := make([]map[string]interface{}, 0, len(lineage.Folders))
	for _, folder := range lineage.Folders {
		if folder == nil || strings.TrimSpace(folder.GetName()) == "" {
			continue
		}
		policy, err := foldersClient.GetIAMPolicy(ctx, folder.GetName())
		if err != nil {
			logger.Warn("failed to fetch GCP folder IAM policy", "project_id", projectID, "folder", folder.GetName(), "error", err)
			continue
		}
		rows = append(rows, map[string]interface{}{
			"_cq_id":           fmt.Sprintf("%s/%s/iam-policy", projectID, folder.GetName()),
			"project_id":       projectID,
			"id":               folder.GetName() + "/iam-policy",
			"folder_id":        gcpResourceSegment(folder.GetName(), "folders"),
			"resource_name":    folder.GetName(),
			"version":          policy.GetVersion(),
			"etag":             string(policy.GetEtag()),
			"bindings":         serializeGCPIAMBindings(policy.GetBindings()),
			"ancestor_path":    lineage.ancestorPath(),
			"lineage_complete": lineageComplete,
			"lineage_error":    lineageError,
		})
	}

	return rows, nil
}

func (e *GCPSyncEngine) fetchGCPOrganizationIAMPolicies(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	lineage, lineageErr := e.fetchGCPProjectLineage(ctx, projectID)
	incomplete := (*gcpProjectLineageIncompleteError)(nil)
	if lineageErr != nil && !errors.As(lineageErr, &incomplete) {
		return nil, fmt.Errorf("resolve GCP project lineage for organization IAM policies: %w", lineageErr)
	}
	if lineage.Organization == nil || strings.TrimSpace(lineage.Organization.GetName()) == "" {
		return nil, nil
	}

	orgsClient, clientErr := e.newGCPOrganizationsClient(ctx)
	if clientErr != nil {
		return nil, fmt.Errorf("create organizations client: %w", clientErr)
	}
	defer func() { _ = orgsClient.Close() }()

	return fetchGCPOrganizationIAMPoliciesFromLineage(ctx, projectID, lineage, lineageErr, orgsClient, e.logger)
}

func fetchGCPOrganizationIAMPoliciesFromLineage(
	ctx context.Context,
	projectID string,
	lineage *gcpProjectLineage,
	lineageErr error,
	orgsClient gcpResourceManagerOrganizationClient,
	logger *slog.Logger,
) ([]map[string]interface{}, error) {
	if lineage == nil || lineage.Organization == nil || strings.TrimSpace(lineage.Organization.GetName()) == "" {
		return nil, nil
	}
	policy, err := orgsClient.GetIAMPolicy(ctx, lineage.Organization.GetName())
	if err != nil {
		logger.Warn("failed to fetch GCP organization IAM policy", "project_id", projectID, "organization", lineage.Organization.GetName(), "error", err)
		return nil, nil
	}

	lineageComplete, lineageError := gcpLineageStatus(lineageErr)
	row := map[string]interface{}{
		"_cq_id":           fmt.Sprintf("%s/%s/iam-policy", projectID, lineage.Organization.GetName()),
		"project_id":       projectID,
		"id":               lineage.Organization.GetName() + "/iam-policy",
		"organization_id":  gcpResourceSegment(lineage.Organization.GetName(), "organizations"),
		"resource_name":    lineage.Organization.GetName(),
		"version":          policy.GetVersion(),
		"etag":             string(policy.GetEtag()),
		"bindings":         serializeGCPIAMBindings(policy.GetBindings()),
		"ancestor_path":    lineage.ancestorPath(),
		"lineage_complete": lineageComplete,
		"lineage_error":    lineageError,
	}

	return []map[string]interface{}{row}, nil
}

func (e *GCPSyncEngine) fetchGCPProjectLineage(ctx context.Context, projectID string) (*gcpProjectLineage, error) {
	projectsClient, err := e.newGCPProjectsClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create projects client: %w", err)
	}
	defer func() { _ = projectsClient.Close() }()

	foldersClient, err := e.newGCPFoldersClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create folders client: %w", err)
	}
	defer func() { _ = foldersClient.Close() }()

	orgsClient, err := e.newGCPOrganizationsClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create organizations client: %w", err)
	}
	defer func() { _ = orgsClient.Close() }()

	return fetchGCPProjectLineageWithClients(ctx, projectID, projectsClient, foldersClient, orgsClient)
}

func (e *GCPSyncEngine) newGCPProjectsClient(ctx context.Context) (gcpResourceManagerProjectClient, error) {
	client, err := resourcemanager.NewProjectsClient(ctx, gcpClientOptionsFromContext(ctx)...)
	if err != nil {
		return nil, err
	}
	return gcpProjectsClientWrapper{client: client}, nil
}

func (e *GCPSyncEngine) newGCPFoldersClient(ctx context.Context) (gcpResourceManagerFolderClient, error) {
	client, err := resourcemanager.NewFoldersClient(ctx, gcpClientOptionsFromContext(ctx)...)
	if err != nil {
		return nil, err
	}
	return gcpFoldersClientWrapper{client: client}, nil
}

func (e *GCPSyncEngine) newGCPOrganizationsClient(ctx context.Context) (gcpResourceManagerOrganizationClient, error) {
	client, err := resourcemanager.NewOrganizationsClient(ctx, gcpClientOptionsFromContext(ctx)...)
	if err != nil {
		return nil, err
	}
	return gcpOrganizationsClientWrapper{client: client}, nil
}

func fetchGCPProjectLineageWithClients(
	ctx context.Context,
	projectID string,
	projectsClient gcpResourceManagerProjectClient,
	foldersClient gcpResourceManagerFolderClient,
	orgsClient gcpResourceManagerOrganizationClient,
) (*gcpProjectLineage, error) {
	project, err := fetchGCPProjectByID(ctx, projectID, projectsClient)
	if err != nil {
		return nil, err
	}

	lineage := &gcpProjectLineage{Project: project}
	parent := strings.TrimSpace(project.GetParent())
	if parent == "" {
		return lineage, nil
	}

	leafToRoot := make([]*resourcemanagerpb.Folder, 0, 4)
	for strings.HasPrefix(parent, "folders/") {
		folder, err := foldersClient.GetFolder(ctx, parent)
		if err != nil {
			return lineage, &gcpProjectLineageIncompleteError{ProjectID: projectID, Resource: parent, Cause: err}
		}
		leafToRoot = append(leafToRoot, folder)
		parent = strings.TrimSpace(folder.GetParent())
	}

	slices.Reverse(leafToRoot)
	lineage.Folders = leafToRoot

	if strings.HasPrefix(parent, "organizations/") {
		org, err := orgsClient.GetOrganization(ctx, parent)
		if err != nil {
			return lineage, &gcpProjectLineageIncompleteError{ProjectID: projectID, Resource: parent, Cause: err}
		}
		lineage.Organization = org
	}

	return lineage, nil
}

func gcpLineageStatus(err error) (bool, string) {
	if err == nil {
		return true, ""
	}
	incomplete := (*gcpProjectLineageIncompleteError)(nil)
	if errors.As(err, &incomplete) {
		return false, err.Error()
	}
	return false, err.Error()
}

func fetchGCPProjectByID(ctx context.Context, projectID string, projectsClient gcpResourceManagerProjectClient) (*resourcemanagerpb.Project, error) {
	it := projectsClient.SearchProjects(ctx, "projectId:"+projectID)
	for {
		project, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("search projects: %w", err)
		}
		if project != nil && strings.EqualFold(project.GetProjectId(), projectID) {
			return project, nil
		}
	}
	return nil, fmt.Errorf("search projects: project %s not found", projectID)
}
