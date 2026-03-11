package sync

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	"cloud.google.com/go/iam/apiv1/iampb"
	"github.com/writer/cerebro/internal/warehouse"
)

func TestFetchGCPIAMGroupPermissionUsageSkipsWithoutTargets(t *testing.T) {
	e := &GCPSyncEngine{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	rows, err := e.fetchGCPIAMGroupPermissionUsage(context.Background(), "project-123")
	if !errors.Is(err, errSkipGCPIAMGroupPermissionUsage) {
		t.Fatalf("expected skip sentinel error, got %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected no rows when skipped, got %d", len(rows))
	}
}

func TestGCPSyncTableSkipsSentinelWithoutDelete(t *testing.T) {
	store := &warehouse.MemoryWarehouse{}
	e := &GCPSyncEngine{
		sf:        store,
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		projectID: "project-123",
	}

	table := GCPTableSpec{
		Name:    gcpIAMGroupPermissionUsageTable,
		Columns: []string{"project_id", "id"},
		Fetch: func(context.Context, string) ([]map[string]interface{}, error) {
			return nil, errSkipGCPIAMGroupPermissionUsage
		},
	}

	result, err := e.syncTable(context.Background(), table)
	if err != nil {
		t.Fatalf("expected syncTable to treat skip sentinel as non-fatal, got %v", err)
	}
	if result.Errors != 0 {
		t.Fatalf("expected zero sync errors, got %+v", result)
	}

	for _, call := range store.Execs {
		if strings.Contains(strings.ToLower(call.Statement), "delete from "+gcpIAMGroupPermissionUsageTable) {
			t.Fatalf("expected no scoped delete for skipped table, found statement %q", call.Statement)
		}
	}
}

func TestBindingIsExclusiveToGroup(t *testing.T) {
	tests := []struct {
		name    string
		binding *iampb.Binding
		group   string
		want    bool
	}{
		{
			name:    "single target group member",
			binding: &iampb.Binding{Role: "roles/viewer", Members: []string{"group:eng@example.com"}},
			group:   "eng@example.com",
			want:    true,
		},
		{
			name:    "mixed members",
			binding: &iampb.Binding{Role: "roles/viewer", Members: []string{"group:eng@example.com", "user:alice@example.com"}},
			group:   "eng@example.com",
			want:    false,
		},
		{
			name:    "different group",
			binding: &iampb.Binding{Role: "roles/viewer", Members: []string{"group:ops@example.com"}},
			group:   "eng@example.com",
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := bindingIsExclusiveToGroup(tc.binding, tc.group); got != tc.want {
				t.Fatalf("bindingIsExclusiveToGroup() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResolvePermissionsGrantedOutsideGroup(t *testing.T) {
	e := &GCPSyncEngine{}
	cache := make(map[string][]string)
	resolutionErrors := make(map[string]error)

	policy := &iampb.Policy{Bindings: []*iampb.Binding{
		{Role: "roles/viewer", Members: []string{"group:eng@example.com"}},
		{Role: "roles/logging.privateLogViewer", Members: []string{"user:alice@example.com"}},
		{Role: "roles/editor", Members: []string{"group:eng@example.com", "group:ops@example.com"}},
	}}

	permissionsByRole := map[string][]string{
		"roles/viewer":                   {"resourcemanager.projects.get"},
		"roles/logging.privateLogViewer": {"logging.logEntries.list"},
		"roles/editor":                   {"resourcemanager.projects.get", "storage.buckets.get"},
	}
	roleLookup := func(_ context.Context, req *adminpb.GetRoleRequest) (*adminpb.Role, error) {
		if req == nil {
			return nil, errors.New("missing request")
		}
		permissions := append([]string(nil), permissionsByRole[req.Name]...)
		return &adminpb.Role{IncludedPermissions: permissions}, nil
	}

	outsidePermissions, hadResolutionError := e.resolvePermissionsGrantedOutsideGroup(
		context.Background(),
		roleLookup,
		policy,
		"eng@example.com",
		cache,
		resolutionErrors,
	)

	if hadResolutionError {
		t.Fatal("did not expect role resolution error")
	}
	if len(resolutionErrors) != 0 {
		t.Fatalf("expected no recorded role resolution errors, got %#v", resolutionErrors)
	}

	for _, permission := range []string{"logging.logEntries.list", "resourcemanager.projects.get", "storage.buckets.get"} {
		if _, ok := outsidePermissions[permission]; !ok {
			t.Fatalf("expected permission %q to be marked as outside-target grant", permission)
		}
	}
}

func TestExtractTargetGroupRolesDoesNotCreateMissingTargetEntries(t *testing.T) {
	policy := &iampb.Policy{Bindings: []*iampb.Binding{
		{Role: "roles/viewer", Members: []string{"group:eng@example.com"}},
	}}
	targets := map[string]struct{}{
		"eng@example.com": {},
		"ops@example.com": {},
	}

	rolesByGroup := extractTargetGroupRoles(policy, targets)
	if len(rolesByGroup) != 1 {
		t.Fatalf("expected only groups present in policy bindings, got %#v", rolesByGroup)
	}
	if _, ok := rolesByGroup["ops@example.com"]; ok {
		t.Fatalf("did not expect missing target group to be materialized: %#v", rolesByGroup)
	}
	if roles, ok := rolesByGroup["eng@example.com"]; !ok || len(roles) != 1 || roles[0] != "roles/viewer" {
		t.Fatalf("unexpected roles for eng@example.com: %#v", roles)
	}
}
