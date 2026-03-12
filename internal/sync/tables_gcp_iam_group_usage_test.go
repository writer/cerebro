package sync

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	"cloud.google.com/go/iam/apiv1/iampb"
	"github.com/writer/cerebro/internal/snowflake"
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

func TestGCPSyncTablePartialFetchDoesNotDeleteScopedRows(t *testing.T) {
	store := &warehouse.MemoryWarehouse{
		QueryFunc: func(_ context.Context, query string, _ ...any) (*snowflake.QueryResult, error) {
			if strings.Contains(strings.ToLower(query), "select _cq_id, _cq_hash from "+gcpIAMGroupPermissionUsageTable) {
				return &snowflake.QueryResult{Rows: []map[string]any{{
					"_cq_id":   "project-123|ops@example.com|storage.buckets.get",
					"_cq_hash": "stale-hash",
				}}}, nil
			}
			return &snowflake.QueryResult{}, nil
		},
	}
	e := &GCPSyncEngine{
		sf:        store,
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		projectID: "project-123",
	}

	table := GCPTableSpec{
		Name:    gcpIAMGroupPermissionUsageTable,
		Columns: []string{"project_id", "id", "group", "permission"},
		Fetch: func(context.Context, string) ([]map[string]interface{}, error) {
			rows := []map[string]interface{}{{
				"_cq_id":     "project-123|eng@example.com|resourcemanager.projects.get",
				"id":         "project-123|eng@example.com|resourcemanager.projects.get",
				"project_id": "project-123",
				"group":      "eng@example.com",
				"permission": "resourcemanager.projects.get",
			}}
			return rows, newPartialFetchError(errors.New("roles/editor: temporarily unavailable"))
		},
	}

	result, err := e.syncTable(context.Background(), table)
	if err != nil {
		t.Fatalf("expected syncTable to accept partial fetch with incremental upsert, got %v", err)
	}
	if result.Errors != 0 {
		t.Fatalf("expected zero sync errors, got %+v", result)
	}
	if result.Changes == nil {
		t.Fatal("expected change set for partial fetch upsert")
	}
	if len(result.Changes.Removed) != 0 {
		t.Fatalf("expected no removals during partial fetch upsert, got %+v", result.Changes)
	}

	for _, call := range store.Execs {
		if strings.Contains(strings.ToLower(call.Statement), "delete from "+gcpIAMGroupPermissionUsageTable) {
			t.Fatalf("expected no scoped delete for partial fetch, found statement %q", call.Statement)
		}
	}
}

func TestFetchWorkspaceGroupMembersExpandsNestedGroups(t *testing.T) {
	store := &warehouse.MemoryWarehouse{
		QueryFunc: func(_ context.Context, _ string, args ...any) (*snowflake.QueryResult, error) {
			rows := make([]map[string]any, 0)
			for _, arg := range args {
				group, _ := arg.(string)
				switch strings.ToLower(group) {
				case "eng@example.com":
					rows = append(rows,
						map[string]any{"group_email": "eng@example.com", "member_email": "alice@example.com", "member_type": "user"},
						map[string]any{"group_email": "eng@example.com", "member_email": "subgroup@example.com", "member_type": "group"},
					)
				case "subgroup@example.com":
					rows = append(rows,
						map[string]any{"group_email": "subgroup@example.com", "member_email": "bob@example.com", "member_type": "user"},
					)
				}
			}
			return &snowflake.QueryResult{Rows: rows}, nil
		},
	}

	e := &GCPSyncEngine{sf: store, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	membersByGroup, ok := e.fetchWorkspaceGroupMembers(context.Background(), []string{"eng@example.com"})
	if !ok {
		t.Fatal("expected workspace data to be available")
	}
	if got, want := membersByGroup["eng@example.com"], []string{"alice@example.com", "bob@example.com"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected nested group expansion: got %#v want %#v", got, want)
	}
}

func TestSummarizeGCPIAMRoleResolutionErrors(t *testing.T) {
	err := summarizeGCPIAMRoleResolutionErrors(map[string]error{
		"roles/editor": errors.New("permission denied"),
		"roles/viewer": errors.New("not found"),
	})
	if err == nil {
		t.Fatal("expected aggregated role resolution error")
	}
	if !strings.Contains(err.Error(), "roles/editor: permission denied") {
		t.Fatalf("expected aggregated error to mention editor role, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "roles/viewer: not found") {
		t.Fatalf("expected aggregated error to mention viewer role, got %q", err.Error())
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
