package applicationworkspace

import (
	"reflect"
	"testing"

	"github.com/writer/cerebro/internal/config"
)

func TestSelectRequiresHeaderAndQueryAgreement(t *testing.T) {
	if _, err := Select("workspace-a", "workspace-b"); err == nil {
		t.Fatal("Select() error = nil, want selector disagreement")
	}
	if got, err := Select("workspace-a", "workspace-a"); err != nil || got != "workspace-a" {
		t.Fatalf("Select() = %q, %v, want workspace-a, nil", got, err)
	}
}

func TestSelectValuesRejectsRepeatedSelectors(t *testing.T) {
	for _, test := range []struct {
		name    string
		headers []string
		query   []string
	}{
		{name: "headers", headers: []string{"workspace-a", "workspace-b"}},
		{name: "query", query: []string{"workspace-a", "workspace-b"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := SelectValues(test.headers, test.query); err == nil {
				t.Fatal("SelectValues() error = nil, want repeated-selector rejection")
			}
		})
	}
}

func TestNormalizeGrantsDeduplicatesAndSorts(t *testing.T) {
	got, ok := NormalizeGrants([]config.ApplicationWorkspaceGrant{
		{TenantID: "writer", ApplicationWorkspaceIDs: []string{"workspace-b", "workspace-a"}},
		{TenantID: "writer", ApplicationWorkspaceIDs: []string{"workspace-a"}},
	})
	want := []config.ApplicationWorkspaceGrant{{TenantID: "writer", ApplicationWorkspaceIDs: []string{"workspace-a", "workspace-b"}}}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizeGrants() = %#v, %v, want %#v, true", got, ok, want)
	}
}

func TestAllowedRequiresTenantQualifiedGrant(t *testing.T) {
	grants := []config.ApplicationWorkspaceGrant{{TenantID: "writer", ApplicationWorkspaceIDs: []string{"workspace-a"}}}
	if !Allowed(grants, "writer", "workspace-a") {
		t.Fatal("Allowed() = false for granted tenant workspace")
	}
	if Allowed(grants, "other", "workspace-a") || Allowed(grants, "writer", "workspace-b") {
		t.Fatal("Allowed() = true outside tenant-qualified grant")
	}
	if !Allowed(nil, "writer", "workspace-a") {
		t.Fatal("Allowed() = false for legacy tenant-wide access")
	}
}
