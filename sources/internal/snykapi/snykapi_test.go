package snykapi

import (
	"reflect"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestFamilyNamesMatchFamilies(t *testing.T) {
	families := Families()
	names := FamilyNames()
	if len(names) != len(families) {
		t.Fatalf("FamilyNames() len = %d, Families() len = %d", len(names), len(families))
	}
	for i, family := range families {
		if names[i] != family.Name {
			t.Errorf("name[%d] = %q, want %q", i, names[i], family.Name)
		}
	}
}

func TestFamilyNamesAreUniqueAndNonEmpty(t *testing.T) {
	seen := map[string]bool{}
	for _, name := range FamilyNames() {
		if name == "" {
			t.Error("found empty family name")
		}
		if seen[name] {
			t.Errorf("duplicate family name %q", name)
		}
		seen[name] = true
	}
	for _, required := range []string{FamilyOrgs, FamilyGroups, FamilyAssets, FamilyAuditLogs} {
		if !seen[required] {
			t.Errorf("expected family %q to be present", required)
		}
	}
}

func TestPathParamValues(t *testing.T) {
	cases := []struct {
		name      string
		family    string
		config    map[string]string
		wantParam string
		wantVals  []string
	}{
		{
			name:      "group family reads group_ids list",
			family:    FamilyGroupMemberships,
			config:    map[string]string{"group_ids": "g1, g2 ,g3"},
			wantParam: GroupIDConfig,
			wantVals:  []string{"g1", "g2", "g3"},
		},
		{
			name:      "group family falls back to singular group_id",
			family:    FamilyGroupAuditLogs,
			config:    map[string]string{GroupIDConfig: "solo"},
			wantParam: GroupIDConfig,
			wantVals:  []string{"solo"},
		},
		{
			name:      "asset family reads asset_ids list",
			family:    FamilyAssetProjects,
			config:    map[string]string{"asset_ids": "a1,a2"},
			wantParam: AssetIDConfig,
			wantVals:  []string{"a1", "a2"},
		},
		{
			name:      "asset target family with whitespace-padded family name",
			family:    "  " + FamilyAssetTargets + "  ",
			config:    map[string]string{AssetIDConfig: "asset-1"},
			wantParam: AssetIDConfig,
			wantVals:  []string{"asset-1"},
		},
		{
			name:      "non parameterized family returns empty",
			family:    FamilyOrgs,
			config:    map[string]string{"group_ids": "ignored"},
			wantParam: "",
			wantVals:  nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotParam, gotVals := PathParamValues(sourcecdk.NewConfig(tc.config), tc.family)
			if gotParam != tc.wantParam {
				t.Errorf("param = %q, want %q", gotParam, tc.wantParam)
			}
			if !reflect.DeepEqual(gotVals, tc.wantVals) {
				t.Errorf("values = %#v, want %#v", gotVals, tc.wantVals)
			}
		})
	}
}

func TestConfigListValues(t *testing.T) {
	cfg := sourcecdk.NewConfig(map[string]string{
		"plural":   " x , y ,, z ",
		"singular": "only",
		"empty":    "  ,  ",
	})
	if got := configListValues(cfg, "plural"); !reflect.DeepEqual(got, []string{"x", "y", "z"}) {
		t.Errorf("configListValues(plural) = %#v", got)
	}
	if got := configListValues(cfg, "empty", "singular"); !reflect.DeepEqual(got, []string{"only"}) {
		t.Errorf("configListValues(empty, singular) = %#v", got)
	}
	if got := configListValues(cfg, "missing"); !reflect.DeepEqual(got, []string{}) {
		t.Errorf("configListValues(missing) = %#v, want empty slice", got)
	}
}

func TestSnykStaticAttributes(t *testing.T) {
	withType := snykStaticAttributes("schema-a", "asset", "host")
	want := map[string]string{
		"record_class":  "asset",
		"schema":        "schema-a",
		"source_system": "snyk",
		"resource_type": "host",
	}
	if !reflect.DeepEqual(withType, want) {
		t.Errorf("snykStaticAttributes() = %#v, want %#v", withType, want)
	}
	withoutType := snykStaticAttributes("schema-b", "finding", "")
	if _, ok := withoutType["resource_type"]; ok {
		t.Errorf("resource_type should be omitted when empty: %#v", withoutType)
	}
}

func TestSnykPagedFamilyDefaults(t *testing.T) {
	family := snykOrgsFamily()
	if family.CursorParam != "starting_after" {
		t.Errorf("CursorParam = %q, want starting_after", family.CursorParam)
	}
	if !reflect.DeepEqual(family.NextCursorKeys, []string{"links.next"}) {
		t.Errorf("NextCursorKeys = %#v", family.NextCursorKeys)
	}
	if !reflect.DeepEqual(family.PageSizeParams, []string{"limit"}) {
		t.Errorf("PageSizeParams = %#v", family.PageSizeParams)
	}
	if got := family.Config.ConfigQuery["version"]; got != APIVersionConfig {
		t.Errorf("version config query = %q, want %q", got, APIVersionConfig)
	}
}

func TestSnykOrgPagedFamilyAttributes(t *testing.T) {
	family := snykProjectsFamily()
	if got := family.Config.ConfigAttributes["org_id"]; got != OrgIDConfig {
		t.Errorf("org_id config attribute = %q, want %q", got, OrgIDConfig)
	}
}
