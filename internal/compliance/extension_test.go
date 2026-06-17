package compliance

import "testing"

func TestLoadControlExtensionPackReadsYAML(t *testing.T) {
	pack, err := LoadControlExtensionPack([]byte(`
version: "2026-06-17"
id: customer-controls
name: Customer Controls
description: Custom control framework and profile selections.
catalogs:
  - controls.yaml
profiles:
  - profiles.yaml
`))
	if err != nil {
		t.Fatalf("LoadControlExtensionPack() error = %v", err)
	}
	if pack.ID != "customer-controls" || len(pack.Catalogs) != 1 || len(pack.Profiles) != 1 {
		t.Fatalf("pack = %#v, want parsed extension manifest", pack)
	}
}

func TestValidateControlExtensionPackRequiresMetadataAndPaths(t *testing.T) {
	issues := ValidateControlExtensionPack(ControlExtensionPack{
		Catalogs: []string{""},
		Profiles: []string{""},
	})
	for _, want := range []string{
		"control extension version is required",
		"control extension id is required",
		"control extension name is required",
		"path is required",
	} {
		if !validationIssuesContain(issues, want) {
			t.Fatalf("issues = %#v, want %q", issues, want)
		}
	}
}

func TestMergeControlProfileSetsAppendsCustomProfiles(t *testing.T) {
	merged := MergeControlProfileSets(
		ControlProfileSet{
			Version: "2026-06-17",
			Profiles: []ControlSelection{{
				ID:   "base",
				Name: "Base",
			}},
		},
		ControlProfileSet{
			Version: "customer",
			Profiles: []ControlSelection{{
				ID:   "custom",
				Name: "Custom",
			}},
		},
	)
	if merged.Version != "2026-06-17" {
		t.Fatalf("Version = %q, want first non-empty version", merged.Version)
	}
	if len(merged.Profiles) != 2 || merged.Profiles[1].ID != "custom" {
		t.Fatalf("Profiles = %#v, want base and custom profiles", merged.Profiles)
	}
}
