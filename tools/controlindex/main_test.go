package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/compliance"
)

func TestGenerateCoverageIndexLoadsExtensionCatalogsAndProfiles(t *testing.T) {
	root := t.TempDir()
	writeControlExtensionFixture(t, root)

	content, err := generateCoverageIndex(root, []string{compliance.DefaultControlCatalogPath}, compliance.DefaultControlProfilesPath, []string{"extensions/customer/extension.yaml"}, nil)
	if err != nil {
		t.Fatalf("generateCoverageIndex() error = %v", err)
	}
	assertGeneratedCoverageIndexContainsExtension(t, content)
}

func TestGenerateCoverageIndexLoadsExtensionsWithRelativeRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	writeControlExtensionFixture(t, root)

	currentDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	if err := os.Chdir(parent); err != nil {
		t.Fatalf("Chdir(%s) error = %v", parent, err)
	}
	defer func() {
		if err := os.Chdir(currentDir); err != nil {
			t.Fatalf("Chdir(%s) error = %v", currentDir, err)
		}
	}()

	content, err := generateCoverageIndex("repo", []string{compliance.DefaultControlCatalogPath}, compliance.DefaultControlProfilesPath, []string{"extensions/customer/extension.yaml"}, nil)
	if err != nil {
		t.Fatalf("generateCoverageIndex() error = %v", err)
	}
	assertGeneratedCoverageIndexContainsExtension(t, content)
}

func TestGenerateCoverageIndexFiltersProfiles(t *testing.T) {
	root := t.TempDir()
	writeControlExtensionFixture(t, root)

	content, err := generateCoverageIndex(root, []string{compliance.DefaultControlCatalogPath}, compliance.DefaultControlProfilesPath, []string{"extensions/customer/extension.yaml"}, []string{"customer-audit"})
	if err != nil {
		t.Fatalf("generateCoverageIndex() error = %v", err)
	}
	output := string(content)
	for _, want := range []string{
		"id: customer-audit",
		"framework_name: Customer Framework",
		"framework_name: SOC 2",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("generated coverage index missing %q:\n%s", want, output)
		}
	}
	for _, notWant := range []string{
		"id: base-soc2",
		"id: customer-iam",
	} {
		if strings.Contains(output, notWant) {
			t.Fatalf("generated coverage index contains %q, want only selected profile:\n%s", notWant, output)
		}
	}
}

func TestGenerateCoverageIndexRejectsUnknownProfileFilter(t *testing.T) {
	root := t.TempDir()
	writeControlExtensionFixture(t, root)

	_, err := generateCoverageIndex(root, []string{compliance.DefaultControlCatalogPath}, compliance.DefaultControlProfilesPath, []string{"extensions/customer/extension.yaml"}, []string{"missing-profile"})
	if err == nil || !strings.Contains(err.Error(), `profile "missing-profile" is not declared`) {
		t.Fatalf("generateCoverageIndex() error = %v, want missing profile error", err)
	}
}

func TestValidateControlIndexFlagsRejectsProfileDefaultOutput(t *testing.T) {
	err := validateControlIndexFlags(false, true, compliance.DefaultControlCoverageIndexPath, []string{"customer-audit"})
	if err == nil || !strings.Contains(err.Error(), "--profile requires --output") {
		t.Fatalf("validateControlIndexFlags() error = %v, want profile output error", err)
	}
	err = validateControlIndexFlags(true, false, "./"+compliance.DefaultControlCoverageIndexPath, []string{"customer-audit"})
	if err == nil || !strings.Contains(err.Error(), "--profile requires --output") {
		t.Fatalf("validateControlIndexFlags() error = %v, want profile output error", err)
	}
	if err := validateControlIndexFlags(false, true, "customer-controls/coverage.yaml", []string{"customer-audit"}); err != nil {
		t.Fatalf("validateControlIndexFlags() error = %v, want nil for explicit profile output", err)
	}
}

func TestValidateControlIndexFlagsRequiresMode(t *testing.T) {
	err := validateControlIndexFlags(false, false, compliance.DefaultControlCoverageIndexPath, nil)
	if err == nil || !strings.Contains(err.Error(), "one of --write or --check is required") {
		t.Fatalf("validateControlIndexFlags() error = %v, want mode error", err)
	}
}

func writeControlExtensionFixture(t *testing.T, root string) {
	t.Helper()
	writeTestFile(t, root, compliance.DefaultControlCatalogPath, `
version: "2026-06-17"
frameworks:
  - name: SOC 2
    families:
      - id: CC6
        name: Logical and Physical Access
        controls:
          - id: CC6.1
`)
	writeTestFile(t, root, compliance.DefaultControlProfilesPath, `
version: "2026-06-17"
profiles:
  - id: base-soc2
    name: Base SOC 2
    frameworks:
      - name: SOC 2
        controls: [CC6.1]
`)
	writeTestFile(t, root, "extensions/customer/extension.yaml", `
version: "2026-06-17"
id: customer-controls
name: Customer Controls
catalogs:
  - controls.yaml
profiles:
  - profiles.yaml
`)
	writeTestFile(t, root, "extensions/customer/controls.yaml", `
version: "2026-06-17"
frameworks:
  - id: customer
    name: Customer Framework
    families:
      - id: IAM
        name: Identity Controls
        controls:
          - id: IAM-1
            title: Privileged access requires MFA
            objective: Privileged production access requires strong authentication evidence.
            audit_procedure:
              - Compare privileged account inventory against MFA enrollment evidence.
            evidence_expectations:
              - id: privileged-mfa-state
                type: identity_configuration
                required: true
            maps_to:
              - framework_name: SOC 2
                control_id: CC6.1
`)
	writeTestFile(t, root, "extensions/customer/profiles.yaml", `
version: "2026-06-17"
profiles:
  - id: customer-iam
    name: Customer IAM
    frameworks:
      - id: customer
        controls: [IAM-1]
  - id: customer-audit
    name: Customer Audit
    include_profiles: [base-soc2, customer-iam]
`)
}

func assertGeneratedCoverageIndexContainsExtension(t *testing.T, content []byte) {
	t.Helper()
	output := string(content)
	for _, want := range []string{
		"id: customer-iam",
		"framework_name: Customer Framework",
		"control_id: IAM-1",
		"evidence_plan:",
		"mapped_control_refs:",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("generated coverage index missing %q:\n%s", want, output)
		}
	}
}

func writeTestFile(t *testing.T, root string, path string, content string) {
	t.Helper()
	fullPath := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", filepath.Dir(fullPath), err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", fullPath, err)
	}
}
