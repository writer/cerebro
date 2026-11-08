package iac

import (
	"context"
	"testing"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

func varFilesRepo(files map[string]string) ci.Repository {
	out := ci.Repository{Pin: ci.SourcePin{Repository: "test-org/infra", Revision: "fixture-rev", Exact: true}}
	for path, content := range files {
		out.Files = append(out.Files, ci.SourceFile{Path: path, Content: []byte(content), Digest: "inline-digest:" + path})
	}
	return out
}

const varFilesRoleFixture = `
variable "role_name" {}

resource "aws_iam_role" "x" {
  name               = var.role_name
  assume_role_policy = "{}"
}
`

// TestVarFilesPrecedenceOrder reproduces Terraform's own "-var-file"
// precedence contract: auto-loaded terraform.tfvars applies first, then
// each TerraformInput.VarFiles entry in order (mirroring repeated
// "-var-file" flags), a later file always winning over an earlier one AND
// over the auto-loaded layer.
func TestVarFilesPrecedenceOrder(t *testing.T) {
	repo := varFilesRepo(map[string]string{
		"root/main.tf":            varFilesRoleFixture,
		"root/terraform.tfvars":   `role_name = "auto"`,
		"variables/global.tfvars": `role_name = "global"`,
		"variables/team.tfvars":   `role_name = "team"`,
	})
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{
		Repository: repo,
		Root:       "root",
		Account:    "111111111111",
		VarFiles:   []string{"variables/global.tfvars", "variables/team.tfvars"},
	})
	if err != nil {
		t.Fatalf("ReadDeclarations() error = %v", err)
	}
	if hasGapCode(gaps, "iac.missing_var_file") {
		t.Fatalf("unexpected missing_var_file gap: %+v", gaps)
	}
	role := mustDecl(t, decls, "arn:aws:iam::111111111111:role/team")
	_ = role
}

// TestVarFilesSingleEntryOverridesAutoLoaded confirms a single var_files
// entry still wins over the auto-loaded terraform.tfvars layer on its own
// (without a second entry to also prove ordering against).
func TestVarFilesSingleEntryOverridesAutoLoaded(t *testing.T) {
	repo := varFilesRepo(map[string]string{
		"root/main.tf":            varFilesRoleFixture,
		"root/terraform.tfvars":   `role_name = "auto"`,
		"variables/global.tfvars": `role_name = "global"`,
	})
	reader := NewDeclarationReader(nil)
	decls, _, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{
		Repository: repo,
		Root:       "root",
		Account:    "222222222222",
		VarFiles:   []string{"variables/global.tfvars"},
	})
	if err != nil {
		t.Fatalf("ReadDeclarations() error = %v", err)
	}
	mustDecl(t, decls, "arn:aws:iam::222222222222:role/global")
}

// TestVarFilesMissingEntryIsGap reproduces a var_files path the pinned
// repository does not contain (e.g. a scan plan whose recorded var_files
// list has gone stale relative to the pinned commit): it must surface as
// an explicit gap, never be silently skipped, and must never block
// evaluation of the rest of the root.
func TestVarFilesMissingEntryIsGap(t *testing.T) {
	repo := varFilesRepo(map[string]string{
		"root/main.tf": varFilesRoleFixture,
	})
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{
		Repository: repo,
		Root:       "root",
		Account:    "333333333333",
		VarFiles:   []string{"variables/does-not-exist.tfvars"},
	})
	if err != nil {
		t.Fatalf("ReadDeclarations() error = %v", err)
	}
	if !hasGapCode(gaps, "iac.missing_var_file") {
		t.Fatalf("expected iac.missing_var_file gap, got %+v", gaps)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "iac.missing_var_file" && g.Message != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected missing_var_file gap to carry a message, got %+v", gaps)
	}
	// role_name has no default and no resolved value: the declaration still
	// exists (the resource itself is declared) but its name is unresolved,
	// which must itself be a gap rather than silently guessed -- the root
	// is still evaluated despite the missing var file.
	if len(decls) != 1 {
		t.Fatalf("expected the role resource to still be declared despite the missing var file, got %+v", decls)
	}
}

// TestVarFilesMalformedHCLSyntaxIsGap reproduces a tfvars file with a plain
// HCL syntax error (finding #8): it must surface as an explicit
// iac.unsupported_tfvars_value gap carrying the file reference, matching
// the already-covered malformed-JSON tfvars path, never be silently
// skipped.
func TestVarFilesMalformedHCLSyntaxIsGap(t *testing.T) {
	repo := varFilesRepo(map[string]string{
		"root/main.tf":          varFilesRoleFixture,
		"root/terraform.tfvars": `role_name = "auto`, // unterminated string literal
	})
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{
		Repository: repo,
		Root:       "root",
		Account:    "444444444444",
	})
	if err != nil {
		t.Fatalf("ReadDeclarations() error = %v", err)
	}
	found := false
	for _, g := range gaps {
		if g.Code != "iac.unsupported_tfvars_value" {
			continue
		}
		if len(g.References) == 0 || g.References[0].Path != "root/terraform.tfvars" {
			t.Fatalf("expected gap to carry the tfvars file reference, got %+v", g)
		}
		found = true
	}
	if !found {
		t.Fatalf("expected iac.unsupported_tfvars_value gap for malformed HCL tfvars, got %+v", gaps)
	}
	// role_name has no default and no resolved value (the malformed file
	// contributed nothing): the resource is still declared, just
	// unresolved, exactly like the missing-var-file case above.
	if len(decls) != 1 {
		t.Fatalf("expected the role resource to still be declared despite the malformed tfvars file, got %+v", decls)
	}
}

// TestVarFilesHCLBodyShapeDiagnosticIsGap reproduces an auto-loaded tfvars
// file that parses as valid HCL syntax but is not flat top-level
// attributes (e.g. it declares a nested block, which JustAttributes
// rejects): this must also surface as a bounded
// iac.unsupported_tfvars_value gap rather than being silently dropped.
func TestVarFilesHCLBodyShapeDiagnosticIsGap(t *testing.T) {
	repo := varFilesRepo(map[string]string{
		"root/main.tf": varFilesRoleFixture,
		"root/terraform.tfvars": `
block "unexpected" {
  role_name = "auto"
}
`,
	})
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{
		Repository: repo,
		Root:       "root",
		Account:    "555555555555",
	})
	if err != nil {
		t.Fatalf("ReadDeclarations() error = %v", err)
	}
	if !hasGapCode(gaps, "iac.unsupported_tfvars_value") {
		t.Fatalf("expected iac.unsupported_tfvars_value gap for a non-flat tfvars body, got %+v", gaps)
	}
	if len(decls) != 1 {
		t.Fatalf("expected the role resource to still be declared despite the malformed tfvars file, got %+v", decls)
	}
}
