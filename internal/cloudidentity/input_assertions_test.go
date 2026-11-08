package cloudidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func inputAssertionTestRepository(files map[string]string, gaps ...Gap) Repository {
	var out []SourceFile
	for p, content := range files {
		out = append(out, SourceFile{Path: p, Content: []byte(content), Digest: "sha1:test"})
	}
	return Repository{
		Pin:   SourcePin{Repository: "example-org/example-repo", Revision: "deadbeef", Exact: true},
		Files: out,
		Gaps:  gaps,
	}
}

func mustInputAssertionJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal expected value: %v", err)
	}
	return raw
}

func baseInputAssertion(kind, p string) InputAssertion {
	return InputAssertion{
		Source: SourcePin{Repository: "example-org/example-repo", Revision: "deadbeef"},
		Path:   p,
		Kind:   kind,
	}
}

func TestVerifyInputAssertionFileDigestMatch(t *testing.T) {
	content := "locals {\n  x = 1\n}\n"
	sum := sha256.Sum256([]byte(content))
	digest := hex.EncodeToString(sum[:])
	repo := inputAssertionTestRepository(map[string]string{"module/locals.tf": content})
	a := baseInputAssertion("file_digest", "module/locals.tf")
	a.Digest = digest

	ref, err := VerifyInputAssertion(repo, a)
	if err != nil {
		t.Fatalf("expected a matching digest to pass, got %v", err)
	}
	if ref.Repository != repo.Pin.Repository || ref.Revision != repo.Pin.Revision || ref.Path != a.Path {
		t.Fatalf("unexpected reference: %+v", ref)
	}
}

func TestVerifyInputAssertionFileDigestMismatch(t *testing.T) {
	repo := inputAssertionTestRepository(map[string]string{"module/locals.tf": "locals {\n  x = 1\n}\n"})
	a := baseInputAssertion("file_digest", "module/locals.tf")
	a.Digest = "0000000000000000000000000000000000000000000000000000000000000000"

	if _, err := VerifyInputAssertion(repo, a); err == nil {
		t.Fatalf("expected a digest mismatch to fail")
	}
}

func TestVerifyInputAssertionFileDigestMissingFile(t *testing.T) {
	repo := inputAssertionTestRepository(nil)
	a := baseInputAssertion("file_digest", "module/missing.tf")
	a.Digest = "0000000000000000000000000000000000000000000000000000000000000000"

	if _, err := VerifyInputAssertion(repo, a); err == nil {
		t.Fatalf("expected a missing file to fail")
	}
}

func TestVerifyInputAssertionHCLValueNonStaticRejected(t *testing.T) {
	repo := inputAssertionTestRepository(map[string]string{
		"module/main.tf": `name = var.environment` + "\n",
	})
	a := baseInputAssertion("hcl_value", "module/main.tf")
	a.Attribute = "name"
	a.Expected = mustInputAssertionJSON(t, "prod")

	if _, err := VerifyInputAssertion(repo, a); err == nil {
		t.Fatalf("expected a non-static attribute to fail")
	}
}

func TestVerifyInputAssertionHCLValueTopLevelAttributeMatch(t *testing.T) {
	repo := inputAssertionTestRepository(map[string]string{
		"module/main.tf": `org_tag = "example-tag"` + "\n",
	})
	a := baseInputAssertion("hcl_value", "module/main.tf")
	a.Attribute = "org_tag"
	a.Expected = mustInputAssertionJSON(t, "example-tag")

	if _, err := VerifyInputAssertion(repo, a); err != nil {
		t.Fatalf("expected a matching attribute to pass, got %v", err)
	}
}

func TestVerifyInputAssertionHCLValueLocalsBlock(t *testing.T) {
	repo := inputAssertionTestRepository(map[string]string{
		"module/main.tf": `
locals {
  chart_path = "charts/example-app"
}
`,
	})
	a := baseInputAssertion("hcl_value", "module/main.tf")
	a.Block = "locals"
	a.Attribute = "chart_path"
	a.Expected = mustInputAssertionJSON(t, "charts/example-app")

	if _, err := VerifyInputAssertion(repo, a); err != nil {
		t.Fatalf("expected a matching locals attribute to pass, got %v", err)
	}
}

func TestVerifyInputAssertionHCLValueWildcardOverObjectMatch(t *testing.T) {
	repo := inputAssertionTestRepository(map[string]string{
		"module/main.tf": `
projects = {
  app-one = {
    root_application = "app-one-apps"
  }
  app-two = {
    root_application = "app-two-apps"
  }
}
`,
	})
	a := baseInputAssertion("hcl_value", "module/main.tf")
	a.Attribute = "projects"
	a.Selector = "*.root_application"
	a.Expected = mustInputAssertionJSON(t, map[string]string{"app-one": "app-one-apps", "app-two": "app-two-apps"})

	if _, err := VerifyInputAssertion(repo, a); err != nil {
		t.Fatalf("expected a matching wildcard selection to pass, got %v", err)
	}
}

func TestVerifyInputAssertionHCLValueWildcardOverListMatch(t *testing.T) {
	repo := inputAssertionTestRepository(map[string]string{
		"module/main.tf": `
entries = [
  { name = "one" },
  { name = "two" },
]
`,
	})
	a := baseInputAssertion("hcl_value", "module/main.tf")
	a.Attribute = "entries"
	a.Selector = "*.name"
	a.Expected = mustInputAssertionJSON(t, []string{"one", "two"})

	if _, err := VerifyInputAssertion(repo, a); err != nil {
		t.Fatalf("expected a matching wildcard-over-list selection to pass, got %v", err)
	}
}

func TestVerifyInputAssertionHCLValueFinalMissingKeyMatchesNull(t *testing.T) {
	repo := inputAssertionTestRepository(map[string]string{
		"module/main.tf": `
clusters = {
  cluster-a = {
    argocd = {
      identity_id = "11111111-1111-1111-1111-111111111111"
    }
  }
}
`,
	})
	a := baseInputAssertion("hcl_value", "module/main.tf")
	a.Attribute = "clusters"
	a.Selector = "cluster-a.argocd.target_revision"
	a.Expected = mustInputAssertionJSON(t, nil)

	if _, err := VerifyInputAssertion(repo, a); err != nil {
		t.Fatalf("expected an absent final key to match null expected, got %v", err)
	}
}

func TestVerifyInputAssertionHCLValueNonFinalMissingKeyErrors(t *testing.T) {
	repo := inputAssertionTestRepository(map[string]string{
		"module/main.tf": `
clusters = {
  cluster-a = {
    identity_id = "11111111-1111-1111-1111-111111111111"
  }
}
`,
	})
	a := baseInputAssertion("hcl_value", "module/main.tf")
	a.Attribute = "clusters"
	a.Selector = "cluster-a.argocd.target_revision"
	a.Expected = mustInputAssertionJSON(t, nil)

	if _, err := VerifyInputAssertion(repo, a); err == nil {
		t.Fatalf("expected a non-final missing key to fail, not resolve to null")
	}
}

func TestVerifyInputAssertionHCLValueKeysOnlyMatch(t *testing.T) {
	repo := inputAssertionTestRepository(map[string]string{
		"module/main.tf": `
registry = {
  rules = {
    rule-one = { upstream = "example.com" }
    rule-two = { upstream = "example.org" }
  }
}
`,
	})
	a := baseInputAssertion("hcl_value", "module/main.tf")
	a.Attribute = "registry"
	a.Selector = "rules"
	a.KeysOnly = true
	a.Expected = mustInputAssertionJSON(t, []string{"rule-one", "rule-two"})

	if _, err := VerifyInputAssertion(repo, a); err != nil {
		t.Fatalf("expected a matching keys_only selection to pass, got %v", err)
	}
}

func TestVerifyInputAssertionDataValueKeysOnlyAndFieldsMatch(t *testing.T) {
	repo := inputAssertionTestRepository(map[string]string{
		"config/example.yaml": `
services:
  svc-a:
    owner: team-a
    tier: 1
  svc-b:
    owner: team-b
    tier: 2
`,
	})
	keysOnly := baseInputAssertion("data_value", "config/example.yaml")
	keysOnly.Selector = "services"
	keysOnly.KeysOnly = true
	keysOnly.Expected = mustInputAssertionJSON(t, []string{"svc-a", "svc-b"})
	if _, err := VerifyInputAssertion(repo, keysOnly); err != nil {
		t.Fatalf("expected a matching data_value keys_only selection to pass, got %v", err)
	}

	fields := baseInputAssertion("data_value", "config/example.yaml")
	fields.Selector = "services.svc-a"
	fields.Fields = []string{"owner", "missing_field"}
	fields.Expected = mustInputAssertionJSON(t, map[string]any{"owner": "team-a", "missing_field": nil})
	if _, err := VerifyInputAssertion(repo, fields); err != nil {
		t.Fatalf("expected a matching data_value fields projection to pass, got %v", err)
	}
}

func TestVerifyInputAssertionDataValueFieldsOverListProjectsEachElement(t *testing.T) {
	repo := inputAssertionTestRepository(map[string]string{
		"config/example.yaml": `
services:
  - name: svc-a
    owner: team-a
  - name: svc-b
`,
	})
	a := baseInputAssertion("data_value", "config/example.yaml")
	a.Selector = "services"
	a.Fields = []string{"name", "owner"}
	a.Expected = mustInputAssertionJSON(t, []map[string]any{
		{"name": "svc-a", "owner": "team-a"},
		{"name": "svc-b", "owner": nil},
	})

	if _, err := VerifyInputAssertion(repo, a); err != nil {
		t.Fatalf("expected a matching fields-over-list projection to pass, got %v", err)
	}
}

func TestVerifyInputAssertionDataValueMismatch(t *testing.T) {
	repo := inputAssertionTestRepository(map[string]string{
		"config/example.yaml": "owner: team-a\n",
	})
	a := baseInputAssertion("data_value", "config/example.yaml")
	a.Expected = mustInputAssertionJSON(t, map[string]string{"owner": "team-b"})

	if _, err := VerifyInputAssertion(repo, a); err == nil {
		t.Fatalf("expected a mismatched data_value to fail")
	}
}

func TestVerifyInputAssertionDirectoryEntriesMatchWithPattern(t *testing.T) {
	repo := inputAssertionTestRepository(map[string]string{
		"modules/app/main.tf":       "x = 1\n",
		"modules/app/variables.tf":  "y = 1\n",
		"modules/app/README.md":     "readme\n",
		"modules/app/sub/nested.tf": "z = 1\n",
	})
	a := baseInputAssertion("directory_entries", "modules/app")
	a.Pattern = "*.tf"
	a.Expected = mustInputAssertionJSON(t, []string{"main.tf", "variables.tf"})

	if _, err := VerifyInputAssertion(repo, a); err != nil {
		t.Fatalf("expected a matching filtered directory listing to pass, got %v", err)
	}
}

func TestVerifyInputAssertionDirectoryEntriesDistinguishesFilesAndDirectories(t *testing.T) {
	repo := inputAssertionTestRepository(map[string]string{
		"modules/app/main.tf":       "x = 1\n",
		"modules/app/sub/nested.tf": "z = 1\n",
	})
	a := baseInputAssertion("directory_entries", "modules/app")
	a.Expected = mustInputAssertionJSON(t, []string{"main.tf", "sub/"})

	if _, err := VerifyInputAssertion(repo, a); err != nil {
		t.Fatalf("expected file/directory distinction to pass, got %v", err)
	}
}

func TestVerifyInputAssertionDirectoryEntriesRootPath(t *testing.T) {
	repo := inputAssertionTestRepository(map[string]string{
		"top.txt":        "x\n",
		"modules/app.tf": "y\n",
	})
	a := baseInputAssertion("directory_entries", "")
	a.Expected = mustInputAssertionJSON(t, []string{"top.txt", "modules/"})

	if _, err := VerifyInputAssertion(repo, a); err != nil {
		t.Fatalf("expected a root-path directory listing to pass, got %v", err)
	}
}

func TestVerifyInputAssertionDirectoryEntriesIndeterminateOnBudgetGap(t *testing.T) {
	repo := inputAssertionTestRepository(
		map[string]string{"modules/app/main.tf": "x = 1\n"},
		Gap{Code: "repository.budget_exceeded", Scope: "modules", Message: "skipped files exceeding budget"},
	)
	a := baseInputAssertion("directory_entries", "modules/app")
	a.Expected = mustInputAssertionJSON(t, []string{"main.tf"})

	if _, err := VerifyInputAssertion(repo, a); err == nil {
		t.Fatalf("expected a budget_exceeded gap on the asserted path's top-level scope to make the listing indeterminate")
	}
}

func TestValidateInputAssertionAcceptsWellFormedAssertions(t *testing.T) {
	cases := []InputAssertion{
		func() InputAssertion {
			a := baseInputAssertion("file_digest", "a/b.tf")
			a.Digest = "0000000000000000000000000000000000000000000000000000000000000000"
			return a
		}(),
		func() InputAssertion {
			a := baseInputAssertion("directory_entries", "")
			a.Expected = mustInputAssertionJSON(t, []string{"a", "b/"})
			return a
		}(),
		func() InputAssertion {
			a := baseInputAssertion("hcl_value", "a/b.tf")
			a.Attribute = "x"
			a.Expected = mustInputAssertionJSON(t, "y")
			return a
		}(),
		func() InputAssertion {
			a := baseInputAssertion("data_value", "a/b.yaml")
			a.Expected = mustInputAssertionJSON(t, "y")
			return a
		}(),
	}
	for i, a := range cases {
		if err := ValidateInputAssertion(a); err != nil {
			t.Fatalf("case %d: expected a well-formed assertion to validate, got %v", i, err)
		}
	}
}

func TestValidateInputAssertionRejectsMalformedAssertions(t *testing.T) {
	cases := map[string]InputAssertion{
		"unknown kind": baseInputAssertion("unknown_kind", "a/b.tf"),
		"bad digest": func() InputAssertion {
			a := baseInputAssertion("file_digest", "a/b.tf")
			a.Digest = "not-hex"
			return a
		}(),
		"non-empty root": func() InputAssertion {
			a := baseInputAssertion("hcl_value", "a/b.tf")
			a.Source.Root = "subdir"
			a.Attribute = "x"
			a.Expected = mustInputAssertionJSON(t, "y")
			return a
		}(),
		"dotdot path": func() InputAssertion {
			a := baseInputAssertion("hcl_value", "../a/b.tf")
			a.Attribute = "x"
			a.Expected = mustInputAssertionJSON(t, "y")
			return a
		}(),
		"keys_only and fields together": func() InputAssertion {
			a := baseInputAssertion("data_value", "a/b.yaml")
			a.KeysOnly = true
			a.Fields = []string{"x"}
			a.Expected = mustInputAssertionJSON(t, "y")
			return a
		}(),
		"directory_entries expected not array of strings": func() InputAssertion {
			a := baseInputAssertion("directory_entries", "a")
			a.Expected = mustInputAssertionJSON(t, map[string]string{"x": "y"})
			return a
		}(),
		"missing attribute for hcl_value": func() InputAssertion {
			a := baseInputAssertion("hcl_value", "a/b.tf")
			a.Expected = mustInputAssertionJSON(t, "y")
			return a
		}(),
		"empty path for non-directory kind": baseInputAssertion("hcl_value", ""),
	}
	for name, a := range cases {
		if err := ValidateInputAssertion(a); err == nil {
			t.Fatalf("%s: expected a malformed assertion to fail validation", name)
		}
	}
}
