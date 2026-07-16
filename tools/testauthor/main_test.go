package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/writer/cerebro/internal/findingdsl"
	policyauthor "github.com/writer/cerebro/internal/testauthor/policy"
	"gopkg.in/yaml.v3"
)

func TestWriteNewRefusesOverwrite(t *testing.T) {
	root := t.TempDir()
	if err := writeNew(root, "policies/aws/example.yaml", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := writeNew(root, "policies/aws/example.yaml", []byte("second")); err == nil {
		t.Fatal("writeNew() overwrite error = nil")
	}
	content, err := os.ReadFile(filepath.Join(root, "policies/aws/example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, []byte("first")) {
		t.Fatalf("content = %q", content)
	}
}

func TestWriteNewRefusesSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "policies", "aws"), 0o750); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target.yaml")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../target.yaml", filepath.Join(root, "policies", "aws", "example.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := writeNew(root, "policies/aws/example.yaml", []byte("replacement")); err == nil {
		t.Fatal("writeNew() symlink error = nil")
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, []byte("target")) {
		t.Fatalf("target content = %q", content)
	}
}

func TestFindGapsClassifiesSupportedPolicies(t *testing.T) {
	root := t.TempDir()
	intent := policyauthor.Intent{ID: "public-bucket", Domain: "aws", Name: "Public bucket", Description: "Flags public buckets.", Severity: "high", Conditions: []string{`cmp_eq(path(resource, "public"), true)`}, Frameworks: []findingdsl.PolicyFramework{{Name: "CIS", Controls: []string{"1"}}}}
	artifacts, err := policyauthor.Author(intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeNew(root, artifacts.PolicyPath, artifacts.PolicyYAML); err != nil {
		t.Fatal(err)
	}
	gaps, err := findGaps(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 1 || !gaps[0].Supported || gaps[0].Test != artifacts.TestPath {
		t.Fatalf("gaps = %#v", gaps)
	}
	if err := writeNew(root, artifacts.TestPath, artifacts.TestYAML); err != nil {
		t.Fatal(err)
	}
	gaps, err = findGaps(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 0 {
		t.Fatalf("gaps after test write = %#v", gaps)
	}
}

func TestIntentYAMLUsesKnownFields(t *testing.T) {
	content, err := yaml.Marshal(policyauthor.Intent{ID: "example"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(content, []byte("id: example")) {
		t.Fatalf("intent YAML = %s", content)
	}
}
