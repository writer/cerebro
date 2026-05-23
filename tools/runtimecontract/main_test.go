package main

import (
	"path/filepath"
	"testing"
)

func TestBuildContractIncludesSourceFamiliesSecretsAndRoleAssumptions(t *testing.T) {
	contract, err := buildContract(filepath.Join("..", ".."), runtimeMetadata{
		Repository: "writer/cerebro",
		Image:      "ghcr.io/writer/cerebro",
		Tag:        "v2.1.59",
		Digest:     "sha256:0123456789abcdef",
		Commit:     "abcdef",
	}, "2026-05-23T00:00:00Z")
	if err != nil {
		t.Fatalf("buildContract() error = %v", err)
	}
	if contract.SchemaVersion != schemaVersion {
		t.Fatalf("SchemaVersion = %q, want %q", contract.SchemaVersion, schemaVersion)
	}
	if contract.ContractID == "" {
		t.Fatal("ContractID is empty")
	}
	if contract.Runtime.Tag != "v2.1.59" || contract.Runtime.Digest != "sha256:0123456789abcdef" {
		t.Fatalf("unexpected runtime metadata: %+v", contract.Runtime)
	}

	aws := sourceByID(t, contract.Sources, "aws")
	assertContains(t, aws.SourceFamilies, "public_endpoint")
	assertContains(t, aws.SourceFamilies, "effective_permission")
	if len(aws.RoleAssumptions) != 1 || aws.RoleAssumptions[0].ConfigKey != "role_arn" {
		t.Fatalf("aws role assumptions = %+v, want role_arn", aws.RoleAssumptions)
	}

	okta := sourceByID(t, contract.Sources, "okta")
	assertContains(t, okta.RequiredSecrets, "OKTA_API_TOKEN")
	assertContains(t, okta.RequiredSecrets, "OKTA_DOMAIN")
	if len(okta.RuntimeTemplates) == 0 {
		t.Fatal("okta runtime templates are empty")
	}
	if okta.RuntimeTemplates[0].Config["token"] != "env:OKTA_API_TOKEN" {
		t.Fatalf("okta token template = %q, want env ref", okta.RuntimeTemplates[0].Config["token"])
	}

	cosmo := sourceByID(t, contract.Sources, "cosmo")
	assertContains(t, cosmo.SourceFamilies, "survey_feedback")
}

func sourceByID(t *testing.T, sources []sourceContract, id string) sourceContract {
	t.Helper()
	for _, source := range sources {
		if source.ID == id {
			return source
		}
	}
	t.Fatalf("source %q not found", id)
	return sourceContract{}
}

func assertContains(t *testing.T, values []string, want string) {
	t.Helper()
	for _, value := range values {
		if value == want {
			return
		}
	}
	t.Fatalf("%v does not contain %q", values, want)
}
