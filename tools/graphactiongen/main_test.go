package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateGraphActionRegistry(t *testing.T) {
	root := t.TempDir()
	writeCatalog(t, root, `version: graph-actions.cerebro/v1alpha1
actions:
  - id: identity.okta.suspend_user
    const_name: ActionIdentityOktaSuspendUser
    provider: access-approvals
    provider_const: ProviderAccessApprovals
    provider_action: suspend
    provider_action_const: AccessApprovalsActionSuspend
    target_kind: identity.okta.user
    target_kind_const: TargetKindOktaUser
    target_resolver: OktaUserTargetForFinding
    eligibility_checker: FindingAllowsAction
    effect: deny_access
    destructive: true
    reversible_by: identity.okta.unsuspend_user
  - id: identity.okta.unsuspend_user
    const_name: ActionIdentityOktaUnsuspendUser
    provider: access-approvals
    provider_const: ProviderAccessApprovals
    provider_action: unsuspend
    provider_action_const: AccessApprovalsActionUnsuspend
    target_kind: identity.okta.user
    target_kind_const: TargetKindOktaUser
    target_resolver: OktaUserTargetForFinding
    eligibility_checker: FindingAllowsAction
    effect: restore_access
    destructive: false
    reversible_by: identity.okta.suspend_user
`)
	content, err := generate(root, defaultCatalogPath)
	if err != nil {
		t.Fatalf("generate() error = %v", err)
	}
	text := string(content)
	for _, want := range []string{
		"ActionIdentityOktaSuspendUser",
		"\"identity.okta.suspend_user\"",
		"TargetKindOktaUser = \"identity.okta.user\"",
		"ProviderAction:   AccessApprovalsActionSuspend",
		"ResolveTarget:    OktaUserTargetForFinding",
		"CheckEligibility: FindingAllowsAction",
		"ReversibleBy:     \"identity.okta.unsuspend_user\"",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("generated registry missing %q:\n%s", want, text)
		}
	}
}

func TestValidateCatalogRejectsUnknownReversibleAction(t *testing.T) {
	err := validateCatalog(actionCatalog{
		Version: "graph-actions.cerebro/v1alpha1",
		Actions: []actionCatalogEntry{{
			ID:                  "identity.okta.suspend_user",
			ConstName:           "ActionIdentityOktaSuspendUser",
			Provider:            "access-approvals",
			ProviderConst:       "ProviderAccessApprovals",
			ProviderAction:      "suspend",
			ProviderActionConst: "AccessApprovalsActionSuspend",
			TargetKind:          "identity.okta.user",
			TargetKindConst:     "TargetKindOktaUser",
			TargetResolver:      "OktaUserTargetForFinding",
			EligibilityChecker:  "FindingAllowsAction",
			Effect:              "deny_access",
			Destructive:         true,
			ReversibleBy:        "identity.okta.unsuspend_user",
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown action") {
		t.Fatalf("validateCatalog() error = %v, want unknown reversible action", err)
	}
}

func TestGenerateIsStableWithCheckedInCatalog(t *testing.T) {
	content, err := generate(filepath.Clean("../.."), defaultCatalogPath)
	if err != nil {
		t.Fatalf("generate() checked-in catalog error = %v", err)
	}
	existing, err := os.ReadFile(filepath.Join("..", "..", defaultOutputPath))
	if err != nil {
		t.Fatalf("read generated registry: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(existing), bytes.TrimSpace(content)) {
		t.Fatalf("checked-in registry is stale; run make graph-action-generate")
	}
}

func writeCatalog(t *testing.T, root string, content string) {
	t.Helper()
	path := filepath.Join(root, defaultCatalogPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir catalog dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write catalog: %v", err)
	}
}
