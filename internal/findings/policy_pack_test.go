package findings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuiltinWithPolicyOverridesUsesVerifiedPolicyValues(t *testing.T) {
	path := filepath.Join("..", "..", "contentpacks", "pilot", "policy-ai-controls", "content", "policy.yaml")
	payload, err := os.ReadFile(path) // #nosec G304 -- test reads a checked-in pilot fixture.
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	payload = []byte(strings.Replace(string(payload), "name: AI Agent Tool Allowlist Required", "name: AI Agent Approved Tool List Required", 1))
	registry, err := BuiltinWithPolicyOverrides(map[string][]byte{pilotPolicyRuleID: payload})
	if err != nil {
		t.Fatalf("BuiltinWithPolicyOverrides() error = %v", err)
	}
	rule, ok := registry.Get(pilotPolicyRuleID)
	if !ok {
		t.Fatalf("Get(%s) = false", pilotPolicyRuleID)
	}
	if rule.Spec().Name != "AI Agent Approved Tool List Required" {
		t.Fatalf("policy Spec().Name = %q", rule.Spec().Name)
	}
	if got := rule.(*policyCatalogRule).config.Conditions; len(got) != 1 || got[0] != `cmp_ne(path(resource, "agent_tool_allowlist_required"), true)` {
		t.Fatalf("policy conditions = %v", got)
	}
	if builtin, _ := Builtin().Get(pilotPolicyRuleID); builtin.Spec().Name != "AI Agent Tool Allowlist Required" {
		t.Fatalf("Builtin() policy name changed to %q", builtin.Spec().Name)
	}
}

func TestBuiltinWithPolicyOverridesRejectsInvalidPolicy(t *testing.T) {
	if _, err := BuiltinWithPolicyOverrides(map[string][]byte{pilotPolicyRuleID: []byte("kind: other\n")}); err == nil {
		t.Fatal("BuiltinWithPolicyOverrides() error = nil")
	}
}
