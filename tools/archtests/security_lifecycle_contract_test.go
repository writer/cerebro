package archtests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecurityLifecycleContractPreservesAuthorityBoundary(t *testing.T) {
	root := repoRoot(t)
	protoBody, err := os.ReadFile(filepath.Join(root, "proto", "cerebro", "v1", "security_lifecycle.proto"))
	if err != nil {
		t.Fatalf("read security lifecycle proto: %v", err)
	}
	protoText := string(protoBody)
	for _, required := range []string{
		"ResourceRef subject_ref",
		"string provider",
		"string authority_id",
		"string stable_locator",
		"SecurityLifecycleActionRoute",
		"SecurityLifecycleVerificationBinding",
		"SecurityLifecycleQuery",
	} {
		if !strings.Contains(protoText, required) {
			t.Fatalf("security lifecycle proto missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"secret_value",
		"private_key",
		"provider_command",
		"mutation_payload",
		"polling_schedule",
	} {
		if strings.Contains(strings.ToLower(protoText), forbidden) {
			t.Fatalf("security lifecycle proto contains mutation or secret field %q", forbidden)
		}
	}
}

func TestSecurityLifecycleProjectorPolicyAndReadAreWired(t *testing.T) {
	root := repoRoot(t)
	for path, markers := range map[string][]string{
		filepath.Join(root, "crates", "security-lifecycle", "src", "lib.rs"): {
			"pub fn decode_protobuf_observation(",
			"pub fn project_observation(",
			"pub fn canonical_resource_urn(",
			"pub fn evaluate(",
			"pub fn bind_verification(",
			"fresh && source_complete && !source_truncated && compliant",
			`"verified_closed"`,
			"pub fn query_records(",
		},
		filepath.Join(root, "crates", "cerebro-platform", "src", "main.rs"): {
			`"/v1/security/lifecycle"`,
			"project_security_lifecycle",
			"query_records(&tenant_id",
		},
		filepath.Join(root, "crates", "source-runtime-next", "src", "append_log.rs"): {
			"CREDENTIAL_EVENT_KIND",
			"CREDENTIAL_SCHEMA_REF",
			"raw_payload",
		},
		filepath.Join(root, "docs", "domains", "security-lifecycle-contract.md"): {
			"Dispatch acceptance or provider-reported action success does not close the finding.",
			"stable locator in the URN",
			"There is no Go lifecycle",
		},
	} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, marker := range markers {
			if !strings.Contains(string(body), marker) {
				t.Fatalf("%s missing architecture marker %q", path, marker)
			}
		}
	}
}
