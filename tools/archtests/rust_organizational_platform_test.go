package archtests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRustOrganizationalPlatformBoundary(t *testing.T) {
	root := repoRoot(t)
	manifest := readText(t, filepath.Join(root, "Cargo.toml"))
	for _, member := range []string{
		"crates/organizational-model",
		"crates/organizational-store",
		"crates/source-catalog",
		"crates/organizational-graph",
		"crates/source-runtime-next",
		"crates/agent-context",
		"crates/cerebro-platform",
	} {
		if !strings.Contains(manifest, `"`+member+`"`) {
			t.Errorf("root Cargo workspace missing %q", member)
		}
	}

	modelSource := readText(t, filepath.Join(root, "crates/organizational-model/src/lib.rs"))
	if strings.Contains(modelSource, "use serde::Deserialize") ||
		strings.Contains(modelSource, "derive(Deserialize") {
		t.Error("validated organizational-model types must not implement or import Deserialize")
	}
	for _, required := range []string{
		"pub struct CanonicalIdentity",
		"pub struct ProviderIdentity",
		"pub struct IdentityBindingAssertion",
		"pub struct IdentityClaim",
		"GraphDeltaBuilder<Authoritative>",
		"IdentityResolutionMethod::ExistingClaimMatch",
		`EntityId::parse(format!("person:canonical:{id}"))`,
	} {
		if !strings.Contains(modelSource, required) {
			t.Errorf("organizational model missing enforced construct %q", required)
		}
	}

	for _, directory := range []string{
		"crates/organizational-model",
		"crates/organizational-graph",
		"crates/organizational-store",
		"crates/source-catalog",
		"crates/source-runtime-next",
		"crates/agent-context",
		"crates/cerebro-platform",
	} {
		err := filepath.WalkDir(filepath.Join(root, directory), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || filepath.Ext(path) != ".rs" {
				return nil
			}
			source := readText(t, path)
			for _, forbidden := range []string{
				"cerebrov1",
				"EventEnvelope",
				"ProjectedEntity",
				"ProjectedLink",
				"internal/sourceprojection",
			} {
				if strings.Contains(source, forbidden) {
					t.Errorf("%s depends on forbidden Go compatibility contract %q", filepath.ToSlash(path), forbidden)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scan %s: %v", directory, err)
		}
	}

	storeSource := readText(t, filepath.Join(root, "crates/organizational-store/src/postgres.rs"))
	for _, required := range []string{
		"FORCE ROW LEVEL SECURITY",
		"PRIMARY KEY (tenant_id, provider_identity_id)",
		"PRIMARY KEY (tenant_id, claim_kind, claim_value)",
		"organizational_projection_outbox",
		"organizational_parity_receipts",
		"current_setting(''cerebro.tenant_id'', true)",
	} {
		if !strings.Contains(storeSource, required) {
			t.Errorf("organizational store missing enforced boundary %q", required)
		}
	}

	paritySource := readText(t, filepath.Join(root, "crates/organizational-store/src/parity.rs"))
	for _, required := range []string{
		"pub struct SemanticSnapshot",
		"pub struct ParityReceipt",
		"MAX_MISMATCHES_IN_RECEIPT",
		"ScopeMismatch",
	} {
		if !strings.Contains(paritySource, required) {
			t.Errorf("projection parity gate missing enforced boundary %q", required)
		}
	}

	catalogSource := readText(t, filepath.Join(root, "crates/source-catalog/src/lib.rs"))
	for _, required := range []string{
		"CollectionAuthority::Authoritative",
		"provider_api",
		"proof_is_complete",
		"ShadowOnly",
	} {
		if !strings.Contains(catalogSource, required) {
			t.Errorf("source catalog missing authority gate %q", required)
		}
	}

	doc := readText(t, filepath.Join(root, "docs/engineering/rust-organizational-platform.md"))
	for _, rule := range []string{
		"replacement architecture",
		"Only the Rust platform workload receives graph-write credentials",
		"Go deployments become read-only",
	} {
		if !strings.Contains(doc, rule) {
			t.Errorf("Rust organizational platform decision missing rule %q", rule)
		}
	}
}

func readText(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}
