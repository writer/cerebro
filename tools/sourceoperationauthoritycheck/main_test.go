package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestRepositoryAuthorityLedgerMatchesCatalogInventory(t *testing.T) {
	summary, err := checkRepository(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if summary.Inventory.FamilyCount == 0 || summary.Inventory.FamilyCount != summary.Inventory.PullFamilyCount+summary.Inventory.PushFamilyCount {
		t.Fatalf("invalid inventory summary = %#v", summary.Inventory)
	}
	if summary.Inventory.PushFamilyCount == 0 {
		t.Fatal("push family inventory is empty")
	}
	if summary.States["shadow_disabled"] != 1 {
		t.Fatalf("shadow_disabled states = %d, want 1", summary.States["shadow_disabled"])
	}
}

func TestRepositoryAuthorityLedgerMatchesJSONSchema(t *testing.T) {
	root := repositoryRoot(t)
	var schemaDocument any
	decodeJSONFile(t, filepath.Join(root, "docs/engineering/source-operation-authority-ledger.schema.json"), &schemaDocument)
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("source-operation-authority-ledger.schema.json", schemaDocument); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile("source-operation-authority-ledger.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var ledgerDocument any
	decodeJSONFile(t, filepath.Join(root, ledgerRelPath), &ledgerDocument)
	if err := compiled.Validate(ledgerDocument); err != nil {
		t.Fatalf("authority ledger does not match its schema: %v", err)
	}
}

func TestAuthorityLedgerDetectsCatalogInventoryDrift(t *testing.T) {
	root, ledger := fixtureRepository(t)
	writeLedger(t, root, ledger)
	writeFile(t, root, "sources/pull_source/catalog.yaml", pullCatalog("alpha", "beta"))

	_, err := checkRepository(root)
	if err == nil || !strings.Contains(err.Error(), "catalog inventory drift") || !strings.Contains(err.Error(), "review the new authority surface") {
		t.Fatalf("check error = %v, want actionable inventory drift", err)
	}
}

func TestAuthorityLedgerDetectsRuntimeImplementationDriftUntilBindingIsRefreshed(t *testing.T) {
	tests := []struct {
		name    string
		role    string
		content string
	}{
		{
			name: "durable dispatch",
			role: "durable_pull_dispatch",
			content: `
package sourceruntime

type Service struct{}

func (s *Service) readSourcePull() bool {
	return false
}
`,
		},
		{
			name: "primary selector",
			role: "rust_authoritative_selector",
			content: `
package sourceworker

func RustAuthoritativeFamily(sourceID, familyID string) (string, bool) {
	return familyID, sourceID == "pull_source" || sourceID == "new_source"
}


func TailscaleFamily(sourceID, familyID string) (string, bool) {
	return familyID, sourceID == "tailscale"
}
`,
		},
		{
			name: "transitive selector",
			role: "tailscale_authoritative_selector",
			content: `
package sourceworker

func RustAuthoritativeFamily(sourceID, familyID string) (string, bool) {
	return familyID, sourceID == "pull_source"
}

func TailscaleFamily(sourceID, familyID string) (string, bool) {
	return familyID, sourceID == "tailscale" || sourceID == "new_tailscale_alias"
}
`,
		},
		{
			name: "preview selector",
			role: "preview_rust_selector",
			content: `
package sourceops

func rustSourceFamily(sourceID string, config map[string]string) (string, bool) {
	return config["family"], sourceID == "pull_source" || sourceID == "new_preview_source"
}
`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, ledger := fixtureRepository(t)
			writeLedger(t, root, ledger)
			writeFile(t, root, requiredRuntimeBindings[test.role].Path, test.content)

			_, err := checkRepository(root)
			if err == nil || !strings.Contains(err.Error(), "runtime implementation drift for "+test.role) || !strings.Contains(err.Error(), "refresh the ledger binding") {
				t.Fatalf("check error = %v, want actionable runtime implementation drift", err)
			}

			refreshRuntimeBinding(t, root, &ledger, test.role)
			writeLedger(t, root, ledger)
			if _, err := checkRepository(root); err != nil {
				t.Fatalf("check after deliberate binding refresh: %v", err)
			}
		})
	}
}

func TestAuthorityLedgerRejectsRuntimeBindingSubstitution(t *testing.T) {
	root, ledger := fixtureRepository(t)
	ledger.RuntimeImplementation.Bindings[0].Path = "internal/sourceruntime/sourceworker/pull.go"
	ledger.RuntimeImplementation.Bindings[0].Symbol = "RustAuthoritativeFamily"
	writeLedger(t, root, ledger)

	_, err := checkRepository(root)
	if err == nil || !strings.Contains(err.Error(), "must bind internal/sourceruntime/source_execution.go#Service.readSourcePull") {
		t.Fatalf("check error = %v, want required runtime-binding rejection", err)
	}
}

func TestRuntimeBindingCanonicalizationIgnoresCommentsAndFormatting(t *testing.T) {
	root := t.TempDir()
	const path = "internal/example/selector.go"
	writeFile(t, root, path, `
package example

func Select(value string) bool { return value == "active" }
`)
	want, err := canonicalGoDeclarationDigest(root, path, "Select")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, path, `
package example

// Select is deliberately formatted differently without changing behavior.
func Select(
	value string,
) bool {
	return value == "active"
}
`)
	got, err := canonicalGoDeclarationDigest(root, path, "Select")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("canonical digest = %s, want %s for comment and formatting-only change", got, want)
	}
}

func TestAuthorityLedgerRejectsNetworkEnabledRustCandidate(t *testing.T) {
	root, ledger := fixtureRepository(t)
	override := rustCandidateOverride()
	override.CandidateKernel.NetworkAllowed = true
	ledger.Overrides = []authorityOverride{override}
	writeLedger(t, root, ledger)

	_, err := checkRepository(root)
	if err == nil || !strings.Contains(err.Error(), "must be credential-free and network-disabled") {
		t.Fatalf("check error = %v, want credential and network boundary rejection", err)
	}
}

func TestAuthorityLedgerRejectsCandidateContractDrift(t *testing.T) {
	root, ledger := fixtureRepository(t)
	override := rustCandidateOverride()
	override.CandidateKernel.SchemaRef = "pull_source/alpha/v2"
	ledger.Overrides = []authorityOverride{override}
	writeLedger(t, root, ledger)

	_, err := checkRepository(root)
	if err == nil || !strings.Contains(err.Error(), "does not match catalog contract") {
		t.Fatalf("check error = %v, want catalog contract rejection", err)
	}
}

func TestAuthorityLedgerRejectsUnknownOverride(t *testing.T) {
	root, ledger := fixtureRepository(t)
	override := rustCandidateOverride()
	override.FamilyID = "unknown"
	ledger.Overrides = []authorityOverride{override}
	writeLedger(t, root, ledger)

	_, err := checkRepository(root)
	if err == nil || !strings.Contains(err.Error(), "references unknown catalog family") {
		t.Fatalf("check error = %v, want unknown family rejection", err)
	}
}

func TestAuthorityLedgerRejectsPullPushOperationConflict(t *testing.T) {
	root, ledger := fixtureRepository(t)
	pull := ledger.Defaults["pull"]
	pull.Operations.PushAdmit = "go_source_push_admission"
	ledger.Defaults["pull"] = pull
	writeLedger(t, root, ledger)

	_, err := checkRepository(root)
	if err == nil || !strings.Contains(err.Error(), "push_admit must be not_applicable for pull families") {
		t.Fatalf("check error = %v, want pull/push authority conflict", err)
	}
}

func TestAuthorityLedgerRejectsUnknownAuthorityOwner(t *testing.T) {
	root, ledger := fixtureRepository(t)
	pull := ledger.Defaults["pull"]
	pull.Operations.Append = "go_and_rust"
	ledger.Defaults["pull"] = pull
	writeLedger(t, root, ledger)

	_, err := checkRepository(root)
	if err == nil || !strings.Contains(err.Error(), "names unknown authority owner") {
		t.Fatalf("check error = %v, want unknown owner rejection", err)
	}
}

func TestAuthorityLedgerExcludesCatalogOnlyImports(t *testing.T) {
	root, ledger := fixtureRepository(t)
	writeFile(t, root, "sources/catalog_only/catalog.yaml", `
id: catalog_only
name: Catalog only
description: Does not construct a source runtime.
emitted_kinds: [catalog_only.record]
event_contracts:
  - kind: catalog_only.record
    schema_ref: catalog_only/record/v1
    required_payload_fields: [id]
`)
	writeLedger(t, root, ledger)

	summary, err := checkRepository(root)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Inventory.FamilyCount != 2 {
		t.Fatalf("family count = %d, want one pull and one push runtime family", summary.Inventory.FamilyCount)
	}
}

func fixtureRepository(t *testing.T) (string, authorityLedger) {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, requiredRuntimeBindings["rust_authoritative_selector"].Path, `
package sourceworker

func RustAuthoritativeFamily(sourceID, familyID string) (string, bool) {
	return familyID, sourceID == "pull_source"
}

func TailscaleFamily(sourceID, familyID string) (string, bool) {
	return familyID, sourceID == "tailscale"
}
`)
	writeFile(t, root, requiredRuntimeBindings["durable_pull_dispatch"].Path, `
package sourceruntime

type Service struct{}

func (s *Service) readSourcePull() bool {
	return true
}
`)
	writeFile(t, root, requiredRuntimeBindings["preview_rust_selector"].Path, `
package sourceops

func rustSourceFamily(sourceID string, config map[string]string) (string, bool) {
	return config["family"], sourceID == "pull_source"
}
`)
	writeFile(t, root, "sources/pull_source/catalog.yaml", pullCatalog("alpha"))
	writeFile(t, root, "sources/push_source/catalog.yaml", `
id: push_source
name: Push source
description: Test push source.
collection_mode: push
emitted_kinds: [push_source.delivery]
event_contracts:
  - kind: push_source.delivery
    schema_ref: push_source/delivery/v1
    required_payload_fields: [id]
`)
	writeFile(t, root, "crates/source-runtime/src/alpha.rs", `
pub struct AlphaAdapter;
const PLAN_ID: &str = "source-plan-v1:pull_source:alpha";
const KIND: &str = "pull_source.alpha";
`)
	families, err := loadCatalogFamilies(root)
	if err != nil {
		t.Fatal(err)
	}
	ledger := authorityLedger{
		SchemaVersion: ledgerSchemaV2,
		Revision:      1,
		Inventory:     inventoryForFamilies(families),
		RuntimeImplementation: runtimeImplementation{
			Canonicalization: goASTDeclarationCanonicalization,
			Bindings: []goDeclarationBinding{
				fixtureRuntimeBinding(t, root, "durable_pull_dispatch"),
				fixtureRuntimeBinding(t, root, "preview_rust_selector"),
				fixtureRuntimeBinding(t, root, "rust_authoritative_selector"),
				fixtureRuntimeBinding(t, root, "tailscale_authoritative_selector"),
			},
		},
		Defaults: map[string]authorityDefinition{
			"pull": pullAuthority(),
			"push": pushAuthority(),
		},
	}
	return root, ledger
}

func fixtureRuntimeBinding(t *testing.T, root, role string) goDeclarationBinding {
	t.Helper()
	requirement, ok := requiredRuntimeBindings[role]
	if !ok {
		t.Fatalf("unknown runtime binding role %q", role)
	}
	digest, err := canonicalGoDeclarationDigest(root, requirement.Path, requirement.Symbol)
	if err != nil {
		t.Fatal(err)
	}
	return goDeclarationBinding{Role: role, Path: requirement.Path, Symbol: requirement.Symbol, DigestSHA256: digest}
}

func refreshRuntimeBinding(t *testing.T, root string, ledger *authorityLedger, role string) {
	t.Helper()
	for index := range ledger.RuntimeImplementation.Bindings {
		if ledger.RuntimeImplementation.Bindings[index].Role != role {
			continue
		}
		binding := &ledger.RuntimeImplementation.Bindings[index]
		digest, err := canonicalGoDeclarationDigest(root, binding.Path, binding.Symbol)
		if err != nil {
			t.Fatal(err)
		}
		binding.DigestSHA256 = digest
		return
	}
	t.Fatalf("runtime binding role %q is missing", role)
}

func pullCatalog(families ...string) string {
	var body strings.Builder
	body.WriteString(`
id: pull_source
name: Pull source
description: Test pull source.
emitted_kinds:
`)
	for _, family := range families {
		body.WriteString("  - pull_source." + family + "\n")
	}
	body.WriteString("runtime_families:\n")
	for _, family := range families {
		body.WriteString("  - " + family + "\n")
	}
	body.WriteString("event_contracts:\n")
	for _, family := range families {
		body.WriteString("  - kind: pull_source." + family + "\n")
		body.WriteString("    schema_ref: pull_source/" + family + "/v1\n")
		body.WriteString("    required_payload_fields: [id]\n")
	}
	return body.String()
}

func pullAuthority() authorityDefinition {
	return authorityDefinition{
		State:           "compatibility",
		CredentialOwner: "go_trusted_runtime_host",
		NetworkOwner:    "go_trusted_runtime_host",
		Operations: operationAuthority{
			Check: "go_source_runtime", Discover: "go_source_runtime", ReadPage: "go_source_runtime",
			PushAdmit: "not_applicable", Append: "go_source_runtime", Project: "go_source_runtime",
			CheckpointCommit: "go_source_runtime_store", ProductRead: "organizational_projection",
		},
	}
}

func pushAuthority() authorityDefinition {
	return authorityDefinition{
		State:           "compatibility",
		CredentialOwner: "authenticated_push_admission",
		NetworkOwner:    "authenticated_push_transport",
		Operations: operationAuthority{
			Check: "not_applicable", Discover: "not_applicable", ReadPage: "not_applicable",
			PushAdmit: "go_source_push_admission", Append: "go_source_runtime", Project: "go_source_runtime",
			CheckpointCommit: "not_applicable", ProductRead: "organizational_projection",
		},
	}
}

func rustCandidateOverride() authorityOverride {
	definition := pullAuthority()
	definition.State = "shadow_disabled"
	definition.CandidateKernel = &candidateKernel{
		Runtime: "credential_free_rust_worker", CredentialFree: true, NetworkAllowed: false,
		PlanID: "source-plan-v1:pull_source:alpha", ProviderKernel: "pull_source.alpha",
		EventKind: "pull_source.alpha", SchemaRef: "pull_source/alpha/v1",
		Evidence: []implementationProof{{
			Path: "crates/source-runtime/src/alpha.rs",
			RequiredMarkers: []string{
				"AlphaAdapter", "source-plan-v1:pull_source:alpha", "pull_source.alpha",
			},
		}},
	}
	return authorityOverride{Mode: "pull", SourceID: "pull_source", FamilyID: "alpha", authorityDefinition: definition}
}

func writeLedger(t *testing.T, root string, ledger authorityLedger) {
	t.Helper()
	payload, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, ledgerRelPath, string(payload)+"\n")
}

func writeFile(t *testing.T, root, relPath, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.TrimLeft(content, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
}

func decodeJSONFile(t *testing.T, path string, destination any) {
	t.Helper()
	payload, err := os.ReadFile(path) // #nosec G304 -- test helper reads explicit repository fixture paths.
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, destination); err != nil {
		t.Fatal(err)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root not found")
		}
		dir = parent
	}
}
