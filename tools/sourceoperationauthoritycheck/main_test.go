package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
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

func TestSelectorOutcomeContractChecksCatalogAndDefaultOutcomes(t *testing.T) {
	families := []catalogFamily{
		{Key: familyKey{Mode: "pull", SourceID: "pull_source", FamilyID: "alpha"}},
		{Key: familyKey{Mode: "pull", SourceID: "pull_source", FamilyID: "beta"}},
		{Key: familyKey{Mode: "push", SourceID: "push_source", FamilyID: "delivery"}},
	}
	policy := selectorPolicy{
		DefaultKernel: goCompatibilityKernel,
		RustKernelRules: []selectorRule{{
			SourceID: "pull_source", Families: []string{"alpha"}, DefaultFamily: "alpha",
			UnknownFamilyPolicy: unknownFamilyGoPolicy,
		}},
	}
	selector := func(sourceID, familyID string) (string, bool) {
		if sourceID != "pull_source" {
			return "", false
		}
		if familyID == "" {
			familyID = "alpha"
		}
		return familyID, familyID == "alpha"
	}
	if err := validateSelectorOutcomes("test", policy, selector, families); err != nil {
		t.Fatal(err)
	}
}

func TestSelectorOutcomeContractDetectsNormalizationDrift(t *testing.T) {
	families := []catalogFamily{{Key: familyKey{Mode: "pull", SourceID: "pull_source", FamilyID: "alpha"}}}
	policy := selectorPolicy{
		DefaultKernel: goCompatibilityKernel,
		RustKernelRules: []selectorRule{{
			SourceID: "pull_source", AllCatalogFamilies: true,
			UnknownFamilyPolicy: unknownFamilyRustPolicy,
		}},
	}
	selector := func(sourceID, familyID string) (string, bool) {
		if sourceID == "pull_source" {
			return "wrong", true
		}
		return "", false
	}
	err := validateSelectorOutcomes("test", policy, selector, families)
	if err == nil || !strings.Contains(err.Error(), "selector normalization drift") {
		t.Fatalf("check error = %v, want normalization drift", err)
	}
}

func TestSelectorOutcomeContractChecksUnknownFamilyPolicy(t *testing.T) {
	families := []catalogFamily{{Key: familyKey{Mode: "pull", SourceID: "pull_source", FamilyID: "alpha"}}}
	policy := selectorPolicy{
		DefaultKernel: goCompatibilityKernel,
		RustKernelRules: []selectorRule{{
			SourceID: "pull_source", AllCatalogFamilies: true,
			UnknownFamilyPolicy: unknownFamilyRustPolicy,
		}},
	}
	selector := func(sourceID, familyID string) (string, bool) {
		if sourceID != "pull_source" || familyID == "" || familyID == unknownFamilySentinel {
			return familyID, false
		}
		return familyID, true
	}
	err := validateSelectorOutcomes("test", policy, selector, families)
	if err == nil || !strings.Contains(err.Error(), "family=\""+unknownFamilySentinel+"\"") || !strings.Contains(err.Error(), "compiled selector selects go_compatibility") {
		t.Fatalf("check error = %v, want unknown-family policy drift", err)
	}
}

func TestSelectorOutcomeContractKeepsRustKernelInsideGoAuthorityBoundary(t *testing.T) {
	families := []catalogFamily{{Key: familyKey{Mode: "pull", SourceID: "pull_source", FamilyID: "alpha"}}}
	policy := selectorPolicy{
		DefaultKernel: goCompatibilityKernel,
		RustKernelRules: []selectorRule{{
			SourceID: "pull_source", Families: []string{"alpha"},
			UnknownFamilyPolicy: unknownFamilyGoPolicy,
		}},
	}
	ledger := authorityLedger{
		Defaults: map[string]authorityDefinition{"pull": pullAuthority()},
	}
	pull := ledger.Defaults["pull"]
	pull.Operations.Append = "organizational_projection"
	ledger.Defaults["pull"] = pull

	err := validateSelectorAuthority("durable_pull", policy, ledger, families)
	if err == nil || !strings.Contains(err.Error(), "crosses the declared Go authority boundary") || !strings.Contains(err.Error(), "operations.append") {
		t.Fatalf("check error = %v, want selector/owner boundary drift", err)
	}
}

func TestAuthorityLedgerDetectsProductionSelectorCallsiteDrift(t *testing.T) {
	root, ledger := fixtureRepository(t)
	writeFile(t, root, "internal/extra/route.go", `
package extra

import "github.com/writer/cerebro/internal/sourceruntime/sourceworker"

func route(sourceID, familyID string) bool {
	_, selected := sourceworker.RustAuthoritativeFamily(sourceID, familyID)
	return selected
}
`)
	writeLedger(t, root, ledger)

	_, err := checkRepository(root)
	if err == nil || !strings.Contains(err.Error(), "production Go selector callsite drift") || !strings.Contains(err.Error(), "internal/extra/route.go#route") {
		t.Fatalf("check error = %v, want actionable callsite drift", err)
	}
}

func TestAuthorityLedgerDetectsEveryBoundDeclarationDriftUntilExplicitRefresh(t *testing.T) {
	roles := make([]string, 0, len(requiredRuntimeBindings))
	for role := range requiredRuntimeBindings {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	for _, role := range roles {
		t.Run(role, func(t *testing.T) {
			root, ledger := fixtureRepository(t)
			requirement := requiredRuntimeBindings[role]
			insertBoundDeclarationStatement(t, root, requirement, "_ = \"reviewed implementation drift\"")
			writeLedger(t, root, ledger)

			_, err := checkRepository(root)
			if err == nil || !strings.Contains(err.Error(), "runtime implementation drift for "+role) || !strings.Contains(err.Error(), "refresh this binding only when it is deliberate") {
				t.Fatalf("check error = %v, want actionable binding drift for %s", err, role)
			}

			refreshRuntimeBinding(t, root, &ledger, role)
			writeLedger(t, root, ledger)
			if _, err := checkRepository(root); err != nil {
				t.Fatalf("check after explicit binding refresh: %v", err)
			}
		})
	}
}

func TestAuthorityLedgerRejectsRetainedUnusedRoutingHelpersAfterBindingRefresh(t *testing.T) {
	tests := []struct {
		callerRole string
		helperRole string
	}{
		{callerRole: "durable_put_entrypoint", helperRole: "durable_runtime_creation"},
		{callerRole: "durable_put_runtimes_entrypoint", helperRole: "durable_runtime_creation"},
		{callerRole: "durable_sync_entrypoint", helperRole: "durable_pull_dispatch"},
		{callerRole: "durable_sync_with_lease_entrypoint", helperRole: "durable_lease_fence_binding"},
		{callerRole: "preview_check_entrypoint", helperRole: "preview_dispatch_adapter"},
		{callerRole: "preview_discover_entrypoint", helperRole: "preview_discovery_dispatch"},
		{callerRole: "preview_read_entrypoint", helperRole: "preview_dispatch_adapter"},
	}
	for _, test := range tests {
		t.Run(test.callerRole, func(t *testing.T) {
			root, ledger := fixtureRepository(t)
			helper := requiredRuntimeBindings[test.helperRole]
			before, err := canonicalGoDeclarationContextDigest(root, helper.Path, helper.Symbol)
			if err != nil {
				t.Fatal(err)
			}

			replaceBoundDeclarationBody(t, root, requiredRuntimeBindings[test.callerRole], `{
	return sourceID == "manual" && familyID == "route"
}`)
			refreshRuntimeBinding(t, root, &ledger, test.callerRole)
			writeLedger(t, root, ledger)

			after, err := canonicalGoDeclarationContextDigest(root, helper.Path, helper.Symbol)
			if err != nil {
				t.Fatal(err)
			}
			if after != before {
				t.Fatalf("retained helper %s changed digest: got %s, want %s", test.helperRole, after, before)
			}
			_, err = checkRepository(root)
			if err == nil || !strings.Contains(err.Error(), "bound runtime call edge "+test.callerRole) {
				t.Fatalf("check error = %v, want retained-helper manual-route rejection for %s", err, test.callerRole)
			}
		})
	}
}

func TestAuthorityLedgerRejectsTaggedTransitiveFenceHelpers(t *testing.T) {
	root, ledger := fixtureRepository(t)
	writeFile(t, root, "internal/sourceruntime/fence_linux.go", `
//go:build linux

package sourceruntime

func sourceRuntimeLeaseFenceFromContext() bool { return true }
`)
	writeFile(t, root, "internal/sourceruntime/fence_darwin.go", `
//go:build darwin

package sourceruntime

func sourceRuntimeLeaseFenceFromContext() bool { return false }
`)
	writeLedger(t, root, ledger)

	_, err := checkRepository(root)
	if err == nil ||
		!strings.Contains(err.Error(), "sourceRuntimeLeaseFenceFromContext must be declared exactly once across all release build contexts") ||
		!strings.Contains(err.Error(), "fence_linux.go") ||
		!strings.Contains(err.Error(), "fence_darwin.go") {
		t.Fatalf("check error = %v, want tagged transitive fence-helper rejection", err)
	}
}

func TestRuntimeBindingEdgeMatchesExactPackageAndReceiver(t *testing.T) {
	tests := []struct {
		name   string
		source string
		caller runtimeBindingRequirement
		callee runtimeBindingRequirement
		want   bool
	}{
		{
			name: "exact imported package alias",
			source: `package sourceops
import worker "github.com/writer/cerebro/internal/sourceruntime/sourceworker"
func route() { worker.PullFromExecutionOutput() }
`,
			caller: runtimeBindingRequirement{Path: "internal/sourceops/source_execution.go", Symbol: "route"},
			callee: runtimeBindingRequirement{Path: "internal/sourceruntime/sourceworker/pull.go", Symbol: "PullFromExecutionOutput"},
			want:   true,
		},
		{
			name: "unrelated imported package",
			source: `package sourceops
import worker "example.com/sourceworker"
func route() { worker.PullFromExecutionOutput() }
`,
			caller: runtimeBindingRequirement{Path: "internal/sourceops/source_execution.go", Symbol: "route"},
			callee: runtimeBindingRequirement{Path: "internal/sourceruntime/sourceworker/pull.go", Symbol: "PullFromExecutionOutput"},
			want:   false,
		},
		{
			name: "caller receiver",
			source: `package sourceruntime
type Service struct{}
func (s *Service) Sync() {}
func (s *Service) SyncWithLease() { s.Sync() }
`,
			caller: runtimeBindingRequirement{Path: "internal/sourceruntime/lease.go", Symbol: "Service.SyncWithLease"},
			callee: runtimeBindingRequirement{Path: "internal/sourceruntime/service.go", Symbol: "Service.Sync"},
			want:   true,
		},
		{
			name: "unrelated receiver",
			source: `package sourceruntime
type Service struct{}
func (s *Service) Sync() {}
func (s *Service) SyncWithLease() { other := &Service{}; other.Sync() }
`,
			caller: runtimeBindingRequirement{Path: "internal/sourceruntime/lease.go", Symbol: "Service.SyncWithLease"},
			callee: runtimeBindingRequirement{Path: "internal/sourceruntime/service.go", Symbol: "Service.Sync"},
			want:   false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fileSet := token.NewFileSet()
			parsed, err := parser.ParseFile(fileSet, "binding.go", test.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			var declaration *ast.FuncDecl
			for _, candidate := range parsed.Decls {
				function, ok := candidate.(*ast.FuncDecl)
				if ok && goDeclarationSymbol(function) == test.caller.Symbol {
					declaration = function
					break
				}
			}
			if declaration == nil {
				t.Fatalf("caller %s is missing", test.caller.Symbol)
			}
			matched := false
			ast.Inspect(declaration.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if ok && goCallMatchesRuntimeBinding(parsed, declaration, test.caller, test.callee, call.Fun) {
					matched = true
				}
				return true
			})
			if matched != test.want {
				t.Fatalf("edge match = %v, want %v", matched, test.want)
			}
		})
	}
}

func TestContextualBindingIncludesImportContextButIgnoresFormattingAndImportOrder(t *testing.T) {
	root := t.TempDir()
	const relPath = "internal/example/selector.go"
	writeFile(t, root, relPath, `
package example

import (
	"fmt"
	text "strings"
)

func Select(value string) string {
	return fmt.Sprint(text.TrimSpace(value))
}
`)
	want, err := canonicalGoDeclarationContextDigest(root, relPath, "Select")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, relPath, `
package example

import (
	text "strings"
	"fmt"
)

// Select deliberately changes only comments and formatting.
func Select(
	value string,
) string {
	return fmt.Sprint(text.TrimSpace(value))
}
`)
	got, err := canonicalGoDeclarationContextDigest(root, relPath, "Select")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("contextual digest = %s, want %s after formatting-only change", got, want)
	}

	writeFile(t, root, relPath, `
package example

import (
	"fmt"
	text "bytes"
)

func Select(value string) string {
	return fmt.Sprint(text.TrimSpace(value))
}
`)
	changed, err := canonicalGoDeclarationContextDigest(root, relPath, "Select")
	if err != nil {
		t.Fatal(err)
	}
	if changed == want {
		t.Fatal("contextual digest ignored an import-path change")
	}
}

func TestContextualBindingRejectsBuildConstrainedOrDuplicateDeclarations(t *testing.T) {
	t.Run("build constrained bound file", func(t *testing.T) {
		root := t.TempDir()
		const relPath = "internal/example/selector.go"
		writeFile(t, root, relPath, `
//go:build darwin

package example

func Select() bool { return true }
`)
		_, err := canonicalGoDeclarationContextDigest(root, relPath, "Select")
		if err == nil || !strings.Contains(err.Error(), "must not use Go build constraints") || !strings.Contains(err.Error(), "release build contexts") {
			t.Fatalf("binding error = %v, want build-context rejection", err)
		}
	})

	t.Run("duplicate across build contexts", func(t *testing.T) {
		root := t.TempDir()
		const relPath = "internal/example/selector.go"
		writeFile(t, root, relPath, `
package example

func Select() bool { return true }
`)
		writeFile(t, root, "internal/example/selector_darwin.go", `
//go:build darwin

package example

func Select() bool { return false }
`)
		_, err := canonicalGoDeclarationContextDigest(root, relPath, "Select")
		if err == nil || !strings.Contains(err.Error(), "declared exactly once across all release build contexts") || !strings.Contains(err.Error(), "selector_darwin.go") {
			t.Fatalf("binding error = %v, want duplicate declaration rejection", err)
		}
	})
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
	writeFile(t, root, "internal/sourceruntime/sourceworker/pull.go", `
package sourceworker

func RustAuthoritativeFamily(sourceID, familyID string) (string, bool) {
	if sourceID == "tailscale" {
		return TailscaleFamily(sourceID, familyID)
	}
	return "", false
}

func TailscaleFamily(sourceID, familyID string) (string, bool) {
	return "", false
}

func PreviewRustFamily(sourceID, familyID string) (string, bool) {
	return RustAuthoritativeFamily(sourceID, familyID)
}

func PullFromExecutionOutput(sourceID, familyID string) bool {
	_, selected := RustAuthoritativeFamily(sourceID, familyID)
	return selected
}
`)
	writeFile(t, root, "internal/sourceruntime/source_execution.go", `
package sourceruntime

import "github.com/writer/cerebro/internal/sourceruntime/sourceworker"

type Service struct{}

func (s *Service) validateRustSourceRuntimePlan(sourceID, familyID string) bool {
	_, selected := sourceworker.RustAuthoritativeFamily(sourceID, familyID)
	return selected
}

func sourceExecutionHostCredential() bool {
	return true
}

func (s *Service) readSourcePull(sourceID, familyID string) bool {
	_, selected := sourceworker.RustAuthoritativeFamily(sourceID, familyID)
	if !selected {
		return readCompatibilitySourcePull()
	}
	if !sourceRuntimeLeaseFenceFromContext() || !sourceExecutionHostCredential() {
		return false
	}
	return sourceworker.PullFromExecutionOutput(sourceID, familyID)
}
`)
	writeFile(t, root, "internal/sourceruntime/service.go", `
package sourceruntime

import "github.com/writer/cerebro/internal/sourceruntime/sourceworker"

func (s *Service) Put(sourceID, familyID string) bool {
	return s.preparePutRuntime(sourceID, familyID)
}

func (s *Service) PutRuntimes(sourceID, familyID string) bool {
	return s.preparePutRuntime(sourceID, familyID)
}

func (s *Service) preparePutRuntime(sourceID, familyID string) bool {
	_, selected := sourceworker.RustAuthoritativeFamily(sourceID, familyID)
	return selected && s.validateRustSourceRuntimePlan(sourceID, familyID)
}

func (s *Service) Sync(sourceID, familyID string) bool {
	return sourceRuntimeLeaseFenceFromContext() && s.readSourcePull(sourceID, familyID)
}

func readCompatibilitySourcePull() bool {
	return true
}
`)
	writeFile(t, root, "internal/sourceruntime/lease.go", `
package sourceruntime

func sourceRuntimeLeaseFenceFromContext() bool {
	return true
}

func WithCurrentSourceRuntimeLeaseFence() bool {
	return true
}

func (s *Service) SyncWithLease(sourceID, familyID string) bool {
	_ = WithCurrentSourceRuntimeLeaseFence()
	return s.Sync(sourceID, familyID)
}
`)
	writeFile(t, root, "internal/sourceops/source_execution.go", `
package sourceops

import "github.com/writer/cerebro/internal/sourceruntime/sourceworker"

type Service struct{}

func rustSourceFamily(sourceID string, config map[string]string) (string, bool) {
	return sourceworker.PreviewRustFamily(sourceID, config["family"])
}

func (s *Service) executeRustSource(sourceID, familyID string) bool {
	return s.previewSourceExecutionCredential() && sourceworker.PullFromExecutionOutput(sourceID, familyID)
}

func (s *Service) discoverRustSource(sourceID, familyID string) bool {
	return s.executeRustSource(sourceID, familyID)
}

func (s *Service) previewSourceExecutionCredential() bool {
	return true
}
`)
	writeFile(t, root, "internal/sourceops/service.go", `
package sourceops

func (s *Service) Check(sourceID, familyID string) bool {
	familyID, selected := rustSourceFamily(sourceID, map[string]string{"family": familyID})
	return selected && s.executeRustSource(sourceID, familyID)
}

func (s *Service) Discover(sourceID, familyID string) bool {
	familyID, selected := rustSourceFamily(sourceID, map[string]string{"family": familyID})
	return selected && s.discoverRustSource(sourceID, familyID)
}

func (s *Service) Read(sourceID, familyID string) bool {
	familyID, selected := rustSourceFamily(sourceID, map[string]string{"family": familyID})
	return selected && s.executeRustSource(sourceID, familyID)
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
		SchemaVersion: ledgerSchemaV3,
		Revision:      1,
		Inventory:     inventoryForFamilies(families),
		RuntimeImplementation: runtimeImplementation{
			Contract:         selectorOutcomeContract,
			Canonicalization: goDeclarationContextV2,
			Bindings:         fixtureRuntimeBindings(t, root),
			DurablePull: selectorPolicy{
				DefaultKernel: goCompatibilityKernel,
			},
			Preview: selectorPolicy{
				DefaultKernel: goCompatibilityKernel,
			},
		},
		Defaults: map[string]authorityDefinition{
			"pull": pullAuthority(),
			"push": pushAuthority(),
		},
	}
	return root, ledger
}

func fixtureRuntimeBindings(t *testing.T, root string) []goDeclarationBinding {
	t.Helper()
	roles := make([]string, 0, len(requiredRuntimeBindings))
	for role := range requiredRuntimeBindings {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	bindings := make([]goDeclarationBinding, 0, len(roles))
	for _, role := range roles {
		requirement := requiredRuntimeBindings[role]
		digest, err := canonicalGoDeclarationContextDigest(root, requirement.Path, requirement.Symbol)
		if err != nil {
			t.Fatal(err)
		}
		bindings = append(bindings, goDeclarationBinding{
			Role: role, Path: requirement.Path, Symbol: requirement.Symbol, DigestSHA256: digest,
		})
	}
	return bindings
}

func refreshRuntimeBinding(t *testing.T, root string, ledger *authorityLedger, role string) {
	t.Helper()
	for index := range ledger.RuntimeImplementation.Bindings {
		binding := &ledger.RuntimeImplementation.Bindings[index]
		if binding.Role != role {
			continue
		}
		digest, err := canonicalGoDeclarationContextDigest(root, binding.Path, binding.Symbol)
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

func insertBoundDeclarationStatement(t *testing.T, root string, requirement runtimeBindingRequirement, statement string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(requirement.Path))
	payload, err := os.ReadFile(path) // #nosec G304 -- test helper reads an explicit fixture path.
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, path, payload, 0)
	if err != nil {
		t.Fatal(err)
	}
	var matched *ast.FuncDecl
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && goDeclarationSymbol(function) == requirement.Symbol {
			matched = function
			break
		}
	}
	if matched == nil || matched.Body == nil {
		t.Fatalf("fixture declaration %s#%s is missing", requirement.Path, requirement.Symbol)
	}
	offset := fileSet.Position(matched.Body.Lbrace).Offset + 1
	mutated := make([]byte, 0, len(payload)+len(statement)+2)
	mutated = append(mutated, payload[:offset]...)
	mutated = append(mutated, '\n', '\t')
	mutated = append(mutated, statement...)
	mutated = append(mutated, payload[offset:]...)
	if err := os.WriteFile(path, mutated, 0o600); err != nil {
		t.Fatal(err)
	}
}

func replaceBoundDeclarationBody(t *testing.T, root string, requirement runtimeBindingRequirement, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(requirement.Path))
	payload, err := os.ReadFile(path) // #nosec G304 -- test helper reads an explicit fixture path.
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, path, payload, 0)
	if err != nil {
		t.Fatal(err)
	}
	var matched *ast.FuncDecl
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && goDeclarationSymbol(function) == requirement.Symbol {
			matched = function
			break
		}
	}
	if matched == nil || matched.Body == nil {
		t.Fatalf("fixture declaration %s#%s is missing", requirement.Path, requirement.Symbol)
	}
	start := fileSet.Position(matched.Body.Lbrace).Offset
	end := fileSet.Position(matched.Body.Rbrace).Offset + 1
	mutated := make([]byte, 0, len(payload)+len(body)-(end-start))
	mutated = append(mutated, payload[:start]...)
	mutated = append(mutated, body...)
	mutated = append(mutated, payload[end:]...)
	if err := os.WriteFile(path, mutated, 0o600); err != nil {
		t.Fatal(err)
	}
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
