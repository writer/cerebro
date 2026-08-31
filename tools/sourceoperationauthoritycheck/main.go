// Command sourceoperationauthoritycheck verifies that every built-in source
// family has one explicit, drift-bound operation authority decision.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceruntime/sourceworker"
	"gopkg.in/yaml.v3"
)

const (
	ledgerRelPath           = "docs/engineering/source-operation-authority-ledger.json"
	ledgerSchemaV3          = "cerebro.source-operation-authority/v3"
	selectorOutcomeContract = "compiled_go_selector_outcomes/v1"
	goDeclarationContextV2  = "go_ast_declaration_context_sha256/v2"
	goCompatibilityKernel   = "go_compatibility"
	rustWorkerKernel        = "credential_free_rust_worker"
	unknownFamilyGoPolicy   = "go_compatibility"
	unknownFamilyRustPolicy = "rust_fail_closed"
	sourceworkerImportPath  = "github.com/writer/cerebro/internal/sourceruntime/sourceworker"
	durableSelectorName     = "RustAuthoritativeFamily"
	previewSelectorName     = "PreviewRustFamily"
	unknownSourceSentinel   = "__cerebro_authority_unknown_source__"
	unknownFamilySentinel   = "__cerebro_authority_unknown_family__"
)

var requiredRuntimeBindings = map[string]runtimeBindingRequirement{
	"durable_compatibility_read": {
		Path:   "internal/sourceruntime/service.go",
		Symbol: "readCompatibilitySourcePull",
	},
	"durable_credential_resolution": {
		Path:   "internal/sourceruntime/source_execution.go",
		Symbol: "sourceExecutionHostCredential",
	},
	"durable_lease_fence_binding": {
		Path:   "internal/sourceruntime/lease.go",
		Symbol: "WithCurrentSourceRuntimeLeaseFence",
	},
	"durable_lease_fence_read": {
		Path:   "internal/sourceruntime/lease.go",
		Symbol: "sourceRuntimeLeaseFenceFromContext",
	},
	"durable_plan_validation": {
		Path:   "internal/sourceruntime/source_execution.go",
		Symbol: "Service.validateRustSourceRuntimePlan",
	},
	"durable_pull_dispatch": {
		Path:   "internal/sourceruntime/source_execution.go",
		Symbol: "Service.readSourcePull",
	},
	"durable_put_entrypoint": {
		Path:   "internal/sourceruntime/service.go",
		Symbol: "Service.Put",
	},
	"durable_put_runtimes_entrypoint": {
		Path:   "internal/sourceruntime/service.go",
		Symbol: "Service.PutRuntimes",
	},
	"durable_runtime_creation": {
		Path:   "internal/sourceruntime/service.go",
		Symbol: "Service.preparePutRuntime",
	},
	"durable_sync_entrypoint": {
		Path:   "internal/sourceruntime/service.go",
		Symbol: "Service.Sync",
	},
	"durable_sync_with_lease_entrypoint": {
		Path:   "internal/sourceruntime/lease.go",
		Symbol: "Service.SyncWithLease",
	},
	"preview_check_entrypoint": {
		Path:   "internal/sourceops/service.go",
		Symbol: "Service.Check",
	},
	"preview_credential_resolution": {
		Path:   "internal/sourceops/source_execution.go",
		Symbol: "Service.previewSourceExecutionCredential",
	},
	"preview_dispatch_adapter": {
		Path:   "internal/sourceops/source_execution.go",
		Symbol: "rustSourceFamily",
	},
	"preview_discover_entrypoint": {
		Path:   "internal/sourceops/service.go",
		Symbol: "Service.Discover",
	},
	"preview_discovery_dispatch": {
		Path:   "internal/sourceops/source_execution.go",
		Symbol: "Service.discoverRustSource",
	},
	"preview_execution_dispatch": {
		Path:   "internal/sourceops/source_execution.go",
		Symbol: "Service.executeRustSource",
	},
	"preview_read_entrypoint": {
		Path:   "internal/sourceops/service.go",
		Symbol: "Service.Read",
	},
	"preview_rust_selector": {
		Path:   "internal/sourceruntime/sourceworker/pull.go",
		Symbol: previewSelectorName,
	},
	"rust_authoritative_selector": {
		Path:   "internal/sourceruntime/sourceworker/pull.go",
		Symbol: durableSelectorName,
	},
	"rust_output_conversion": {
		Path:   "internal/sourceruntime/sourceworker/pull.go",
		Symbol: "PullFromExecutionOutput",
	},
	"tailscale_authoritative_selector": {
		Path:   "internal/sourceruntime/sourceworker/pull.go",
		Symbol: "TailscaleFamily",
	},
}

var requiredRuntimeBindingEdges = []runtimeBindingEdge{
	{CallerRole: "durable_plan_validation", CalleeRole: "rust_authoritative_selector", Count: 1},
	{CallerRole: "durable_pull_dispatch", CalleeRole: "durable_compatibility_read", Count: 1},
	{CallerRole: "durable_pull_dispatch", CalleeRole: "durable_credential_resolution", Count: 1},
	{CallerRole: "durable_pull_dispatch", CalleeRole: "durable_lease_fence_read", Count: 1},
	{CallerRole: "durable_pull_dispatch", CalleeRole: "rust_authoritative_selector", Count: 1},
	{CallerRole: "durable_pull_dispatch", CalleeRole: "rust_output_conversion", Count: 1},
	{CallerRole: "durable_put_entrypoint", CalleeRole: "durable_runtime_creation", Count: 1},
	{CallerRole: "durable_put_runtimes_entrypoint", CalleeRole: "durable_runtime_creation", Count: 1},
	{CallerRole: "durable_runtime_creation", CalleeRole: "durable_plan_validation", Count: 1},
	{CallerRole: "durable_runtime_creation", CalleeRole: "rust_authoritative_selector", Count: 1},
	{CallerRole: "durable_sync_entrypoint", CalleeRole: "durable_lease_fence_read", Count: 1},
	{CallerRole: "durable_sync_entrypoint", CalleeRole: "durable_pull_dispatch", Count: 1},
	{CallerRole: "durable_sync_with_lease_entrypoint", CalleeRole: "durable_lease_fence_binding", Count: 1},
	{CallerRole: "durable_sync_with_lease_entrypoint", CalleeRole: "durable_sync_entrypoint", Count: 1},
	{CallerRole: "preview_check_entrypoint", CalleeRole: "preview_dispatch_adapter", Count: 1},
	{CallerRole: "preview_check_entrypoint", CalleeRole: "preview_execution_dispatch", Count: 1},
	{CallerRole: "preview_discover_entrypoint", CalleeRole: "preview_discovery_dispatch", Count: 1},
	{CallerRole: "preview_discover_entrypoint", CalleeRole: "preview_dispatch_adapter", Count: 1},
	{CallerRole: "preview_discovery_dispatch", CalleeRole: "preview_execution_dispatch", Count: 1},
	{CallerRole: "preview_dispatch_adapter", CalleeRole: "preview_rust_selector", Count: 1},
	{CallerRole: "preview_execution_dispatch", CalleeRole: "preview_credential_resolution", Count: 1},
	{CallerRole: "preview_execution_dispatch", CalleeRole: "rust_output_conversion", Count: 1},
	{CallerRole: "preview_read_entrypoint", CalleeRole: "preview_dispatch_adapter", Count: 1},
	{CallerRole: "preview_read_entrypoint", CalleeRole: "preview_execution_dispatch", Count: 1},
	{CallerRole: "preview_rust_selector", CalleeRole: "rust_authoritative_selector", Count: 1},
	{CallerRole: "rust_authoritative_selector", CalleeRole: "tailscale_authoritative_selector", Count: 1},
	{CallerRole: "rust_output_conversion", CalleeRole: "rust_authoritative_selector", Count: 1},
}

var requiredSelectorCallsites = map[selectorCallsite]int{
	{Selector: durableSelectorName, Path: "internal/sourceruntime/source_execution.go", Symbol: "Service.validateRustSourceRuntimePlan"}: 1,
	{Selector: durableSelectorName, Path: "internal/sourceruntime/source_execution.go", Symbol: "Service.readSourcePull"}:                1,
	{Selector: durableSelectorName, Path: "internal/sourceruntime/service.go", Symbol: "Service.preparePutRuntime"}:                      1,
	{Selector: durableSelectorName, Path: "internal/sourceruntime/sourceworker/pull.go", Symbol: "PullFromExecutionOutput"}:              1,
	{Selector: durableSelectorName, Path: "internal/sourceruntime/sourceworker/pull.go", Symbol: previewSelectorName}:                    1,
	{Selector: previewSelectorName, Path: "internal/sourceops/source_execution.go", Symbol: "rustSourceFamily"}:                          1,
}

var validStates = map[string]struct{}{
	"authoritative":   {},
	"blocked":         {},
	"compatibility":   {},
	"shadow":          {},
	"shadow_disabled": {},
}

var validOwners = map[string]struct{}{
	"authenticated_push_admission": {},
	"authenticated_push_transport": {},
	"go_source_push_admission":     {},
	"go_source_runtime":            {},
	"go_source_runtime_store":      {},
	"go_trusted_runtime_host":      {},
	"not_applicable":               {},
	"organizational_projection":    {},
}

type inventory struct {
	DigestSHA256    string `json:"digest_sha256"`
	FamilyCount     int    `json:"family_count"`
	PullFamilyCount int    `json:"pull_family_count"`
	PushFamilyCount int    `json:"push_family_count"`
}

type operationAuthority struct {
	Check            string `json:"check"`
	Discover         string `json:"discover"`
	ReadPage         string `json:"read_page"`
	PushAdmit        string `json:"push_admit"`
	Append           string `json:"append"`
	Project          string `json:"project"`
	CheckpointCommit string `json:"checkpoint_commit"`
	ProductRead      string `json:"product_read"`
}

type authorityDefinition struct {
	State           string             `json:"state"`
	CredentialOwner string             `json:"credential_owner"`
	NetworkOwner    string             `json:"network_owner"`
	Operations      operationAuthority `json:"operations"`
	CandidateKernel *candidateKernel   `json:"candidate_kernel,omitempty"`
}

type candidateKernel struct {
	Runtime        string                `json:"runtime"`
	CredentialFree bool                  `json:"credential_free"`
	NetworkAllowed bool                  `json:"network_allowed"`
	PlanID         string                `json:"plan_id"`
	ProviderKernel string                `json:"provider_kernel"`
	EventKind      string                `json:"event_kind"`
	SchemaRef      string                `json:"schema_ref"`
	Evidence       []implementationProof `json:"implementation_evidence"`
}

type implementationProof struct {
	Path            string   `json:"path"`
	RequiredMarkers []string `json:"required_markers"`
}

type authorityOverride struct {
	Mode     string `json:"mode"`
	SourceID string `json:"source_id"`
	FamilyID string `json:"family_id"`
	authorityDefinition
}

type runtimeImplementation struct {
	Contract         string                 `json:"contract"`
	Canonicalization string                 `json:"canonicalization"`
	Bindings         []goDeclarationBinding `json:"bindings"`
	DurablePull      selectorPolicy         `json:"durable_pull"`
	Preview          selectorPolicy         `json:"preview"`
}

type goDeclarationBinding struct {
	Role         string `json:"role"`
	Path         string `json:"path"`
	Symbol       string `json:"symbol"`
	DigestSHA256 string `json:"digest_sha256"`
}

type runtimeBindingRequirement struct {
	Path   string
	Symbol string
}

type runtimeBindingEdge struct {
	CallerRole string
	CalleeRole string
	Count      int
}

type selectorPolicy struct {
	DefaultKernel   string         `json:"default_kernel"`
	RustKernelRules []selectorRule `json:"rust_kernel_rules"`
}

type selectorRule struct {
	SourceID            string   `json:"source_id"`
	AllCatalogFamilies  bool     `json:"all_catalog_families,omitempty"`
	Families            []string `json:"families,omitempty"`
	DefaultFamily       string   `json:"default_family,omitempty"`
	UnknownFamilyPolicy string   `json:"unknown_family_policy"`
}

type selectorFunc func(sourceID, familyID string) (string, bool)

type selectorCallsite struct {
	Selector string
	Path     string
	Symbol   string
}

type authorityLedger struct {
	SchemaVersion         string                         `json:"schema_version"`
	Revision              int                            `json:"revision"`
	Inventory             inventory                      `json:"inventory"`
	RuntimeImplementation runtimeImplementation          `json:"runtime_implementation"`
	Defaults              map[string]authorityDefinition `json:"defaults"`
	Overrides             []authorityOverride            `json:"overrides"`
}

type catalogHeader struct {
	CollectionMode string `yaml:"collection_mode"`
}

type familyKey struct {
	Mode     string
	SourceID string
	FamilyID string
}

type catalogFamily struct {
	Key       familyKey
	Contracts map[string]sourcecdk.EventContract
}

type checkSummary struct {
	Inventory     inventory
	States        map[string]int
	Overrides     int
	SelectorRules int
}

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	summary, err := checkRepository(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "source-operation-authority-check: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf(
		"source-operation-authority-check: %d families (%d pull, %d push), %d overrides, %d selector rules, states=%s, digest=%s\n",
		summary.Inventory.FamilyCount,
		summary.Inventory.PullFamilyCount,
		summary.Inventory.PushFamilyCount,
		summary.Overrides,
		summary.SelectorRules,
		formatStateCounts(summary.States),
		summary.Inventory.DigestSHA256,
	)
}

func checkRepository(root string) (checkSummary, error) {
	root = filepath.Clean(root)
	ledger, err := loadLedger(filepath.Join(root, filepath.FromSlash(ledgerRelPath)))
	if err != nil {
		return checkSummary{}, err
	}
	families, err := loadCatalogFamilies(root)
	if err != nil {
		return checkSummary{}, err
	}
	selectorFamilies, err := loadSelectorFamilies(root, families)
	if err != nil {
		return checkSummary{}, err
	}
	actualInventory := inventoryForFamilies(families)
	if ledger.Inventory != actualInventory {
		return checkSummary{}, fmt.Errorf(
			"catalog inventory drift: ledger has count=%d pull=%d push=%d digest=%s; catalog has count=%d pull=%d push=%d digest=%s; review the new authority surface and update the ledger",
			ledger.Inventory.FamilyCount,
			ledger.Inventory.PullFamilyCount,
			ledger.Inventory.PushFamilyCount,
			ledger.Inventory.DigestSHA256,
			actualInventory.FamilyCount,
			actualInventory.PullFamilyCount,
			actualInventory.PushFamilyCount,
			actualInventory.DigestSHA256,
		)
	}
	if err := validateLedger(root, ledger, families, selectorFamilies); err != nil {
		return checkSummary{}, err
	}
	states := map[string]int{}
	overrides := make(map[familyKey]authorityDefinition, len(ledger.Overrides))
	for _, override := range ledger.Overrides {
		overrides[override.key()] = override.authorityDefinition
	}
	for _, family := range families {
		definition := ledger.Defaults[family.Key.Mode]
		if override, ok := overrides[family.Key]; ok {
			definition = override
		}
		states[definition.State]++
	}
	return checkSummary{
		Inventory:     actualInventory,
		States:        states,
		Overrides:     len(ledger.Overrides),
		SelectorRules: len(ledger.RuntimeImplementation.DurablePull.RustKernelRules) + len(ledger.RuntimeImplementation.Preview.RustKernelRules),
	}, nil
}

func loadLedger(path string) (authorityLedger, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return authorityLedger{}, fmt.Errorf("stat %s: %w", ledgerRelPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return authorityLedger{}, fmt.Errorf("%s must be a regular non-symlink file", ledgerRelPath)
	}
	payload, err := os.ReadFile(path) // #nosec G304 -- fixed repository policy path.
	if err != nil {
		return authorityLedger{}, fmt.Errorf("read %s: %w", ledgerRelPath, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var ledger authorityLedger
	if err := decoder.Decode(&ledger); err != nil {
		return authorityLedger{}, fmt.Errorf("decode %s: %w", ledgerRelPath, err)
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return authorityLedger{}, fmt.Errorf("decode %s: %w", ledgerRelPath, err)
	}
	return ledger, nil
}

func rejectTrailingJSON(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func loadCatalogFamilies(root string) ([]catalogFamily, error) {
	sourcesRoot := filepath.Join(root, "sources")
	entries, err := os.ReadDir(sourcesRoot)
	if err != nil {
		return nil, fmt.Errorf("read sources directory: %w", err)
	}
	families := make([]catalogFamily, 0)
	seen := map[familyKey]string{}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("sources/%s must not be a symlink", entry.Name())
		}
		if !entry.IsDir() || entry.Name() == "catalogruntime" {
			continue
		}
		relPath := filepath.ToSlash(filepath.Join("sources", entry.Name(), "catalog.yaml"))
		path := filepath.Join(sourcesRoot, entry.Name(), "catalog.yaml")
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", relPath, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s must be a regular non-symlink file", relPath)
		}
		payload, err := os.ReadFile(path) // #nosec G304 -- bounded to repository source catalogs.
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", relPath, err)
		}
		var header catalogHeader
		if err := yaml.Unmarshal(payload, &header); err != nil {
			return nil, fmt.Errorf("decode %s collection mode: %w", relPath, err)
		}
		mode := strings.TrimSpace(header.CollectionMode)
		if mode == "" {
			mode = "pull"
		}
		if mode != "pull" && mode != "push" {
			return nil, fmt.Errorf("%s has unsupported collection_mode %q", relPath, mode)
		}
		catalog, err := sourcecdk.LoadSourceCatalog(payload)
		if err != nil {
			return nil, fmt.Errorf("decode %s: %w", relPath, err)
		}
		sourceID := strings.TrimSpace(catalog.Spec.GetId())
		contracts := make(map[string]sourcecdk.EventContract, len(catalog.EventContracts))
		for _, contract := range catalog.EventContracts {
			contracts[contract.Kind] = contract
		}
		familyIDs, err := catalogFamilyIDs(mode, sourceID, catalog)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", relPath, err)
		}
		for _, familyID := range familyIDs {
			key := familyKey{Mode: mode, SourceID: sourceID, FamilyID: familyID}
			if prior, ok := seen[key]; ok {
				return nil, fmt.Errorf("duplicate source family %s in %s and %s", key.String(), prior, relPath)
			}
			seen[key] = relPath
			families = append(families, catalogFamily{Key: key, Contracts: contracts})
		}
	}
	sort.Slice(families, func(i, j int) bool { return families[i].Key.String() < families[j].Key.String() })
	return families, nil
}

func loadSelectorFamilies(root string, runtimeFamilies []catalogFamily) ([]catalogFamily, error) {
	families := append([]catalogFamily(nil), runtimeFamilies...)
	seen := make(map[familyKey]struct{}, len(families))
	for _, family := range families {
		seen[family.Key] = struct{}{}
	}
	sourcesRoot := filepath.Join(root, "sources")
	entries, err := os.ReadDir(sourcesRoot)
	if err != nil {
		return nil, fmt.Errorf("read sources directory for selector catalog: %w", err)
	}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("sources/%s must not be a symlink", entry.Name())
		}
		if !entry.IsDir() || entry.Name() == "catalogruntime" {
			continue
		}
		relPath := filepath.ToSlash(filepath.Join("sources", entry.Name(), "catalog.yaml"))
		path := filepath.Join(sourcesRoot, entry.Name(), "catalog.yaml")
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", relPath, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s must be a regular non-symlink file", relPath)
		}
		payload, err := os.ReadFile(path) // #nosec G304 -- bounded to repository source catalogs.
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", relPath, err)
		}
		var header catalogHeader
		if err := yaml.Unmarshal(payload, &header); err != nil {
			return nil, fmt.Errorf("decode %s collection mode: %w", relPath, err)
		}
		mode := strings.TrimSpace(header.CollectionMode)
		if mode == "" {
			mode = "pull"
		}
		if mode != "pull" {
			continue
		}
		catalog, err := sourcecdk.LoadSourceCatalog(payload)
		if err != nil {
			return nil, fmt.Errorf("decode %s: %w", relPath, err)
		}
		if len(catalog.RuntimeFamilies) > 0 {
			continue
		}
		sourceID := strings.TrimSpace(catalog.Spec.GetId())
		contracts := make(map[string]sourcecdk.EventContract, len(catalog.EventContracts))
		for _, contract := range catalog.EventContracts {
			contracts[contract.Kind] = contract
		}
		for _, contract := range catalog.EventContracts {
			prefix := sourceID + "."
			if !strings.HasPrefix(contract.Kind, prefix) {
				continue
			}
			familyID := strings.TrimPrefix(contract.Kind, prefix)
			if familyID == "" || strings.Contains(familyID, ".") {
				continue
			}
			key := familyKey{Mode: "pull", SourceID: sourceID, FamilyID: familyID}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			families = append(families, catalogFamily{Key: key, Contracts: contracts})
		}
	}
	sort.Slice(families, func(i, j int) bool { return families[i].Key.String() < families[j].Key.String() })
	return families, nil
}

func catalogFamilyIDs(mode, sourceID string, catalog *sourcecdk.SourceCatalog) ([]string, error) {
	if mode == "pull" {
		if len(catalog.RuntimeFamilies) == 0 {
			// Catalog-only imports and internal event producers do not construct a
			// pull runtime. They enter this ledger only when runtime_families is
			// declared or collection_mode is explicitly push.
			return nil, nil
		}
		return append([]string(nil), catalog.RuntimeFamilies...), nil
	}
	if len(catalog.EventContracts) == 0 {
		return nil, fmt.Errorf("push source %q has no event_contracts", sourceID)
	}
	prefix := sourceID + "."
	familyIDs := make([]string, 0, len(catalog.EventContracts))
	for _, contract := range catalog.EventContracts {
		if !strings.HasPrefix(contract.Kind, prefix) {
			return nil, fmt.Errorf("push event kind %q must begin with %q", contract.Kind, prefix)
		}
		familyID := strings.TrimPrefix(contract.Kind, prefix)
		if familyID == "" || strings.Contains(familyID, ".") {
			return nil, fmt.Errorf("push event kind %q must identify exactly one family", contract.Kind)
		}
		familyIDs = append(familyIDs, familyID)
	}
	sort.Strings(familyIDs)
	return familyIDs, nil
}

func inventoryForFamilies(families []catalogFamily) inventory {
	hasher := sha256.New()
	result := inventory{FamilyCount: len(families)}
	for _, family := range families {
		_, _ = io.WriteString(hasher, family.Key.String()+"\n")
		switch family.Key.Mode {
		case "pull":
			result.PullFamilyCount++
		case "push":
			result.PushFamilyCount++
		}
	}
	result.DigestSHA256 = hex.EncodeToString(hasher.Sum(nil))
	return result
}

func validateLedger(root string, ledger authorityLedger, families, selectorFamilies []catalogFamily) error {
	if ledger.SchemaVersion != ledgerSchemaV3 {
		return fmt.Errorf("schema_version must be %q", ledgerSchemaV3)
	}
	if ledger.Revision < 1 {
		return fmt.Errorf("revision must be positive")
	}
	if err := validateRuntimeImplementation(
		root,
		ledger,
		selectorFamilies,
		sourceworker.RustAuthoritativeFamily,
		sourceworker.PreviewRustFamily,
	); err != nil {
		return err
	}
	if len(ledger.Defaults) != 2 {
		return fmt.Errorf("defaults must contain exactly pull and push authority")
	}
	for _, mode := range []string{"pull", "push"} {
		definition, ok := ledger.Defaults[mode]
		if !ok {
			return fmt.Errorf("defaults.%s is required", mode)
		}
		if err := validateDefinition(root, mode, "defaults."+mode, definition, nil); err != nil {
			return err
		}
		if definition.CandidateKernel != nil {
			return fmt.Errorf("defaults.%s must not declare a candidate_kernel", mode)
		}
	}
	familyByKey := make(map[familyKey]catalogFamily, len(families))
	for _, family := range families {
		familyByKey[family.Key] = family
	}
	seenOverrides := map[familyKey]struct{}{}
	for index, override := range ledger.Overrides {
		path := fmt.Sprintf("overrides[%d]", index)
		key := override.key()
		if err := validateFamilyKey(key); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if _, ok := seenOverrides[key]; ok {
			return fmt.Errorf("%s duplicates %s", path, key.String())
		}
		seenOverrides[key] = struct{}{}
		family, ok := familyByKey[key]
		if !ok {
			return fmt.Errorf("%s references unknown catalog family %s", path, key.String())
		}
		if err := validateDefinition(root, key.Mode, path, override.authorityDefinition, &family); err != nil {
			return err
		}
	}
	return nil
}

func validateRuntimeImplementation(root string, ledger authorityLedger, families []catalogFamily, durable, preview selectorFunc) error {
	implementation := ledger.RuntimeImplementation
	if implementation.Contract != selectorOutcomeContract {
		return fmt.Errorf("runtime_implementation.contract must be %q", selectorOutcomeContract)
	}
	if err := validateRuntimeBindings(root, implementation); err != nil {
		return err
	}
	selectors := []struct {
		name     string
		policy   selectorPolicy
		selector selectorFunc
	}{
		{name: "durable_pull", policy: implementation.DurablePull, selector: durable},
		{name: "preview", policy: implementation.Preview, selector: preview},
	}
	for _, selected := range selectors {
		if err := validateSelectorPolicy("runtime_implementation."+selected.name, selected.policy, families); err != nil {
			return err
		}
		if err := validateSelectorOutcomes(selected.name, selected.policy, selected.selector, families); err != nil {
			return err
		}
		if err := validateSelectorAuthority(selected.name, selected.policy, ledger, families); err != nil {
			return err
		}
	}
	return validateSelectorCallsites(root)
}

func validateRuntimeBindings(root string, implementation runtimeImplementation) error {
	if implementation.Canonicalization != goDeclarationContextV2 {
		return fmt.Errorf("runtime_implementation.canonicalization must be %q", goDeclarationContextV2)
	}
	if err := validateRuntimeBindingCoverage(); err != nil {
		return err
	}
	if len(implementation.Bindings) != len(requiredRuntimeBindings) {
		return fmt.Errorf("runtime_implementation.bindings must contain exactly %d required bindings", len(requiredRuntimeBindings))
	}
	seen := make(map[string]struct{}, len(implementation.Bindings))
	priorRole := ""
	for index, binding := range implementation.Bindings {
		path := fmt.Sprintf("runtime_implementation.bindings[%d]", index)
		requirement, ok := requiredRuntimeBindings[binding.Role]
		if !ok {
			return fmt.Errorf("%s.role %q is not a required runtime binding", path, binding.Role)
		}
		if priorRole != "" && binding.Role <= priorRole {
			return fmt.Errorf("%s.role must be unique and sorted after %q", path, priorRole)
		}
		priorRole = binding.Role
		if _, duplicate := seen[binding.Role]; duplicate {
			return fmt.Errorf("%s duplicates role %q", path, binding.Role)
		}
		seen[binding.Role] = struct{}{}
		if binding.Path != requirement.Path || binding.Symbol != requirement.Symbol {
			return fmt.Errorf("%s must bind %s#%s", path, requirement.Path, requirement.Symbol)
		}
		if len(binding.DigestSHA256) != sha256.Size*2 || strings.ToLower(binding.DigestSHA256) != binding.DigestSHA256 {
			return fmt.Errorf("%s.digest_sha256 must be 64 lowercase hexadecimal characters", path)
		}
		if _, err := hex.DecodeString(binding.DigestSHA256); err != nil {
			return fmt.Errorf("%s.digest_sha256 must be 64 lowercase hexadecimal characters", path)
		}
		actualDigest, err := canonicalGoDeclarationContextDigest(root, binding.Path, binding.Symbol)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if binding.DigestSHA256 != actualDigest {
			return fmt.Errorf(
				"runtime implementation drift for %s: ledger has digest=%s; %s#%s has contextual digest=%s; review the selector or routing change and refresh this binding only when it is deliberate",
				binding.Role,
				binding.DigestSHA256,
				binding.Path,
				binding.Symbol,
				actualDigest,
			)
		}
	}
	return validateRuntimeBindingEdges(root)
}

func validateRuntimeBindingCoverage() error {
	boundDeclarations := make(map[string]struct{}, len(requiredRuntimeBindings))
	for _, requirement := range requiredRuntimeBindings {
		boundDeclarations[requirement.Path+"#"+requirement.Symbol] = struct{}{}
	}
	for callsite := range requiredSelectorCallsites {
		key := callsite.Path + "#" + callsite.Symbol
		if _, ok := boundDeclarations[key]; !ok {
			return fmt.Errorf("required selector callsite %s is not protected by a full declaration binding", selectorCallsiteString(callsite))
		}
	}
	for _, edge := range requiredRuntimeBindingEdges {
		if _, ok := requiredRuntimeBindings[edge.CallerRole]; !ok {
			return fmt.Errorf("required runtime binding edge names unbound caller role %q", edge.CallerRole)
		}
		if _, ok := requiredRuntimeBindings[edge.CalleeRole]; !ok {
			return fmt.Errorf("required runtime binding edge names unbound callee role %q", edge.CalleeRole)
		}
		if edge.Count <= 0 {
			return fmt.Errorf("required runtime binding edge %s -> %s must have a positive call count", edge.CallerRole, edge.CalleeRole)
		}
	}
	return nil
}

func validateRuntimeBindingEdges(root string) error {
	for _, edge := range requiredRuntimeBindingEdges {
		caller := requiredRuntimeBindings[edge.CallerRole]
		callee := requiredRuntimeBindings[edge.CalleeRole]
		fullPath := filepath.Join(root, filepath.FromSlash(caller.Path))
		payload, err := os.ReadFile(fullPath) // #nosec G304 -- caller path is fixed by requiredRuntimeBindings.
		if err != nil {
			return fmt.Errorf("read bound caller %s#%s: %w", caller.Path, caller.Symbol, err)
		}
		parsed, declaration, err := parseBoundGoDeclaration(fullPath, caller.Path, payload, caller.Symbol)
		if err != nil {
			return err
		}
		count := 0
		ast.Inspect(declaration.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if ok && goCallMatchesRuntimeBinding(parsed, declaration, caller, callee, call.Fun) {
				count++
			}
			return true
		})
		if count != edge.Count {
			return fmt.Errorf(
				"bound runtime call edge %s (%s#%s) -> %s (%s#%s) must occur exactly %d time(s); found %d",
				edge.CallerRole, caller.Path, caller.Symbol,
				edge.CalleeRole, callee.Path, callee.Symbol,
				edge.Count, count,
			)
		}
	}
	return nil
}

func goDeclarationBaseName(symbol string) string {
	if index := strings.LastIndex(symbol, "."); index >= 0 {
		return symbol[index+1:]
	}
	return symbol
}

func goCallMatchesRuntimeBinding(parsed *ast.File, callerDeclaration *ast.FuncDecl, caller, callee runtimeBindingRequirement, expression ast.Expr) bool {
	calleeName := goDeclarationBaseName(callee.Symbol)
	callerDirectory := filepath.ToSlash(filepath.Dir(caller.Path))
	calleeDirectory := filepath.ToSlash(filepath.Dir(callee.Path))
	if callerDirectory == calleeDirectory {
		if !strings.Contains(callee.Symbol, ".") {
			identifier, ok := expression.(*ast.Ident)
			return ok && identifier.Name == calleeName
		}
		selector, ok := expression.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != calleeName {
			return false
		}
		receiver, ok := selector.X.(*ast.Ident)
		if !ok || callerDeclaration.Recv == nil {
			return false
		}
		for _, field := range callerDeclaration.Recv.List {
			for _, name := range field.Names {
				if name.Name == receiver.Name {
					return true
				}
			}
		}
		return false
	}
	if strings.Contains(callee.Symbol, ".") {
		return false
	}
	calleeImportPath := "github.com/writer/cerebro/" + calleeDirectory
	for _, spec := range parsed.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil || importPath != calleeImportPath {
			continue
		}
		alias := filepath.Base(importPath)
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		if alias == "." {
			identifier, ok := expression.(*ast.Ident)
			return ok && identifier.Name == calleeName
		}
		selector, ok := expression.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != calleeName {
			return false
		}
		qualifier, ok := selector.X.(*ast.Ident)
		return ok && qualifier.Name == alias
	}
	return false
}

func canonicalGoDeclarationContextDigest(root, relPath, symbol string) (string, error) {
	clean := filepath.Clean(relPath)
	if relPath == "" || filepath.IsAbs(relPath) || clean != relPath || clean == "." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path must be a clean repository-relative path")
	}
	if filepath.Ext(clean) != ".go" {
		return "", fmt.Errorf("%s must identify Go source", relPath)
	}
	fullPath := filepath.Join(root, clean)
	info, err := os.Lstat(fullPath)
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", relPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s must be a regular non-symlink file", relPath)
	}
	payload, err := os.ReadFile(fullPath) // #nosec G304 -- repository-relative path is fixed by requiredRuntimeBindings.
	if err != nil {
		return "", fmt.Errorf("read %s: %w", relPath, err)
	}
	if err := rejectGoBuildConstraints(relPath, payload); err != nil {
		return "", err
	}
	parsed, matched, err := parseBoundGoDeclaration(fullPath, relPath, payload, symbol)
	if err != nil {
		return "", err
	}
	if err := requireUniqueGoDeclarationAcrossBuildContexts(root, relPath, symbol); err != nil {
		return "", err
	}

	imports := make([]string, 0, len(parsed.Imports))
	for _, spec := range parsed.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return "", fmt.Errorf("parse import context in %s: %w", relPath, err)
		}
		alias := ""
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		imports = append(imports, alias+"\t"+strconv.Quote(importPath))
	}
	sort.Strings(imports)

	var canonical bytes.Buffer
	_, _ = io.WriteString(&canonical, goDeclarationContextV2+"\n")
	_, _ = io.WriteString(&canonical, "package\t"+parsed.Name.Name+"\n")
	for _, imported := range imports {
		_, _ = io.WriteString(&canonical, "import\t"+imported+"\n")
	}
	_, _ = io.WriteString(&canonical, "declaration\n")
	if err := format.Node(&canonical, token.NewFileSet(), matched); err != nil {
		return "", fmt.Errorf("canonicalize %s#%s: %w", relPath, symbol, err)
	}
	digest := sha256.Sum256(canonical.Bytes())
	return hex.EncodeToString(digest[:]), nil
}

func rejectGoBuildConstraints(relPath string, payload []byte) error {
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if constraint.IsGoBuild(line) || constraint.IsPlusBuild(line) {
			return fmt.Errorf("%s must not use Go build constraints because its authority binding must be identical across release build contexts", relPath)
		}
		if strings.HasPrefix(line, "package ") {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan build constraints in %s: %w", relPath, err)
	}
	return nil
}

func parseBoundGoDeclaration(fullPath, relPath string, payload []byte, symbol string) (*ast.File, *ast.FuncDecl, error) {
	parsed, err := parser.ParseFile(token.NewFileSet(), fullPath, payload, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", relPath, err)
	}
	var matched *ast.FuncDecl
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || goDeclarationSymbol(function) != symbol {
			continue
		}
		if matched != nil {
			return nil, nil, fmt.Errorf("%s declares %s more than once", relPath, symbol)
		}
		matched = function
	}
	if matched == nil {
		return nil, nil, fmt.Errorf("%s does not declare %s", relPath, symbol)
	}
	return parsed, matched, nil
}

func requireUniqueGoDeclarationAcrossBuildContexts(root, relPath, symbol string) error {
	directory := filepath.Dir(filepath.Join(root, filepath.FromSlash(relPath)))
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read declaration directory for %s: %w", relPath, err)
	}
	locations := make([]string, 0, 1)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		candidatePath := filepath.Join(directory, entry.Name())
		candidateRel, err := filepath.Rel(root, candidatePath)
		if err != nil {
			return fmt.Errorf("resolve declaration candidate path: %w", err)
		}
		candidateRel = filepath.ToSlash(candidateRel)
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s must not be a symlink", candidateRel)
		}
		payload, err := os.ReadFile(candidatePath) // #nosec G304 -- candidate is a Go file in a fixed bound declaration directory.
		if err != nil {
			return fmt.Errorf("read %s: %w", candidateRel, err)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), candidatePath, payload, 0)
		if err != nil {
			return fmt.Errorf("parse %s across release build contexts: %w", candidateRel, err)
		}
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if ok && goDeclarationSymbol(function) == symbol {
				locations = append(locations, candidateRel)
			}
		}
	}
	sort.Strings(locations)
	if len(locations) != 1 || locations[0] != filepath.ToSlash(relPath) {
		return fmt.Errorf("%s must be declared exactly once across all release build contexts at %s; found %v", symbol, filepath.ToSlash(relPath), locations)
	}
	return nil
}

func validateSelectorPolicy(path string, policy selectorPolicy, families []catalogFamily) error {
	if policy.DefaultKernel != goCompatibilityKernel {
		return fmt.Errorf("%s.default_kernel must be %q", path, goCompatibilityKernel)
	}
	pullFamilies := make(map[string]map[string]struct{})
	for _, family := range families {
		if family.Key.Mode != "pull" {
			continue
		}
		if pullFamilies[family.Key.SourceID] == nil {
			pullFamilies[family.Key.SourceID] = map[string]struct{}{}
		}
		pullFamilies[family.Key.SourceID][family.Key.FamilyID] = struct{}{}
	}
	seenSources := make(map[string]struct{}, len(policy.RustKernelRules))
	priorSource := ""
	for index, rule := range policy.RustKernelRules {
		rulePath := fmt.Sprintf("%s.rust_kernel_rules[%d]", path, index)
		if strings.TrimSpace(rule.SourceID) == "" || strings.TrimSpace(rule.SourceID) != rule.SourceID || containsControl(rule.SourceID) {
			return fmt.Errorf("%s.source_id must be non-empty, trimmed, and printable", rulePath)
		}
		if priorSource != "" && rule.SourceID <= priorSource {
			return fmt.Errorf("%s.source_id must be unique and sorted after %q", rulePath, priorSource)
		}
		priorSource = rule.SourceID
		if _, duplicate := seenSources[rule.SourceID]; duplicate {
			return fmt.Errorf("%s duplicates source_id %q", rulePath, rule.SourceID)
		}
		seenSources[rule.SourceID] = struct{}{}
		catalogFamilies, ok := pullFamilies[rule.SourceID]
		if !ok {
			return fmt.Errorf("%s references unknown pull source %q", rulePath, rule.SourceID)
		}
		if rule.AllCatalogFamilies == (len(rule.Families) > 0) {
			return fmt.Errorf("%s must select exactly one of all_catalog_families or families", rulePath)
		}
		priorFamily := ""
		for familyIndex, familyID := range rule.Families {
			familyPath := fmt.Sprintf("%s.families[%d]", rulePath, familyIndex)
			if strings.TrimSpace(familyID) == "" || strings.TrimSpace(familyID) != familyID || containsControl(familyID) {
				return fmt.Errorf("%s must be non-empty, trimmed, and printable", familyPath)
			}
			if priorFamily != "" && familyID <= priorFamily {
				return fmt.Errorf("%s must be unique and sorted after %q", familyPath, priorFamily)
			}
			priorFamily = familyID
			if _, ok := catalogFamilies[familyID]; !ok {
				return fmt.Errorf("%s references unknown catalog family pull\t%s\t%s", familyPath, rule.SourceID, familyID)
			}
		}
		if rule.DefaultFamily != "" {
			if strings.TrimSpace(rule.DefaultFamily) != rule.DefaultFamily || containsControl(rule.DefaultFamily) {
				return fmt.Errorf("%s.default_family must be trimmed and printable", rulePath)
			}
			if _, ok := catalogFamilies[rule.DefaultFamily]; !ok {
				return fmt.Errorf("%s.default_family %q is not a catalog family", rulePath, rule.DefaultFamily)
			}
			if !ruleSelectsFamily(rule, rule.DefaultFamily) {
				return fmt.Errorf("%s.default_family %q must select the Rust kernel", rulePath, rule.DefaultFamily)
			}
		}
		switch rule.UnknownFamilyPolicy {
		case unknownFamilyGoPolicy:
		case unknownFamilyRustPolicy:
			if !rule.AllCatalogFamilies {
				return fmt.Errorf("%s unknown Rust fail-closed policy requires all_catalog_families", rulePath)
			}
		default:
			return fmt.Errorf("%s.unknown_family_policy %q is not supported", rulePath, rule.UnknownFamilyPolicy)
		}
	}
	return nil
}

func validateSelectorOutcomes(name string, policy selectorPolicy, selector selectorFunc, families []catalogFamily) error {
	if selector == nil {
		return fmt.Errorf("runtime selector %s is unavailable", name)
	}
	rules := selectorRulesBySource(policy)
	seenSources := map[string]struct{}{}
	for _, family := range families {
		rule, hasRule := rules[family.Key.SourceID]
		wantRust := family.Key.Mode == "pull" && hasRule && ruleSelectsFamily(rule, family.Key.FamilyID)
		if err := compareSelectorOutcome(name, selector, family.Key.SourceID, family.Key.FamilyID, family.Key.FamilyID, wantRust); err != nil {
			return err
		}
		if family.Key.Mode == "pull" {
			seenSources[family.Key.SourceID] = struct{}{}
		}
	}
	sourceIDs := make([]string, 0, len(seenSources))
	for sourceID := range seenSources {
		sourceIDs = append(sourceIDs, sourceID)
	}
	sort.Strings(sourceIDs)
	for _, sourceID := range sourceIDs {
		rule, hasRule := rules[sourceID]
		wantEmpty := hasRule && rule.DefaultFamily != ""
		wantEmptyFamily := ""
		if wantEmpty {
			wantEmptyFamily = rule.DefaultFamily
		}
		if err := compareSelectorOutcome(name, selector, sourceID, "", wantEmptyFamily, wantEmpty); err != nil {
			return err
		}
		wantUnknown := hasRule && rule.UnknownFamilyPolicy == unknownFamilyRustPolicy
		if err := compareSelectorOutcome(name, selector, sourceID, unknownFamilySentinel, unknownFamilySentinel, wantUnknown); err != nil {
			return err
		}
	}
	for _, sentinel := range []struct{ sourceID, familyID string }{
		{sourceID: "", familyID: ""},
		{sourceID: unknownSourceSentinel, familyID: unknownFamilySentinel},
	} {
		if err := compareSelectorOutcome(name, selector, sentinel.sourceID, sentinel.familyID, "", false); err != nil {
			return err
		}
	}
	return nil
}

func compareSelectorOutcome(name string, selector selectorFunc, sourceID, familyID, wantFamily string, wantRust bool) error {
	gotFamily, gotRust := selector(sourceID, familyID)
	if gotRust != wantRust {
		return fmt.Errorf(
			"%s selector outcome drift for source=%q family=%q: ledger selects %s; compiled selector selects %s",
			name,
			sourceID,
			familyID,
			selectorKernel(wantRust),
			selectorKernel(gotRust),
		)
	}
	if gotRust && gotFamily != wantFamily {
		return fmt.Errorf(
			"%s selector normalization drift for source=%q family=%q: ledger expects normalized family=%q; compiled selector returns %q",
			name,
			sourceID,
			familyID,
			wantFamily,
			gotFamily,
		)
	}
	return nil
}

func validateSelectorAuthority(name string, policy selectorPolicy, ledger authorityLedger, families []catalogFamily) error {
	rules := selectorRulesBySource(policy)
	overrides := make(map[familyKey]authorityDefinition, len(ledger.Overrides))
	for _, override := range ledger.Overrides {
		overrides[override.key()] = override.authorityDefinition
	}
	for _, family := range families {
		if family.Key.Mode != "pull" {
			continue
		}
		rule, ok := rules[family.Key.SourceID]
		if !ok || !ruleSelectsFamily(rule, family.Key.FamilyID) {
			continue
		}
		definition := ledger.Defaults["pull"]
		if override, ok := overrides[family.Key]; ok {
			definition = override
		}
		if err := validateGoBoundaryAuthority(definition); err != nil {
			return fmt.Errorf("%s selector route %s crosses the declared Go authority boundary: %w", name, family.Key.String(), err)
		}
	}
	return nil
}

func validateGoBoundaryAuthority(definition authorityDefinition) error {
	expected := map[string]string{
		"credential_owner":             "go_trusted_runtime_host",
		"network_owner":                "go_trusted_runtime_host",
		"operations.check":             "go_source_runtime",
		"operations.discover":          "go_source_runtime",
		"operations.read_page":         "go_source_runtime",
		"operations.push_admit":        "not_applicable",
		"operations.append":            "go_source_runtime",
		"operations.project":           "go_source_runtime",
		"operations.checkpoint_commit": "go_source_runtime_store",
		"operations.product_read":      "organizational_projection",
	}
	actual := map[string]string{
		"credential_owner":             definition.CredentialOwner,
		"network_owner":                definition.NetworkOwner,
		"operations.check":             definition.Operations.Check,
		"operations.discover":          definition.Operations.Discover,
		"operations.read_page":         definition.Operations.ReadPage,
		"operations.push_admit":        definition.Operations.PushAdmit,
		"operations.append":            definition.Operations.Append,
		"operations.project":           definition.Operations.Project,
		"operations.checkpoint_commit": definition.Operations.CheckpointCommit,
		"operations.product_read":      definition.Operations.ProductRead,
	}
	keys := make([]string, 0, len(expected))
	for key := range expected {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if actual[key] != expected[key] {
			return fmt.Errorf("%s is %q, want %q", key, actual[key], expected[key])
		}
	}
	return nil
}

func selectorRulesBySource(policy selectorPolicy) map[string]selectorRule {
	rules := make(map[string]selectorRule, len(policy.RustKernelRules))
	for _, rule := range policy.RustKernelRules {
		rules[rule.SourceID] = rule
	}
	return rules
}

func ruleSelectsFamily(rule selectorRule, familyID string) bool {
	if rule.AllCatalogFamilies {
		return true
	}
	for _, selected := range rule.Families {
		if familyID == selected {
			return true
		}
	}
	return false
}

func selectorKernel(rust bool) string {
	if rust {
		return rustWorkerKernel
	}
	return goCompatibilityKernel
}

func validateSelectorCallsites(root string) error {
	actual := map[selectorCallsite]int{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("resolve selector callsite path: %w", err)
		}
		relPath = filepath.ToSlash(relPath)
		if entry.IsDir() {
			if relPath == "tools/sourceoperationauthoritycheck" || selectorCallsiteExcludedDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if filepath.Ext(path) == ".go" {
				return fmt.Errorf("%s must not be a symlink", relPath)
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		payload, err := os.ReadFile(path) // #nosec G304 -- path is bounded to repository Go source.
		if err != nil {
			return fmt.Errorf("read %s: %w", relPath, err)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, payload, 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", relPath, err)
		}
		aliases, err := sourceworkerImportAliases(parsed)
		if err != nil {
			return fmt.Errorf("parse imports in %s: %w", relPath, err)
		}
		insideSourceworker := strings.HasPrefix(relPath, "internal/sourceruntime/sourceworker/") && parsed.Name.Name == "sourceworker"
		dotImported := aliases["."]
		recordReferences := func(node ast.Node, symbol string) {
			ast.Inspect(node, func(node ast.Node) bool {
				switch expression := node.(type) {
				case *ast.SelectorExpr:
					identifier, ok := expression.X.(*ast.Ident)
					if !ok || !aliases[identifier.Name] {
						return true
					}
					if expression.Sel.Name == durableSelectorName || expression.Sel.Name == previewSelectorName {
						actual[selectorCallsite{Selector: expression.Sel.Name, Path: relPath, Symbol: symbol}]++
					}
				case *ast.Ident:
					if (insideSourceworker || dotImported) && (expression.Name == durableSelectorName || expression.Name == previewSelectorName) {
						actual[selectorCallsite{Selector: expression.Name, Path: relPath, Symbol: symbol}]++
					}
				}
				return true
			})
		}
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				recordReferences(declaration, "<package>")
				continue
			}
			if function.Body != nil {
				recordReferences(function.Body, goDeclarationSymbol(function))
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("scan production Go selector callsites: %w", err)
	}
	keys := make([]selectorCallsite, 0, len(requiredSelectorCallsites)+len(actual))
	seen := map[selectorCallsite]struct{}{}
	for callsite := range requiredSelectorCallsites {
		keys = append(keys, callsite)
		seen[callsite] = struct{}{}
	}
	for callsite := range actual {
		if _, ok := seen[callsite]; !ok {
			keys = append(keys, callsite)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		return selectorCallsiteString(keys[i]) < selectorCallsiteString(keys[j])
	})
	for _, callsite := range keys {
		want := requiredSelectorCallsites[callsite]
		got := actual[callsite]
		if got != want {
			return fmt.Errorf("production Go selector callsite drift for %s: found %d references, want %d; update routing and the closed callsite contract together", selectorCallsiteString(callsite), got, want)
		}
	}
	return nil
}

func selectorCallsiteExcludedDirectory(name string) bool {
	switch name {
	case ".git", ".cache", ".venv", "node_modules", "target", "vendor":
		return true
	default:
		return false
	}
}

func sourceworkerImportAliases(file *ast.File) (map[string]bool, error) {
	aliases := map[string]bool{}
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return nil, err
		}
		if importPath != sourceworkerImportPath {
			continue
		}
		alias := "sourceworker"
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		if alias == "_" {
			continue
		}
		aliases[alias] = true
	}
	return aliases, nil
}

func selectorCallsiteString(callsite selectorCallsite) string {
	return callsite.Selector + " at " + callsite.Path + "#" + callsite.Symbol
}

func goDeclarationSymbol(function *ast.FuncDecl) string {
	if function == nil || function.Name == nil {
		return ""
	}
	if function.Recv == nil || len(function.Recv.List) != 1 {
		return function.Name.Name
	}
	receiver := function.Recv.List[0].Type
	if pointer, ok := receiver.(*ast.StarExpr); ok {
		receiver = pointer.X
	}
	identifier, ok := receiver.(*ast.Ident)
	if !ok {
		return ""
	}
	return identifier.Name + "." + function.Name.Name
}

func validateDefinition(root, mode, path string, definition authorityDefinition, family *catalogFamily) error {
	if _, ok := validStates[definition.State]; !ok {
		return fmt.Errorf("%s.state %q is not supported", path, definition.State)
	}
	if err := requireOwner(path+".credential_owner", definition.CredentialOwner); err != nil {
		return err
	}
	if err := requireOwner(path+".network_owner", definition.NetworkOwner); err != nil {
		return err
	}
	if err := validateOperations(mode, path+".operations", definition.Operations); err != nil {
		return err
	}
	if definition.CandidateKernel == nil {
		if definition.State == "shadow" || definition.State == "shadow_disabled" {
			return fmt.Errorf("%s state %q requires candidate_kernel", path, definition.State)
		}
		return nil
	}
	if family == nil {
		return fmt.Errorf("%s candidate_kernel is only valid on an exact catalog override", path)
	}
	if definition.State != "shadow" && definition.State != "shadow_disabled" {
		return fmt.Errorf("%s candidate_kernel requires shadow or shadow_disabled state", path)
	}
	candidate := definition.CandidateKernel
	if candidate.Runtime != "credential_free_rust_worker" {
		return fmt.Errorf("%s.candidate_kernel.runtime must be credential_free_rust_worker", path)
	}
	if !candidate.CredentialFree || candidate.NetworkAllowed {
		return fmt.Errorf("%s.candidate_kernel must be credential-free and network-disabled", path)
	}
	for field, value := range map[string]string{
		"plan_id": candidate.PlanID, "provider_kernel": candidate.ProviderKernel,
		"event_kind": candidate.EventKind, "schema_ref": candidate.SchemaRef,
	} {
		if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value || containsControl(value) {
			return fmt.Errorf("%s.candidate_kernel.%s must be non-empty, trimmed, and printable", path, field)
		}
	}
	contract, ok := family.Contracts[candidate.EventKind]
	if !ok {
		return fmt.Errorf("%s.candidate_kernel.event_kind %q is not declared by %s", path, candidate.EventKind, family.Key.String())
	}
	if contract.SchemaRef != candidate.SchemaRef {
		return fmt.Errorf("%s.candidate_kernel.schema_ref %q does not match catalog contract %q", path, candidate.SchemaRef, contract.SchemaRef)
	}
	if len(candidate.Evidence) == 0 {
		return fmt.Errorf("%s.candidate_kernel.implementation_evidence is required", path)
	}
	for index, proof := range candidate.Evidence {
		if err := validateImplementationProof(root, fmt.Sprintf("%s.candidate_kernel.implementation_evidence[%d]", path, index), proof); err != nil {
			return err
		}
	}
	return nil
}

func validateOperations(mode, path string, operations operationAuthority) error {
	values := map[string]string{
		"check": operations.Check, "discover": operations.Discover, "read_page": operations.ReadPage,
		"push_admit": operations.PushAdmit, "append": operations.Append, "project": operations.Project,
		"checkpoint_commit": operations.CheckpointCommit, "product_read": operations.ProductRead,
	}
	for operation, owner := range values {
		if err := requireOwner(path+"."+operation, owner); err != nil {
			return err
		}
	}
	if mode == "pull" && operations.PushAdmit != "not_applicable" {
		return fmt.Errorf("%s.push_admit must be not_applicable for pull families", path)
	}
	if mode == "push" {
		for operation, owner := range map[string]string{
			"check": operations.Check, "discover": operations.Discover,
			"read_page": operations.ReadPage, "checkpoint_commit": operations.CheckpointCommit,
		} {
			if owner != "not_applicable" {
				return fmt.Errorf("%s.%s must be not_applicable for push families", path, operation)
			}
		}
		if operations.PushAdmit == "not_applicable" {
			return fmt.Errorf("%s.push_admit must name the push admission authority", path)
		}
	}
	return nil
}

func validateImplementationProof(root, path string, proof implementationProof) error {
	clean := filepath.Clean(proof.Path)
	if proof.Path == "" || filepath.IsAbs(proof.Path) || clean != proof.Path || clean == "." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s.path must be a clean repository-relative path", path)
	}
	if filepath.Ext(clean) != ".rs" || !strings.HasPrefix(filepath.ToSlash(clean), "crates/") {
		return fmt.Errorf("%s.path must identify Rust source under crates/", path)
	}
	fullPath := filepath.Join(root, clean)
	info, err := os.Lstat(fullPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", proof.Path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular non-symlink file", proof.Path)
	}
	payload, err := os.ReadFile(fullPath) // #nosec G304 -- path is repository-relative, clean, and lstat-checked.
	if err != nil {
		return fmt.Errorf("read %s: %w", proof.Path, err)
	}
	if len(proof.RequiredMarkers) == 0 {
		return fmt.Errorf("%s.required_markers is required", path)
	}
	seen := map[string]struct{}{}
	for index, marker := range proof.RequiredMarkers {
		if strings.TrimSpace(marker) == "" || strings.TrimSpace(marker) != marker || containsControl(marker) {
			return fmt.Errorf("%s.required_markers[%d] must be non-empty, trimmed, and printable", path, index)
		}
		if _, ok := seen[marker]; ok {
			return fmt.Errorf("%s.required_markers contains duplicate %q", path, marker)
		}
		seen[marker] = struct{}{}
		if !bytes.Contains(payload, []byte(marker)) {
			return fmt.Errorf("%s is missing required marker %q", proof.Path, marker)
		}
	}
	return nil
}

func requireOwner(path, value string) error {
	if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value || containsControl(value) {
		return fmt.Errorf("%s must be non-empty, trimmed, and printable", path)
	}
	if _, ok := validOwners[value]; !ok {
		return fmt.Errorf("%s names unknown authority owner %q", path, value)
	}
	return nil
}

func validateFamilyKey(key familyKey) error {
	if key.Mode != "pull" && key.Mode != "push" {
		return fmt.Errorf("mode must be pull or push")
	}
	if strings.TrimSpace(key.SourceID) == "" || strings.TrimSpace(key.FamilyID) == "" {
		return fmt.Errorf("source_id and family_id are required")
	}
	if strings.TrimSpace(key.SourceID) != key.SourceID || strings.TrimSpace(key.FamilyID) != key.FamilyID || containsControl(key.SourceID) || containsControl(key.FamilyID) {
		return fmt.Errorf("source_id and family_id must be trimmed and printable")
	}
	return nil
}

func containsControl(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}

func (override authorityOverride) key() familyKey {
	return familyKey{Mode: override.Mode, SourceID: override.SourceID, FamilyID: override.FamilyID}
}

func (key familyKey) String() string {
	return key.Mode + "\t" + key.SourceID + "\t" + key.FamilyID
}

func formatStateCounts(states map[string]int) string {
	keys := make([]string, 0, len(states))
	for state := range states {
		keys = append(keys, state)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, state := range keys {
		parts = append(parts, fmt.Sprintf("%s:%d", state, states[state]))
	}
	return strings.Join(parts, ",")
}
