// Command sourceoperationauthoritycheck verifies that every built-in source
// family has one explicit, drift-bound operation authority decision.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/writer/cerebro/internal/sourcecdk"
	"gopkg.in/yaml.v3"
)

const (
	ledgerRelPath                    = "docs/engineering/source-operation-authority-ledger.json"
	ledgerSchemaV2                   = "cerebro.source-operation-authority/v2"
	goASTDeclarationCanonicalization = "go_ast_declaration_sha256/v1"
)

var requiredRuntimeBindings = map[string]runtimeBindingRequirement{
	"durable_pull_dispatch": {
		Path:   "internal/sourceruntime/source_execution.go",
		Symbol: "Service.readSourcePull",
	},
	"preview_rust_selector": {
		Path:   "internal/sourceops/source_execution.go",
		Symbol: "rustSourceFamily",
	},
	"rust_authoritative_selector": {
		Path:   "internal/sourceruntime/sourceworker/pull.go",
		Symbol: "RustAuthoritativeFamily",
	},
	"tailscale_authoritative_selector": {
		Path:   "internal/sourceruntime/sourceworker/pull.go",
		Symbol: "TailscaleFamily",
	},
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
	Canonicalization string                 `json:"canonicalization"`
	Bindings         []goDeclarationBinding `json:"bindings"`
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
	Inventory       inventory
	States          map[string]int
	Overrides       int
	RuntimeBindings int
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
		"source-operation-authority-check: %d families (%d pull, %d push), %d overrides, %d runtime bindings, states=%s, digest=%s\n",
		summary.Inventory.FamilyCount,
		summary.Inventory.PullFamilyCount,
		summary.Inventory.PushFamilyCount,
		summary.Overrides,
		summary.RuntimeBindings,
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
	if err := validateLedger(root, ledger, families); err != nil {
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
		Inventory:       actualInventory,
		States:          states,
		Overrides:       len(ledger.Overrides),
		RuntimeBindings: len(ledger.RuntimeImplementation.Bindings),
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

func validateLedger(root string, ledger authorityLedger, families []catalogFamily) error {
	if ledger.SchemaVersion != ledgerSchemaV2 {
		return fmt.Errorf("schema_version must be %q", ledgerSchemaV2)
	}
	if ledger.Revision < 1 {
		return fmt.Errorf("revision must be positive")
	}
	if err := validateRuntimeImplementation(root, ledger.RuntimeImplementation); err != nil {
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

func validateRuntimeImplementation(root string, implementation runtimeImplementation) error {
	if implementation.Canonicalization != goASTDeclarationCanonicalization {
		return fmt.Errorf("runtime_implementation.canonicalization must be %q", goASTDeclarationCanonicalization)
	}
	if len(implementation.Bindings) != len(requiredRuntimeBindings) {
		return fmt.Errorf("runtime_implementation.bindings must contain exactly %d required bindings", len(requiredRuntimeBindings))
	}
	seen := make(map[string]struct{}, len(implementation.Bindings))
	for index, binding := range implementation.Bindings {
		path := fmt.Sprintf("runtime_implementation.bindings[%d]", index)
		requirement, ok := requiredRuntimeBindings[binding.Role]
		if !ok {
			return fmt.Errorf("%s.role %q is not a required runtime binding", path, binding.Role)
		}
		if _, duplicate := seen[binding.Role]; duplicate {
			return fmt.Errorf("%s duplicates role %q", path, binding.Role)
		}
		seen[binding.Role] = struct{}{}
		if binding.Path != requirement.Path || binding.Symbol != requirement.Symbol {
			return fmt.Errorf(
				"%s must bind %s#%s",
				path,
				requirement.Path,
				requirement.Symbol,
			)
		}
		if len(binding.DigestSHA256) != sha256.Size*2 || strings.ToLower(binding.DigestSHA256) != binding.DigestSHA256 {
			return fmt.Errorf("%s.digest_sha256 must be 64 lowercase hexadecimal characters", path)
		}
		if _, err := hex.DecodeString(binding.DigestSHA256); err != nil {
			return fmt.Errorf("%s.digest_sha256 must be 64 lowercase hexadecimal characters", path)
		}
		actualDigest, err := canonicalGoDeclarationDigest(root, binding.Path, binding.Symbol)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if binding.DigestSHA256 != actualDigest {
			return fmt.Errorf(
				"runtime implementation drift for %s: ledger has digest=%s; %s#%s has digest=%s; review the production routing change and refresh the ledger binding only when it is deliberate",
				binding.Role,
				binding.DigestSHA256,
				binding.Path,
				binding.Symbol,
				actualDigest,
			)
		}
	}
	return nil
}

func canonicalGoDeclarationDigest(root, relPath, symbol string) (string, error) {
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
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, fullPath, payload, 0)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", relPath, err)
	}
	var matched *ast.FuncDecl
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || goDeclarationSymbol(function) != symbol {
			continue
		}
		if matched != nil {
			return "", fmt.Errorf("%s declares %s more than once", relPath, symbol)
		}
		matched = function
	}
	if matched == nil {
		return "", fmt.Errorf("%s does not declare %s", relPath, symbol)
	}
	var canonical bytes.Buffer
	if err := format.Node(&canonical, token.NewFileSet(), matched); err != nil {
		return "", fmt.Errorf("canonicalize %s#%s: %w", relPath, symbol, err)
	}
	digest := sha256.Sum256(canonical.Bytes())
	return hex.EncodeToString(digest[:]), nil
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
