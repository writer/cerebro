package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const defaultMaxInputBytes int64 = 4 * 1024 * 1024

type sourceCatalogWire struct {
	ID              string          `yaml:"id"`
	RuntimeFamilies []string        `yaml:"runtime_families"`
	EventContracts  []eventContract `yaml:"event_contracts"`
}

type differentialReceipt struct {
	SchemaVersion              string       `json:"schema_version"`
	ToolRevision               string       `json:"tool_revision"`
	Mode                       string       `json:"mode"`
	BehaviorKind               behaviorKind `json:"behavior_kind"`
	SubjectID                  string       `json:"subject_id"`
	GoFactsDigestSHA256        string       `json:"go_facts_digest_sha256"`
	IRVersion                  string       `json:"ir_version"`
	IRDigestSHA256             string       `json:"ir_digest_sha256"`
	RustImplementationRevision string       `json:"rust_implementation_revision"`
	EvidenceDigestsSHA256      []string     `json:"evidence_digests_sha256"`
	InputDigestSHA256          string       `json:"input_digest_sha256"`
	FixtureOrGraphRevision     string       `json:"fixture_or_graph_revision"`
	NormalizedRowsDigestSHA256 string       `json:"normalized_rows_digest_sha256"`
	OrderCursorDigestSHA256    string       `json:"order_cursor_digest_sha256"`
	MismatchCount              int          `json:"mismatch_count"`
}

type carveResult struct {
	IR          migrationIR
	Manifest    deletionManifest
	Artifacts   map[string][]byte
	Unsupported *unsupportedReport
}

func loadCarveRequest(path string) (carveRequest, error) {
	info, err := os.Stat(path)
	if err != nil {
		return carveRequest{}, fmt.Errorf("stat request: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > defaultMaxInputBytes {
		return carveRequest{}, typedInputError{Reason: reasonUnboundedShape, Err: errors.New("request is not a bounded regular file")}
	}
	payload, err := os.ReadFile(path) // #nosec G304 -- explicit operator-owned request path.
	if err != nil {
		return carveRequest{}, fmt.Errorf("read request: %w", err)
	}
	var request carveRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return carveRequest{}, typedInputError{Reason: reasonMalformedJSON, Err: fmt.Errorf("decode request: %w", err)}
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return carveRequest{}, typedInputError{Reason: reasonMalformedJSON, Err: errors.New("decode request: trailing JSON value")}
	}
	return request, nil
}

func distill(root string, request carveRequest) (carveResult, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return carveResult{}, fmt.Errorf("resolve root: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return carveResult{}, fmt.Errorf("resolve root symlinks: %w", err)
	}
	reasons, details := validateRequest(request)
	if len(reasons) != 0 {
		return unsupportedResult(request, reasons, details), nil
	}
	facts, factReasons, factDetails := analyzeGoFacts(root, request)
	if len(factReasons) != 0 {
		return unsupportedResult(request, factReasons, factDetails), nil
	}
	if request.BehaviorKind == behaviorFindingRule {
		if containsString(facts.Calls, "<side_effecting_goroutine>") {
			return unsupportedResult(request, []reasonCode{reasonSideEffectingMatcher}, []string{"finding owner starts a goroutine"}), nil
		}
		for _, call := range facts.Calls {
			if call == "time.Now" || strings.HasPrefix(call, "rand.") || strings.HasPrefix(call, "crypto/rand.") {
				return unsupportedResult(request, []reasonCode{reasonNonDeterministicTime}, []string{"finding owner reads nondeterministic time or randomness"}), nil
			}
		}
	}
	fixtures, fixtureReasons, fixtureDetails := digestArtifacts(root, request.FixtureCorpus, request.Options.MaxInputBytes)
	traces, traceReasons, traceDetails := digestArtifacts(root, request.PortTraces, request.Options.MaxInputBytes)
	if evidenceReasons := append(fixtureReasons, traceReasons...); len(evidenceReasons) != 0 {
		return unsupportedResult(request, evidenceReasons, append(fixtureDetails, traceDetails...)), nil
	}

	ir := migrationIR{
		SchemaVersion: migrationIRSchemaVersion,
		ToolRevision:  rustcarveToolRevision,
		IRVersion:     irVersion(request.BehaviorKind),
		BehaviorKind:  request.BehaviorKind,
		Subject: distilledSubject{
			ID:                         request.Subject.ID,
			RustImplementationRevision: request.Subject.RustImplementationRevision,
			AuthorityState:             request.Subject.AuthorityState,
		},
		Scope:   request.Scope,
		GoFacts: facts,
		Evidence: evidenceContract{
			Fixtures: fixtures,
			Traces:   traces,
		},
	}

	switch request.BehaviorKind {
	case behaviorStandardSource, behaviorProviderSource:
		expectedCall := "catalogruntimesource.New"
		if request.Options.ExpectedRegistrationShape == "worker_fail_closed_metadata" {
			expectedCall = "newWorkerCatalogSource"
		}
		if !containsString(facts.Calls, expectedCall) {
			return unsupportedResult(request, []reasonCode{reasonUnsupportedRegistration}, []string{"owner facts do not contain " + expectedCall}), nil
		}
		standard, standardReasons, standardDetails := distillSourceCatalog(root, request)
		if len(standardReasons) != 0 {
			return unsupportedResult(request, standardReasons, standardDetails), nil
		}
		if request.BehaviorKind == behaviorStandardSource {
			ir.Standard = &standard
		} else {
			ir.Provider = &standard
		}
	case behaviorGraphQuery:
		if graphReasons := validateGraphQuery(request.GraphQuery, request.Scope); len(graphReasons) != 0 {
			return unsupportedResult(request, graphReasons, []string{graphValidationError(graphReasons).Error()}), nil
		}
		ir.GraphQuery = request.GraphQuery
	case behaviorFindingRule:
		if findingReasons := validateFindingRule(request.FindingRule, request.Scope); len(findingReasons) != 0 {
			return unsupportedResult(request, findingReasons, []string{"finding rule failed closed validation"}), nil
		}
		ir.FindingRule = request.FindingRule
	}
	ir.DigestSHA256, err = digestIR(ir)
	if err != nil {
		return carveResult{}, err
	}

	manifest, err := buildDeletionManifest(root, request, ir)
	if err != nil {
		return carveResult{}, err
	}
	artifacts, err := generateArtifacts(ir, manifest)
	if err != nil {
		return carveResult{}, err
	}
	return carveResult{IR: ir, Manifest: manifest, Artifacts: artifacts}, nil
}

func validateRequest(request carveRequest) ([]reasonCode, []string) {
	reasons := make([]reasonCode, 0)
	details := make([]string, 0)
	if request.SchemaVersion != requestSchemaVersion {
		reasons = append(reasons, reasonUnknownBehaviorKind)
		details = append(details, "request schema_version is not supported")
	}
	if irVersion(request.BehaviorKind) == "" {
		reasons = append(reasons, reasonUnknownBehaviorKind)
		details = append(details, "behavior_kind is not in the closed registry")
	}
	if strings.TrimSpace(request.Subject.ID) == "" || strings.TrimSpace(request.Subject.PackageDir) == "" || len(request.Subject.GoFiles) == 0 || len(request.Subject.OwnerSymbols) == 0 {
		reasons = append(reasons, reasonAmbiguousGoOwner)
		details = append(details, "subject id, package_dir, go_files, and owner_symbols are required")
	}
	if request.Subject.RustImplementationRevision == "" {
		reasons = append(reasons, reasonReceiptBindingMismatch)
		details = append(details, "Rust implementation revision is required")
	}
	if scopeReasons := reasonsForScope(request.Scope); len(scopeReasons) != 0 {
		reasons = append(reasons, scopeReasons...)
		details = append(details, "scope is not explicitly tenant/workspace bound")
	}
	if request.Options.MaxInputBytes < 0 || request.Options.MaxInputBytes > 8*1024*1024 {
		reasons = append(reasons, reasonUnboundedShape)
		details = append(details, "max_input_bytes must be 0..8388608")
	}
	return uniqueReasons(reasons), details
}

func reasonsForScope(scope scopeContract) []reasonCode {
	reasons := make([]reasonCode, 0)
	if scope.Tenant != (typedInput{Name: "tenant_id", Type: "tenant_id", Required: true}) {
		reasons = append(reasons, reasonUnboundTenantScope)
	}
	switch scope.WorkspacePolicy {
	case "forbidden":
		if scope.Workspace != nil {
			reasons = append(reasons, reasonUnboundWorkspaceScope)
		}
	case "required":
		if scope.Workspace == nil || *scope.Workspace != (typedInput{Name: "workspace_id", Type: "workspace_id", Required: true}) {
			reasons = append(reasons, reasonUnboundWorkspaceScope)
		}
	case "optional":
		if scope.Workspace == nil || *scope.Workspace != (typedInput{Name: "workspace_id", Type: "workspace_id", Required: false}) {
			reasons = append(reasons, reasonUnboundWorkspaceScope)
		}
	default:
		reasons = append(reasons, reasonUnboundWorkspaceScope)
	}
	return reasons
}

func analyzeGoFacts(root string, request carveRequest) (goPackageFacts, []reasonCode, []string) {
	facts := goPackageFacts{Files: append([]string(nil), request.Subject.GoFiles...)}
	sort.Strings(facts.Files)
	owners := stringSetOf(request.Subject.OwnerSymbols...)
	foundOwners := map[string]int{}
	imports := map[string]bool{}
	calls := map[string]bool{}
	fileSet := token.NewFileSet()
	packageDir := filepath.Clean(request.Subject.PackageDir)
	for _, relative := range facts.Files {
		cleaned := filepath.Clean(relative)
		if filepath.Ext(cleaned) != ".go" || (cleaned != packageDir && !strings.HasPrefix(cleaned, packageDir+string(filepath.Separator))) {
			return goPackageFacts{}, []reasonCode{reasonAmbiguousGoOwner}, []string{fmt.Sprintf("Go file %q is outside package_dir %q", relative, request.Subject.PackageDir)}
		}
		payload, absolute, err := readRepoFile(root, relative, request.Options.MaxInputBytes)
		if err != nil {
			return goPackageFacts{}, []reasonCode{reasonAmbiguousGoOwner}, []string{err.Error()}
		}
		facts.FileDigests = append(facts.FileDigests, artifactDigest{Path: relative, Role: "go_source", DigestSHA256: digestBytes(payload)})
		file, err := parser.ParseFile(fileSet, absolute, payload, parser.SkipObjectResolution)
		if err != nil {
			return goPackageFacts{}, []reasonCode{reasonAmbiguousGoOwner}, []string{fmt.Sprintf("parse %s: %v", relative, err)}
		}
		if facts.PackageName == "" {
			facts.PackageName = file.Name.Name
		} else if facts.PackageName != file.Name.Name {
			return goPackageFacts{}, []reasonCode{reasonAmbiguousGoOwner}, []string{"Go files span multiple packages"}
		}
		for _, imported := range file.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err == nil {
				imports[path] = true
			}
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || !owners[function.Name.Name] {
				continue
			}
			foundOwners[function.Name.Name]++
			ast.Inspect(function.Body, func(node ast.Node) bool {
				switch typed := node.(type) {
				case *ast.CallExpr:
					if name := callName(typed.Fun); name != "" {
						calls[name] = true
					}
					for _, argument := range typed.Args {
						if _, dynamic := argument.(*ast.FuncLit); dynamic {
							calls["<dynamic_callback>"] = true
						}
					}
				case *ast.GoStmt:
					calls["<side_effecting_goroutine>"] = true
				}
				return true
			})
		}
	}
	missing := make([]string, 0)
	for owner := range owners {
		if foundOwners[owner] != 1 {
			missing = append(missing, owner)
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		return goPackageFacts{}, []reasonCode{reasonAmbiguousGoOwner}, []string{"owner symbols must each resolve exactly once: " + strings.Join(missing, ",")}
	}
	if calls["<dynamic_callback>"] {
		return goPackageFacts{}, []reasonCode{reasonDynamicGoCallback}, []string{"owner function passes a Go closure"}
	}
	facts.Imports = sortedKeys(imports)
	facts.Calls = sortedKeys(calls)
	facts.OwnerSymbols = sortedCountKeys(foundOwners)
	canonical := facts
	canonical.DigestSHA256 = ""
	payload, err := json.Marshal(canonical)
	if err != nil {
		return goPackageFacts{}, []reasonCode{reasonAmbiguousGoOwner}, []string{err.Error()}
	}
	facts.DigestSHA256 = digestBytes(payload)
	return facts, nil, nil
}

func distillSourceCatalog(root string, request carveRequest) (standardSourceIR, []reasonCode, []string) {
	payload, _, err := readRepoFile(root, request.Subject.CatalogPath, request.Options.MaxInputBytes)
	if err != nil {
		return standardSourceIR{}, []reasonCode{reasonAmbiguousGoOwner}, []string{err.Error()}
	}
	var catalog sourceCatalogWire
	decoder := yaml.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&catalog); err != nil {
		return standardSourceIR{}, []reasonCode{reasonMalformedJSON}, []string{fmt.Sprintf("decode catalog: %v", err)}
	}
	if catalog.ID != request.Subject.ID || len(catalog.RuntimeFamilies) == 0 || len(catalog.EventContracts) == 0 {
		return standardSourceIR{}, []reasonCode{reasonAmbiguousGoOwner}, []string{"catalog identity, runtime families, or event contracts are incomplete"}
	}
	registration := request.Options.ExpectedRegistrationShape
	if registration != "generic_catalog_runtime" && registration != "worker_fail_closed_metadata" {
		return standardSourceIR{}, []reasonCode{reasonUnsupportedRegistration}, []string{"only generic catalog or fail-closed worker registration can be distilled"}
	}
	return standardSourceIR{
		CatalogPath:     request.Subject.CatalogPath,
		Registration:    registration,
		ExecutionOwner:  "compiled_rust_source_plan",
		FailClosed:      true,
		RuntimeFamilies: append([]string(nil), catalog.RuntimeFamilies...),
		EventContracts:  append([]eventContract(nil), catalog.EventContracts...),
	}, nil, nil
}

func digestArtifacts(root string, requests []artifactRequest, maxBytes int64) ([]artifactDigest, []reasonCode, []string) {
	result := make([]artifactDigest, 0, len(requests))
	for _, request := range requests {
		payload, _, err := readRepoFile(root, request.Path, maxBytes)
		if err != nil {
			return nil, []reasonCode{reasonUnboundedShape}, []string{err.Error()}
		}
		if secretReason := detectSecretMaterial(payload); secretReason != "" {
			return nil, []reasonCode{reasonSecretMaterial}, []string{fmt.Sprintf("%s contains secret-like material at %s", request.Path, secretReason)}
		}
		result = append(result, artifactDigest{Path: request.Path, Role: request.Role, DigestSHA256: digestBytes(payload)})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, nil, nil
}

func buildDeletionManifest(root string, request carveRequest, ir migrationIR) (deletionManifest, error) {
	requiredModes := requiredReceiptModes(request.BehaviorKind)
	accepted, receiptReasons, err := validateReceipts(root, request, ir, requiredModes)
	if err != nil {
		return deletionManifest{}, err
	}
	reasons := append([]reasonCode(nil), receiptReasons...)
	if len(request.Deletion.Paths)+len(request.Deletion.Imports)+len(request.Deletion.Symbols) == 0 {
		reasons = append(reasons, reasonNoDeletionTargets)
	}
	if request.Subject.AuthorityState != "rust_only_fail_closed" && request.Subject.AuthorityState != "rust_authoritative_no_go_writer" {
		if request.BehaviorKind == behaviorStandardSource || request.BehaviorKind == behaviorProviderSource {
			reasons = append(reasons, reasonActiveGoRegistryPath)
		} else {
			reasons = append(reasons, reasonActiveGoExecutionPath)
		}
	}
	manifest := deletionManifest{
		SchemaVersion:              deletionManifestV1,
		ToolRevision:               rustcarveToolRevision,
		BehaviorKind:               request.BehaviorKind,
		SubjectID:                  request.Subject.ID,
		IRVersion:                  ir.IRVersion,
		IRDigestSHA256:             ir.DigestSHA256,
		GoFactsDigestSHA256:        ir.GoFacts.DigestSHA256,
		RustImplementationRevision: request.Subject.RustImplementationRevision,
		ReasonCodes:                uniqueReasons(reasons),
		Paths:                      sortedCopy(request.Deletion.Paths),
		Imports:                    sortedCopy(request.Deletion.Imports),
		Symbols:                    sortedCopy(request.Deletion.Symbols),
		RequiredReceiptModes:       requiredModes,
		AcceptedReceipts:           append([]artifactDigest{}, accepted...),
	}
	manifest.Eligible = len(manifest.ReasonCodes) == 0 && len(manifest.Paths)+len(manifest.Imports)+len(manifest.Symbols) > 0
	return manifest, nil
}

func validateReceipts(root string, request carveRequest, ir migrationIR, requiredModes []string) ([]artifactDigest, []reasonCode, error) {
	if len(request.Receipts) == 0 {
		return nil, []reasonCode{reasonMissingParityReceipt}, nil
	}
	expectedEvidence := make([]string, 0, len(ir.Evidence.Fixtures)+len(ir.Evidence.Traces))
	for _, artifact := range append(append([]artifactDigest(nil), ir.Evidence.Fixtures...), ir.Evidence.Traces...) {
		expectedEvidence = append(expectedEvidence, artifact.DigestSHA256)
	}
	sort.Strings(expectedEvidence)
	foundModes := map[string]bool{}
	accepted := make([]artifactDigest, 0, len(request.Receipts))
	reasons := make([]reasonCode, 0)
	for _, reference := range request.Receipts {
		payload, _, err := readRepoFile(root, reference.Path, request.Options.MaxInputBytes)
		if err != nil {
			return nil, nil, err
		}
		var receipt differentialReceipt
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&receipt); err != nil {
			reasons = append(reasons, reasonReceiptBindingMismatch)
			continue
		}
		evidence := sortedCopy(receipt.EvidenceDigestsSHA256)
		valid := receipt.SchemaVersion == differentialReceiptV1 && receipt.ToolRevision == rustcarveToolRevision && receipt.BehaviorKind == request.BehaviorKind && receipt.SubjectID == request.Subject.ID && receipt.GoFactsDigestSHA256 == ir.GoFacts.DigestSHA256 && receipt.IRVersion == ir.IRVersion && receipt.IRDigestSHA256 == ir.DigestSHA256 && receipt.RustImplementationRevision == request.Subject.RustImplementationRevision && equalStrings(evidence, expectedEvidence) && validSHA256Digest(receipt.InputDigestSHA256) && receipt.FixtureOrGraphRevision != "" && validSHA256Digest(receipt.NormalizedRowsDigestSHA256) && validSHA256Digest(receipt.OrderCursorDigestSHA256) && receipt.MismatchCount == 0
		if !valid {
			reasons = append(reasons, reasonReceiptBindingMismatch)
			continue
		}
		foundModes[receipt.Mode] = true
		accepted = append(accepted, artifactDigest{Path: reference.Path, Role: receipt.Mode, DigestSHA256: digestBytes(payload)})
	}
	for _, mode := range requiredModes {
		if !foundModes[mode] {
			reasons = append(reasons, reasonMissingParityReceipt)
		}
	}
	return accepted, uniqueReasons(reasons), nil
}

func requiredReceiptModes(kind behaviorKind) []string {
	switch kind {
	case behaviorGraphQuery:
		return []string{"fixed_fixture", "live_safe_local_graph"}
	case behaviorFindingRule:
		return []string{"replay"}
	default:
		return []string{"fixed_fixture"}
	}
}

func irVersion(kind behaviorKind) string {
	switch kind {
	case behaviorStandardSource:
		return standardSourceIRVersion
	case behaviorProviderSource:
		return providerSourceIRVersion
	case behaviorGraphQuery:
		return graphQueryIRVersion
	case behaviorFindingRule:
		return findingRuleIRVersion
	default:
		return ""
	}
}

func digestIR(ir migrationIR) (string, error) {
	canonical := ir
	canonical.DigestSHA256 = ""
	payload, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("marshal migration IR: %w", err)
	}
	return digestBytes(payload), nil
}

func readRepoFile(root, relative string, maxBytes int64) ([]byte, string, error) {
	relative = filepath.Clean(strings.TrimSpace(relative))
	if relative == "." || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, "", fmt.Errorf("path %q escapes the repository", relative)
	}
	absolute := filepath.Join(root, relative)
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, "", fmt.Errorf("resolve %s: %w", relative, err)
	}
	if resolved != root && !strings.HasPrefix(resolved, root+string(filepath.Separator)) {
		return nil, "", fmt.Errorf("path %q resolves outside the repository", relative)
	}
	limit := maxBytes
	if limit == 0 {
		limit = defaultMaxInputBytes
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, "", fmt.Errorf("stat %s: %w", relative, err)
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, "", fmt.Errorf("%s is not a bounded regular file", relative)
	}
	payload, err := os.ReadFile(resolved) // #nosec G304 -- path is bounded to the repository root above.
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", relative, err)
	}
	return payload, resolved, nil
}

func detectSecretMaterial(payload []byte) string {
	var value any
	if json.Unmarshal(payload, &value) != nil {
		return ""
	}
	var visit func(any, string) string
	visit = func(current any, path string) string {
		switch typed := current.(type) {
		case map[string]any:
			for key, item := range typed {
				lower := strings.ToLower(key)
				if stringSetOf("access_token", "api_key", "client_secret", "password", "private_key", "session_cookie")[lower] {
					if text, ok := item.(string); ok && text != "" && !strings.HasPrefix(text, "${") && text != "REDACTED" {
						return path + "." + key
					}
				}
				if found := visit(item, path+"."+key); found != "" {
					return found
				}
			}
		case []any:
			for index, item := range typed {
				if found := visit(item, fmt.Sprintf("%s[%d]", path, index)); found != "" {
					return found
				}
			}
		}
		return ""
	}
	return visit(value, "$")
}

func callName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		if prefix := callName(typed.X); prefix != "" {
			return prefix + "." + typed.Sel.Name
		}
	}
	return ""
}

func unsupportedResult(request carveRequest, reasons []reasonCode, details []string) carveResult {
	report := unsupportedReport{SchemaVersion: unsupportedReportV1, BehaviorKind: request.BehaviorKind, SubjectID: request.Subject.ID, ReasonCodes: uniqueReasons(reasons), Details: details}
	return carveResult{Unsupported: &report}
}

func digestBytes(payload []byte) string {
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validSHA256Digest(value string) bool {
	encoded := strings.TrimPrefix(value, "sha256:")
	if encoded == value || len(encoded) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(encoded)
	return err == nil
}

func sortedKeys[T ~string](values map[T]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, string(value))
	}
	sort.Strings(result)
	return result
}

func sortedCountKeys[T ~string](values map[T]int) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, string(value))
	}
	sort.Strings(result)
	return result
}

func sortedCopy(values []string) []string {
	result := append([]string{}, values...)
	sort.Strings(result)
	return result
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
