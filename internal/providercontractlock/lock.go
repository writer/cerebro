// Package providercontractlock creates deterministic locks for the portions of
// a provider OpenAPI contract selected by connector generation.
package providercontractlock

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/writer/cerebro/internal/sourcegen/stampfile"
)

const (
	SchemaVersion        = "cerebro.provider-contract-lock/v1"
	NormalizationVersion = "openapi-json-ref-closure/v1"

	DriftNew              = "new"
	DriftUnchanged        = "unchanged"
	DriftAdditive         = "additive"
	DriftBehavioralReview = "behavioral_review"
	DriftBreaking         = "breaking"
)

// Selection identifies one provider operation chosen for generation.
type Selection struct {
	FamilyID    string
	Method      string
	Path        string
	OperationID string
}

// Lock binds generated resource families to normalized provider contract
// content without including run timestamps.
type Lock struct {
	SchemaVersion        string          `json:"schema_version"`
	NormalizationVersion string          `json:"normalization_version"`
	SourceID             string          `json:"source_id"`
	DocumentDigest       string          `json:"document_digest"`
	AuthDigest           string          `json:"auth_digest"`
	Operations           []OperationLock `json:"operations"`
}

// OperationLock binds one selected method and path to its operation and
// transitive local-reference content.
type OperationLock struct {
	FamilyID    string `json:"family_id"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	OperationID string `json:"operation_id,omitempty"`
	Digest      string `json:"digest"`
}

// Drift classifies the effect of a current provider contract on a reviewed
// lock.
type Drift struct {
	Status  string   `json:"status"`
	Summary string   `json:"summary"`
	Changes []string `json:"changes,omitempty"`
}

// Build creates a deterministic lock for a normalized OpenAPI document and
// selected operations.
func Build(doc *openapi3.T, sourceID string, selections []Selection) (Lock, error) {
	if doc == nil {
		return Lock{}, fmt.Errorf("provider OpenAPI document is required")
	}
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" {
		return Lock{}, fmt.Errorf("source id is required")
	}
	root, documentPayload, err := normalizedDocument(doc)
	if err != nil {
		return Lock{}, err
	}
	documentDigest, err := stampfile.HashReader(bytes.NewReader(documentPayload))
	if err != nil {
		return Lock{}, fmt.Errorf("hash provider document: %w", err)
	}
	authDigest, err := digestValue(authContract(root, selections))
	if err != nil {
		return Lock{}, fmt.Errorf("hash provider auth contract: %w", err)
	}
	operations := make([]OperationLock, 0, len(selections))
	for _, selection := range selections {
		operation, err := lockOperation(root, selection)
		if err != nil {
			return Lock{}, err
		}
		operations = append(operations, operation)
	}
	sort.Slice(operations, func(left, right int) bool {
		if operations[left].Method != operations[right].Method {
			return operations[left].Method < operations[right].Method
		}
		if operations[left].Path != operations[right].Path {
			return operations[left].Path < operations[right].Path
		}
		return operations[left].FamilyID < operations[right].FamilyID
	})
	return Lock{
		SchemaVersion:        SchemaVersion,
		NormalizationVersion: NormalizationVersion,
		SourceID:             sourceID,
		DocumentDigest:       documentDigest,
		AuthDigest:           authDigest,
		Operations:           operations,
	}, nil
}

// Compare classifies provider drift against a previously reviewed lock.
func Compare(previous *Lock, current Lock) Drift {
	if previous == nil {
		return Drift{Status: DriftNew, Summary: "No provider contract lock exists yet."}
	}
	if previous.SourceID != current.SourceID || previous.NormalizationVersion != current.NormalizationVersion {
		return Drift{Status: DriftBreaking, Summary: "The provider contract lock identity or normalization version changed.", Changes: []string{"lock.identity"}}
	}
	changes := []string{}
	if previous.AuthDigest != current.AuthDigest {
		changes = append(changes, "auth")
	}
	previousOperations := operationMap(previous.Operations)
	currentOperations := operationMap(current.Operations)
	removed := false
	changed := false
	for key, before := range previousOperations {
		after, ok := currentOperations[key]
		if !ok {
			removed = true
			changes = append(changes, "operation.removed:"+key)
			continue
		}
		if before.Digest != after.Digest || before.FamilyID != after.FamilyID {
			changed = true
			changes = append(changes, "operation.changed:"+key)
		}
	}
	for key := range currentOperations {
		if _, ok := previousOperations[key]; !ok {
			changed = true
			changes = append(changes, "operation.added:"+key)
		}
	}
	sort.Strings(changes)
	switch {
	case previous.AuthDigest != current.AuthDigest || removed:
		return Drift{Status: DriftBreaking, Summary: "Provider auth or a selected operation changed incompatibly.", Changes: changes}
	case changed:
		return Drift{Status: DriftBehavioralReview, Summary: "A selected provider operation or generated family mapping changed.", Changes: changes}
	case previous.DocumentDigest != current.DocumentDigest:
		return Drift{Status: DriftAdditive, Summary: "The provider document changed outside selected operations and auth.", Changes: []string{"document.unselected"}}
	default:
		return Drift{Status: DriftUnchanged, Summary: "The provider contract matches the reviewed lock."}
	}
}

// Read decodes a provider contract lock from disk.
func Read(path string) (Lock, error) {
	payload, err := os.ReadFile(path) // #nosec G304 -- operator-provided build-time lock path.
	if err != nil {
		return Lock{}, err
	}
	var lock Lock
	if err := json.Unmarshal(payload, &lock); err != nil {
		return Lock{}, fmt.Errorf("decode provider contract lock %s: %w", path, err)
	}
	if lock.SchemaVersion != SchemaVersion || lock.SourceID == "" || lock.DocumentDigest == "" || lock.AuthDigest == "" {
		return Lock{}, fmt.Errorf("provider contract lock %s is incomplete or unsupported", path)
	}
	return lock, nil
}

// Write atomically writes one provider contract lock.
func Write(path string, lock Lock) error {
	payload, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".provider-contract-lock-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

// Digest returns the deterministic digest used to bind a lock into another
// proof artifact.
func Digest(lock Lock) (string, error) {
	return digestValue(lock)
}

func normalizedDocument(doc *openapi3.T) (map[string]any, []byte, error) {
	payload, err := json.Marshal(doc)
	if err != nil {
		return nil, nil, fmt.Errorf("normalize provider document: %w", err)
	}
	var root map[string]any
	if err := json.Unmarshal(payload, &root); err != nil {
		return nil, nil, fmt.Errorf("decode normalized provider document: %w", err)
	}
	return root, payload, nil
}

func lockOperation(root map[string]any, selection Selection) (OperationLock, error) {
	method := strings.ToUpper(strings.TrimSpace(selection.Method))
	path := strings.TrimSpace(selection.Path)
	pathItem, operation, err := selectedOperation(root, method, path)
	if err != nil {
		return OperationLock{}, err
	}
	references := map[string]any{}
	if err := collectReferences(operation, root, references); err != nil {
		return OperationLock{}, fmt.Errorf("resolve %s %s references: %w", method, path, err)
	}
	if parameters, ok := pathItem["parameters"]; ok {
		if err := collectReferences(parameters, root, references); err != nil {
			return OperationLock{}, fmt.Errorf("resolve %s %s path parameters: %w", method, path, err)
		}
	}
	payload := map[string]any{
		"method":          method,
		"path":            path,
		"operation":       operation,
		"path_parameters": pathItem["parameters"],
		"references":      references,
	}
	digest, err := digestValue(payload)
	if err != nil {
		return OperationLock{}, fmt.Errorf("hash provider operation %s %s: %w", method, path, err)
	}
	operationID := strings.TrimSpace(selection.OperationID)
	if operationID == "" {
		operationID, _ = operation["operationId"].(string)
	}
	return OperationLock{
		FamilyID:    strings.TrimSpace(selection.FamilyID),
		Method:      method,
		Path:        path,
		OperationID: strings.TrimSpace(operationID),
		Digest:      digest,
	}, nil
}

func selectedOperation(root map[string]any, method string, path string) (map[string]any, map[string]any, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	path = strings.TrimSpace(path)
	paths, ok := root["paths"].(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("provider document has no paths")
	}
	pathItem, ok := paths[path].(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("selected provider path %q is missing", path)
	}
	operation, ok := pathItem[strings.ToLower(method)].(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("selected provider operation %s %s is missing", method, path)
	}
	return pathItem, operation, nil
}

func authContract(root map[string]any, selections []Selection) map[string]any {
	operations := map[string]any{}
	for _, selection := range selections {
		_, operation, err := selectedOperation(root, selection.Method, selection.Path)
		if err != nil {
			continue
		}
		if security, ok := operation["security"]; ok {
			operations[operationKey(selection.Method, selection.Path)] = security
		}
	}
	components, _ := root["components"].(map[string]any)
	return map[string]any{
		"global_security":    root["security"],
		"operation_security": operations,
		"security_schemes":   components["securitySchemes"],
	}
}

func collectReferences(value any, root map[string]any, references map[string]any) error {
	switch typed := value.(type) {
	case map[string]any:
		if rawReference, ok := typed["$ref"].(string); ok && strings.HasPrefix(rawReference, "#/") {
			if _, exists := references[rawReference]; !exists {
				resolved, err := resolveLocalReference(root, rawReference)
				if err != nil {
					return err
				}
				references[rawReference] = resolved
				if err := collectReferences(resolved, root, references); err != nil {
					return err
				}
			}
		}
		for _, child := range typed {
			if err := collectReferences(child, root, references); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := collectReferences(child, root, references); err != nil {
				return err
			}
		}
	}
	return nil
}

func resolveLocalReference(root map[string]any, reference string) (any, error) {
	var current any = root
	for _, token := range strings.Split(strings.TrimPrefix(reference, "#/"), "/") {
		token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
		object, ok := current.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("local reference %q crosses a non-object value", reference)
		}
		current, ok = object[token]
		if !ok {
			return nil, fmt.Errorf("local reference %q is missing token %q", reference, token)
		}
	}
	return current, nil
}

func digestValue(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return stampfile.HashReader(bytes.NewReader(payload))
}

func operationMap(operations []OperationLock) map[string]OperationLock {
	result := make(map[string]OperationLock, len(operations))
	for _, operation := range operations {
		result[operationKey(operation.Method, operation.Path)] = operation
	}
	return result
}

func operationKey(method string, path string) string {
	return strings.ToUpper(strings.TrimSpace(method)) + " " + strings.TrimSpace(path)
}
