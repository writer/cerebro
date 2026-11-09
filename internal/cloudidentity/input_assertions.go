package cloudidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	k8syaml "sigs.k8s.io/yaml"
)

// InputAssertion is a plan-generator-supplied fact about a pinned input --
// a file's content digest, a directory's immediate entries, a statically
// evaluable HCL attribute, or a parsed YAML/JSON value -- checked once per
// run against the input actually materialized at Source. The generator
// derives Expected from its own (possibly private) view of the input; this
// package never knows or assumes anything about that view, only how to
// re-read the pinned input generically and compare.
type InputAssertion struct {
	Source    SourcePin       `json:"source"`
	Path      string          `json:"path"`
	Kind      string          `json:"kind"`
	Digest    string          `json:"digest,omitempty"`
	Pattern   string          `json:"pattern,omitempty"`
	Block     string          `json:"block,omitempty"`
	Attribute string          `json:"attribute,omitempty"`
	Selector  string          `json:"selector,omitempty"`
	KeysOnly  bool            `json:"keys_only,omitempty"`
	Fields    []string        `json:"fields,omitempty"`
	Expected  json.RawMessage `json:"expected,omitempty"`
}

// InputAssertionFailedGapCode is the gap code callers attach when
// VerifyInputAssertion fails; this package never constructs gaps itself, so
// it never decides a gap's Scope (callers scope it to the declaring target).
const InputAssertionFailedGapCode = "cloud_identity.input_assertion_failed"

var inputAssertionDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidateInputAssertion performs static shape checks only; it never reads
// any file or repository.
func ValidateInputAssertion(a InputAssertion) error {
	switch a.Kind {
	case "file_digest", "directory_entries", "hcl_value", "data_value":
	default:
		return fmt.Errorf("unknown input assertion kind %q", a.Kind)
	}
	if a.Source.Repository == "" {
		return fmt.Errorf("source.repository is required")
	}
	if a.Source.Revision == "" {
		return fmt.Errorf("source.revision is required")
	}
	if a.Source.Root != "" {
		return fmt.Errorf("source.root must be empty")
	}
	if err := validateInputAssertionPath(a.Kind, a.Path); err != nil {
		return err
	}
	if a.Block != "" && a.Block != "locals" {
		return fmt.Errorf("block must be \"\" or \"locals\", got %q", a.Block)
	}
	if a.Pattern != "" {
		if _, err := path.Match(a.Pattern, ""); err != nil {
			return fmt.Errorf("pattern %q is not a valid path.Match pattern: %w", a.Pattern, err)
		}
	}
	if a.KeysOnly && len(a.Fields) > 0 {
		return fmt.Errorf("keys_only and fields are mutually exclusive")
	}
	if len(a.Fields) > 0 && a.Kind != "data_value" {
		return fmt.Errorf("fields is only valid for kind %q, got %q", "data_value", a.Kind)
	}
	for _, f := range a.Fields {
		if f == "" {
			return fmt.Errorf("fields must not contain empty strings")
		}
	}
	switch a.Kind {
	case "file_digest":
		if !inputAssertionDigestPattern.MatchString(a.Digest) {
			return fmt.Errorf("digest must be 64 lowercase hex characters, got %q", a.Digest)
		}
	case "directory_entries":
		if len(a.Expected) == 0 {
			return fmt.Errorf("expected is required for kind %q", a.Kind)
		}
		var entries []string
		if err := json.Unmarshal(a.Expected, &entries); err != nil {
			return fmt.Errorf("expected must be an array of strings for kind %q: %w", a.Kind, err)
		}
	case "hcl_value":
		if a.Attribute == "" {
			return fmt.Errorf("attribute is required for kind %q", a.Kind)
		}
		if len(a.Expected) == 0 {
			return fmt.Errorf("expected is required for kind %q", a.Kind)
		}
		var v any
		if err := json.Unmarshal(a.Expected, &v); err != nil {
			return fmt.Errorf("expected is not valid JSON: %w", err)
		}
	case "data_value":
		if len(a.Expected) == 0 {
			return fmt.Errorf("expected is required for kind %q", a.Kind)
		}
		var v any
		if err := json.Unmarshal(a.Expected, &v); err != nil {
			return fmt.Errorf("expected is not valid JSON: %w", err)
		}
	}
	return nil
}

// validateInputAssertionPath enforces a clean, relative, repository-scoped
// path with no ".." segments. Only directory_entries may use "" to mean the
// repository root.
func validateInputAssertionPath(kind, p string) error {
	if p == "" {
		if kind == "directory_entries" {
			return nil
		}
		return fmt.Errorf("path is required for kind %q", kind)
	}
	if strings.HasPrefix(p, "/") {
		return fmt.Errorf("path %q must be relative", p)
	}
	cleaned := path.Clean(p)
	if cleaned != p || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return fmt.Errorf("path %q must be a clean repository-relative path with no \"..\" segments", p)
	}
	return nil
}

// VerifyInputAssertion is pure: it never performs I/O itself, only inspects
// repo (already materialized by the caller through the run's shared
// repository cache). It returns a Reference to the inspected input and a
// non-nil error when the assertion does not hold.
func VerifyInputAssertion(repo Repository, a InputAssertion) (Reference, error) {
	ref := Reference{Repository: repo.Pin.Repository, Revision: repo.Pin.Revision, Path: a.Path}
	switch a.Kind {
	case "file_digest":
		file, err := findInputAssertionFile(repo, a.Path)
		if err != nil {
			return ref, err
		}
		ref.Digest = file.Digest
		return ref, verifyFileDigestAssertion(file, a)
	case "directory_entries":
		return ref, verifyDirectoryEntriesAssertion(repo, a)
	case "hcl_value":
		file, err := findInputAssertionFile(repo, a.Path)
		if err != nil {
			return ref, err
		}
		ref.Digest = file.Digest
		return ref, verifyHCLValueAssertion(file, a)
	case "data_value":
		file, err := findInputAssertionFile(repo, a.Path)
		if err != nil {
			return ref, err
		}
		ref.Digest = file.Digest
		return ref, verifyDataValueAssertion(file, a)
	default:
		return ref, fmt.Errorf("unknown input assertion kind %q", a.Kind)
	}
}

func findInputAssertionFile(repo Repository, p string) (SourceFile, error) {
	for _, f := range repo.Files {
		if f.Path == p {
			return f, nil
		}
	}
	return SourceFile{}, fmt.Errorf("%q was not found among the pinned repository's materialized files", p)
}

func verifyFileDigestAssertion(file SourceFile, a InputAssertion) error {
	sum := sha256.Sum256(file.Content)
	got := hex.EncodeToString(sum[:])
	if got != a.Digest {
		return fmt.Errorf("sha256 %s disagrees with the asserted digest %s", got, a.Digest)
	}
	return nil
}

// verifyDirectoryEntriesAssertion lists the immediate children of a.Path
// among repo.Files and compares them to a.Expected as a sorted set. If
// repo.Gaps records that the repository read skipped files under this
// path's own top-level scope on budget, the listing cannot be trusted and
// the assertion fails as indeterminate rather than silently passing or
// failing on an incomplete view.
func verifyDirectoryEntriesAssertion(repo Repository, a InputAssertion) error {
	// Scope mirrors topLevelPathScope in
	// sources/internal/cloudidentity/repository_reader.go, which that
	// package's repositoryGapAccumulator uses to scope
	// "repository.budget_exceeded" gaps; this package cannot import that
	// internal reader package, so the string derivation is duplicated here.
	// Every top-level scope is a root entry, so a root listing (Path "")
	// is indeterminate after any budget skip.
	scope := inputAssertionTopLevelPathScope(a.Path)
	for _, gap := range repo.Gaps {
		if gap.Code == "repository.budget_exceeded" && (a.Path == "" || gap.Scope == scope) {
			return fmt.Errorf("directory listing under %q is indeterminate: the repository read exceeded its budget under scope %q", a.Path, gap.Scope)
		}
	}
	observed := inputAssertionDirectoryEntries(repo.Files, a.Path, a.Pattern)
	var expected []string
	if err := json.Unmarshal(a.Expected, &expected); err != nil {
		return fmt.Errorf("expected is not an array of strings: %w", err)
	}
	if !inputAssertionEqualSets(observed, expected) {
		return fmt.Errorf("observed entries %v disagree with expected entries %v", observed, expected)
	}
	return nil
}

func inputAssertionTopLevelPathScope(relPath string) string {
	if idx := strings.Index(relPath, "/"); idx >= 0 {
		return relPath[:idx]
	}
	return relPath
}

func inputAssertionDirectoryEntries(files []SourceFile, dir, pattern string) []string {
	var prefix string
	if dir != "" {
		prefix = dir + "/"
	}
	seen := map[string]bool{}
	for _, f := range files {
		rel := f.Path
		if prefix != "" {
			if !strings.HasPrefix(rel, prefix) {
				continue
			}
			rel = rel[len(prefix):]
		}
		if rel == "" {
			continue
		}
		name := rel
		isDir := false
		if idx := strings.Index(rel, "/"); idx >= 0 {
			name = rel[:idx]
			isDir = true
		}
		if pattern != "" {
			if matched, _ := path.Match(pattern, name); !matched {
				continue
			}
		}
		if isDir {
			seen[name+"/"] = true
		} else {
			seen[name] = true
		}
	}
	out := make([]string, 0, len(seen))
	for entry := range seen {
		out = append(out, entry)
	}
	sort.Strings(out)
	return out
}

func inputAssertionEqualSets(a, b []string) bool {
	return reflect.DeepEqual(inputAssertionSortedSet(a), inputAssertionSortedSet(b))
}

func inputAssertionSortedSet(items []string) []string {
	seen := map[string]bool{}
	for _, s := range items {
		seen[s] = true
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func verifyHCLValueAssertion(file SourceFile, a InputAssertion) error {
	parsed, diags := hclsyntax.ParseConfig(file.Content, a.Path, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return fmt.Errorf("%s is not valid HCL: %s", a.Path, diags.Error())
	}
	if parsed == nil {
		return fmt.Errorf("%s has no statically parseable body", a.Path)
	}
	body, ok := parsed.Body.(*hclsyntax.Body)
	if !ok {
		return fmt.Errorf("%s has no statically parseable body", a.Path)
	}
	attr, err := findInputAssertionHCLAttribute(body, a.Block, a.Attribute)
	if err != nil {
		return fmt.Errorf("%s: %w", a.Path, err)
	}
	value, diags := attr.Expr.Value(nil)
	if diags.HasErrors() {
		return fmt.Errorf("%s attribute %q is not a static literal: %s", a.Path, a.Attribute, diags.Error())
	}
	converted, err := inputAssertionCtyToGo(value)
	if err != nil {
		return fmt.Errorf("%s attribute %q: %w", a.Path, a.Attribute, err)
	}
	var segments []string
	if a.Selector != "" {
		segments = strings.Split(a.Selector, ".")
	}
	selected, err := selectInputAssertionValue(converted, segments)
	if err != nil {
		return fmt.Errorf("%s attribute %q selector %q: %w", a.Path, a.Attribute, a.Selector, err)
	}
	var got any
	if a.KeysOnly {
		keys, err := inputAssertionKeysOnly(selected)
		if err != nil {
			return fmt.Errorf("%s attribute %q selector %q: %w", a.Path, a.Attribute, a.Selector, err)
		}
		got = keys
	} else {
		got = selected
	}
	return compareInputAssertionValue(got, a.Expected, fmt.Sprintf("%s attribute %q selector %q", a.Path, a.Attribute, a.Selector))
}

// findInputAssertionHCLAttribute locates either a top-level attribute
// (block "") or an attribute inside a top-level `locals { ... }` block
// (block "locals") by exact name.
func findInputAssertionHCLAttribute(body *hclsyntax.Body, block, attribute string) (*hclsyntax.Attribute, error) {
	switch block {
	case "":
		attr, ok := body.Attributes[attribute]
		if !ok {
			return nil, fmt.Errorf("declares no top-level attribute %q", attribute)
		}
		return attr, nil
	case "locals":
		for _, b := range body.Blocks {
			if b.Type != "locals" {
				continue
			}
			if attr, ok := b.Body.Attributes[attribute]; ok {
				return attr, nil
			}
		}
		return nil, fmt.Errorf("declares no locals attribute %q", attribute)
	default:
		return nil, fmt.Errorf("unknown block %q", block)
	}
}

// inputAssertionCtyToGo converts a static HCL literal value into a plain Go
// value (map[string]any/[]any/string/float64/bool/nil) for canonical JSON
// comparison. Capsule, unknown and non-literal types never reach here:
// attr.Expr.Value(nil) already rejected anything that needed an
// EvalContext to resolve (a variable, data source, or function call).
func inputAssertionCtyToGo(value cty.Value) (any, error) {
	if value.IsNull() {
		return nil, nil
	}
	t := value.Type()
	switch {
	case t == cty.String:
		return value.AsString(), nil
	case t == cty.Bool:
		return value.True(), nil
	case t == cty.Number:
		f, _ := value.AsBigFloat().Float64()
		return f, nil
	case t.IsObjectType() || t.IsMapType():
		entries := value.AsValueMap()
		out := make(map[string]any, len(entries))
		for key, entry := range entries {
			converted, err := inputAssertionCtyToGo(entry)
			if err != nil {
				return nil, err
			}
			out[key] = converted
		}
		return out, nil
	case t.IsListType() || t.IsTupleType() || t.IsSetType():
		out := []any{}
		for it := value.ElementIterator(); it.Next(); {
			_, element := it.Element()
			converted, err := inputAssertionCtyToGo(element)
			if err != nil {
				return nil, err
			}
			out = append(out, converted)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported HCL value type %s", t.FriendlyName())
	}
}

func verifyDataValueAssertion(file SourceFile, a InputAssertion) error {
	jsonBytes, err := k8syaml.YAMLToJSON(file.Content)
	if err != nil {
		return fmt.Errorf("%s is not valid YAML/JSON: %w", a.Path, err)
	}
	var parsed any
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		return fmt.Errorf("%s: decoding parsed value: %w", a.Path, err)
	}
	var segments []string
	if a.Selector != "" {
		segments = strings.Split(a.Selector, ".")
	}
	selected, err := selectInputAssertionValue(parsed, segments)
	if err != nil {
		return fmt.Errorf("%s selector %q: %w", a.Path, a.Selector, err)
	}
	var got any
	switch {
	case a.KeysOnly:
		keys, err := inputAssertionKeysOnly(selected)
		if err != nil {
			return fmt.Errorf("%s selector %q: %w", a.Path, a.Selector, err)
		}
		got = keys
	case len(a.Fields) > 0:
		fields, err := inputAssertionFieldsProjection(selected, a.Fields)
		if err != nil {
			return fmt.Errorf("%s selector %q: %w", a.Path, a.Selector, err)
		}
		got = fields
	default:
		got = selected
	}
	return compareInputAssertionValue(got, a.Expected, fmt.Sprintf("%s selector %q", a.Path, a.Selector))
}

// selectInputAssertionValue narrows value by segments over a plain
// JSON-compatible Go value (map[string]any, []any, scalars, nil): a literal
// segment is an object key lookup; "*" iterates every entry of an object
// (narrowing each by the remaining segments and keying the result the same
// way, so key identity is never lost) or every element of a list (narrowing
// each by the remaining segments, preserving order). A final segment naming
// a key an object does not declare resolves to JSON null rather than an
// error -- the one way an assertion can prove a key's absence; any
// non-final missing key, or a literal segment applied to a list or scalar,
// still errors, since there is no object left to keep narrowing.
func selectInputAssertionValue(value any, segments []string) (any, error) {
	if len(segments) == 0 {
		return value, nil
	}
	seg, rest := segments[0], segments[1:]
	if value == nil {
		return nil, fmt.Errorf("value is null before selector segment %q", seg)
	}
	if seg == "*" {
		switch v := value.(type) {
		case map[string]any:
			out := make(map[string]any, len(v))
			for key, entry := range v {
				selected, err := selectInputAssertionValue(entry, rest)
				if err != nil {
					return nil, err
				}
				out[key] = selected
			}
			return out, nil
		case []any:
			out := make([]any, len(v))
			for i, entry := range v {
				selected, err := selectInputAssertionValue(entry, rest)
				if err != nil {
					return nil, err
				}
				out[i] = selected
			}
			return out, nil
		default:
			return nil, fmt.Errorf("wildcard segment requires an object or list, got %T", value)
		}
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("selector segment %q requires an object, got %T", seg, value)
	}
	entry, ok := obj[seg]
	if !ok {
		if len(rest) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("object has no key %q", seg)
	}
	return selectInputAssertionValue(entry, rest)
}

func inputAssertionKeysOnly(value any) ([]string, error) {
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("keys_only requires an object, got %T", value)
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

func inputAssertionFieldsProjection(value any, fields []string) (any, error) {
	switch v := value.(type) {
	case map[string]any:
		return inputAssertionProjectFields(v, fields), nil
	case []any:
		out := make([]any, len(v))
		for i, entry := range v {
			obj, ok := entry.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("fields requires each list element to be an object, got %T", entry)
			}
			out[i] = inputAssertionProjectFields(obj, fields)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("fields requires an object or a list of objects, got %T", value)
	}
}

func inputAssertionProjectFields(obj map[string]any, fields []string) map[string]any {
	out := make(map[string]any, len(fields))
	for _, f := range fields {
		if v, ok := obj[f]; ok {
			out[f] = v
		} else {
			out[f] = nil
		}
	}
	return out
}

// compareInputAssertionValue compares got against expected by value (never
// byte-for-byte: the plan's own JSON key order/number formatting is never
// guaranteed to match what this package's own json.Marshal produces).
func compareInputAssertionValue(got any, expected json.RawMessage, context string) error {
	gotJSON, err := json.Marshal(got)
	if err != nil {
		return fmt.Errorf("encoding observed value: %w", err)
	}
	var gotAny, expectedAny any
	if err := json.Unmarshal(gotJSON, &gotAny); err != nil {
		return fmt.Errorf("decoding observed value: %w", err)
	}
	if err := json.Unmarshal(expected, &expectedAny); err != nil {
		return fmt.Errorf("decoding expected value: %w", err)
	}
	if !reflect.DeepEqual(gotAny, expectedAny) {
		return fmt.Errorf("%s: observed %s disagrees with expected %s", context, gotJSON, expected)
	}
	return nil
}
