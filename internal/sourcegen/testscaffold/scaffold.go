// Package testscaffold generates mock HTTP server stubs and integration test
// scaffolds from connector definitions. It uses the definition's resource
// families (paths, methods, response shapes, pagination) to generate realistic
// mock responses and tests that verify the generated source can read from them.
package testscaffold

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/connectordefinitions"
)

// ScaffoldResult holds the generated test scaffold output.
type ScaffoldResult struct {
	MockHandler string
	TestFile    string
	Fixtures    map[string]string // fixture filename -> JSON content
}

// Generate produces a mock handler, test file, and JSON fixtures from a
// connector definition.
func Generate(definition connectordefinitions.Definition) (ScaffoldResult, error) {
	definition, err := connectordefinitions.Normalize(definition)
	if err != nil {
		return ScaffoldResult{}, fmt.Errorf("normalize definition: %w", err)
	}
	if len(definition.ResourceFamilies) == 0 {
		return ScaffoldResult{}, fmt.Errorf("definition has no resource families")
	}

	result := ScaffoldResult{
		Fixtures: make(map[string]string),
	}
	result.MockHandler = renderMockHandler(definition)
	result.TestFile = renderTestFile(definition)
	for _, family := range definition.ResourceFamilies {
		fixture := renderFixture(family)
		result.Fixtures[family.ID+".json"] = fixture
	}
	return result, nil
}

func renderMockHandler(definition connectordefinitions.Definition) string {
	var b strings.Builder
	fmt.Fprintf(&b, "package %s_test\n\n", sanitizePackageName(definition.SourceID))
	fmt.Fprintf(&b, "import (\n")
	fmt.Fprintf(&b, "\t\"encoding/json\"\n")
	fmt.Fprintf(&b, "\t\"net/http\"\n")
	fmt.Fprintf(&b, "\t\"net/http/httptest\"\n")
	fmt.Fprintf(&b, ")\n\n")
	fmt.Fprintf(&b, "// newMockServer returns a test server that responds to all resource family\n")
	fmt.Fprintf(&b, "// endpoints defined in the connector definition for %s.\n", definition.SourceID)
	fmt.Fprintf(&b, "func newMockServer() *httptest.Server {\n")
	fmt.Fprintf(&b, "\tmux := http.NewServeMux()\n")

	// Verification endpoint.
	if definition.Transport != nil && definition.Transport.Verification != nil {
		path := strings.TrimSpace(definition.Transport.Verification.Path)
		if path != "" {
			fmt.Fprintf(&b, "\tmux.HandleFunc(%q, func(w http.ResponseWriter, r *http.Request) {\n", path)
			fmt.Fprintf(&b, "\t\tw.WriteHeader(http.StatusOK)\n")
			fmt.Fprintf(&b, "\t\t_ = json.NewEncoder(w).Encode(map[string]string{\"status\": \"ok\"})\n")
			fmt.Fprintf(&b, "\t})\n")
		}
	}

	for _, family := range definition.ResourceFamilies {
		renderFamilyHandler(&b, family)
	}

	fmt.Fprintf(&b, "\treturn httptest.NewServer(mux)\n")
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

func renderFamilyHandler(b *strings.Builder, family connectordefinitions.ResourceFamily) {
	path := strings.TrimSpace(family.Path)
	if path == "" {
		return
	}
	fmt.Fprintf(b, "\tmux.HandleFunc(%q, func(w http.ResponseWriter, r *http.Request) {\n", path)
	fmt.Fprintf(b, "\t\tif r.Method != %q {\n", strings.ToUpper(firstNonEmpty(family.Method, "GET")))
	fmt.Fprintf(b, "\t\t\tw.WriteHeader(http.StatusMethodNotAllowed)\n")
	fmt.Fprintf(b, "\t\t\treturn\n")
	fmt.Fprintf(b, "\t\t}\n")
	fmt.Fprintf(b, "\t\tw.Header().Set(\"Content-Type\", \"application/json\")\n")
	fmt.Fprintf(b, "\t\t_ = json.NewEncoder(w).Encode(mockResponseFor%s())\n", toPascal(family.ID))
	fmt.Fprintf(b, "\t})\n")
}

func renderTestFile(definition connectordefinitions.Definition) string {
	var b strings.Builder
	pkg := sanitizePackageName(definition.SourceID)
	fmt.Fprintf(&b, "package %s_test\n\n", pkg)
	fmt.Fprintf(&b, "import (\n")
	fmt.Fprintf(&b, "\t\"context\"\n")
	fmt.Fprintf(&b, "\t\"testing\"\n\n")
	fmt.Fprintf(&b, "\t\"github.com/writer/cerebro/internal/sourcecdk\"\n")
	fmt.Fprintf(&b, ")\n\n")
	fmt.Fprintf(&b, "func TestSourceCheck(t *testing.T) {\n")
	fmt.Fprintf(&b, "\tsrv := newMockServer()\n")
	fmt.Fprintf(&b, "\tdefer srv.Close()\n\n")
	fmt.Fprintf(&b, "\tsource, err := New()\n")
	fmt.Fprintf(&b, "\tif err != nil {\n")
	fmt.Fprintf(&b, "\t\tt.Fatalf(\"New: %%v\", err)\n")
	fmt.Fprintf(&b, "\t}\n")
	fmt.Fprintf(&b, "\tsource.allowLoopbackForTest()\n\n")
	fmt.Fprintf(&b, "\tcfg := sourcecdk.Config{\n")
	fmt.Fprintf(&b, "\t\t\"tenant_id\":  \"test-tenant\",\n")
	fmt.Fprintf(&b, "\t\t\"base_url\":   srv.URL,\n")

	// Add auth-specific config.
	switch definition.Auth.Model {
	case "api_key":
		fmt.Fprintf(&b, "\t\t\"api_key\":    \"test-key\",\n")
	case "bearer_token":
		fmt.Fprintf(&b, "\t\t\"token\":      \"test-token\",\n")
	case "basic":
		fmt.Fprintf(&b, "\t\t\"username\":   \"test-user\",\n")
		fmt.Fprintf(&b, "\t\t\"password\":   \"test-password\",\n")
	}

	fmt.Fprintf(&b, "\t}\n\n")
	fmt.Fprintf(&b, "\tif err := source.Check(context.Background(), cfg); err != nil {\n")
	fmt.Fprintf(&b, "\t\tt.Errorf(\"Check: %%v\", err)\n")
	fmt.Fprintf(&b, "\t}\n")
	fmt.Fprintf(&b, "}\n\n")

	// Add Discover test.
	fmt.Fprintf(&b, "func TestSourceDiscover(t *testing.T) {\n")
	fmt.Fprintf(&b, "\tsrv := newMockServer()\n")
	fmt.Fprintf(&b, "\tdefer srv.Close()\n\n")
	fmt.Fprintf(&b, "\tsource, err := New()\n")
	fmt.Fprintf(&b, "\tif err != nil {\n")
	fmt.Fprintf(&b, "\t\tt.Fatalf(\"New: %%v\", err)\n")
	fmt.Fprintf(&b, "\t}\n")
	fmt.Fprintf(&b, "\tsource.allowLoopbackForTest()\n\n")
	fmt.Fprintf(&b, "\tcfg := sourcecdk.Config{\n")
	fmt.Fprintf(&b, "\t\t\"tenant_id\":  \"test-tenant\",\n")
	fmt.Fprintf(&b, "\t\t\"base_url\":   srv.URL,\n")

	switch definition.Auth.Model {
	case "api_key":
		fmt.Fprintf(&b, "\t\t\"api_key\":    \"test-key\",\n")
	case "bearer_token":
		fmt.Fprintf(&b, "\t\t\"token\":      \"test-token\",\n")
	case "basic":
		fmt.Fprintf(&b, "\t\t\"username\":   \"test-user\",\n")
		fmt.Fprintf(&b, "\t\t\"password\":   \"test-password\",\n")
	}

	fmt.Fprintf(&b, "\t}\n\n")
	fmt.Fprintf(&b, "\turns, err := source.Discover(context.Background(), cfg)\n")
	fmt.Fprintf(&b, "\tif err != nil {\n")
	fmt.Fprintf(&b, "\t\tt.Fatalf(\"Discover: %%v\", err)\n")
	fmt.Fprintf(&b, "\t}\n")
	fmt.Fprintf(&b, "\tif len(urns) == 0 {\n")
	fmt.Fprintf(&b, "\t\tt.Error(\"Discover returned no URNs\")\n")
	fmt.Fprintf(&b, "\t}\n")
	fmt.Fprintf(&b, "}\n")

	return b.String()
}

func renderFixture(family connectordefinitions.ResourceFamily) string {
	recordID := fmt.Sprintf("fixture-%s-001", family.ID)
	recordName := fmt.Sprintf("Test %s", toPascal(family.ID))
	record := map[string]any{
		"id":   recordID,
		"name": recordName,
		"type": family.ID,
	}
	idField := strings.TrimSpace(family.IDField)
	if idField != "" {
		setFixtureField(record, idField, recordID)
	}
	nameField := strings.TrimSpace(family.NameField)
	if nameField != "" && fixturePrimaryPath(nameField) != fixturePrimaryPath(idField) {
		setFixtureField(record, nameField, recordName)
	}

	records := []map[string]any{record}

	// Wrap in nested structure matching the record selector path.
	var response any
	selector := strings.TrimSpace(family.RecordSelector)
	if selector != "" && strings.Contains(selector, ".") {
		parts := strings.Split(selector, ".")
		// Skip "$" prefix and collect path segments.
		var keys []string
		for _, p := range parts {
			p = strings.TrimPrefix(p, "$")
			p = strings.TrimSuffix(p, "[*]")
			p = strings.TrimSpace(p)
			if p != "" {
				keys = append(keys, p)
			}
		}
		if len(keys) > 0 {
			// Build nested structure from innermost to outermost.
			var inner any = records
			for i := len(keys) - 1; i >= 0; i-- {
				inner = map[string]any{keys[i]: inner}
			}
			response = inner
		} else {
			response = records
		}
	} else {
		response = records
	}
	payload, _ := json.MarshalIndent(response, "", "  ")
	return string(payload) + "\n"
}

func setFixtureField(record map[string]any, rawPath string, value any) {
	if path := fixturePrimaryPath(rawPath); path != "" {
		setFixturePath(record, strings.Split(path, "."), value)
	}
}

func fixturePrimaryPath(rawPath string) string {
	for _, path := range strings.Split(rawPath, "|") {
		path = strings.TrimSpace(strings.TrimPrefix(path, "$."))
		if path != "" {
			return path
		}
	}
	return ""
}

func setFixturePath(record map[string]any, parts []string, value any) {
	current := record
	for index, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return
		}
		if index == len(parts)-1 {
			current[part] = value
			return
		}
		next, ok := current[part].(map[string]any)
		if !ok {
			next = map[string]any{}
			current[part] = next
		}
		current = next
	}
}

func sanitizePackageName(sourceID string) string {
	return strings.ReplaceAll(strings.ReplaceAll(sourceID, "-", ""), "_", "")
}

func toPascal(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '_' || r == '-' || r == ' '
	})
	var result strings.Builder
	for _, part := range parts {
		if len(part) > 0 {
			result.WriteString(strings.ToUpper(part[:1]) + part[1:])
		}
	}
	return result.String()
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
