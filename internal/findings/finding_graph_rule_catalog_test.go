package findings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestRustFindingGraphRuleCatalogMatchesGoSemantics(t *testing.T) {
	sources := []string{"graph", "grc", "github", "okta", "aws", "azure", "gcp", "sentinelone", "vulnview", "cosmo"}
	families := []string{"", "integration", "control_test", "document", "person", "vulnerability", "user", "iam_role_assignment", "effective_permission", "audit", "group_membership", "role_assignment", "public_endpoint", "resource_exposure", "ecs_service", "threat_insight", "authenticator", "org_inventory", "agent", "threat", "dns_alert", "application", "survey_feedback", "message", "crown_jewel", "data_sensitivity", "service_account", "access_key", "admin_role", "directory_role_assignment", "app_role_assignment"}
	type entry struct {
		Query      string            `json:"query"`
		RowLimit   int               `json:"row_limit"`
		ParamTypes map[string]string `json:"param_types"`
	}
	entries := map[string]entry{}
	ids := make([]string, 0, len(Builtin().rules))
	for id := range Builtin().rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		rule, ok := Builtin().rules[id].(GraphRule)
		if !ok {
			continue
		}
		for _, source := range sources {
			for _, family := range families {
				runtime := &cerebrov1.SourceRuntime{Id: "writer-runtime", TenantId: "writer", SourceId: source, Config: map[string]string{"family": family}}
				if !rule.SupportsRuntime(runtime) {
					continue
				}
				request := rule.QueryFor(runtime)
				if request.Query == "" {
					continue
				}
				types := map[string]string{}
				for key, value := range request.Params {
					switch value.(type) {
					case string:
						types[key] = "string"
					case int, int32, int64, uint, uint32, uint64:
						types[key] = "integer"
					case bool:
						types[key] = "boolean"
					case []string:
						types[key] = "string_list"
					default:
						t.Fatalf("rule %s param %s has unsupported type %T", id, key, value)
					}
				}
				entries[id] = entry{Query: request.Query, RowLimit: request.RowLimit, ParamTypes: types}
				break
			}
			if _, found := entries[id]; found {
				break
			}
		}
		if retiredGraphRule(rule) {
			continue
		}
		if _, found := entries[id]; !found {
			request := rule.QueryFor(&cerebrov1.SourceRuntime{TenantId: "writer"})
			if request.Query != "" {
				types := map[string]string{}
				for key, value := range request.Params {
					switch value.(type) {
					case string:
						types[key] = "string"
					case int, int32, int64, uint, uint32, uint64:
						types[key] = "integer"
					case bool:
						types[key] = "boolean"
					case []string:
						types[key] = "string_list"
					default:
						t.Fatalf("rule %s param %s has unsupported type %T", id, key, value)
					}
				}
				entries[id] = entry{Query: request.Query, RowLimit: request.RowLimit, ParamTypes: types}
			}
		}
		if _, found := entries[id]; !found {
			t.Fatalf("no representative runtime found for graph rule %s", id)
		}
	}
	payload, err := os.ReadFile(filepath.Join("..", "..", "crates", "organizational-store", "src", "finding_graph_rule_catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]entry{}
	if err := json.Unmarshal(payload, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(entries, want) {
		t.Fatal("Rust finding graph rule catalog drifted from registered Go rule semantics")
	}
}

// Neo4j only rejects a malformed rule when the runtime executes it, so catch
// mismatched delimiters (for example an EXISTS { ... ) subquery) here.
func TestFindingGraphRuleQueriesHaveBalancedDelimiters(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "..", "crates", "organizational-store", "src", "finding_graph_rule_catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	var catalog map[string]struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(payload, &catalog); err != nil {
		t.Fatal(err)
	}
	for id, rule := range catalog {
		if err := cypherDelimiterError(rule.Query); err != "" {
			t.Errorf("graph rule %s: %s", id, err)
		}
	}
}

func TestCypherDelimiterErrorFindsMismatchedSubquery(t *testing.T) {
	for query, want := range map[string]bool{
		"MATCH (n) WHERE NOT EXISTS { MATCH (n)-[:R]->(m) } RETURN n": false,
		"MATCH (n) WHERE NOT EXISTS { MATCH (n)-[:R]->(m) ) RETURN n": true,
		"MATCH (n {name: '}'}) RETURN [x IN n.xs | x]":                false,
		"MATCH (n) RETURN n.a + \"(\" AS label":                       false,
		"MATCH (n RETURN n":                                           true,
	} {
		if got := cypherDelimiterError(query) != ""; got != want {
			t.Errorf("cypherDelimiterError(%q) reported=%t, want %t", query, got, want)
		}
	}
}

func cypherDelimiterError(query string) string {
	closers := map[rune]rune{')': '(', ']': '[', '}': '{'}
	var stack []rune
	var quote rune
	for offset, char := range query {
		if quote != 0 {
			if char == quote {
				quote = 0
			}
			continue
		}
		switch char {
		case '\'', '"', '`':
			quote = char
		case '(', '[', '{':
			stack = append(stack, char)
		case ')', ']', '}':
			if len(stack) == 0 || stack[len(stack)-1] != closers[char] {
				return "unexpected " + string(char) + " at offset " + strconv.Itoa(offset)
			}
			stack = stack[:len(stack)-1]
		}
	}
	if quote != 0 {
		return "unterminated string literal"
	}
	if len(stack) > 0 {
		return "unclosed " + string(stack[len(stack)-1])
	}
	return ""
}
