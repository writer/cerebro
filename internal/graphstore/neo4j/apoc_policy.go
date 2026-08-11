package neo4j

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	apocCoreCatalogVersion = "5.26"
	maxAPOCTraversalHops   = uint64(6)
	maxAPOCReadRows        = uint64(100)
)

var boundedAPOCProcedures = map[string]struct{}{
	"apoc.neighbors.athop":    {},
	"apoc.neighbors.byhop":    {},
	"apoc.neighbors.tohop":    {},
	"apoc.path.expandconfig":  {},
	"apoc.path.subgraphnodes": {},
}

type apocTokenKind uint8

const (
	apocIdentifier apocTokenKind = iota
	apocString
	apocNumber
	apocSymbol
	apocParameter
)

type apocToken struct {
	kind apocTokenKind
	text string
}

func validateBoundedAPOCProcedureCalls(query string) error {
	tokens := lexAPOCCypher(query)
	for index, token := range tokens {
		if token.kind != apocIdentifier || !strings.EqualFold(token.text, "CALL") {
			continue
		}
		nameIndex := index + 1
		if nameIndex >= len(tokens) || tokens[nameIndex].kind != apocIdentifier {
			continue
		}
		name := strings.ToLower(tokens[nameIndex].text)
		if _, bounded := boundedAPOCProcedures[name]; !bounded {
			continue
		}
		if !validBoundedAPOCInvocation(tokens, nameIndex, maxAPOCReadRows) {
			return fmt.Errorf("read cypher APOC procedure %q violates bounded traversal policy", name)
		}
	}
	return nil
}

func validBoundedAPOCInvocation(tokens []apocToken, nameIndex int, maxRows uint64) bool {
	name := strings.ToLower(tokens[nameIndex].text)
	arguments, closeIndex, ok := apocCallArguments(tokens, nameIndex)
	if !ok {
		return false
	}
	switch name {
	case "apoc.path.expandconfig", "apoc.path.subgraphnodes":
		return validAPOCPathInvocation(name, arguments, tokens, closeIndex, maxRows)
	case "apoc.neighbors.athop", "apoc.neighbors.byhop", "apoc.neighbors.tohop":
		return validAPOCNeighborInvocation(name, arguments, tokens, closeIndex)
	default:
		return false
	}
}

func validAPOCPathInvocation(name string, arguments [][]apocToken, tokens []apocToken, closeIndex int, maxRows uint64) bool {
	if len(arguments) != 2 || !simpleAPOCVariable(arguments[0]) {
		return false
	}
	config, ok := parseAPOCLiteralMap(arguments[1])
	if !ok || !config.hasOnly(
		"bfs",
		"filterstartnode",
		"labelfilter",
		"limit",
		"maxlevel",
		"minlevel",
		"relationshipfilter",
		"uniqueness",
	) {
		return false
	}
	labelFilter, labelOK := config.string("labelfilter")
	uniqueness, uniquenessOK := config.string("uniqueness")
	relationshipFilter, relationshipOK := config.string("relationshipfilter")
	bfs, bfsOK := config.boolean("bfs")
	filterStartNode, filterOK := config.boolean("filterstartnode")
	minLevel, minOK := config.integer("minlevel")
	maxLevel, maxOK := config.integer("maxlevel")
	limit, limitOK := config.integer("limit")
	if !labelOK || labelFilter != "+Entity" ||
		!uniquenessOK || uniqueness != "NODE_GLOBAL" ||
		!relationshipOK || !validAPOCRelationshipFilter(relationshipFilter) ||
		!bfsOK || !bfs || !filterOK || !filterStartNode ||
		!minOK || !maxOK || !limitOK || minLevel > maxLevel ||
		maxLevel == 0 || maxLevel > maxAPOCTraversalHops || limit == 0 || limit > maxRows {
		return false
	}
	if name == "apoc.path.expandconfig" {
		return apocGuardedThenProjected(tokens, closeIndex+1, []string{
			"YIELD", "path", "WHERE", "all", "(", "node", "IN", "nodes", "(", "path", ")",
			"WHERE", "node.tenant_id", "=", "$tenant_id", ")", "AND", "all", "(", "rel", "IN",
			"relationships", "(", "path", ")", "WHERE", "rel.tenant_id", "=", "$tenant_id", ")",
		})
	}
	return apocGuardedThenProjected(tokens, closeIndex+1, []string{
		"YIELD", "node", "WHERE", "node.tenant_id", "=", "$tenant_id",
	})
}

func validAPOCNeighborInvocation(name string, arguments [][]apocToken, tokens []apocToken, closeIndex int) bool {
	if len(arguments) != 3 || !simpleAPOCVariable(arguments[0]) {
		return false
	}
	relationshipFilter, relationshipOK := singleAPOCString(arguments[1])
	distance, distanceOK := singleAPOCInteger(arguments[2])
	if !relationshipOK || !validAPOCRelationshipFilter(relationshipFilter) ||
		!distanceOK || distance == 0 || distance > maxAPOCTraversalHops {
		return false
	}
	if name == "apoc.neighbors.byhop" {
		return apocGuardedThenProjected(tokens, closeIndex+1, []string{
			"YIELD", "nodes", "WHERE", "all", "(", "node", "IN", "nodes", "WHERE",
			"node.tenant_id", "=", "$tenant_id", ")",
		})
	}
	return apocGuardedThenProjected(tokens, closeIndex+1, []string{
		"YIELD", "node", "WHERE", "node.tenant_id", "=", "$tenant_id",
	})
}

func validAPOCRelationshipFilter(value string) bool {
	if value == "" {
		return false
	}
	for _, part := range strings.Split(value, "|") {
		part = strings.TrimSpace(part)
		name := strings.TrimPrefix(part, "<")
		if name == part {
			name = strings.TrimSuffix(part, ">")
		}
		if !strings.EqualFold(name, "RELATION") {
			return false
		}
		for _, character := range name {
			if (character < 'a' || character > 'z') &&
				(character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '_' {
				return false
			}
		}
	}
	return true
}

func apocGuardedThenProjected(tokens []apocToken, start int, expected []string) bool {
	if start+len(expected) >= len(tokens) {
		return false
	}
	for offset, text := range expected {
		if !strings.EqualFold(tokens[start+offset].text, text) {
			return false
		}
	}
	next := tokens[start+len(expected)].text
	return strings.EqualFold(next, "WITH") || strings.EqualFold(next, "RETURN")
}

func simpleAPOCVariable(tokens []apocToken) bool {
	return len(tokens) == 1 && tokens[0].kind == apocIdentifier && !strings.Contains(tokens[0].text, ".")
}

func singleAPOCString(tokens []apocToken) (string, bool) {
	if len(tokens) != 1 || tokens[0].kind != apocString {
		return "", false
	}
	return tokens[0].text, true
}

func singleAPOCInteger(tokens []apocToken) (uint64, bool) {
	if len(tokens) != 1 || tokens[0].kind != apocNumber || strings.Contains(tokens[0].text, ".") {
		return 0, false
	}
	value, err := strconv.ParseUint(tokens[0].text, 10, 64)
	return value, err == nil
}

func apocCallArguments(tokens []apocToken, nameIndex int) ([][]apocToken, int, bool) {
	if nameIndex+1 >= len(tokens) || tokens[nameIndex+1].text != "(" {
		return nil, 0, false
	}
	stack := make([]string, 0, 4)
	arguments := make([][]apocToken, 0, 4)
	start := nameIndex + 2
	for index := start; index < len(tokens); index++ {
		switch tokens[index].text {
		case "(", "[", "{":
			stack = append(stack, tokens[index].text)
		case ")":
			if len(stack) == 0 {
				if index > start || len(arguments) > 0 {
					arguments = append(arguments, tokens[start:index])
				}
				return arguments, index, true
			}
			if stack[len(stack)-1] != "(" {
				return nil, 0, false
			}
			stack = stack[:len(stack)-1]
		case "]":
			if len(stack) == 0 || stack[len(stack)-1] != "[" {
				return nil, 0, false
			}
			stack = stack[:len(stack)-1]
		case "}":
			if len(stack) == 0 || stack[len(stack)-1] != "{" {
				return nil, 0, false
			}
			stack = stack[:len(stack)-1]
		case ",":
			if len(stack) == 0 {
				if index == start {
					return nil, 0, false
				}
				arguments = append(arguments, tokens[start:index])
				start = index + 1
			}
		}
	}
	return nil, 0, false
}

type apocLiteralMap map[string][]apocToken

func parseAPOCLiteralMap(tokens []apocToken) (apocLiteralMap, bool) {
	if len(tokens) < 2 || tokens[0].text != "{" || tokens[len(tokens)-1].text != "}" {
		return nil, false
	}
	result := make(apocLiteralMap)
	start := 1
	depth := 0
	push := func(entry []apocToken) bool {
		if len(entry) < 3 || (entry[0].kind != apocIdentifier && entry[0].kind != apocString) || entry[1].text != ":" {
			return false
		}
		key := strings.ToLower(entry[0].text)
		if _, exists := result[key]; exists {
			return false
		}
		result[key] = entry[2:]
		return true
	}
	for index := 1; index < len(tokens)-1; index++ {
		switch tokens[index].text {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			depth--
			if depth < 0 {
				return nil, false
			}
		case ",":
			if depth == 0 {
				if !push(tokens[start:index]) {
					return nil, false
				}
				start = index + 1
			}
		}
	}
	if start < len(tokens)-1 && !push(tokens[start:len(tokens)-1]) {
		return nil, false
	}
	return result, len(result) > 0
}

func (config apocLiteralMap) hasOnly(keys ...string) bool {
	if len(config) == 0 {
		return false
	}
	for key := range config {
		found := false
		for _, allowed := range keys {
			if key == allowed {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (config apocLiteralMap) string(key string) (string, bool) {
	return singleAPOCString(config[key])
}

func (config apocLiteralMap) integer(key string) (uint64, bool) {
	return singleAPOCInteger(config[key])
}

func (config apocLiteralMap) boolean(key string) (bool, bool) {
	value := config[key]
	if len(value) != 1 || value[0].kind != apocIdentifier {
		return false, false
	}
	switch strings.ToLower(value[0].text) {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

func lexAPOCCypher(query string) []apocToken {
	tokens := make([]apocToken, 0, len(query)/4)
	for index := 0; index < len(query); {
		character := query[index]
		switch {
		case character == ' ' || character == '\t' || character == '\n' || character == '\r':
			index++
		case index+1 < len(query) && query[index:index+2] == "//":
			index += 2
			for index < len(query) && query[index] != '\n' && query[index] != '\r' {
				index++
			}
		case index+1 < len(query) && query[index:index+2] == "/*":
			index += 2
			for index+1 < len(query) && query[index:index+2] != "*/" {
				index++
			}
			if index+1 < len(query) {
				index += 2
			}
		case character == '\'' || character == '"':
			text, end := readAPOCQuoted(query, index, character)
			tokens = append(tokens, apocToken{kind: apocString, text: text})
			index = end
		case character == '`':
			text, end := readAPOCQuoted(query, index, character)
			tokens = append(tokens, apocToken{kind: apocIdentifier, text: text})
			index = end
		case character == '$':
			start := index
			index++
			for index < len(query) && apocIdentifierByte(query[index]) {
				index++
			}
			tokens = append(tokens, apocToken{kind: apocParameter, text: query[start:index]})
		case apocIdentifierStart(character):
			start := index
			for index < len(query) && (apocIdentifierByte(query[index]) || query[index] == '.') {
				index++
			}
			tokens = append(tokens, apocToken{kind: apocIdentifier, text: query[start:index]})
		case character >= '0' && character <= '9':
			start := index
			for index < len(query) && ((query[index] >= '0' && query[index] <= '9') || query[index] == '.') {
				index++
			}
			tokens = append(tokens, apocToken{kind: apocNumber, text: query[start:index]})
		default:
			tokens = append(tokens, apocToken{kind: apocSymbol, text: query[index : index+1]})
			index++
		}
	}
	return tokens
}

func readAPOCQuoted(query string, start int, quote byte) (string, int) {
	var value strings.Builder
	for index := start + 1; index < len(query); index++ {
		if query[index] == '\\' && quote != '`' && index+1 < len(query) {
			index++
			value.WriteByte(query[index])
			continue
		}
		if query[index] != quote {
			value.WriteByte(query[index])
			continue
		}
		if index+1 < len(query) && query[index+1] == quote {
			value.WriteByte(quote)
			index++
			continue
		}
		return value.String(), index + 1
	}
	return value.String(), len(query)
}

func apocIdentifierStart(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || value == '_'
}

func apocIdentifierByte(value byte) bool {
	return apocIdentifierStart(value) || (value >= '0' && value <= '9')
}
