package graph

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// GraphPattern describes a structural motif to match in the graph.
type GraphPattern struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description,omitempty"`
	Severity    string             `json:"severity,omitempty"`
	Nodes       []PatternNode      `json:"nodes"`
	Edges       []PatternEdge      `json:"edges,omitempty"`
	Conditions  []PatternCondition `json:"conditions,omitempty"`
}

// PatternNode defines constraints for one pattern alias.
type PatternNode struct {
	Alias      string         `json:"alias"`
	Kind       NodeKind       `json:"kind,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// PatternEdge defines one directed edge requirement between aliases.
type PatternEdge struct {
	Source string   `json:"source"`
	Target string   `json:"target"`
	Kind   EdgeKind `json:"kind,omitempty"`
}

// PatternCondition adds boolean constraints evaluated over alias bindings.
type PatternCondition struct {
	Expression string `json:"expression"`
}

// PatternMatch captures one set of alias bindings satisfying a pattern.
type PatternMatch struct {
	Bindings map[string]*Node `json:"bindings"`
	Edges    []*Edge          `json:"edges"`
	Score    float64          `json:"score"`
}

// FindPattern returns all motif matches for the provided pattern.
func (g *Graph) FindPattern(pattern *GraphPattern) []PatternMatch {
	if pattern == nil || len(pattern.Nodes) == 0 {
		return nil
	}

	aliasOrder := make([]string, 0, len(pattern.Nodes))
	nodeByAlias := make(map[string]PatternNode, len(pattern.Nodes))
	for _, node := range pattern.Nodes {
		alias := strings.TrimSpace(node.Alias)
		if alias == "" {
			return nil
		}
		if _, ok := nodeByAlias[alias]; ok {
			return nil
		}
		node.Alias = alias
		aliasOrder = append(aliasOrder, alias)
		nodeByAlias[alias] = node
	}

	for _, edge := range pattern.Edges {
		if _, ok := nodeByAlias[strings.TrimSpace(edge.Source)]; !ok {
			return nil
		}
		if _, ok := nodeByAlias[strings.TrimSpace(edge.Target)]; !ok {
			return nil
		}
	}

	allNodes := g.GetAllNodes()
	if len(allNodes) == 0 {
		return nil
	}

	candidates := make(map[string][]*Node, len(aliasOrder))
	for _, alias := range aliasOrder {
		nodePattern := nodeByAlias[alias]
		candidateSet := make([]*Node, 0, len(allNodes))
		for _, node := range allNodes {
			if patternNodeMatches(node, nodePattern, nil, true) {
				candidateSet = append(candidateSet, node)
			}
		}
		if len(candidateSet) == 0 {
			return nil
		}
		candidates[alias] = candidateSet
	}

	matches := make([]PatternMatch, 0)
	seen := make(map[string]struct{})
	bindings := make(map[string]*Node, len(aliasOrder))
	used := make(map[string]struct{}, len(aliasOrder))

	var search func(idx int)
	search = func(idx int) {
		if idx >= len(aliasOrder) {
			edges, ok := g.collectPatternEdges(bindings, pattern)
			if !ok {
				return
			}
			if !evaluatePatternConditions(pattern.Conditions, bindings) {
				return
			}

			bindingCopy := make(map[string]*Node, len(bindings))
			for alias, node := range bindings {
				bindingCopy[alias] = node
			}
			key := patternBindingKey(bindingCopy)
			if _, exists := seen[key]; exists {
				return
			}
			seen[key] = struct{}{}

			score := float64(len(bindingCopy)*10 + len(edges)*5 + len(pattern.Conditions)*2)
			matches = append(matches, PatternMatch{
				Bindings: bindingCopy,
				Edges:    edges,
				Score:    score,
			})
			return
		}

		alias := aliasOrder[idx]
		nodePattern := nodeByAlias[alias]
		for _, node := range candidates[alias] {
			if _, taken := used[node.ID]; taken {
				continue
			}
			if !patternNodeMatches(node, nodePattern, bindings, false) {
				continue
			}

			bindings[alias] = node
			used[node.ID] = struct{}{}
			if g.partialPatternFeasible(bindings, pattern) {
				search(idx + 1)
			}
			delete(bindings, alias)
			delete(used, node.ID)
		}
	}

	search(0)

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Score == matches[j].Score {
			return patternBindingKey(matches[i].Bindings) < patternBindingKey(matches[j].Bindings)
		}
		return matches[i].Score > matches[j].Score
	})
	return matches
}

func (g *Graph) partialPatternFeasible(bindings map[string]*Node, pattern *GraphPattern) bool {
	for _, nodePattern := range pattern.Nodes {
		node, bound := bindings[nodePattern.Alias]
		if !bound {
			continue
		}
		if !patternNodeMatches(node, nodePattern, bindings, false) {
			return false
		}
	}

	for _, edgePattern := range pattern.Edges {
		src, srcBound := bindings[edgePattern.Source]
		tgt, tgtBound := bindings[edgePattern.Target]
		if !srcBound || !tgtBound {
			continue
		}
		if len(findMatchingPatternEdges(g.GetOutEdges(src.ID), tgt.ID, edgePattern.Kind)) == 0 {
			return false
		}
	}

	return true
}

func (g *Graph) collectPatternEdges(bindings map[string]*Node, pattern *GraphPattern) ([]*Edge, bool) {
	if len(pattern.Edges) == 0 {
		return nil, true
	}

	edges := make([]*Edge, 0, len(pattern.Edges))
	seen := make(map[*Edge]struct{})
	for _, edgePattern := range pattern.Edges {
		src := bindings[edgePattern.Source]
		tgt := bindings[edgePattern.Target]
		if src == nil || tgt == nil {
			return nil, false
		}

		matches := findMatchingPatternEdges(g.GetOutEdges(src.ID), tgt.ID, edgePattern.Kind)
		if len(matches) == 0 {
			return nil, false
		}
		for _, edge := range matches {
			if _, ok := seen[edge]; ok {
				continue
			}
			seen[edge] = struct{}{}
			edges = append(edges, edge)
		}
	}

	sort.Slice(edges, func(i, j int) bool {
		left := edges[i].ID + ":" + edges[i].Source + ":" + edges[i].Target
		right := edges[j].ID + ":" + edges[j].Source + ":" + edges[j].Target
		return left < right
	})
	return edges, true
}

func findMatchingPatternEdges(edges []*Edge, target string, kind EdgeKind) []*Edge {
	matches := make([]*Edge, 0)
	for _, edge := range edges {
		if edge == nil {
			continue
		}
		if edge.Target != target {
			continue
		}
		if kind != "" && edge.Kind != kind {
			continue
		}
		matches = append(matches, edge)
	}
	return matches
}

func patternNodeMatches(node *Node, nodePattern PatternNode, bindings map[string]*Node, staticOnly bool) bool {
	if node == nil {
		return false
	}
	if nodePattern.Kind != "" && nodePattern.Kind != NodeKindAny && node.Kind != nodePattern.Kind {
		return false
	}
	for key, expected := range nodePattern.Properties {
		actual, ok := patternNodeFieldValue(node, key)
		if !ok {
			return false
		}
		if !patternPropertyMatches(actual, key, expected, bindings, staticOnly) {
			return false
		}
	}
	return true
}

func patternNodeFieldValue(node *Node, field string) (any, bool) {
	normalized := strings.ToLower(strings.TrimSpace(field))
	switch normalized {
	case "id":
		return node.ID, true
	case "kind":
		return string(node.Kind), true
	case "name":
		return node.Name, true
	case "provider":
		return node.Provider, true
	case "account":
		return node.Account, true
	case "region":
		return node.Region, true
	case "risk":
		return string(node.Risk), true
	case "created_at":
		return node.CreatedAt, true
	case "updated_at":
		return node.UpdatedAt, true
	case "version":
		return node.Version, true
	}

	if node.Properties == nil {
		return nil, false
	}
	if value, ok := node.Properties[field]; ok {
		return value, true
	}
	if value, ok := node.Properties[normalized]; ok {
		return value, true
	}
	for key, value := range node.Properties {
		if strings.EqualFold(key, field) {
			return value, true
		}
	}
	return nil, false
}

func patternPropertyMatches(actual any, key string, expected any, bindings map[string]*Node, staticOnly bool) bool {
	expectedStr, ok := expected.(string)
	if !ok {
		return patternValuesEqual(actual, expected)
	}

	relation, alias, field, dynamic := parseDynamicReference(expectedStr, key)
	if !dynamic {
		return patternValuesEqual(actual, expected)
	}
	if staticOnly {
		return true
	}
	if bindings == nil {
		return false
	}
	referenceNode, bound := bindings[alias]
	if !bound || referenceNode == nil {
		return true
	}
	referenceValue, ok := patternNodeFieldValue(referenceNode, field)
	if !ok {
		return false
	}
	equal := patternValuesEqual(actual, referenceValue)
	if relation == "same" {
		return equal
	}
	return !equal
}

func parseDynamicReference(expected string, fallbackField string) (relation string, alias string, field string, dynamic bool) {
	raw := strings.TrimSpace(expected)
	switch {
	case strings.HasPrefix(raw, "same_as_"):
		relation = "same"
		raw = strings.TrimPrefix(raw, "same_as_")
	case strings.HasPrefix(raw, "different_from_"):
		relation = "different"
		raw = strings.TrimPrefix(raw, "different_from_")
	default:
		return "", "", "", false
	}

	alias = strings.TrimSpace(raw)
	field = fallbackField
	if idx := strings.Index(raw, "."); idx > 0 {
		alias = strings.TrimSpace(raw[:idx])
		field = strings.TrimSpace(raw[idx+1:])
	}
	if alias == "" {
		return "", "", "", false
	}
	if field == "" {
		field = fallbackField
	}
	return relation, alias, field, true
}

func evaluatePatternConditions(conditions []PatternCondition, bindings map[string]*Node) bool {
	for _, condition := range conditions {
		expression := strings.TrimSpace(condition.Expression)
		if expression == "" {
			continue
		}
		if !evaluatePatternConditionExpression(expression, bindings) {
			return false
		}
	}
	return true
}

func evaluatePatternConditionExpression(expression string, bindings map[string]*Node) bool {
	clauses := splitConditionClauses(expression)
	if len(clauses) == 0 {
		return false
	}
	for _, clause := range clauses {
		if !evaluatePatternConditionClause(clause, bindings) {
			return false
		}
	}
	return true
}

func splitConditionClauses(expression string) []string {
	tokens := strings.Fields(expression)
	if len(tokens) == 0 {
		return nil
	}
	clauses := make([]string, 0, 4)
	current := make([]string, 0, len(tokens))
	for _, token := range tokens {
		if strings.EqualFold(token, "AND") {
			if len(current) > 0 {
				clauses = append(clauses, strings.Join(current, " "))
				current = current[:0]
			}
			continue
		}
		current = append(current, token)
	}
	if len(current) > 0 {
		clauses = append(clauses, strings.Join(current, " "))
	}
	return clauses
}

func evaluatePatternConditionClause(clause string, bindings map[string]*Node) bool {
	operator := "=="
	idx := strings.Index(clause, operator)
	if idx < 0 {
		operator = "!="
		idx = strings.Index(clause, operator)
	}
	if idx < 0 {
		return false
	}

	leftToken := strings.TrimSpace(clause[:idx])
	rightToken := strings.TrimSpace(clause[idx+len(operator):])
	leftValue, ok := resolvePatternOperand(leftToken, bindings)
	if !ok {
		return false
	}
	rightValue, ok := resolvePatternOperand(rightToken, bindings)
	if !ok {
		return false
	}
	equal := patternValuesEqual(leftValue, rightValue)
	if operator == "==" {
		return equal
	}
	return !equal
}

func resolvePatternOperand(token string, bindings map[string]*Node) (any, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, false
	}
	if idx := strings.Index(token, "."); idx > 0 {
		alias := strings.TrimSpace(token[:idx])
		field := strings.TrimSpace(token[idx+1:])
		node, ok := bindings[alias]
		if !ok || node == nil {
			return nil, false
		}
		return patternNodeFieldValue(node, field)
	}
	return parsePatternLiteral(token), true
}

func parsePatternLiteral(token string) any {
	if len(token) >= 2 {
		if (token[0] == '\'' && token[len(token)-1] == '\'') || (token[0] == '"' && token[len(token)-1] == '"') {
			return token[1 : len(token)-1]
		}
	}
	if strings.EqualFold(token, "true") {
		return true
	}
	if strings.EqualFold(token, "false") {
		return false
	}
	if strings.EqualFold(token, "null") || strings.EqualFold(token, "nil") {
		return nil
	}
	if i, err := strconv.ParseInt(token, 10, 64); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(token, 64); err == nil {
		return f
	}
	return token
}

func patternValuesEqual(left any, right any) bool {
	l, lok := normalizePatternValue(left)
	r, rok := normalizePatternValue(right)
	if !lok || !rok {
		return false
	}
	switch lv := l.(type) {
	case float64:
		rv, ok := r.(float64)
		if !ok {
			return false
		}
		return lv == rv
	case time.Time:
		rv, ok := r.(time.Time)
		if !ok {
			return false
		}
		return lv.Equal(rv)
	}
	return l == r
}

func normalizePatternValue(value any) (any, bool) {
	if value == nil {
		return nil, true
	}
	switch v := value.(type) {
	case NodeKind:
		return string(v), true
	case EdgeKind:
		return string(v), true
	case RiskLevel:
		return string(v), true
	case string:
		return v, true
	case bool:
		return v, true
	case int:
		return float64(v), true
	case int8:
		return float64(v), true
	case int16:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint8:
		return float64(v), true
	case uint16:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case float32:
		return float64(v), true
	case float64:
		return v, true
	case time.Time:
		return v.UTC(), true
	}
	return nil, false
}

func patternBindingKey(bindings map[string]*Node) string {
	if len(bindings) == 0 {
		return ""
	}
	aliases := make([]string, 0, len(bindings))
	for alias := range bindings {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	parts := make([]string, 0, len(aliases))
	for _, alias := range aliases {
		node := bindings[alias]
		nodeID := ""
		if node != nil {
			nodeID = node.ID
		}
		parts = append(parts, alias+"="+nodeID)
	}
	return strings.Join(parts, "|")
}
