package findingdsl

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type expression interface {
	eval(*evalEnv) (any, error)
}

type evalEnv struct {
	vars map[string]any
}

// PolicyResource is the resource document evaluated by condition-backed rules.
type PolicyResource map[string]any

type literalExpression struct {
	value any
}

func (e literalExpression) eval(_ *evalEnv) (any, error) {
	return e.value, nil
}

type identExpression struct {
	name string
}

func (e identExpression) eval(env *evalEnv) (any, error) {
	value, ok := env.vars[e.name]
	if !ok {
		return nil, fmt.Errorf("unknown identifier %q", e.name)
	}
	return value, nil
}

type listExpression struct {
	items []expression
}

func (e listExpression) eval(env *evalEnv) (any, error) {
	out := make([]any, 0, len(e.items))
	for _, item := range e.items {
		value, err := item.eval(env)
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, nil
}

type objectExpression struct {
	values map[string]expression
}

func (e objectExpression) eval(env *evalEnv) (any, error) {
	out := make(map[string]any, len(e.values))
	for key, expr := range e.values {
		value, err := expr.eval(env)
		if err != nil {
			return nil, err
		}
		out[key] = value
	}
	return out, nil
}

type unaryExpression struct {
	op   string
	expr expression
}

func (e unaryExpression) eval(env *evalEnv) (any, error) {
	value, err := e.expr.eval(env)
	if err != nil {
		return nil, err
	}
	switch e.op {
	case "!":
		boolean, ok := value.(bool)
		if !ok {
			return nil, fmt.Errorf("operator ! requires bool, got %T", value)
		}
		return !boolean, nil
	default:
		return nil, fmt.Errorf("unsupported unary operator %q", e.op)
	}
}

type binaryExpression struct {
	op    string
	left  expression
	right expression
}

func (e binaryExpression) eval(env *evalEnv) (any, error) {
	left, err := e.left.eval(env)
	if err != nil {
		return nil, err
	}
	leftBool, ok := left.(bool)
	if !ok {
		return nil, fmt.Errorf("operator %s requires bool left operand, got %T", e.op, left)
	}
	switch e.op {
	case "&&":
		if !leftBool {
			return false, nil
		}
	case "||":
		if leftBool {
			return true, nil
		}
	default:
		return nil, fmt.Errorf("unsupported binary operator %q", e.op)
	}
	right, err := e.right.eval(env)
	if err != nil {
		return nil, err
	}
	rightBool, ok := right.(bool)
	if !ok {
		return nil, fmt.Errorf("operator %s requires bool right operand, got %T", e.op, right)
	}
	if e.op == "&&" {
		return leftBool && rightBool, nil
	}
	return leftBool || rightBool, nil
}

type callExpression struct {
	name string
	args []expression
}

func (e callExpression) eval(env *evalEnv) (any, error) {
	args, err := evalArgs(env, e.args)
	if err != nil {
		return nil, err
	}
	switch e.name {
	case "path":
		return evalPath(args)
	case "exists_path":
		_, ok, err := pathLookupArgs(args)
		if err != nil {
			return nil, err
		}
		return ok, nil
	case "cmp_eq", "cmp_ne", "cmp_gt", "cmp_lt", "cmp_ge", "cmp_le":
		return evalCompare(e.name, args)
	case "in_list":
		return evalInList(args)
	case "contains_value":
		return evalContainsValue(args)
	case "matches_value":
		return evalMatchesValue(args)
	case "ends_with_value":
		return evalEndsWithValue(args)
	case "list_value":
		return evalListValue(args)
	default:
		return nil, fmt.Errorf("unsupported function %q", e.name)
	}
}

type methodCallExpression struct {
	receiver expression
	name     string
	args     []expression
}

func (e methodCallExpression) eval(env *evalEnv) (any, error) {
	switch e.name {
	case "exists":
		return evalExistsMethod(env, e.receiver, e.args)
	default:
		return nil, fmt.Errorf("unsupported method %q", e.name)
	}
}

func ParsePolicyCondition(condition string) error {
	_, err := parsePolicyExpression(condition)
	return err
}

func EvaluatePolicyConditions(conditions []string, resource PolicyResource) (bool, error) {
	env := &evalEnv{vars: map[string]any{"resource": resource}}
	for idx, condition := range conditions {
		expr, err := parsePolicyExpression(condition)
		if err != nil {
			return false, fmt.Errorf("condition[%d]: %w", idx, err)
		}
		value, err := expr.eval(env)
		if err != nil {
			return false, fmt.Errorf("condition[%d]: %w", idx, err)
		}
		boolean, ok := value.(bool)
		if !ok {
			return false, fmt.Errorf("condition[%d]: expression returned %T, want bool", idx, value)
		}
		if !boolean {
			return false, nil
		}
	}
	return true, nil
}

func parsePolicyExpression(input string) (expression, error) {
	tokens, err := lexPolicyExpression(input)
	if err != nil {
		return nil, err
	}
	parser := expressionParser{tokens: tokens}
	expr, err := parser.parseOr()
	if err != nil {
		return nil, err
	}
	if token := parser.peek(); token.kind != tokenEOF {
		return nil, fmt.Errorf("unexpected token %q", token.value)
	}
	return expr, nil
}

type tokenKind int

const (
	tokenEOF tokenKind = iota
	tokenIdent
	tokenString
	tokenNumber
	tokenSymbol
)

type expressionToken struct {
	kind  tokenKind
	value string
}

func lexPolicyExpression(input string) ([]expressionToken, error) {
	var tokens []expressionToken
	for idx := 0; idx < len(input); {
		ch := input[idx]
		if isSpace(ch) {
			idx++
			continue
		}
		if isIdentStart(ch) {
			start := idx
			idx++
			for idx < len(input) && isIdentPart(input[idx]) {
				idx++
			}
			tokens = append(tokens, expressionToken{kind: tokenIdent, value: input[start:idx]})
			continue
		}
		if ch == '"' {
			value, next, err := lexString(input, idx)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, expressionToken{kind: tokenString, value: value})
			idx = next
			continue
		}
		if isNumberStart(input, idx) {
			start := idx
			idx++
			for idx < len(input) && (input[idx] == '.' || input[idx] >= '0' && input[idx] <= '9') {
				idx++
			}
			tokens = append(tokens, expressionToken{kind: tokenNumber, value: input[start:idx]})
			continue
		}
		if idx+1 < len(input) {
			pair := input[idx : idx+2]
			if pair == "&&" || pair == "||" {
				tokens = append(tokens, expressionToken{kind: tokenSymbol, value: pair})
				idx += 2
				continue
			}
		}
		if strings.ContainsRune("(),[].!{}:", rune(ch)) {
			tokens = append(tokens, expressionToken{kind: tokenSymbol, value: string(ch)})
			idx++
			continue
		}
		return nil, fmt.Errorf("unexpected character %q", ch)
	}
	tokens = append(tokens, expressionToken{kind: tokenEOF})
	return tokens, nil
}

func lexString(input string, start int) (string, int, error) {
	var builder strings.Builder
	for idx := start + 1; idx < len(input); idx++ {
		ch := input[idx]
		if ch == '"' {
			return builder.String(), idx + 1, nil
		}
		if ch == '\\' {
			if idx+1 >= len(input) {
				return "", 0, fmt.Errorf("unterminated string escape")
			}
			idx++
			switch escaped := input[idx]; escaped {
			case '\\', '"':
				builder.WriteByte(escaped)
			case 'n':
				builder.WriteByte('\n')
			case 't':
				builder.WriteByte('\t')
			case 'u':
				if idx+4 >= len(input) {
					return "", 0, fmt.Errorf("short unicode string escape")
				}
				hex := input[idx+1 : idx+5]
				value, err := strconv.ParseInt(hex, 16, 32)
				if err != nil {
					return "", 0, fmt.Errorf("invalid unicode string escape \\u%s", hex)
				}
				builder.WriteRune(rune(value))
				idx += 4
			default:
				return "", 0, fmt.Errorf("unsupported string escape \\%c", escaped)
			}
			continue
		}
		builder.WriteByte(ch)
	}
	return "", 0, fmt.Errorf("unterminated string")
}

type expressionParser struct {
	tokens []expressionToken
	pos    int
}

func (p *expressionParser) parseOr() (expression, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.match("||") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = binaryExpression{op: "||", left: left, right: right}
	}
	return left, nil
}

func (p *expressionParser) parseAnd() (expression, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.match("&&") {
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = binaryExpression{op: "&&", left: left, right: right}
	}
	return left, nil
}

func (p *expressionParser) parseUnary() (expression, error) {
	if p.match("!") {
		expr, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return unaryExpression{op: "!", expr: expr}, nil
	}
	return p.parsePostfix()
}

func (p *expressionParser) parsePostfix() (expression, error) {
	expr, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	for p.match(".") {
		name, err := p.consumeIdent("method name")
		if err != nil {
			return nil, err
		}
		args, err := p.parseCallArgs()
		if err != nil {
			return nil, err
		}
		expr = methodCallExpression{receiver: expr, name: name, args: args}
	}
	return expr, nil
}

func (p *expressionParser) parsePrimary() (expression, error) {
	token := p.advance()
	switch token.kind {
	case tokenIdent:
		switch token.value {
		case "true":
			return literalExpression{value: true}, nil
		case "false":
			return literalExpression{value: false}, nil
		case "null":
			return literalExpression{value: nil}, nil
		}
		if p.peek().value == "(" {
			args, err := p.parseCallArgs()
			if err != nil {
				return nil, err
			}
			return callExpression{name: token.value, args: args}, nil
		}
		return identExpression{name: token.value}, nil
	case tokenString:
		return literalExpression{value: token.value}, nil
	case tokenNumber:
		number, err := strconv.ParseFloat(token.value, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid number %q", token.value)
		}
		return literalExpression{value: number}, nil
	case tokenSymbol:
		if token.value == "(" {
			expr, err := p.parseOr()
			if err != nil {
				return nil, err
			}
			if !p.match(")") {
				return nil, fmt.Errorf("expected )")
			}
			return expr, nil
		}
		if token.value == "[" {
			return p.parseList()
		}
		if token.value == "{" {
			return p.parseObject()
		}
	}
	return nil, fmt.Errorf("unexpected token %q", token.value)
}

func (p *expressionParser) parseList() (expression, error) {
	var items []expression
	if p.match("]") {
		return listExpression{items: items}, nil
	}
	for {
		item, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		items = append(items, item)
		if p.match("]") {
			return listExpression{items: items}, nil
		}
		if !p.match(",") {
			return nil, fmt.Errorf("expected , or ]")
		}
	}
}

func (p *expressionParser) parseObject() (expression, error) {
	values := map[string]expression{}
	if p.match("}") {
		return objectExpression{values: values}, nil
	}
	for {
		keyToken := p.advance()
		if keyToken.kind != tokenString && keyToken.kind != tokenIdent {
			return nil, fmt.Errorf("expected object key")
		}
		if !p.match(":") {
			return nil, fmt.Errorf("expected colon")
		}
		value, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		values[keyToken.value] = value
		if p.match("}") {
			return objectExpression{values: values}, nil
		}
		if !p.match(",") {
			return nil, fmt.Errorf("expected , or }")
		}
	}
}

func (p *expressionParser) parseCallArgs() ([]expression, error) {
	if !p.match("(") {
		return nil, fmt.Errorf("expected (")
	}
	var args []expression
	if p.match(")") {
		return args, nil
	}
	for {
		arg, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		args = append(args, arg)
		if p.match(")") {
			return args, nil
		}
		if !p.match(",") {
			return nil, fmt.Errorf("expected , or )")
		}
	}
}

func (p *expressionParser) consumeIdent(label string) (string, error) {
	token := p.advance()
	if token.kind != tokenIdent {
		return "", fmt.Errorf("expected %s", label)
	}
	return token.value, nil
}

func (p *expressionParser) match(value string) bool {
	if p.peek().value != value {
		return false
	}
	p.pos++
	return true
}

func (p *expressionParser) advance() expressionToken {
	token := p.peek()
	if token.kind != tokenEOF {
		p.pos++
	}
	return token
}

func (p *expressionParser) peek() expressionToken {
	if p.pos >= len(p.tokens) {
		return expressionToken{kind: tokenEOF}
	}
	return p.tokens[p.pos]
}

func evalArgs(env *evalEnv, expressions []expression) ([]any, error) {
	out := make([]any, 0, len(expressions))
	for _, expr := range expressions {
		value, err := expr.eval(env)
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, nil
}

func evalPath(args []any) (any, error) {
	value, _, err := pathLookupArgs(args)
	return value, err
}

func pathLookupArgs(args []any) (any, bool, error) {
	if len(args) != 2 {
		return nil, false, fmt.Errorf("path requires 2 arguments")
	}
	path, ok := args[1].(string)
	if !ok {
		return nil, false, fmt.Errorf("path argument 2 must be string")
	}
	value, found := lookupPath(args[0], path)
	return value, found, nil
}

func evalCompare(name string, args []any) (bool, error) {
	if len(args) != 2 {
		return false, fmt.Errorf("%s requires 2 arguments", name)
	}
	cmp := compareValues(args[0], args[1])
	switch name {
	case "cmp_eq":
		return cmp == 0, nil
	case "cmp_ne":
		return cmp != 0, nil
	case "cmp_gt":
		return cmp > 0, nil
	case "cmp_lt":
		return cmp < 0, nil
	case "cmp_ge":
		return cmp >= 0, nil
	case "cmp_le":
		return cmp <= 0, nil
	default:
		return false, fmt.Errorf("unsupported comparison %q", name)
	}
}

func evalInList(args []any) (bool, error) {
	if len(args) != 2 {
		return false, fmt.Errorf("in_list requires 2 arguments")
	}
	values, ok := toAnySlice(args[1])
	if !ok {
		return false, fmt.Errorf("in_list argument 2 must be a list")
	}
	for _, value := range values {
		if compareValues(args[0], value) == 0 {
			return true, nil
		}
	}
	return false, nil
}

func evalContainsValue(args []any) (bool, error) {
	if len(args) != 2 {
		return false, fmt.Errorf("contains_value requires 2 arguments")
	}
	needle := fmt.Sprint(args[1])
	switch haystack := args[0].(type) {
	case string:
		return strings.Contains(haystack, needle), nil
	case []any:
		for _, item := range haystack {
			if compareValues(item, args[1]) == 0 || strings.Contains(fmt.Sprint(item), needle) {
				return true, nil
			}
		}
		return false, nil
	default:
		return false, nil
	}
}

func evalMatchesValue(args []any) (bool, error) {
	if len(args) != 2 {
		return false, fmt.Errorf("matches_value requires 2 arguments")
	}
	pattern, ok := args[1].(string)
	if !ok {
		return false, fmt.Errorf("matches_value argument 2 must be string")
	}
	return regexp.MatchString(pattern, fmt.Sprint(args[0]))
}

func evalEndsWithValue(args []any) (bool, error) {
	if len(args) != 2 {
		return false, fmt.Errorf("ends_with_value requires 2 arguments")
	}
	return strings.HasSuffix(fmt.Sprint(args[0]), fmt.Sprint(args[1])), nil
}

func evalListValue(args []any) ([]any, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("list_value requires 1 argument")
	}
	if args[0] == nil {
		return nil, nil
	}
	values, ok := toAnySlice(args[0])
	if !ok {
		return nil, fmt.Errorf("list_value argument must be a list")
	}
	return values, nil
}

func evalExistsMethod(env *evalEnv, receiver expression, args []expression) (bool, error) {
	if len(args) != 2 {
		return false, fmt.Errorf("exists requires iterator name and predicate")
	}
	ident, ok := args[0].(identExpression)
	if !ok {
		return false, fmt.Errorf("exists first argument must be an identifier")
	}
	value, err := receiver.eval(env)
	if err != nil {
		return false, err
	}
	values, ok := toAnySlice(value)
	if !ok {
		return false, fmt.Errorf("exists receiver must be a list")
	}
	oldValue, hadOldValue := env.vars[ident.name]
	defer func() {
		if hadOldValue {
			env.vars[ident.name] = oldValue
			return
		}
		delete(env.vars, ident.name)
	}()
	for _, item := range values {
		env.vars[ident.name] = item
		result, err := args[1].eval(env)
		if err != nil {
			return false, err
		}
		boolean, ok := result.(bool)
		if !ok {
			return false, fmt.Errorf("exists predicate returned %T, want bool", result)
		}
		if boolean {
			return true, nil
		}
	}
	return false, nil
}

func lookupPath(value any, path string) (any, bool) {
	current := value
	for _, part := range strings.Split(path, ".") {
		if part == "" {
			return nil, false
		}
		switch typed := current.(type) {
		case PolicyResource:
			next, ok := typed[part]
			if !ok {
				return nil, false
			}
			current = next
		case map[string]any:
			next, ok := typed[part]
			if !ok {
				return nil, false
			}
			current = next
		case map[any]any:
			next, ok := typed[part]
			if !ok {
				return nil, false
			}
			current = next
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(typed) {
				return nil, false
			}
			current = typed[index]
		default:
			return nil, false
		}
	}
	return current, true
}

func compareValues(left any, right any) int {
	if left == nil && right == nil {
		return 0
	}
	if left == nil {
		return -1
	}
	if right == nil {
		return 1
	}
	if leftNumber, ok := toFloat(left); ok {
		if rightNumber, ok := toFloat(right); ok {
			if leftNumber < rightNumber {
				return -1
			}
			if leftNumber > rightNumber {
				return 1
			}
			return 0
		}
	}
	leftString := fmt.Sprint(left)
	rightString := fmt.Sprint(right)
	if leftString < rightString {
		return -1
	}
	if leftString > rightString {
		return 1
	}
	return 0
}

func toFloat(value any) (float64, bool) {
	switch typed := value.(type) {
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case uint64:
		return float64(typed), true
	case uint:
		return float64(typed), true
	default:
		return 0, false
	}
}

func toAnySlice(value any) ([]any, bool) {
	switch typed := value.(type) {
	case []any:
		return typed, true
	case []map[string]any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, item)
		}
		return out, true
	default:
		return nil, false
	}
}

func isSpace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
}

func isIdentStart(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch == '_'
}

func isIdentPart(ch byte) bool {
	return isIdentStart(ch) || ch >= '0' && ch <= '9'
}

func isNumberStart(input string, idx int) bool {
	ch := input[idx]
	if ch >= '0' && ch <= '9' {
		return true
	}
	return ch == '-' && idx+1 < len(input) && input[idx+1] >= '0' && input[idx+1] <= '9'
}
