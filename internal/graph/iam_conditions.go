package graph

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
)

// PermissionEvaluationContext supplies request-time attributes for condition evaluation.
// When omitted, Calculate() behaves conservatively and only includes grants whose
// conditions can be proven with static graph metadata.
type PermissionEvaluationContext struct {
	Keys             map[string]any    `json:"keys,omitempty"`
	Request          map[string]any    `json:"request,omitempty"`
	Principal        map[string]any    `json:"principal,omitempty"`
	Resource         map[string]any    `json:"resource,omitempty"`
	SourceIP         string            `json:"source_ip,omitempty"`
	SourceVPCe       string            `json:"source_vpce,omitempty"`
	CurrentTime      time.Time         `json:"current_time,omitempty"`
	PrincipalARN     string            `json:"principal_arn,omitempty"`
	PrincipalAccount string            `json:"principal_account,omitempty"`
	ResourceARN      string            `json:"resource_arn,omitempty"`
	ResourceAccount  string            `json:"resource_account,omitempty"`
	PrincipalTags    map[string]string `json:"principal_tags,omitempty"`
	ResourceTags     map[string]string `json:"resource_tags,omitempty"`
}

type conditionMatchResult int

const (
	conditionMatchYes conditionMatchResult = iota
	conditionMatchNo
	conditionMatchUnknown
)

type awsConditionOperator struct {
	base       string
	ifExists   bool
	quantifier string
}

var (
	gcpConditionEnvOnce sync.Once
	gcpConditionEnv     *cel.Env
	gcpConditionEnvErr  error
)

func evaluateEdgeConditions(
	edge *Edge,
	principalNode *Node,
	targetNode *Node,
	ctx *PermissionEvaluationContext,
) conditionMatchResult {
	awsConditions := awsConditionsForEdge(edge)
	gcpCondition := gcpConditionForEdge(edge)

	result := conditionMatchYes
	if len(awsConditions) > 0 {
		result = combineConditionResult(result, evaluateAWSConditions(awsConditions, principalNode, targetNode, ctx))
	}
	if len(gcpCondition) > 0 {
		result = combineConditionResult(result, evaluateGCPCondition(gcpCondition, principalNode, targetNode, ctx))
	}
	return result
}

func combineConditionResult(left, right conditionMatchResult) conditionMatchResult {
	if left == conditionMatchNo || right == conditionMatchNo {
		return conditionMatchNo
	}
	if left == conditionMatchUnknown || right == conditionMatchUnknown {
		return conditionMatchUnknown
	}
	return conditionMatchYes
}

func awsConditionsForEdge(edge *Edge) map[string]any {
	if edge == nil || edge.Properties == nil {
		return nil
	}
	raw, ok := edge.Properties["conditions"]
	if !ok || raw == nil {
		return nil
	}
	conditions, ok := raw.(map[string]any)
	if !ok || len(conditions) == 0 {
		return nil
	}
	return conditions
}

func gcpConditionForEdge(edge *Edge) map[string]any {
	if edge == nil || edge.Properties == nil {
		return nil
	}
	raw, ok := edge.Properties["condition"]
	if !ok || raw == nil {
		return nil
	}
	condition, ok := raw.(map[string]any)
	if !ok || len(condition) == 0 {
		return nil
	}
	return condition
}

func evaluateAWSConditions(
	conditions map[string]any,
	principalNode *Node,
	targetNode *Node,
	ctx *PermissionEvaluationContext,
) conditionMatchResult {
	if len(conditions) == 0 {
		return conditionMatchYes
	}

	result := conditionMatchYes
	for operatorName, rawClause := range conditions {
		operator, supported := parseAWSConditionOperator(operatorName)
		if !supported {
			return conditionMatchUnknown
		}
		clause, ok := rawClause.(map[string]any)
		if !ok || len(clause) == 0 {
			return conditionMatchUnknown
		}
		for conditionKey, expectedRaw := range clause {
			actualValues, present := awsConditionValues(conditionKey, principalNode, targetNode, ctx)
			clauseResult := evaluateAWSConditionClause(operator, expectedRaw, actualValues, present)
			if clauseResult == conditionMatchNo {
				return conditionMatchNo
			}
			if clauseResult == conditionMatchUnknown {
				result = conditionMatchUnknown
			}
		}
	}
	return result
}

func parseAWSConditionOperator(value string) (awsConditionOperator, bool) {
	operator := awsConditionOperator{}
	name := strings.TrimSpace(strings.ToLower(value))
	if name == "" {
		return operator, false
	}
	if strings.HasPrefix(name, "foranyvalue:") {
		operator.quantifier = "any"
		name = strings.TrimPrefix(name, "foranyvalue:")
	} else if strings.HasPrefix(name, "forallvalues:") {
		operator.quantifier = "all"
		name = strings.TrimPrefix(name, "forallvalues:")
	}
	if strings.HasSuffix(name, "ifexists") {
		operator.ifExists = true
		name = strings.TrimSuffix(name, "ifexists")
	}
	operator.base = name
	switch operator.base {
	case "stringequals",
		"stringequalsignorecase",
		"stringnotequals",
		"stringlike",
		"stringnotlike",
		"arnequals",
		"arnnotequals",
		"arnlike",
		"arnnotlike",
		"bool",
		"numericequals",
		"numericnotequals",
		"numericlessthan",
		"numericlessthanequals",
		"numericgreaterthan",
		"numericgreaterthanequals",
		"dateequals",
		"datenotequals",
		"datelessthan",
		"datelessthanequals",
		"dategreaterthan",
		"dategreaterthanequals",
		"ipaddress",
		"notipaddress",
		"null":
		return operator, true
	default:
		return operator, false
	}
}

func evaluateAWSConditionClause(
	operator awsConditionOperator,
	expectedRaw any,
	actualValues []string,
	present bool,
) conditionMatchResult {
	if operator.base == "null" {
		expectedBool, ok := boolFromAny(expectedRaw)
		if !ok {
			return conditionMatchUnknown
		}
		if expectedBool {
			if present {
				return conditionMatchNo
			}
			return conditionMatchYes
		}
		if present {
			return conditionMatchYes
		}
		return conditionMatchNo
	}

	if !present || len(actualValues) == 0 {
		if operator.ifExists {
			return conditionMatchYes
		}
		return conditionMatchUnknown
	}

	expectedValues := conditionExpectedValues(expectedRaw)
	if len(expectedValues) == 0 {
		return conditionMatchUnknown
	}

	switch operator.base {
	case "stringequals":
		return evaluateStringCondition(actualValues, expectedValues, operator.quantifier, false, false)
	case "stringequalsignorecase":
		return evaluateStringCondition(actualValues, expectedValues, operator.quantifier, true, false)
	case "stringnotequals":
		return evaluateStringCondition(actualValues, expectedValues, operator.quantifier, false, true)
	case "stringlike":
		return evaluatePatternCondition(actualValues, expectedValues, operator.quantifier, false)
	case "stringnotlike":
		return evaluatePatternCondition(actualValues, expectedValues, operator.quantifier, true)
	case "arnequals":
		return evaluateStringCondition(actualValues, expectedValues, operator.quantifier, false, false)
	case "arnnotequals":
		return evaluateStringCondition(actualValues, expectedValues, operator.quantifier, false, true)
	case "arnlike":
		return evaluatePatternCondition(actualValues, expectedValues, operator.quantifier, false)
	case "arnnotlike":
		return evaluatePatternCondition(actualValues, expectedValues, operator.quantifier, true)
	case "bool":
		return evaluateBoolCondition(actualValues, expectedValues, operator.quantifier)
	case "numericequals":
		return evaluateNumericCondition(actualValues, expectedValues, operator.quantifier, func(actual, expected float64) bool {
			return actual == expected
		})
	case "numericnotequals":
		return evaluateNumericCondition(actualValues, expectedValues, operator.quantifier, func(actual, expected float64) bool {
			return actual != expected
		})
	case "numericlessthan":
		return evaluateNumericCondition(actualValues, expectedValues, operator.quantifier, func(actual, expected float64) bool {
			return actual < expected
		})
	case "numericlessthanequals":
		return evaluateNumericCondition(actualValues, expectedValues, operator.quantifier, func(actual, expected float64) bool {
			return actual <= expected
		})
	case "numericgreaterthan":
		return evaluateNumericCondition(actualValues, expectedValues, operator.quantifier, func(actual, expected float64) bool {
			return actual > expected
		})
	case "numericgreaterthanequals":
		return evaluateNumericCondition(actualValues, expectedValues, operator.quantifier, func(actual, expected float64) bool {
			return actual >= expected
		})
	case "dateequals":
		return evaluateDateCondition(actualValues, expectedValues, operator.quantifier, func(actual, expected time.Time) bool {
			return actual.Equal(expected)
		})
	case "datenotequals":
		return evaluateDateCondition(actualValues, expectedValues, operator.quantifier, func(actual, expected time.Time) bool {
			return !actual.Equal(expected)
		})
	case "datelessthan":
		return evaluateDateCondition(actualValues, expectedValues, operator.quantifier, func(actual, expected time.Time) bool {
			return actual.Before(expected)
		})
	case "datelessthanequals":
		return evaluateDateCondition(actualValues, expectedValues, operator.quantifier, func(actual, expected time.Time) bool {
			return actual.Before(expected) || actual.Equal(expected)
		})
	case "dategreaterthan":
		return evaluateDateCondition(actualValues, expectedValues, operator.quantifier, func(actual, expected time.Time) bool {
			return actual.After(expected)
		})
	case "dategreaterthanequals":
		return evaluateDateCondition(actualValues, expectedValues, operator.quantifier, func(actual, expected time.Time) bool {
			return actual.After(expected) || actual.Equal(expected)
		})
	case "ipaddress":
		return evaluateIPCondition(actualValues, expectedValues, operator.quantifier, false)
	case "notipaddress":
		return evaluateIPCondition(actualValues, expectedValues, operator.quantifier, true)
	default:
		return conditionMatchUnknown
	}
}

func conditionExpectedValues(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			values = append(values, strings.TrimSpace(toString(item)))
		}
		return compactStrings(values)
	default:
		text := strings.TrimSpace(toString(value))
		if text == "" {
			return nil
		}
		return []string{text}
	}
}

func compactStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func evaluateStringCondition(actualValues, expectedValues []string, quantifier string, ignoreCase, negate bool) conditionMatchResult {
	comparator := func(actual, expected string) bool {
		if ignoreCase {
			return strings.EqualFold(actual, expected)
		}
		return actual == expected
	}
	return evaluateComparableCondition(actualValues, expectedValues, quantifier, negate, comparator)
}

func evaluatePatternCondition(actualValues, expectedValues []string, quantifier string, negate bool) conditionMatchResult {
	comparator := func(actual, expected string) bool {
		return matchComponent(actual, expected)
	}
	return evaluateComparableCondition(actualValues, expectedValues, quantifier, negate, comparator)
}

func evaluateComparableCondition(
	actualValues []string,
	expectedValues []string,
	quantifier string,
	negate bool,
	comparator func(actual, expected string) bool,
) conditionMatchResult {
	if len(actualValues) == 0 || len(expectedValues) == 0 {
		return conditionMatchUnknown
	}

	matchAnyExpected := func(actual string) bool {
		for _, expected := range expectedValues {
			if comparator(actual, expected) {
				return true
			}
		}
		return false
	}

	switch quantifier {
	case "all":
		for _, actual := range actualValues {
			matched := matchAnyExpected(actual)
			if negate {
				matched = !matched
			}
			if !matched {
				return conditionMatchNo
			}
		}
		return conditionMatchYes
	default:
		for _, actual := range actualValues {
			matched := matchAnyExpected(actual)
			if negate {
				matched = !matched
			}
			if matched {
				return conditionMatchYes
			}
		}
		return conditionMatchNo
	}
}

func evaluateBoolCondition(actualValues, expectedValues []string, quantifier string) conditionMatchResult {
	actualBools := make([]string, 0, len(actualValues))
	for _, actual := range actualValues {
		parsed, err := strconv.ParseBool(strings.TrimSpace(actual))
		if err != nil {
			return conditionMatchUnknown
		}
		actualBools = append(actualBools, strconv.FormatBool(parsed))
	}

	expectedBools := make([]string, 0, len(expectedValues))
	for _, expected := range expectedValues {
		parsed, err := strconv.ParseBool(strings.TrimSpace(expected))
		if err != nil {
			return conditionMatchUnknown
		}
		expectedBools = append(expectedBools, strconv.FormatBool(parsed))
	}

	return evaluateComparableCondition(actualBools, expectedBools, quantifier, false, func(actual, expected string) bool {
		return actual == expected
	})
}

func evaluateNumericCondition(
	actualValues []string,
	expectedValues []string,
	quantifier string,
	comparator func(actual, expected float64) bool,
) conditionMatchResult {
	if len(actualValues) == 0 || len(expectedValues) == 0 {
		return conditionMatchUnknown
	}

	parseFloat := func(value string) (float64, error) {
		return strconv.ParseFloat(strings.TrimSpace(value), 64)
	}

	matchAnyExpected := func(actual float64) (bool, error) {
		for _, expectedRaw := range expectedValues {
			expected, err := parseFloat(expectedRaw)
			if err != nil {
				return false, err
			}
			if comparator(actual, expected) {
				return true, nil
			}
		}
		return false, nil
	}

	switch quantifier {
	case "all":
		for _, actualRaw := range actualValues {
			actual, err := parseFloat(actualRaw)
			if err != nil {
				return conditionMatchUnknown
			}
			matched, err := matchAnyExpected(actual)
			if err != nil {
				return conditionMatchUnknown
			}
			if !matched {
				return conditionMatchNo
			}
		}
		return conditionMatchYes
	default:
		for _, actualRaw := range actualValues {
			actual, err := parseFloat(actualRaw)
			if err != nil {
				return conditionMatchUnknown
			}
			matched, err := matchAnyExpected(actual)
			if err != nil {
				return conditionMatchUnknown
			}
			if matched {
				return conditionMatchYes
			}
		}
		return conditionMatchNo
	}
}

func evaluateDateCondition(
	actualValues []string,
	expectedValues []string,
	quantifier string,
	comparator func(actual, expected time.Time) bool,
) conditionMatchResult {
	if len(actualValues) == 0 || len(expectedValues) == 0 {
		return conditionMatchUnknown
	}

	matchAnyExpected := func(actual time.Time) (bool, error) {
		for _, expectedRaw := range expectedValues {
			expected, err := parseConditionTime(expectedRaw)
			if err != nil {
				return false, err
			}
			if comparator(actual, expected) {
				return true, nil
			}
		}
		return false, nil
	}

	switch quantifier {
	case "all":
		for _, actualRaw := range actualValues {
			actual, err := parseConditionTime(actualRaw)
			if err != nil {
				return conditionMatchUnknown
			}
			matched, err := matchAnyExpected(actual)
			if err != nil {
				return conditionMatchUnknown
			}
			if !matched {
				return conditionMatchNo
			}
		}
		return conditionMatchYes
	default:
		for _, actualRaw := range actualValues {
			actual, err := parseConditionTime(actualRaw)
			if err != nil {
				return conditionMatchUnknown
			}
			matched, err := matchAnyExpected(actual)
			if err != nil {
				return conditionMatchUnknown
			}
			if matched {
				return conditionMatchYes
			}
		}
		return conditionMatchNo
	}
}

func parseConditionTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, fmt.Errorf("empty time")
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed.UTC(), nil
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("unsupported time format %q", value)
}

func evaluateIPCondition(actualValues, expectedValues []string, quantifier string, negate bool) conditionMatchResult {
	if len(actualValues) == 0 || len(expectedValues) == 0 {
		return conditionMatchUnknown
	}

	matchAnyExpected := func(actual net.IP) (bool, error) {
		for _, expected := range expectedValues {
			expected = strings.TrimSpace(expected)
			if expected == "" {
				continue
			}
			if strings.Contains(expected, "/") {
				_, network, err := net.ParseCIDR(expected)
				if err != nil {
					return false, err
				}
				if network.Contains(actual) {
					return true, nil
				}
				continue
			}
			if candidate := net.ParseIP(expected); candidate != nil && candidate.Equal(actual) {
				return true, nil
			}
		}
		return false, nil
	}

	switch quantifier {
	case "all":
		for _, actualRaw := range actualValues {
			actual := net.ParseIP(strings.TrimSpace(actualRaw))
			if actual == nil {
				return conditionMatchUnknown
			}
			matched, err := matchAnyExpected(actual)
			if err != nil {
				return conditionMatchUnknown
			}
			if negate {
				matched = !matched
			}
			if !matched {
				return conditionMatchNo
			}
		}
		return conditionMatchYes
	default:
		for _, actualRaw := range actualValues {
			actual := net.ParseIP(strings.TrimSpace(actualRaw))
			if actual == nil {
				return conditionMatchUnknown
			}
			matched, err := matchAnyExpected(actual)
			if err != nil {
				return conditionMatchUnknown
			}
			if negate {
				matched = !matched
			}
			if matched {
				return conditionMatchYes
			}
		}
		return conditionMatchNo
	}
}

func boolFromAny(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		return parsed, err == nil
	default:
		parsed, err := strconv.ParseBool(strings.TrimSpace(toString(value)))
		return parsed, err == nil
	}
}

func awsConditionValues(
	conditionKey string,
	principalNode *Node,
	targetNode *Node,
	ctx *PermissionEvaluationContext,
) ([]string, bool) {
	if ctx != nil {
		if values, ok := valueFromCaseInsensitiveMap(ctx.Keys, conditionKey); ok {
			return conditionExpectedValues(values), true
		}
	}

	lowerKey := strings.ToLower(strings.TrimSpace(conditionKey))
	switch {
	case lowerKey == "aws:sourceip":
		if ctx != nil && strings.TrimSpace(ctx.SourceIP) != "" {
			return []string{strings.TrimSpace(ctx.SourceIP)}, true
		}
	case lowerKey == "aws:sourcevpce":
		if ctx != nil && strings.TrimSpace(ctx.SourceVPCe) != "" {
			return []string{strings.TrimSpace(ctx.SourceVPCe)}, true
		}
	case lowerKey == "aws:currenttime":
		if ctx != nil && !ctx.CurrentTime.IsZero() {
			return []string{ctx.CurrentTime.UTC().Format(time.RFC3339)}, true
		}
	case lowerKey == "aws:principalarn":
		if ctx != nil && strings.TrimSpace(ctx.PrincipalARN) != "" {
			return []string{strings.TrimSpace(ctx.PrincipalARN)}, true
		}
		if principalNode != nil && strings.HasPrefix(principalNode.ID, "arn:") {
			return []string{principalNode.ID}, true
		}
	case lowerKey == "aws:principalaccount":
		if ctx != nil && strings.TrimSpace(ctx.PrincipalAccount) != "" {
			return []string{strings.TrimSpace(ctx.PrincipalAccount)}, true
		}
		if principalNode != nil && strings.TrimSpace(principalNode.Account) != "" {
			return []string{strings.TrimSpace(principalNode.Account)}, true
		}
	case lowerKey == "aws:resourceaccount":
		if ctx != nil && strings.TrimSpace(ctx.ResourceAccount) != "" {
			return []string{strings.TrimSpace(ctx.ResourceAccount)}, true
		}
		if targetNode != nil && strings.TrimSpace(targetNode.Account) != "" {
			return []string{strings.TrimSpace(targetNode.Account)}, true
		}
	case lowerKey == "aws:resourcearn":
		if ctx != nil && strings.TrimSpace(ctx.ResourceARN) != "" {
			return []string{strings.TrimSpace(ctx.ResourceARN)}, true
		}
		if targetNode != nil && strings.TrimSpace(targetNode.ID) != "" {
			return []string{strings.TrimSpace(targetNode.ID)}, true
		}
	case strings.HasPrefix(lowerKey, "aws:principaltag/"):
		tagKey := conditionTagKey(conditionKey)
		if tagKey == "" {
			return nil, false
		}
		if ctx != nil {
			if value, ok := stringFromCaseInsensitiveMap(ctx.PrincipalTags, tagKey); ok {
				return []string{value}, true
			}
			if value, ok := valueFromCaseInsensitiveMap(ctx.Principal, "tags."+tagKey); ok {
				return conditionExpectedValues(value), true
			}
		}
		if principalNode != nil {
			if value, ok := stringFromCaseInsensitiveMap(principalNode.Tags, tagKey); ok {
				return []string{value}, true
			}
		}
	case strings.HasPrefix(lowerKey, "aws:resourcetag/"), strings.HasPrefix(lowerKey, "s3:existingobjecttag/"):
		tagKey := conditionTagKey(conditionKey)
		if tagKey == "" {
			return nil, false
		}
		if ctx != nil {
			if value, ok := stringFromCaseInsensitiveMap(ctx.ResourceTags, tagKey); ok {
				return []string{value}, true
			}
			if value, ok := valueFromCaseInsensitiveMap(ctx.Resource, "tags."+tagKey); ok {
				return conditionExpectedValues(value), true
			}
		}
		if targetNode != nil {
			if value, ok := stringFromCaseInsensitiveMap(targetNode.Tags, tagKey); ok {
				return []string{value}, true
			}
		}
	}

	return nil, false
}

func conditionTagKey(conditionKey string) string {
	parts := strings.SplitN(conditionKey, "/", 2)
	if len(parts) != 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func valueFromCaseInsensitiveMap(values map[string]any, key string) (any, bool) {
	if len(values) == 0 {
		return nil, false
	}
	if value, ok := values[key]; ok {
		return value, true
	}
	for candidateKey, value := range values {
		if strings.EqualFold(strings.TrimSpace(candidateKey), strings.TrimSpace(key)) {
			return value, true
		}
	}
	return nil, false
}

func stringFromCaseInsensitiveMap(values map[string]string, key string) (string, bool) {
	if len(values) == 0 {
		return "", false
	}
	if value, ok := values[key]; ok {
		return strings.TrimSpace(value), true
	}
	for candidateKey, value := range values {
		if strings.EqualFold(strings.TrimSpace(candidateKey), strings.TrimSpace(key)) {
			return strings.TrimSpace(value), true
		}
	}
	return "", false
}

func evaluateGCPCondition(
	condition map[string]any,
	principalNode *Node,
	targetNode *Node,
	ctx *PermissionEvaluationContext,
) conditionMatchResult {
	if ctx == nil {
		return conditionMatchUnknown
	}
	expression := strings.TrimSpace(toString(condition["expression"]))
	if expression == "" {
		return conditionMatchUnknown
	}

	env, err := gcpIAMConditionEnv()
	if err != nil {
		return conditionMatchUnknown
	}
	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return conditionMatchUnknown
	}
	program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return conditionMatchUnknown
	}

	activation := map[string]any{
		"request":   buildGCPRequestActivation(ctx),
		"principal": buildGCPPrincipalActivation(principalNode, ctx),
		"resource":  buildGCPResourceActivation(targetNode, ctx),
	}
	out, _, err := program.Eval(activation)
	if err != nil {
		return conditionMatchUnknown
	}
	matched, ok := out.Value().(bool)
	if !ok {
		return conditionMatchUnknown
	}
	if matched {
		return conditionMatchYes
	}
	return conditionMatchNo
}

func gcpIAMConditionEnv() (*cel.Env, error) {
	gcpConditionEnvOnce.Do(func() {
		gcpConditionEnv, gcpConditionEnvErr = cel.NewEnv(
			cel.Variable("request", cel.DynType),
			cel.Variable("principal", cel.DynType),
			cel.Variable("resource", cel.DynType),
			ext.Strings(),
		)
	})
	return gcpConditionEnv, gcpConditionEnvErr
}

func buildGCPRequestActivation(ctx *PermissionEvaluationContext) map[string]any {
	request := map[string]any{}
	if ctx == nil {
		return request
	}
	for key, value := range ctx.Request {
		request[key] = value
	}
	if !ctx.CurrentTime.IsZero() {
		request["time"] = ctx.CurrentTime.UTC()
	}
	if strings.TrimSpace(ctx.SourceIP) != "" {
		request["ip"] = strings.TrimSpace(ctx.SourceIP)
	}
	return request
}

func buildGCPPrincipalActivation(principalNode *Node, ctx *PermissionEvaluationContext) map[string]any {
	principal := map[string]any{}
	if principalNode != nil {
		principal["id"] = principalNode.ID
		principal["name"] = principalNode.Name
		principal["account"] = principalNode.Account
		if len(principalNode.Tags) > 0 {
			principal["tags"] = principalNode.Tags
		}
	}
	if ctx == nil {
		return principal
	}
	for key, value := range ctx.Principal {
		principal[key] = value
	}
	if strings.TrimSpace(ctx.PrincipalARN) != "" {
		principal["arn"] = strings.TrimSpace(ctx.PrincipalARN)
	}
	if strings.TrimSpace(ctx.PrincipalAccount) != "" {
		principal["account"] = strings.TrimSpace(ctx.PrincipalAccount)
	}
	if len(ctx.PrincipalTags) > 0 {
		principal["tags"] = ctx.PrincipalTags
	}
	return principal
}

func buildGCPResourceActivation(targetNode *Node, ctx *PermissionEvaluationContext) map[string]any {
	resource := map[string]any{}
	if targetNode != nil {
		resource["id"] = targetNode.ID
		resource["name"] = targetNode.Name
		resource["account"] = targetNode.Account
		resource["type"] = string(targetNode.Kind)
		if len(targetNode.Tags) > 0 {
			resource["tags"] = targetNode.Tags
		}
	}
	if ctx == nil {
		return resource
	}
	for key, value := range ctx.Resource {
		resource[key] = value
	}
	if strings.TrimSpace(ctx.ResourceARN) != "" {
		resource["arn"] = strings.TrimSpace(ctx.ResourceARN)
	}
	if strings.TrimSpace(ctx.ResourceAccount) != "" {
		resource["account"] = strings.TrimSpace(ctx.ResourceAccount)
	}
	if len(ctx.ResourceTags) > 0 {
		resource["tags"] = ctx.ResourceTags
	}
	return resource
}
