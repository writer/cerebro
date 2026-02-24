package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var queryTableReferencePattern = regexp.MustCompile("(?i)\\b(?:from|join)\\s+([a-zA-Z0-9_.$\"`]+)")

// QueryPolicyExecutor executes a query-backed policy and returns matched rows.
type QueryPolicyExecutor func(ctx context.Context, policy *Policy) ([]map[string]interface{}, error)

// ListQueryPolicies returns loaded query-backed policies in stable ID order.
func (e *Engine) ListQueryPolicies() []*Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*Policy, 0, len(e.policies))
	for _, p := range e.policies {
		if strings.TrimSpace(p.Query) == "" {
			continue
		}
		result = append(result, p)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})

	return result
}

// EvaluateQueryPolicies executes all query-backed policies and maps rows into findings.
func (e *Engine) EvaluateQueryPolicies(ctx context.Context, executor QueryPolicyExecutor) ([]Finding, []error) {
	if executor == nil {
		return nil, []error{fmt.Errorf("query policy executor is required")}
	}

	policies := e.ListQueryPolicies()
	if len(policies) == 0 {
		return nil, nil
	}

	findings := make([]Finding, 0)
	errs := make([]error, 0)
	seenFindingIDs := make(map[string]struct{})

	for _, p := range policies {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}

		rows, err := executor(ctx, p)
		if err != nil {
			errs = append(errs, fmt.Errorf("policy %s: %w", p.ID, err))
			continue
		}

		for _, row := range rows {
			finding := queryFindingFromRow(p, row)
			if _, exists := seenFindingIDs[finding.ID]; exists {
				continue
			}
			seenFindingIDs[finding.ID] = struct{}{}
			findings = append(findings, finding)
		}
	}

	return findings, errs
}

func queryFindingFromRow(p *Policy, row map[string]interface{}) Finding {
	resource := copyMap(row)
	resourceID := strings.Trim(strings.TrimSpace(extractResourceID(resource)), `"'`)
	if resourceID == "" {
		resourceID = "row:" + stableRowHash(resource)
	}

	resourceType := strings.Trim(strings.TrimSpace(queryRowString(resource, "_cq_table")), `"'`)
	if resourceType == "" {
		resourceType = "query_result"
	}

	return Finding{
		ID:             fmt.Sprintf("%s:%s", p.ID, resourceID),
		PolicyID:       p.ID,
		PolicyName:     p.Name,
		Title:          p.Name,
		Severity:       p.Severity,
		Resource:       resource,
		Description:    p.Description,
		Remediation:    p.Remediation,
		ControlID:      p.ControlID,
		RiskCategories: p.RiskCategories,
		ResourceType:   resourceType,
		ResourceID:     resourceID,
		ResourceName:   extractResourceName(resource),
		Frameworks:     p.Frameworks,
		MitreAttack:    p.MitreAttack,
	}
}

func stableRowHash(row map[string]interface{}) string {
	payload, err := json.Marshal(row)
	if err != nil {
		payload = []byte(fmt.Sprintf("%v", row))
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])[:16]
}

func copyMap(input map[string]interface{}) map[string]interface{} {
	if len(input) == 0 {
		return map[string]interface{}{}
	}
	cloned := make(map[string]interface{}, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

// ExtractQueryTableReferences returns normalized table names referenced in query FROM/JOIN clauses.
func ExtractQueryTableReferences(query string) []string {
	matches := queryTableReferencePattern.FindAllStringSubmatch(query, -1)
	if len(matches) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(matches))
	tables := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		table := normalizeQueryTableReference(match[1])
		if table == "" {
			continue
		}
		if _, exists := seen[table]; exists {
			continue
		}
		seen[table] = struct{}{}
		tables = append(tables, table)
	}

	return tables
}

func normalizeQueryTableReference(raw string) string {
	table := strings.TrimSpace(raw)
	if table == "" {
		return ""
	}

	table = strings.TrimRight(table, ",;")
	if table == "" || strings.HasPrefix(table, "(") {
		return ""
	}

	segments := strings.Split(table, ".")
	table = strings.TrimSpace(segments[len(segments)-1])
	table = strings.Trim(table, `"`+"`")
	table = strings.TrimSpace(table)
	if table == "" {
		return ""
	}

	return strings.ToLower(table)
}

func queryRowString(row map[string]interface{}, key string) string {
	value := getFieldCaseInsensitive(row, key)
	if value == nil {
		return ""
	}
	if typed, ok := value.(string); ok {
		return typed
	}
	return fmt.Sprintf("%v", value)
}
