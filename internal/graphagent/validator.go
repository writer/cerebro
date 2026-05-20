package graphagent

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

const (
	defaultMaxRows           = 100
	defaultAllNodesScanLimit = 1_000_000
)

var (
	forbiddenTokenPattern = regexp.MustCompile(`(?i)\b(CREATE|MERGE|DELETE|REMOVE|SET|DROP|FOREACH)\b`)
	loadCSVPattern        = regexp.MustCompile(`(?i)\bLOAD\s+CSV\b`)
	usingPeriodicPattern  = regexp.MustCompile(`(?i)\bUSING\s+PERIODIC\b`)
	forbiddenAPOCPattern  = regexp.MustCompile(`(?i)\bCALL\s+apoc\.(trigger|periodic)\.`)
	limitPattern          = regexp.MustCompile(`(?i)\bLIMIT\s+(\d+)\b`)
	entityTenantPattern   = regexp.MustCompile(`(?is)\(\s*[A-Za-z_][A-Za-z0-9_]*\s*:\s*Entity[^)]*tenant_id\s*:`)
	whereTenantPattern    = regexp.MustCompile(`(?i)\b[A-Za-z_][A-Za-z0-9_]*\.tenant_id\s*=\s*\$tenant_id\b`)
	quotedLiteralPattern  = regexp.MustCompile(`'[^']*'|"[^"]*"`)
	commentPattern        = regexp.MustCompile(`(?m)//.*$|/\*.*?\*/`)
	integerPattern        = regexp.MustCompile(`\d+`)
)

type ValidatorOptions struct {
	MaxRows           int
	AllNodesScanLimit int
	Explain           bool
}

type Validator struct {
	store   ports.GraphQueryStore
	options ValidatorOptions
}

func NewValidator(store ports.GraphQueryStore, options ValidatorOptions) *Validator {
	if options.MaxRows <= 0 {
		options.MaxRows = defaultMaxRows
	}
	if options.AllNodesScanLimit <= 0 {
		options.AllNodesScanLimit = defaultAllNodesScanLimit
	}
	return &Validator{store: store, options: options}
}

func (v *Validator) validate(ctx context.Context, cypher string, params map[string]any) (ValidatorResult, int) {
	query := strings.TrimSpace(cypher)
	if query == "" {
		return ValidatorResult{OK: false, Reason: "cypher is required"}, 0
	}
	safeQuery := scrubCypher(query)
	if forbiddenTokenPattern.MatchString(safeQuery) || loadCSVPattern.MatchString(safeQuery) || usingPeriodicPattern.MatchString(safeQuery) {
		return ValidatorResult{OK: false, Reason: "write or bulk-load Cypher clauses are forbidden"}, 0
	}
	if forbiddenAPOCPattern.MatchString(safeQuery) {
		return ValidatorResult{OK: false, Reason: "apoc trigger and periodic procedures are forbidden"}, 0
	}
	limit, ok := queryLimit(safeQuery)
	if !ok {
		return ValidatorResult{OK: false, Reason: "read Cypher must include a numeric LIMIT clause"}, 0
	}
	if limit > v.options.MaxRows {
		return ValidatorResult{OK: false, Reason: fmt.Sprintf("LIMIT %d exceeds maximum %d", limit, v.options.MaxRows)}, 0
	}
	if !hasTenantEntityFilter(safeQuery) {
		return ValidatorResult{OK: false, Reason: "query must filter at least one Entity by tenant_id"}, 0
	}
	if v.options.Explain && v.store != nil {
		rows, err := v.store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{
			Query:    "EXPLAIN " + query,
			Params:   params,
			RowLimit: 10,
		})
		if err != nil {
			return ValidatorResult{OK: false, Reason: "EXPLAIN failed: " + err.Error()}, 0
		}
		if allNodesScanOverLimit(rows, v.options.AllNodesScanLimit) {
			return ValidatorResult{OK: false, Reason: fmt.Sprintf("EXPLAIN plan contains AllNodesScan over more than %d nodes", v.options.AllNodesScanLimit)}, 0
		}
	}
	return ValidatorResult{OK: true}, limit
}

func scrubCypher(query string) string {
	noComments := commentPattern.ReplaceAllString(query, " ")
	return quotedLiteralPattern.ReplaceAllString(noComments, "''")
}

func queryLimit(query string) (int, bool) {
	matches := limitPattern.FindAllStringSubmatch(query, -1)
	if len(matches) == 0 {
		return 0, false
	}
	value := matches[len(matches)-1][1]
	limit, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}
	return limit, true
}

func hasTenantEntityFilter(query string) bool {
	return entityTenantPattern.MatchString(query) || whereTenantPattern.MatchString(query)
}

func allNodesScanOverLimit(rows []ports.CypherRow, limit int) bool {
	for _, row := range rows {
		for _, value := range row.Values {
			text := fmt.Sprint(value)
			if !strings.Contains(text, "AllNodesScan") {
				continue
			}
			for _, raw := range integerPattern.FindAllString(text, -1) {
				n, err := strconv.Atoi(raw)
				if err == nil && n > limit {
					return true
				}
			}
		}
	}
	return false
}
