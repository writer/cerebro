package app

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/evalops/cerebro/internal/metrics"
	"github.com/evalops/cerebro/internal/policy"
	"github.com/evalops/cerebro/internal/scanner"
	"github.com/evalops/cerebro/internal/snowflake"
)

const (
	queryPolicyDefaultRowLimit = snowflake.MaxReadOnlyQueryLimit
	queryPolicyMetaFindingID   = "query-result-limit"
)

var executeReadOnlyQueryFn = func(ctx context.Context, client *snowflake.Client, query string) (*snowflake.QueryResult, error) {
	return client.Query(ctx, query)
}

type QueryPolicyScanResult struct {
	Policies int
	Findings []policy.Finding
	Errors   []string
}

// ScanQueryPolicies executes query-backed policies with read-only SQL guardrails.
func (a *App) ScanQueryPolicies(ctx context.Context) QueryPolicyScanResult {
	result := QueryPolicyScanResult{Findings: make([]policy.Finding, 0)}
	if a == nil || a.Policy == nil || a.Snowflake == nil {
		return result
	}

	logger := a.Logger
	if logger == nil {
		logger = slog.Default()
	}

	queryPolicies := a.Policy.ListQueryPolicies()
	result.Policies = len(queryPolicies)
	if len(queryPolicies) == 0 {
		return result
	}

	allowlist := a.queryPolicyAllowlist(ctx)
	if len(allowlist) == 0 {
		result.Errors = append(result.Errors, "query policy scan skipped: no allowlisted tables available")
		return result
	}

	tuning := a.ScanTuning()
	rowLimit := a.queryPolicyRowLimit()
	truncatedPolicies := make(map[string]int)

	findings, errs := a.Policy.EvaluateQueryPolicies(ctx, func(runCtx context.Context, queryPolicy *policy.Policy) ([]map[string]interface{}, error) {
		references := policy.ExtractQueryTableReferences(queryPolicy.Query)
		if len(references) == 0 {
			return nil, fmt.Errorf("query does not reference any FROM/JOIN tables")
		}
		for _, table := range references {
			if _, ok := allowlist[table]; !ok {
				logger.Debug("skipping query policy for unavailable table", "policy_id", queryPolicy.ID, "table", table)
				return nil, nil
			}
		}

		boundedQuery, boundedLimit, err := snowflake.BuildReadOnlyLimitedQuery(queryPolicy.Query, rowLimit)
		if err != nil {
			return nil, fmt.Errorf("invalid read-only query: %w", err)
		}

		queryCtx, cancel := context.WithTimeout(runCtx, snowflake.ClampReadOnlyQueryTimeout(0))
		defer cancel()

		queryResult, attempts, err := scanner.WithRetryValue(queryCtx, tuning.RetryOptions, func() (*snowflake.QueryResult, error) {
			return executeReadOnlyQueryFn(queryCtx, a.Snowflake, boundedQuery)
		})
		if attempts > 1 {
			logger.Debug("query policy retried", "policy_id", queryPolicy.ID, "attempts", attempts)
		}
		if err != nil {
			return nil, fmt.Errorf("query execution failed: %w", err)
		}

		if queryResult == nil || len(queryResult.Rows) == 0 {
			return nil, nil
		}

		rows := queryResult.Rows
		if len(rows) > boundedLimit {
			rows = rows[:boundedLimit]
		}
		if len(rows) >= boundedLimit {
			truncatedPolicies[queryPolicy.ID] = len(rows)
			metrics.RecordPolicyQueryTruncation(queryPolicy.ID)
			logger.Warn("query policy results hit row limit; findings may be truncated",
				"policy_id", queryPolicy.ID,
				"row_count", len(rows),
				"row_limit", boundedLimit,
			)
		}

		return rows, nil
	})

	result.Findings = findings
	if len(truncatedPolicies) > 0 {
		for _, queryPolicy := range queryPolicies {
			rowCount, ok := truncatedPolicies[queryPolicy.ID]
			if !ok {
				continue
			}
			result.Findings = append(result.Findings, queryPolicyTruncationMetaFinding(queryPolicy, rowCount, rowLimit))
		}
	}
	if len(errs) > 0 {
		result.Errors = make([]string, 0, len(errs))
		for _, err := range errs {
			result.Errors = append(result.Errors, err.Error())
		}
	}

	logger.Info("query policy scan complete",
		"policies", result.Policies,
		"findings", len(result.Findings),
		"errors", len(result.Errors),
	)

	return result
}

func queryPolicyTruncationMetaFinding(queryPolicy *policy.Policy, rowCount, rowLimit int) policy.Finding {
	description := fmt.Sprintf(
		"Policy %s returned %d rows and reached the query row limit (%d). Results may be truncated; refine the query or increase QUERY_POLICY_ROW_LIMIT.",
		queryPolicy.ID,
		rowCount,
		rowLimit,
	)
	return policy.Finding{
		ID:             fmt.Sprintf("%s:%s", queryPolicy.ID, queryPolicyMetaFindingID),
		PolicyID:       queryPolicy.ID,
		PolicyName:     queryPolicy.Name,
		Title:          "Query policy row limit reached",
		Severity:       queryPolicy.Severity,
		Resource:       map[string]interface{}{"policy_id": queryPolicy.ID, "rows_returned": rowCount, "row_limit": rowLimit},
		Description:    description,
		Remediation:    "Refine the query with tighter filters or increase QUERY_POLICY_ROW_LIMIT.",
		ControlID:      queryPolicy.ControlID,
		RiskCategories: queryPolicy.RiskCategories,
		ResourceType:   "query_policy_scan",
		ResourceID:     queryPolicy.ID,
		ResourceName:   queryPolicy.Name,
		Frameworks:     queryPolicy.Frameworks,
		MitreAttack:    queryPolicy.MitreAttack,
	}
}

func (a *App) queryPolicyRowLimit() int {
	rowLimit := queryPolicyDefaultRowLimit
	if a != nil && a.Config != nil && a.Config.QueryPolicyRowLimit > 0 {
		rowLimit = a.Config.QueryPolicyRowLimit
	}
	return snowflake.ClampReadOnlyQueryLimit(rowLimit)
}

func (a *App) queryPolicyAllowlist(ctx context.Context) map[string]struct{} {
	tables := a.AvailableTables
	if len(tables) == 0 && a.Snowflake != nil {
		if refreshed, err := a.Snowflake.ListAvailableTables(ctx); err == nil {
			a.AvailableTables = refreshed
			tables = refreshed
		} else if ctx.Err() == nil && a.Logger != nil {
			a.Logger.Warn("failed to refresh query policy allowlist tables", "error", err)
		}
	}

	allowlist := make(map[string]struct{}, len(tables))
	for _, table := range tables {
		normalized := strings.ToLower(strings.TrimSpace(table))
		if normalized == "" {
			continue
		}
		allowlist[normalized] = struct{}{}
	}

	return allowlist
}
