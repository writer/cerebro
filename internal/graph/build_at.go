package graph

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// BuildAt constructs a graph from table state at a historical timestamp using
// Snowflake time-travel table clauses.
func (b *Builder) BuildAt(ctx context.Context, timestamp time.Time) (*Graph, error) {
	if timestamp.IsZero() {
		return nil, fmt.Errorf("timestamp is required")
	}

	timeTravelBuilder := NewBuilder(&timeTravelDataSource{
		base:      b.source,
		timestamp: timestamp.UTC(),
	}, b.logger)
	if err := timeTravelBuilder.Build(ctx); err != nil {
		return nil, err
	}
	return timeTravelBuilder.Graph(), nil
}

type timeTravelDataSource struct {
	base      DataSource
	timestamp time.Time
}

func (s *timeTravelDataSource) Query(ctx context.Context, query string, args ...any) (*QueryResult, error) {
	rewritten := applyTimeTravelClauses(query, s.timestamp)
	return s.base.Query(ctx, rewritten, args...)
}

var timeTravelClausePattern = regexp.MustCompile(`(?i)\b(FROM|JOIN|UPDATE|INTO)\s+([a-z][a-z0-9_\.]*)`)

func applyTimeTravelClauses(query string, timestamp time.Time) string {
	clauseTimestamp := timestamp.UTC().Format("2006-01-02 15:04:05")

	return timeTravelClausePattern.ReplaceAllStringFunc(query, func(match string) string {
		parts := timeTravelClausePattern.FindStringSubmatch(match)
		if len(parts) < 3 {
			return match
		}
		keyword := parts[1]
		tableName := parts[2]
		if strings.Contains(strings.ToLower(tableName), "information_schema") {
			return match
		}
		if strings.Contains(strings.ToUpper(match), "AT(TIMESTAMP") {
			return match
		}
		return fmt.Sprintf("%s %s AT(TIMESTAMP => '%s')", keyword, tableName, clauseTimestamp)
	})
}
