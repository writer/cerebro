package builders

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

type HistoricalDataSource interface {
	HistoricalQuery(ctx context.Context, timestamp time.Time, query string, args ...any) (*DataQueryResult, error)
}

// BuildAt constructs a graph from table state at a historical timestamp when
// the backing data source supports historical warehouse reads.
func (b *Builder) BuildAt(ctx context.Context, timestamp time.Time) (*Graph, error) {
	if timestamp.IsZero() {
		return nil, fmt.Errorf("timestamp is required")
	}
	historicalSource, ok := b.source.(HistoricalDataSource)
	if !ok {
		return nil, fmt.Errorf("historical graph builds are not supported by the current warehouse source")
	}

	timeTravelBuilder := NewBuilder(&historicalDataSource{
		base:      historicalSource,
		timestamp: timestamp.UTC(),
	}, b.logger)
	if err := timeTravelBuilder.Build(ctx); err != nil {
		return nil, err
	}
	return timeTravelBuilder.Graph(), nil
}

type historicalDataSource struct {
	base      HistoricalDataSource
	timestamp time.Time
}

func (s *historicalDataSource) Query(ctx context.Context, query string, args ...any) (*DataQueryResult, error) {
	return s.base.HistoricalQuery(ctx, s.timestamp, query, args...)
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
