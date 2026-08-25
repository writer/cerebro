package grcdashboard

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/grcproductareas"
	"github.com/writer/cerebro/internal/operationtelemetry"
	"github.com/writer/cerebro/internal/sourcecoverage"
	"github.com/writer/cerebro/internal/telemetry"
	"golang.org/x/sync/errgroup"
)

const PreviewLimit = uint32(25)

type Enrichments string

const (
	EnrichmentsInline   Enrichments = "inline"
	EnrichmentsDeferred Enrichments = "deferred"
)

func TelemetryAttrs() telemetry.Attributes {
	return telemetry.Attrs(
		telemetry.Field{Key: "route", Value: "/grc/dashboard"},
		telemetry.Field{Key: "dashboard", Value: "grc"},
	)
}

func ScopeTelemetryAttrs(tenantID, runtimeID, sourceID string, limit uint32) telemetry.Attributes {
	return TelemetryAttrs().
		WithField(telemetry.Field{Key: "tenant_id", Value: tenantID}).
		WithField(telemetry.Field{Key: "runtime_id", Value: runtimeID}).
		WithField(telemetry.Field{Key: "source_id", Value: sourceID}).
		WithField(telemetry.Field{Key: "limit", Value: limit})
}

func ParseEnrichments(values url.Values) (Enrichments, error) {
	switch strings.ToLower(strings.TrimSpace(values.Get("enrichments"))) {
	case "", string(EnrichmentsInline):
		return EnrichmentsInline, nil
	case string(EnrichmentsDeferred):
		return EnrichmentsDeferred, nil
	default:
		return EnrichmentsInline, errors.New("enrichments must be inline or deferred when provided")
	}
}

func (e Enrichments) String() string {
	return string(e)
}

func (e Enrichments) SourceSummariesStatus(inlineStatus string) string {
	if e == EnrichmentsDeferred {
		return string(EnrichmentsDeferred)
	}
	return inlineStatus
}

func PreviewLimitFor(limit uint32) uint32 {
	if limit == 0 || limit > PreviewLimit {
		return PreviewLimit
	}
	return limit
}

func ProductAreas(enrichments Enrichments, coverage []sourcecoverage.Record) []grcproductareas.View {
	if enrichments == EnrichmentsDeferred {
		return nil
	}
	return grcproductareas.BuildCoverageViews(coverage)
}

type EnrichmentWork[Summary, Coverage any] struct {
	RuntimeCount         int
	RuntimeHealthTimeout time.Duration
	RuntimeHealth        func(context.Context) ([]Summary, error)
	Coverage             func(context.Context) ([]Coverage, error)
}

type EnrichmentResult[Summary, Coverage any] struct {
	SourceSummaries  []Summary
	Coverage         []Coverage
	RuntimeHealthErr error
}

func ScheduleEnrichments[Summary, Coverage any](
	group *errgroup.Group,
	groupCtx context.Context,
	enrichments Enrichments,
	work EnrichmentWork[Summary, Coverage],
) *EnrichmentResult[Summary, Coverage] {
	result := &EnrichmentResult[Summary, Coverage]{}
	if enrichments == EnrichmentsDeferred {
		return result
	}
	group.Go(func() error {
		runtimeHealthCtx, cancel := context.WithTimeout(groupCtx, work.RuntimeHealthTimeout)
		defer cancel()
		result.RuntimeHealthErr = operationtelemetry.RunMainPhase(runtimeHealthCtx, "grc.dashboard.runtime_health", telemetry.Attrs(telemetry.Field{Key: "runtime_count", Value: work.RuntimeCount}), func(ctx context.Context) (telemetry.Attributes, error) {
			var err error
			result.SourceSummaries, err = work.RuntimeHealth(ctx)
			return telemetry.Attrs(telemetry.Field{Key: "source_summary_count", Value: len(result.SourceSummaries)}), err
		})
		if result.RuntimeHealthErr != nil {
			result.SourceSummaries = nil
		}
		return nil
	})
	group.Go(func() error {
		var err error
		return operationtelemetry.RunMainPhase(groupCtx, "grc.dashboard.coverage", telemetry.Attrs(telemetry.Field{Key: "runtime_count", Value: work.RuntimeCount}), func(ctx context.Context) (telemetry.Attributes, error) {
			result.Coverage, err = work.Coverage(ctx)
			return telemetry.Attrs(telemetry.Field{Key: "coverage_record_count", Value: len(result.Coverage)}), err
		})
	})
	return result
}
