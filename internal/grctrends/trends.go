package grctrends

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type RequestParams struct {
	Interval  string
	Days      int
	Compare   bool
	Severity  string
	Framework string
	TargetParams
}

type DrilldownFilters struct {
	FirstObservedFrom   time.Time
	FirstObservedBefore time.Time
	StatusUpdatedFrom   time.Time
	StatusUpdatedBefore time.Time
	MinAgeDays          uint32
	MaxAgeDays          uint32
	SLAStatus           string
}

type Filter struct {
	Severity  string
	Framework string
}

type Provider interface {
	SummarizeGRCFindingTrends(context.Context, ports.GRCFindingTrendsRequest) (ports.GRCFindingTrends, error)
}

type Point struct {
	Date                  string  `json:"date"`
	Opened                int     `json:"opened"`
	OpenedCritical        int     `json:"opened_critical"`
	OpenedHigh            int     `json:"opened_high"`
	Closed                int     `json:"closed"`
	ClosedCritical        int     `json:"closed_critical"`
	ClosedHigh            int     `json:"closed_high"`
	ClosedSLABreached     int     `json:"closed_sla_breached"`
	AvgTimeToCloseSeconds float64 `json:"avg_time_to_close_seconds"`
	OpenTotal             int     `json:"open_total"`
}

type AgingBucket struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	MinDays int    `json:"min_days"`
	MaxDays int    `json:"max_days,omitempty"`
	Count   int    `json:"count"`
}

type Targets struct {
	MTTRSeconds int `json:"mttr_seconds,omitempty"`
	Backlog     int `json:"backlog,omitempty"`
	SLADays     int `json:"sla_days,omitempty"`
}

type TargetParams struct {
	MTTRTargetDays int
	BacklogTarget  int
	SLATargetDays  int
}

func ParseParams(values url.Values, defaultDays int, maxDays int) (RequestParams, error) {
	interval := strings.ToLower(strings.TrimSpace(values.Get("interval")))
	if interval == "" {
		interval = "day"
	}
	switch interval {
	case "day", "week", "month":
	default:
		return RequestParams{}, fmt.Errorf("interval must be day, week, or month")
	}
	days, err := positiveInt(values, "days")
	if err != nil {
		return RequestParams{}, err
	}
	if days == 0 {
		days = defaultDays
	}
	if days > maxDays {
		days = maxDays
	}
	compare, err := boolValue(values, "compare")
	if err != nil {
		return RequestParams{}, err
	}
	mttrTargetDays, err := positiveInt(values, "mttr_target_days")
	if err != nil {
		return RequestParams{}, err
	}
	backlogTarget, err := positiveInt(values, "backlog_target")
	if err != nil {
		return RequestParams{}, err
	}
	slaTargetDays, err := positiveInt(values, "sla_target_days")
	if err != nil {
		return RequestParams{}, err
	}
	return RequestParams{
		Interval:  interval,
		Days:      days,
		Compare:   compare,
		Severity:  strings.TrimSpace(values.Get("severity")),
		Framework: strings.TrimSpace(values.Get("framework")),
		TargetParams: TargetParams{
			MTTRTargetDays: mttrTargetDays,
			BacklogTarget:  backlogTarget,
			SLATargetDays:  slaTargetDays,
		},
	}, nil
}

func positiveInt(values url.Values, key string) (int, error) {
	value := strings.TrimSpace(values.Get(key))
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s", key)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("%s must be at least 1", key)
	}
	return parsed, nil
}

func ParseDrilldownFilters(values url.Values) (DrilldownFilters, error) {
	openedAfter, err := timeValue(values, "opened_after")
	if err != nil {
		return DrilldownFilters{}, err
	}
	openedBefore, err := timeValue(values, "opened_before")
	if err != nil {
		return DrilldownFilters{}, err
	}
	closedAfter, err := timeValue(values, "closed_after")
	if err != nil {
		return DrilldownFilters{}, err
	}
	closedBefore, err := timeValue(values, "closed_before")
	if err != nil {
		return DrilldownFilters{}, err
	}
	minAgeDays, err := positiveUint32(values, "age_min_days")
	if err != nil {
		return DrilldownFilters{}, err
	}
	maxAgeDays, err := positiveUint32(values, "age_max_days")
	if err != nil {
		return DrilldownFilters{}, err
	}
	return DrilldownFilters{
		FirstObservedFrom:   openedAfter,
		FirstObservedBefore: openedBefore,
		StatusUpdatedFrom:   closedAfter,
		StatusUpdatedBefore: closedBefore,
		MinAgeDays:          minAgeDays,
		MaxAgeDays:          maxAgeDays,
		SLAStatus:           strings.TrimSpace(values.Get("sla_status")),
	}, nil
}

func positiveUint32(values url.Values, key string) (uint32, error) {
	value := strings.TrimSpace(values.Get(key))
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid %s", key)
	}
	if parsed == 0 {
		return 0, fmt.Errorf("%s must be at least 1", key)
	}
	return uint32(parsed), nil
}

func boolValue(values url.Values, key string) (bool, error) {
	value := strings.TrimSpace(values.Get(key))
	if value == "" {
		return false, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("invalid %s", key)
	}
	return parsed, nil
}

func timeValue(values url.Values, key string) (time.Time, error) {
	value := strings.TrimSpace(values.Get(key))
	if value == "" {
		return time.Time{}, nil
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed.UTC(), nil
	}
	if parsed, err := time.Parse("2006-01-02", value); err == nil {
		return parsed.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("invalid %s", key)
}

type Comparison struct {
	PreviousStart              time.Time `json:"previous_start"`
	PreviousEnd                time.Time `json:"previous_end"`
	OpenedDelta                int       `json:"opened_delta"`
	ClosedDelta                int       `json:"closed_delta"`
	CurrentOpenDelta           int       `json:"current_open_delta"`
	AvgTimeToCloseSecondsDelta float64   `json:"avg_time_to_close_seconds_delta"`
	ClosedSLABreachedDelta     int       `json:"closed_sla_breached_delta"`
}

type Accuracy struct {
	StatusHistory string `json:"status_history"`
	Caveat        string `json:"caveat"`
}

type Response struct {
	Interval     string        `json:"interval"`
	Start        time.Time     `json:"start"`
	End          time.Time     `json:"end"`
	Points       []Point       `json:"points"`
	AgingBuckets []AgingBucket `json:"aging_buckets"`
	Targets      Targets       `json:"targets,omitempty"`
	Comparison   *Comparison   `json:"comparison,omitempty"`
	Accuracy     Accuracy      `json:"accuracy"`
	GeneratedAt  time.Time     `json:"generated_at"`
}

func BuildPoints(trends *ports.GRCFindingTrends) []Point {
	if trends == nil {
		return []Point{}
	}
	running := trends.OpenAtStart
	points := make([]Point, 0, len(trends.Points))
	for _, point := range trends.Points {
		running += point.Opened - point.Closed
		if running < 0 {
			running = 0
		}
		points = append(points, Point{
			Date:                  point.BucketStart.UTC().Format("2006-01-02"),
			Opened:                point.Opened,
			OpenedCritical:        point.OpenedCritical,
			OpenedHigh:            point.OpenedHigh,
			Closed:                point.Closed,
			ClosedCritical:        point.ClosedCritical,
			ClosedHigh:            point.ClosedHigh,
			ClosedSLABreached:     point.ClosedSLABreached,
			AvgTimeToCloseSeconds: averageSeconds(point.ClosedDurationSecondsTotal, point.ClosedDurationCount),
			OpenTotal:             running,
		})
	}
	return points
}

func BuildAgingBuckets(trends *ports.GRCFindingTrends) []AgingBucket {
	if trends == nil {
		return []AgingBucket{}
	}
	buckets := make([]AgingBucket, 0, len(trends.AgingBuckets))
	for _, bucket := range trends.AgingBuckets {
		buckets = append(buckets, AgingBucket{
			ID:      bucket.ID,
			Label:   bucket.Label,
			MinDays: bucket.MinDays,
			MaxDays: bucket.MaxDays,
			Count:   bucket.Count,
		})
	}
	return buckets
}

func BuildTargets(params TargetParams) Targets {
	targets := Targets{}
	if params.MTTRTargetDays > 0 {
		targets.MTTRSeconds = params.MTTRTargetDays * int((24 * time.Hour).Seconds())
	}
	if params.BacklogTarget > 0 {
		targets.Backlog = params.BacklogTarget
	}
	if params.SLATargetDays > 0 {
		targets.SLADays = params.SLATargetDays
	}
	return targets
}

func BuildComparison(previous *ports.GRCFindingTrends, current *ports.GRCFindingTrends, previousStart time.Time, previousEnd time.Time) *Comparison {
	prev := summarize(previous)
	next := summarize(current)
	return &Comparison{
		PreviousStart:              previousStart.UTC(),
		PreviousEnd:                previousEnd.UTC(),
		OpenedDelta:                next.Opened - prev.Opened,
		ClosedDelta:                next.Closed - prev.Closed,
		CurrentOpenDelta:           next.CurrentOpen - prev.CurrentOpen,
		AvgTimeToCloseSecondsDelta: next.AvgTimeToCloseSeconds - prev.AvgTimeToCloseSeconds,
		ClosedSLABreachedDelta:     next.ClosedSLABreached - prev.ClosedSLABreached,
	}
}

func Merge(ctx context.Context, provider Provider, runtimes []*cerebrov1.SourceRuntime, start time.Time, end time.Time, interval string, filter Filter) (*ports.GRCFindingTrends, error) {
	runtimeIDsByTenant := map[string][]string{}
	for _, runtime := range runtimes {
		if runtime == nil {
			continue
		}
		tenantID := strings.TrimSpace(runtime.GetTenantId())
		runtimeID := strings.TrimSpace(runtime.GetId())
		if tenantID == "" || runtimeID == "" {
			continue
		}
		runtimeIDsByTenant[tenantID] = append(runtimeIDsByTenant[tenantID], runtimeID)
	}
	merged := map[time.Time]*ports.GRCFindingTrendPoint{}
	agingByID := map[string]ports.GRCAgingBucket{}
	openAtStart := 0
	for tenantID, runtimeIDs := range runtimeIDsByTenant {
		trends, err := provider.SummarizeGRCFindingTrends(ctx, ports.GRCFindingTrendsRequest{
			FindingRequest: ports.ListFindingsRequest{
				TenantID:   tenantID,
				RuntimeIDs: runtimeIDs,
				Severity:   filter.Severity,
				Framework:  filter.Framework,
			},
			Start:    start,
			End:      end,
			Interval: interval,
		})
		if err != nil {
			return nil, err
		}
		openAtStart += trends.OpenAtStart
		for _, point := range trends.Points {
			key := point.BucketStart.UTC()
			agg := merged[key]
			if agg == nil {
				agg = &ports.GRCFindingTrendPoint{BucketStart: key}
				merged[key] = agg
			}
			agg.Opened += point.Opened
			agg.OpenedCritical += point.OpenedCritical
			agg.OpenedHigh += point.OpenedHigh
			agg.Closed += point.Closed
			agg.ClosedCritical += point.ClosedCritical
			agg.ClosedHigh += point.ClosedHigh
			agg.ClosedSLABreached += point.ClosedSLABreached
			agg.ClosedDurationSecondsTotal += point.ClosedDurationSecondsTotal
			agg.ClosedDurationCount += point.ClosedDurationCount
		}
		for _, bucket := range trends.AgingBuckets {
			id := strings.TrimSpace(bucket.ID)
			if id == "" {
				continue
			}
			agg := agingByID[id]
			if agg.ID == "" {
				agg = bucket
				agg.Count = 0
			}
			agg.Count += bucket.Count
			agingByID[id] = agg
		}
	}
	points := make([]ports.GRCFindingTrendPoint, 0, len(merged))
	for _, point := range merged {
		points = append(points, *point)
	}
	sort.Slice(points, func(i, j int) bool {
		return points[i].BucketStart.Before(points[j].BucketStart)
	})
	agingBuckets := make([]ports.GRCAgingBucket, 0, len(agingByID))
	for _, bucket := range agingByID {
		agingBuckets = append(agingBuckets, bucket)
	}
	sort.Slice(agingBuckets, func(i, j int) bool {
		return agingBuckets[i].MinDays < agingBuckets[j].MinDays
	})
	return &ports.GRCFindingTrends{Points: points, OpenAtStart: openAtStart, AgingBuckets: agingBuckets}, nil
}

type summaryValues struct {
	Opened                int
	Closed                int
	CurrentOpen           int
	ClosedSLABreached     int
	AvgTimeToCloseSeconds float64
	durationSecondsTotal  float64
	durationSecondsCount  int
}

func summarize(trends *ports.GRCFindingTrends) summaryValues {
	if trends == nil {
		return summaryValues{}
	}
	summary := summaryValues{CurrentOpen: trends.OpenAtStart}
	for _, point := range trends.Points {
		summary.Opened += point.Opened
		summary.Closed += point.Closed
		summary.ClosedSLABreached += point.ClosedSLABreached
		summary.durationSecondsTotal += point.ClosedDurationSecondsTotal
		summary.durationSecondsCount += point.ClosedDurationCount
		summary.CurrentOpen += point.Opened - point.Closed
		if summary.CurrentOpen < 0 {
			summary.CurrentOpen = 0
		}
	}
	summary.AvgTimeToCloseSeconds = averageSeconds(summary.durationSecondsTotal, summary.durationSecondsCount)
	return summary
}

func averageSeconds(total float64, count int) float64 {
	if count <= 0 || total <= 0 {
		return 0
	}
	return total / float64(count)
}
