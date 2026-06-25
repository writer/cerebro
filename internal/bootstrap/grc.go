package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphagent"
	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/grccontrol"
	"github.com/writer/cerebro/internal/grctrends"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecoverage"
	"github.com/writer/cerebro/internal/sourceruntime"
	"github.com/writer/cerebro/internal/telemetry"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	grcDefaultLimit          = uint32(100)
	grcMaxLimit              = uint32(500)
	grcDashboardPreviewLimit = uint32(25)
)

type grcScope struct {
	TenantID   string
	RuntimeID  string
	RuntimeIDs []string
	SourceID   string
	Limit      uint32
}

type grcDashboardResponse struct {
	Summary            grcSummary                   `json:"summary"`
	Findings           []grcFindingItem             `json:"findings"`
	Controls           []grcControlItem             `json:"controls"`
	Evidence           []grcEvidenceItem            `json:"evidence"`
	Connectors         []grcConnector               `json:"connectors"`
	SourceSummaries    []sourceRuntimeHealthSummary `json:"source_summaries,omitempty"`
	CoverageBlindSpots []sourcecoverage.Record      `json:"coverage_blind_spots,omitempty"`
	CoverageSummaries  []sourcecoverage.Summary     `json:"coverage_summaries,omitempty"`
	GeneratedAt        time.Time                    `json:"generated_at"`
}

type grcSummary struct {
	OpenFindings     int `json:"open_findings"`
	CriticalFindings int `json:"critical_findings"`
	HighFindings     int `json:"high_findings"`
	OverdueFindings  int `json:"overdue_findings"`
	Unassigned       int `json:"unassigned"`
	ControlsFailing  int `json:"controls_failing"`
	EvidenceItems    int `json:"evidence_items"`
	Connectors       int `json:"connectors"`
	StaleConnectors  int `json:"stale_connectors"`
}

type grcFindingItem struct {
	ID           string          `json:"id"`
	Title        string          `json:"title"`
	Severity     string          `json:"severity"`
	Status       string          `json:"status"`
	Summary      string          `json:"summary,omitempty"`
	TenantID     string          `json:"tenant_id,omitempty"`
	RuntimeID    string          `json:"runtime_id,omitempty"`
	SourceID     string          `json:"source_id,omitempty"`
	Entity       string          `json:"entity,omitempty"`
	ResourceURNs []string        `json:"resource_urns,omitempty"`
	RuleID       string          `json:"rule_id,omitempty"`
	PolicyID     string          `json:"policy_id,omitempty"`
	PolicyName   string          `json:"policy_name,omitempty"`
	Controls     []grcControlRef `json:"controls,omitempty"`
	GRCFindingRisk
	GRCFindingWorkflowMetadata
	EvidenceCount   int        `json:"evidence_count"`
	Owner           string     `json:"owner"`
	SLAStatus       string     `json:"sla_status"`
	FirstObservedAt *time.Time `json:"first_observed_at,omitempty"`
	LastObservedAt  *time.Time `json:"last_observed_at,omitempty"`
}

type GRCFindingWorkflowMetadata struct {
	Disposition     string                     `json:"disposition,omitempty"`
	StatusReason    string                     `json:"status_reason,omitempty"`
	Assignee        string                     `json:"assignee,omitempty"`
	DueAt           *time.Time                 `json:"due_at,omitempty"`
	StatusUpdatedAt *time.Time                 `json:"status_updated_at,omitempty"`
	Notes           []ports.FindingNote        `json:"notes,omitempty"`
	Tickets         []ports.FindingTicket      `json:"tickets,omitempty"`
	ExternalRefs    []ports.FindingExternalRef `json:"external_refs,omitempty"`
}

type GRCFindingRisk struct {
	RiskScore       int      `json:"risk_score,omitempty"`
	LikelihoodScore int      `json:"likelihood_score,omitempty"`
	ImpactScore     int      `json:"impact_score,omitempty"`
	ConfidenceScore int      `json:"confidence_score,omitempty"`
	LikelihoodLevel string   `json:"likelihood_level,omitempty"`
	ImpactLevel     string   `json:"impact_level,omitempty"`
	RiskReasons     []string `json:"risk_reasons,omitempty"`
	RiskModel       string   `json:"risk_model_version,omitempty"`
}

type grcControlRef struct {
	FrameworkName string `json:"framework_name"`
	ControlID     string `json:"control_id"`
}

type grcControlItem struct {
	FrameworkName    string           `json:"framework_name"`
	ControlID        string           `json:"control_id"`
	Status           string           `json:"status"`
	OpenFindings     int              `json:"open_findings"`
	CriticalFindings int              `json:"critical_findings"`
	HighFindings     int              `json:"high_findings"`
	EvidenceItems    int              `json:"evidence_items"`
	Findings         []grcFindingItem `json:"findings,omitempty"`
}

type grcEvidenceItem struct {
	ID            string    `json:"id"`
	RuntimeID     string    `json:"runtime_id,omitempty"`
	RuleID        string    `json:"rule_id,omitempty"`
	FindingID     string    `json:"finding_id,omitempty"`
	FindingTitle  string    `json:"finding_title,omitempty"`
	RunID         string    `json:"run_id,omitempty"`
	ClaimIDs      []string  `json:"claim_ids,omitempty"`
	EventIDs      []string  `json:"event_ids,omitempty"`
	GraphRootURNs []string  `json:"graph_root_urns,omitempty"`
	CreatedAt     time.Time `json:"created_at,omitempty"`
}

type grcConnector struct {
	RuntimeID           string     `json:"runtime_id"`
	SourceID            string     `json:"source_id,omitempty"`
	TenantID            string     `json:"tenant_id,omitempty"`
	Status              string     `json:"status"`
	Freshness           string     `json:"freshness"`
	SyncLagSeconds      *int64     `json:"sync_lag_seconds,omitempty"`
	CheckpointWatermark *time.Time `json:"checkpoint_watermark,omitempty"`
	WatermarkLagSeconds *int64     `json:"watermark_lag_seconds,omitempty"`
	WatermarkFreshness  string     `json:"watermark_freshness,omitempty"`
	LastSyncedAt        *time.Time `json:"last_synced_at,omitempty"`
}

type grcEntityImpactResponse struct {
	EntityURN   string                    `json:"entity_urn"`
	Graph       *ports.EntityNeighborhood `json:"graph,omitempty"`
	Findings    []grcFindingItem          `json:"findings"`
	GeneratedAt time.Time                 `json:"generated_at"`
}

type grcAuditPacketResponse struct {
	ID                string                    `json:"id"`
	Finding           grcFindingItem            `json:"finding"`
	Evidence          []grcEvidenceItem         `json:"evidence"`
	Graph             *ports.EntityNeighborhood `json:"graph,omitempty"`
	Controls          []grcControlRef           `json:"controls,omitempty"`
	RecommendedAction string                    `json:"recommended_action"`
	Metadata          grccontrol.ReportMetadata `json:"metadata"`
	GeneratedAt       time.Time                 `json:"generated_at"`
}

func (a *App) handleGRCDashboard(w http.ResponseWriter, r *http.Request) {
	ctx, span := telemetry.Start(r.Context(), "grc.dashboard", grcDashboardTelemetryAttrs())
	dashboardCtx := ctx
	r = r.WithContext(ctx)
	status := "completed"
	statusCode := http.StatusOK
	endAttrs := grcDashboardTelemetryAttrs()
	defer func() {
		endAttrs = endAttrs.WithField(telemetry.Field{Key: "status_code", Value: statusCode})
		telemetry.IncrementMain(dashboardCtx, "grc.dashboard.count", 1)
		if status != "completed" {
			telemetry.IncrementMain(dashboardCtx, "grc.dashboard.error.count", 1)
		}
		telemetry.AnnotateMain(dashboardCtx, endAttrs.With(telemetry.Attrs(
			telemetry.Field{Key: "grc.dashboard.status", Value: status},
			telemetry.Field{Key: "grc.dashboard.status_code", Value: statusCode},
		)))
		telemetry.AnnotateMainPhase(dashboardCtx, "grc.dashboard", status, endAttrs)
		telemetry.End(span, status, endAttrs)
	}()
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		statusCode = grcHTTPStatusCode(err)
		status, endAttrs = grcTelemetryError(endAttrs, err)
		writeGRCError(w, err)
		return
	}
	endAttrs = endAttrs.WithField(telemetry.Field{Key: "limit", Value: scope.Limit})
	previewLimit := grcDashboardPreviewLimitFor(scope.Limit)
	endAttrs = endAttrs.WithField(telemetry.Field{Key: "preview_limit", Value: previewLimit})
	ctx, runtimesSpan := telemetry.Start(r.Context(), "grc.dashboard.runtimes", grcDashboardScopeTelemetryAttrs(scope))
	runtimesRequest := r.WithContext(ctx)
	runtimes, err := a.grcListRuntimes(runtimesRequest, scope)
	runtimeAttrs := telemetry.Attrs(telemetry.Field{Key: "runtime_count", Value: len(runtimes)})
	telemetry.AnnotateMainPhase(ctx, "grc.dashboard.runtimes", grcTelemetryStatus(err), runtimeAttrs)
	telemetry.End(runtimesSpan, grcTelemetryStatus(err), runtimeAttrs)
	if err != nil {
		statusCode = grcHTTPStatusCode(err)
		status, endAttrs = grcTelemetryError(endAttrs, err)
		writeGRCError(w, err)
		return
	}
	ctx, findingsSpan := telemetry.Start(r.Context(), "grc.dashboard.findings", grcDashboardScopeTelemetryAttrs(scope))
	findingsRequest := r.WithContext(ctx)
	findings, err := a.grcListFindingRecords(findingsRequest, runtimes, grcFindingFilter{Status: "open", Limit: previewLimit})
	findingAttrs := telemetry.Attrs(telemetry.Field{Key: "finding_count", Value: len(findings)})
	telemetry.AnnotateMainPhase(ctx, "grc.dashboard.findings", grcTelemetryStatus(err), findingAttrs)
	telemetry.End(findingsSpan, grcTelemetryStatus(err), findingAttrs)
	if err != nil {
		statusCode = grcHTTPStatusCode(err)
		status, endAttrs = grcTelemetryError(endAttrs, err)
		writeGRCError(w, err)
		return
	}
	findingIDs := grcFindingIDs(findings)
	var (
		evidence       []*cerebrov1.FindingEvidence
		findingSummary *ports.FindingSummary
		evidenceCount  *int
		aggregate      *ports.GRCDashboardAggregate
		wg             sync.WaitGroup
		errs           = make(chan error, 3)
	)
	wg.Add(2)
	go func(parent context.Context) {
		defer wg.Done()
		var err error
		ctx, evidenceSpan := telemetry.Start(parent, "grc.dashboard.evidence", telemetry.Attrs(telemetry.Field{Key: "finding_count", Value: len(findingIDs)}))
		evidenceRequest := r.WithContext(ctx)
		evidence, err = a.grcListEvidenceRecords(evidenceRequest, runtimes, grcEvidenceFilter{FindingIDs: findingIDs, Limit: previewLimit})
		evidenceAttrs := telemetry.Attrs(telemetry.Field{Key: "evidence_count", Value: len(evidence)})
		telemetry.AnnotateMainPhase(ctx, "grc.dashboard.evidence", grcTelemetryStatus(err), evidenceAttrs)
		telemetry.End(evidenceSpan, grcTelemetryStatus(err), evidenceAttrs)
		if err != nil {
			errs <- err
		}
	}(r.Context())
	go func(parent context.Context) {
		defer wg.Done()
		var err error
		ctx, aggregateSpan := telemetry.Start(parent, "grc.dashboard.aggregate", telemetry.Attrs(telemetry.Field{Key: "finding_count", Value: len(findingIDs)}))
		aggregateRequest := r.WithContext(ctx)
		aggregate, err = a.grcDashboardAggregate(aggregateRequest, runtimes, grcFindingFilter{Status: "open"}, grcEvidenceFilter{})
		if err == nil && aggregate == nil {
			findingSummary, err = a.grcFindingSummary(aggregateRequest, runtimes, grcFindingFilter{Status: "open"})
			if err == nil {
				evidenceCount, err = a.grcEvidenceCount(aggregateRequest, runtimes, grcEvidenceFilter{FindingIDs: findingIDs})
			}
		}
		attrs := telemetry.Attrs()
		if aggregate != nil {
			attrs = attrs.WithField(telemetry.Field{Key: "evidence_count", Value: aggregate.EvidenceCount})
			attrs = attrs.WithField(telemetry.Field{Key: "open_findings", Value: aggregate.FindingSummary.OpenFindings})
		}
		telemetry.AnnotateMainPhase(ctx, "grc.dashboard.aggregate", grcTelemetryStatus(err), attrs)
		telemetry.End(aggregateSpan, grcTelemetryStatus(err), attrs)
		if err != nil {
			errs <- err
		}
	}(r.Context())
	wg.Wait()
	close(errs)
	if err := joinGRCErrors(errs); err != nil {
		statusCode = grcHTTPStatusCode(err)
		status, endAttrs = grcTelemetryError(endAttrs, err)
		writeGRCError(w, err)
		return
	}
	if aggregate != nil {
		findingSummary = &aggregate.FindingSummary
		evidenceCount = &aggregate.EvidenceCount
	}
	runtimeSourceIDs := grcRuntimeSourceIDs(runtimes)
	evidenceCounts := grcEvidenceCounts(evidence)
	if aggregate != nil && len(aggregate.EvidenceCountsByFindingID) > 0 {
		evidenceCounts = aggregate.EvidenceCountsByFindingID
	}
	findingItems := grcFindingItems(findings, runtimeSourceIDs, evidenceCounts)
	evidenceItems := grcEvidenceItems(evidence, grcFindingTitleMap(findings))
	controls := grcControlItems(findingItems, evidenceItems)
	generatedAt := time.Now().UTC()
	sourceSummaries, err := a.grcSourceRuntimeHealthSummaries(r.Context(), runtimes, generatedAt)
	if err != nil {
		statusCode = grcHTTPStatusCode(err)
		status, endAttrs = grcTelemetryError(endAttrs, err)
		writeGRCError(w, err)
		return
	}
	coverage := a.sourceCoverageRecords(runtimes, ports.SourceRuntimeFilter{TenantID: scope.TenantID, SourceID: scope.SourceID}, generatedAt)
	coverageBlindSpots := sourcecoverage.BlindSpots(coverage)
	endAttrs = endAttrs.WithField(telemetry.Field{Key: "runtime_count", Value: len(runtimes)})
	endAttrs = endAttrs.WithField(telemetry.Field{Key: "finding_count", Value: len(findingItems)})
	endAttrs = endAttrs.WithField(telemetry.Field{Key: "evidence_count", Value: len(evidenceItems)})

	writeJSON(w, http.StatusOK, grcDashboardResponse{
		Summary:            grcBuildSummary(findingItems, controls, evidenceItems, runtimes, findingSummary, evidenceCount),
		Findings:           grcLimitFindings(findingItems, 25),
		Controls:           grcLimitControls(controls, 25),
		Evidence:           grcLimitEvidence(evidenceItems, 25),
		Connectors:         grcConnectorItems(runtimes),
		SourceSummaries:    sourceSummaries,
		CoverageBlindSpots: coverageBlindSpots,
		CoverageSummaries:  sourcecoverage.Summaries(coverage),
		GeneratedAt:        generatedAt,
	})
}

func (a *App) grcSourceRuntimeHealthSummaries(ctx context.Context, runtimes []*cerebrov1.SourceRuntime, generatedAt time.Time) ([]sourceRuntimeHealthSummary, error) {
	records := make([]sourceRuntimeHealthRecord, 0, len(runtimes))
	for _, runtime := range runtimes {
		if runtime == nil {
			continue
		}
		record, err := a.sourceRuntimeHealthRecord(ctx, runtime, generatedAt)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return sourceRuntimeHealthSummaries(records), nil
}

func grcDashboardPreviewLimitFor(limit uint32) uint32 {
	if limit == 0 || limit > grcDashboardPreviewLimit {
		return grcDashboardPreviewLimit
	}
	return limit
}

func joinGRCErrors(errs <-chan error) error {
	var joined error
	for err := range errs {
		joined = errors.Join(joined, err)
	}
	return joined
}

const (
	grcTrendsDefaultDays = 90
	grcTrendsMaxDays     = 366
)

func (a *App) handleGRCTrends(w http.ResponseWriter, r *http.Request) {
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	params, err := grctrends.ParseParams(r.URL.Query(), grcTrendsDefaultDays, grcTrendsMaxDays)
	if err != nil {
		writeGRCError(w, fmt.Errorf("%w: %w", errInvalidHTTPRequest, err))
		return
	}
	end := time.Now().UTC()
	start := end.AddDate(0, 0, -params.Days)
	runtimes, err := a.grcListRuntimes(r, scope)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	filter := grcFindingFilter{
		Severity:  params.Severity,
		Framework: params.Framework,
	}
	var trends *ports.GRCFindingTrends
	var previous *ports.GRCFindingTrends
	var comparison *grctrends.Comparison
	var previousStart time.Time
	var previousEnd time.Time
	if params.Compare {
		previousEnd = start
		previousStart = previousEnd.Add(end.Sub(start) * -1)
	}
	group, trendsCtx := errgroup.WithContext(r.Context())
	group.Go(func() error {
		var err error
		trends, err = a.grcFindingTrends(r.WithContext(trendsCtx), runtimes, start, end, params.Interval, filter)
		return err
	})
	if params.Compare {
		group.Go(func() error {
			var err error
			previous, err = a.grcFindingTrends(r.WithContext(trendsCtx), runtimes, previousStart, previousEnd, params.Interval, filter)
			return err
		})
	}
	if err := group.Wait(); err != nil {
		writeGRCError(w, err)
		return
	}
	if params.Compare {
		comparison = grctrends.BuildComparison(previous, trends, previousStart, previousEnd)
	}
	writeJSON(w, http.StatusOK, grctrends.Response{
		Interval:     params.Interval,
		Start:        start,
		End:          end,
		Points:       grctrends.BuildPoints(trends),
		AgingBuckets: grctrends.BuildAgingBuckets(trends),
		Summary:      grctrends.BuildSummary(trends),
		Targets:      grctrends.BuildTargets(params.TargetParams),
		Comparison:   comparison,
		Accuracy: grctrends.Accuracy{
			StatusHistory: "current_state_with_status_history_forward_capture",
			Caveat:        "Trend points use first_observed_at and the latest status_updated_at for existing rows; durable status history is captured for new lifecycle transitions, so reopen accuracy improves as history accrues.",
		},
		GeneratedAt: time.Now().UTC(),
	})
}

func (a *App) grcFindingTrends(r *http.Request, runtimes []*cerebrov1.SourceRuntime, start, end time.Time, interval string, filter grcFindingFilter) (*ports.GRCFindingTrends, error) {
	store := findingStore(a.deps.StateStore)
	provider, ok := store.(grcFindingTrendsProvider)
	if !ok {
		return nil, findings.ErrRuntimeUnavailable
	}
	return grctrends.Merge(r.Context(), provider, runtimes, start, end, interval, grctrends.Filter{
		Severity:  filter.Severity,
		Framework: filter.Framework,
	})
}

func (a *App) handleGRCFindings(w http.ResponseWriter, r *http.Request) {
	items, err := a.grcFindingItemsFromRequest(r, 0)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"findings":     items,
		"generated_at": time.Now().UTC(),
	})
}

// grcFindingItemsFromRequest gathers risk-inbox finding items for a request,
// shared by the JSON list handler and the CSV export. A non-zero limitOverride
// replaces the request's scope limit (the export pulls the full dataset).
func (a *App) grcFindingItemsFromRequest(r *http.Request, limitOverride uint32) ([]grcFindingItem, error) {
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		return nil, err
	}
	runtimes, err := a.grcListRuntimes(r, scope)
	if err != nil {
		return nil, err
	}
	limit := scope.Limit
	if limitOverride > 0 {
		limit = limitOverride
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if status == "" {
		status = "open"
	} else if strings.EqualFold(status, "all") {
		status = ""
	}
	drilldown, err := grctrends.ParseDrilldownFilters(r.URL.Query())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalidHTTPRequest, err)
	}
	findings, err := a.grcListFindingRecords(r, runtimes, grcFindingFilter{
		FindingID:           strings.TrimSpace(r.URL.Query().Get("finding_id")),
		RuleID:              strings.TrimSpace(r.URL.Query().Get("rule_id")),
		Severity:            strings.TrimSpace(r.URL.Query().Get("severity")),
		Status:              status,
		ResourceURN:         strings.TrimSpace(r.URL.Query().Get("resource_urn")),
		EventID:             strings.TrimSpace(r.URL.Query().Get("event_id")),
		PolicyID:            strings.TrimSpace(r.URL.Query().Get("policy_id")),
		Framework:           strings.TrimSpace(r.URL.Query().Get("framework")),
		FirstObservedFrom:   drilldown.FirstObservedFrom,
		FirstObservedBefore: drilldown.FirstObservedBefore,
		StatusUpdatedFrom:   drilldown.StatusUpdatedFrom,
		StatusUpdatedBefore: drilldown.StatusUpdatedBefore,
		MinAgeDays:          drilldown.MinAgeDays,
		MaxAgeDays:          drilldown.MaxAgeDays,
		SLAStatus:           drilldown.SLAStatus,
		Limit:               limit,
	})
	if err != nil {
		return nil, err
	}
	evidenceCounts, counted, err := a.grcEvidenceCountsByFindingID(r, runtimes, grcEvidenceFilter{FindingIDs: grcFindingIDs(findings)})
	if err != nil {
		return nil, err
	}
	if !counted {
		evidence, err := a.grcListEvidenceRecords(r, runtimes, grcEvidenceFilter{FindingIDs: grcFindingIDs(findings), Limit: limit})
		if err != nil {
			return nil, err
		}
		evidenceCounts = grcEvidenceCounts(evidence)
	}
	items := grcFindingItems(findings, grcRuntimeSourceIDs(runtimes), evidenceCounts)
	grcApplyFindingDispositions(items, a.grcFindingDispositions(r, findings))
	return items, nil
}

func (a *App) handleGRCControls(w http.ResponseWriter, r *http.Request) {
	controls, err := a.grcControlItemsFromRequest(r, 0)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"controls":     controls,
		"generated_at": time.Now().UTC(),
	})
}

// grcControlItemsFromRequest groups open findings into control posture rows,
// shared by the JSON list handler and the CSV export. A non-zero limitOverride
// replaces the request's scope limit (the export pulls the full dataset).
func (a *App) grcControlItemsFromRequest(r *http.Request, limitOverride uint32) ([]grcControlItem, error) {
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		return nil, err
	}
	runtimes, err := a.grcListRuntimes(r, scope)
	if err != nil {
		return nil, err
	}
	limit := scope.Limit
	if limitOverride > 0 {
		limit = limitOverride
	}
	findings, err := a.grcListFindingRecords(r, runtimes, grcFindingFilter{Status: "open", Limit: limit})
	if err != nil {
		return nil, err
	}
	evidenceCounts, counted, err := a.grcEvidenceCountsByFindingID(r, runtimes, grcEvidenceFilter{FindingIDs: grcFindingIDs(findings)})
	if err != nil {
		return nil, err
	}
	var evidenceItems []grcEvidenceItem
	if !counted {
		evidence, err := a.grcListEvidenceRecords(r, runtimes, grcEvidenceFilter{FindingIDs: grcFindingIDs(findings), Limit: limit})
		if err != nil {
			return nil, err
		}
		evidenceCounts = grcEvidenceCounts(evidence)
		evidenceItems = grcEvidenceItems(evidence, grcFindingTitleMap(findings))
	}
	items := grcFindingItems(findings, grcRuntimeSourceIDs(runtimes), evidenceCounts)
	return grcControlItems(items, evidenceItems), nil
}

func (a *App) handleGRCEvidence(w http.ResponseWriter, r *http.Request) {
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	runtimes, err := a.grcListRuntimes(r, scope)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	findings, err := a.grcListFindingRecords(r, runtimes, grcFindingFilter{Limit: scope.Limit})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	evidence, err := a.grcListEvidenceRecords(r, runtimes, grcEvidenceFilter{
		FindingID:    strings.TrimSpace(r.URL.Query().Get("finding_id")),
		RunID:        strings.TrimSpace(r.URL.Query().Get("run_id")),
		RuleID:       strings.TrimSpace(r.URL.Query().Get("rule_id")),
		GraphRootURN: strings.TrimSpace(r.URL.Query().Get("graph_root_urn")),
		Limit:        scope.Limit,
	})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"evidence":     grcEvidenceItems(evidence, grcFindingTitleMap(findings)),
		"generated_at": time.Now().UTC(),
	})
}

func (a *App) handleGRCEntityImpact(w http.ResponseWriter, r *http.Request) {
	entityURN := strings.TrimSpace(r.PathValue("entityID"))
	if rootURN := strings.TrimSpace(r.URL.Query().Get("root_urn")); rootURN != "" {
		entityURN = rootURN
	}
	if entityURN == "" {
		writeGRCError(w, fmt.Errorf("%w: entity urn is required", errInvalidHTTPRequest))
		return
	}
	if err := authorizeCerebroURNTenant(r.Context(), entityURN); err != nil {
		writeGRCError(w, err)
		return
	}
	limit, err := grcLimitFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	graphStore := graphQueryStore(a.deps.GraphStore)
	if graphStore == nil {
		writeGRCError(w, graphquery.ErrRuntimeUnavailable)
		return
	}
	graph, err := graphStore.GetEntityNeighborhood(r.Context(), entityURN, int(limit))
	if err != nil {
		writeGRCError(w, err)
		return
	}
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	runtimes, err := a.grcListRuntimes(r, scope)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	findings, err := a.grcListFindingRecords(r, runtimes, grcFindingFilter{ResourceURN: entityURN, Limit: limit})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	evidence, err := a.grcListEvidenceRecords(r, runtimes, grcEvidenceFilter{FindingIDs: grcFindingIDs(findings), Limit: limit})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, grcEntityImpactResponse{
		EntityURN:   entityURN,
		Graph:       graph,
		Findings:    grcFindingItems(findings, grcRuntimeSourceIDs(runtimes), grcEvidenceCounts(evidence)),
		GeneratedAt: time.Now().UTC(),
	})
}

func (a *App) handleGRCAuditPacket(w http.ResponseWriter, r *http.Request) {
	packet, err := a.buildGRCAuditPacket(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, packet)
}

func (a *App) handleGRCAuditPacketExport(w http.ResponseWriter, r *http.Request) {
	packet, err := a.buildGRCAuditPacket(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	if strings.EqualFold(r.URL.Query().Get("format"), "json") {
		writeJSON(w, http.StatusOK, packet)
		return
	}
	writeGRCMarkdownExport(w, "finding-audit-packet.md", grccontrol.RenderFindingAuditPacketMarkdown(grcFindingAuditMarkdownInput(packet)))
}

func (a *App) buildGRCAuditPacket(r *http.Request) (grcAuditPacketResponse, error) {
	findingID := strings.TrimSpace(r.PathValue("packetID"))
	if findingID == "" {
		return grcAuditPacketResponse{}, fmt.Errorf("%w: finding id is required", errInvalidHTTPRequest)
	}
	limit, err := grcLimitFromRequest(r)
	if err != nil {
		return grcAuditPacketResponse{}, err
	}
	store := findingStore(a.deps.StateStore)
	if store == nil {
		return grcAuditPacketResponse{}, findings.ErrRuntimeUnavailable
	}
	if err := authorizeFindingIDTenant(r.Context(), store, findingID); err != nil {
		return grcAuditPacketResponse{}, normalizeIDLookupError(err, ports.ErrFindingNotFound)
	}
	finding, err := a.findingService().GetFinding(r.Context(), findingID)
	if err != nil {
		return grcAuditPacketResponse{}, err
	}
	scope := grcScope{TenantID: finding.TenantID, RuntimeID: finding.RuntimeID, Limit: limit}
	runtimes, err := a.grcListRuntimes(r, scope)
	if err != nil {
		return grcAuditPacketResponse{}, err
	}
	reportScopeRuntimes := a.grcReportScopeRuntimes(r, scope, runtimes)
	evidence, err := a.grcListEvidenceRecords(r, runtimes, grcEvidenceFilter{FindingID: finding.ID, Limit: limit})
	if err != nil {
		return grcAuditPacketResponse{}, err
	}
	var graph *ports.EntityNeighborhood
	if len(finding.ResourceURNs) > 0 {
		if graphStore := graphQueryStore(a.deps.GraphStore); graphStore != nil {
			var graphErr error
			graph, graphErr = graphStore.GetEntityNeighborhood(r.Context(), finding.ResourceURNs[0], int(limit))
			if graphErr != nil {
				graph = nil
			}
		}
	}
	items := grcFindingItems([]*ports.FindingRecord{finding}, grcRuntimeSourceIDs(runtimes), grcEvidenceCounts(evidence))
	if len(items) == 0 {
		return grcAuditPacketResponse{}, ports.ErrFindingNotFound
	}
	generatedAt := time.Now().UTC()
	controls := grcControlRefs(finding.ControlRefs)
	packet := grcAuditPacketResponse{
		ID:                finding.ID,
		Finding:           items[0],
		Evidence:          grcEvidenceItems(evidence, map[string]string{finding.ID: finding.Title}),
		Graph:             graph,
		Controls:          controls,
		RecommendedAction: grcRecommendedAction(items[0]),
		GeneratedAt:       generatedAt,
	}
	packet.Metadata = grccontrol.BuildReportMetadata(grccontrol.ReportMetadataInput{
		ReportType:    "finding",
		GeneratedAt:   generatedAt,
		ControlCount:  len(controls),
		FindingCount:  1,
		EvidenceCount: len(evidence),
		Readiness: grccontrol.BuildFindingAuditReadiness(grccontrol.FindingAuditReadinessInput{
			Owner:          packet.Finding.Owner,
			ControlCount:   len(controls),
			EvidenceCount:  len(evidence),
			HasImpactProof: packet.Graph != nil && packet.Graph.Root != nil,
		}),
		Runtimes: reportScopeRuntimes,
	})
	return packet, nil
}

func grcFindingAuditMarkdownInput(packet grcAuditPacketResponse) grccontrol.FindingAuditMarkdownInput {
	controls := make([]grccontrol.ControlRef, 0, len(packet.Controls))
	for _, control := range packet.Controls {
		controls = append(controls, grccontrol.ControlRef{FrameworkName: control.FrameworkName, ControlID: control.ControlID})
	}
	evidence := make([]grccontrol.FindingAuditMarkdownEvidence, 0, len(packet.Evidence))
	for _, item := range packet.Evidence {
		evidence = append(evidence, grccontrol.FindingAuditMarkdownEvidence{
			ID:        item.ID,
			RuleID:    item.RuleID,
			CreatedAt: item.CreatedAt,
		})
	}
	return grccontrol.FindingAuditMarkdownInput{
		Finding: grccontrol.FindingAuditMarkdownFinding{
			ID:        packet.Finding.ID,
			Title:     packet.Finding.Title,
			Severity:  packet.Finding.Severity,
			Status:    packet.Finding.Status,
			Summary:   packet.Finding.Summary,
			RiskScore: packet.Finding.RiskScore,
			Owner:     packet.Finding.Owner,
			SLAStatus: packet.Finding.SLAStatus,
		},
		Controls:          controls,
		Evidence:          evidence,
		RecommendedAction: packet.RecommendedAction,
		Metadata:          packet.Metadata,
		GeneratedAt:       packet.GeneratedAt,
	}
}

type grcFindingFilter = ports.ListFindingsRequest

type grcEvidenceFilter struct {
	FindingID    string
	FindingIDs   []string
	RunID        string
	RuleID       string
	GraphRootURN string
	Limit        uint32
}

type grcFindingSummaryProvider interface {
	SummarizeFindings(context.Context, ports.ListFindingsRequest) (ports.FindingSummary, error)
}

type grcFindingEvidenceCounter interface {
	CountFindingEvidence(context.Context, ports.ListFindingEvidenceRequest) (int, error)
}

type grcFindingEvidenceByFindingCounter interface {
	CountGRCFindingEvidenceByFindingID(context.Context, ports.ListFindingEvidenceRequest) (map[string]int, error)
}

type grcFindingEvidenceHeaderLister interface {
	ListGRCFindingEvidence(context.Context, ports.ListFindingEvidenceRequest) ([]*cerebrov1.FindingEvidence, error)
}

type grcFindingHeaderLister interface {
	ListGRCFindings(context.Context, ports.ListFindingsRequest) ([]*ports.FindingRecord, error)
}

type grcFindingTrendsProvider interface {
	SummarizeGRCFindingTrends(context.Context, ports.GRCFindingTrendsRequest) (ports.GRCFindingTrends, error)
}

func grcDashboardTelemetryAttrs() telemetry.Attributes {
	return telemetry.Attrs(
		telemetry.Field{Key: "route", Value: "/grc/dashboard"},
		telemetry.Field{Key: "dashboard", Value: "grc"},
	)
}

func grcDashboardScopeTelemetryAttrs(scope grcScope) telemetry.Attributes {
	return grcDashboardTelemetryAttrs().
		WithField(telemetry.Field{Key: "tenant_id", Value: scope.TenantID}).
		WithField(telemetry.Field{Key: "runtime_id", Value: scope.RuntimeID}).
		WithField(telemetry.Field{Key: "source_id", Value: scope.SourceID}).
		WithField(telemetry.Field{Key: "limit", Value: scope.Limit})
}

func grcTelemetryStatus(err error) string {
	if err != nil {
		return "failed"
	}
	return "completed"
}

func grcTelemetryError(attrs telemetry.Attributes, err error) (string, telemetry.Attributes) {
	if err == nil {
		return "completed", attrs
	}
	return "failed", attrs.WithField(telemetry.Field{Key: "error_kind", Value: grcTelemetryErrorKind(err)})
}

func grcTelemetryErrorKind(err error) string {
	switch {
	case errors.Is(err, errTenantForbidden):
		return "tenant_forbidden"
	case errors.Is(err, ports.ErrSourceRuntimeNotFound),
		errors.Is(err, ports.ErrFindingNotFound),
		errors.Is(err, ports.ErrFindingEvidenceNotFound),
		errors.Is(err, ports.ErrGraphEntityNotFound),
		errors.Is(err, ports.ErrGRCInventoryAssetReportNotFound):
		return "not_found"
	case errors.Is(err, graphagent.ErrLLMAuthenticationFailed):
		return "llm_authentication_failed"
	case errors.Is(err, graphagent.ErrLLMAccessDenied):
		return "llm_access_denied"
	case errors.Is(err, sourceruntime.ErrRuntimeUnavailable),
		errors.Is(err, findings.ErrRuntimeUnavailable),
		errors.Is(err, graphagent.ErrRuntimeUnavailable),
		errors.Is(err, graphquery.ErrRuntimeUnavailable):
		return "runtime_unavailable"
	case errors.Is(err, sourceruntime.ErrInvalidRequest),
		errors.Is(err, findings.ErrInvalidRequest),
		errors.Is(err, graphagent.ErrInvalidRequest),
		errors.Is(err, graphquery.ErrInvalidRequest),
		errors.Is(err, errInvalidHTTPRequest):
		return "invalid_request"
	default:
		return "grc_request_failed"
	}
}

func grcScopeFromRequest(r *http.Request) (grcScope, error) {
	limit, err := grcLimitFromRequest(r)
	if err != nil {
		return grcScope{}, err
	}
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		if auth, ok := r.Context().Value(authContextKey{}).(authContext); ok {
			tenantID = strings.TrimSpace(auth.principal.TenantID)
		}
	}
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Cerebro-Tenant"))
	}
	if tenantID == "" && requiresTenantFilter(r.Context()) {
		return grcScope{}, errTenantForbidden
	}
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		return grcScope{}, err
	}
	return grcScope{
		TenantID:   tenantID,
		RuntimeID:  strings.TrimSpace(r.URL.Query().Get("runtime_id")),
		RuntimeIDs: csvQueryValues(r.URL.Query().Get("runtime_ids")),
		SourceID:   strings.TrimSpace(r.URL.Query().Get("source_id")),
		Limit:      limit,
	}, nil
}

func csvQueryValues(value string) []string {
	seen := map[string]struct{}{}
	values := []string{}
	for _, part := range strings.Split(value, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		values = append(values, trimmed)
	}
	return values
}

func grcLimitFromRequest(r *http.Request) (uint32, error) {
	limit, err := uint32QueryParam(r, "limit")
	if err != nil {
		return 0, err
	}
	if limit == 0 {
		return grcDefaultLimit, nil
	}
	if limit > grcMaxLimit {
		return 0, fmt.Errorf("%w: limit must be <= %d", errInvalidHTTPRequest, grcMaxLimit)
	}
	return limit, nil
}

func (a *App) grcListRuntimes(r *http.Request, scope grcScope) ([]*cerebrov1.SourceRuntime, error) {
	runtimes, err := a.runtimeService().List(r.Context(), ports.SourceRuntimeFilter{
		RuntimeID:  scope.RuntimeID,
		RuntimeIDs: scope.RuntimeIDs,
		TenantID:   scope.TenantID,
		SourceID:   scope.SourceID,
		Limit:      scope.Limit,
	})
	if err != nil {
		return nil, err
	}
	return runtimes, nil
}

func (a *App) grcReportScopeRuntimes(r *http.Request, scope grcScope, fallback []*cerebrov1.SourceRuntime) []*cerebrov1.SourceRuntime {
	store, ok := a.deps.StateStore.(ports.SourceRuntimeListStore)
	if !ok {
		return grccontrol.ReportScopeRuntimeSnapshots(fallback)
	}
	runtimes, err := store.ListSourceRuntimes(r.Context(), ports.SourceRuntimeFilter{
		RuntimeID:  scope.RuntimeID,
		RuntimeIDs: scope.RuntimeIDs,
		TenantID:   scope.TenantID,
		SourceID:   scope.SourceID,
		Limit:      scope.Limit,
	})
	if err != nil {
		return grccontrol.ReportScopeRuntimeSnapshots(fallback)
	}
	return grccontrol.ReportScopeRuntimeSnapshots(runtimes)
}

func (a *App) grcListFindingRecords(r *http.Request, runtimes []*cerebrov1.SourceRuntime, filter grcFindingFilter) ([]*ports.FindingRecord, error) {
	store := findingStore(a.deps.StateStore)
	if store == nil {
		return nil, findings.ErrRuntimeUnavailable
	}
	limit := filter.Limit
	if limit == 0 {
		limit = grcDefaultLimit
	}
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
	var records []*ports.FindingRecord
	for tenantID, runtimeIDs := range runtimeIDsByTenant {
		request := ports.ListFindingsRequest{
			TenantID:            tenantID,
			RuntimeIDs:          runtimeIDs,
			FindingID:           filter.FindingID,
			RuleID:              filter.RuleID,
			Severity:            filter.Severity,
			Status:              filter.Status,
			ResourceURN:         filter.ResourceURN,
			EventID:             filter.EventID,
			PolicyID:            filter.PolicyID,
			Framework:           filter.Framework,
			FirstObservedFrom:   filter.FirstObservedFrom,
			FirstObservedBefore: filter.FirstObservedBefore,
			StatusUpdatedFrom:   filter.StatusUpdatedFrom,
			StatusUpdatedBefore: filter.StatusUpdatedBefore,
			MinAgeDays:          filter.MinAgeDays,
			MaxAgeDays:          filter.MaxAgeDays,
			SLAStatus:           filter.SLAStatus,
			Limit:               limit,
			PriorityOrder:       true,
			Order:               ports.FindingOrderRiskScore,
		}
		var (
			items []*ports.FindingRecord
			err   error
		)
		if lister, ok := store.(grcFindingHeaderLister); ok {
			items, err = lister.ListGRCFindings(r.Context(), request)
		} else {
			items, err = store.ListFindings(r.Context(), request)
		}
		if err != nil {
			return nil, err
		}
		records = append(records, items...)
	}
	sort.Slice(records, func(i, j int) bool {
		left := records[i]
		right := records[j]
		if left.RiskScore != right.RiskScore {
			return left.RiskScore > right.RiskScore
		}
		if severityRank(left.Severity) != severityRank(right.Severity) {
			return severityRank(left.Severity) < severityRank(right.Severity)
		}
		if left.LastObservedAt.Equal(right.LastObservedAt) {
			return left.ID < right.ID
		}
		return left.LastObservedAt.After(right.LastObservedAt)
	})
	if len(records) > int(limit) {
		records = records[:int(limit)]
	}
	return records, nil
}

func (a *App) grcFindingSummary(r *http.Request, runtimes []*cerebrov1.SourceRuntime, filter grcFindingFilter) (*ports.FindingSummary, error) {
	store := findingStore(a.deps.StateStore)
	provider, ok := store.(grcFindingSummaryProvider)
	if !ok {
		return nil, nil
	}
	var summary ports.FindingSummary
	controlKeys := map[string]struct{}{}
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
	for tenantID, runtimeIDs := range runtimeIDsByTenant {
		item, err := provider.SummarizeFindings(r.Context(), ports.ListFindingsRequest{
			TenantID:            tenantID,
			RuntimeIDs:          runtimeIDs,
			FindingID:           filter.FindingID,
			RuleID:              filter.RuleID,
			Severity:            filter.Severity,
			Status:              filter.Status,
			ResourceURN:         filter.ResourceURN,
			EventID:             filter.EventID,
			PolicyID:            filter.PolicyID,
			Framework:           filter.Framework,
			FirstObservedFrom:   filter.FirstObservedFrom,
			FirstObservedBefore: filter.FirstObservedBefore,
			StatusUpdatedFrom:   filter.StatusUpdatedFrom,
			StatusUpdatedBefore: filter.StatusUpdatedBefore,
			MinAgeDays:          filter.MinAgeDays,
			MaxAgeDays:          filter.MaxAgeDays,
			SLAStatus:           filter.SLAStatus,
		})
		if err != nil {
			return nil, err
		}
		summary.OpenFindings += item.OpenFindings
		summary.CriticalFindings += item.CriticalFindings
		summary.HighFindings += item.HighFindings
		summary.OverdueFindings += item.OverdueFindings
		summary.Unassigned += item.Unassigned
		for _, key := range item.FailingControlKeys {
			if trimmed := strings.TrimSpace(key); trimmed != "" {
				controlKeys[trimmed] = struct{}{}
			}
		}
	}
	summary.ControlsFailing = len(controlKeys)
	return &summary, nil
}

func (a *App) grcListEvidenceRecords(r *http.Request, runtimes []*cerebrov1.SourceRuntime, filter grcEvidenceFilter) ([]*cerebrov1.FindingEvidence, error) {
	store := findingEvidenceStore(a.deps.StateStore)
	if store == nil {
		return nil, findings.ErrRuntimeUnavailable
	}
	limit := filter.Limit
	if limit == 0 {
		limit = grcDefaultLimit
	}
	var runtimeIDs []string
	for _, runtime := range runtimes {
		if runtime == nil {
			continue
		}
		if runtimeID := strings.TrimSpace(runtime.GetId()); runtimeID != "" {
			runtimeIDs = append(runtimeIDs, runtimeID)
		}
	}
	if len(runtimeIDs) == 0 {
		return nil, nil
	}
	if filter.FindingIDs != nil && strings.TrimSpace(filter.FindingID) == "" && len(grcNonEmptyFindingIDs(filter.FindingIDs)) == 0 {
		return nil, nil
	}
	request := ports.ListFindingEvidenceRequest{
		RuntimeIDs:   runtimeIDs,
		FindingID:    filter.FindingID,
		FindingIDs:   filter.FindingIDs,
		RunID:        filter.RunID,
		RuleID:       filter.RuleID,
		GraphRootURN: filter.GraphRootURN,
		Limit:        limit,
		CreatedOrder: true,
	}
	var (
		records []*cerebrov1.FindingEvidence
		err     error
	)
	if lister, ok := store.(grcFindingEvidenceHeaderLister); ok {
		records, err = lister.ListGRCFindingEvidence(r.Context(), request)
	} else {
		records, err = store.ListFindingEvidence(r.Context(), request)
	}
	if err != nil {
		return nil, err
	}
	sort.Slice(records, func(i, j int) bool {
		left := records[i].GetCreatedAt().AsTime()
		right := records[j].GetCreatedAt().AsTime()
		if left.Equal(right) {
			return records[i].GetId() < records[j].GetId()
		}
		return left.After(right)
	})
	if len(records) > int(limit) {
		records = records[:int(limit)]
	}
	return records, nil
}

func (a *App) grcEvidenceCount(r *http.Request, runtimes []*cerebrov1.SourceRuntime, filter grcEvidenceFilter) (*int, error) {
	store := findingEvidenceStore(a.deps.StateStore)
	counter, ok := store.(grcFindingEvidenceCounter)
	if !ok {
		return nil, nil
	}
	if filter.FindingIDs != nil && strings.TrimSpace(filter.FindingID) == "" && len(grcNonEmptyFindingIDs(filter.FindingIDs)) == 0 {
		count := 0
		return &count, nil
	}
	var runtimeIDs []string
	for _, runtime := range runtimes {
		if runtime == nil {
			continue
		}
		if runtimeID := strings.TrimSpace(runtime.GetId()); runtimeID != "" {
			runtimeIDs = append(runtimeIDs, runtimeID)
		}
	}
	count := 0
	if len(runtimeIDs) == 0 {
		return &count, nil
	}
	item, err := counter.CountFindingEvidence(r.Context(), ports.ListFindingEvidenceRequest{
		RuntimeIDs:   runtimeIDs,
		FindingID:    filter.FindingID,
		FindingIDs:   filter.FindingIDs,
		RunID:        filter.RunID,
		RuleID:       filter.RuleID,
		GraphRootURN: filter.GraphRootURN,
		Limit:        0,
	})
	if err != nil {
		return nil, err
	}
	count += item
	return &count, nil
}

func (a *App) grcEvidenceCountsByFindingID(r *http.Request, runtimes []*cerebrov1.SourceRuntime, filter grcEvidenceFilter) (map[string]int, bool, error) {
	store := findingEvidenceStore(a.deps.StateStore)
	counter, ok := store.(grcFindingEvidenceByFindingCounter)
	if !ok {
		return nil, false, nil
	}
	if filter.FindingIDs != nil && strings.TrimSpace(filter.FindingID) == "" && len(grcNonEmptyFindingIDs(filter.FindingIDs)) == 0 {
		return map[string]int{}, true, nil
	}
	var runtimeIDs []string
	for _, runtime := range runtimes {
		if runtime == nil {
			continue
		}
		if runtimeID := strings.TrimSpace(runtime.GetId()); runtimeID != "" {
			runtimeIDs = append(runtimeIDs, runtimeID)
		}
	}
	if len(runtimeIDs) == 0 {
		return map[string]int{}, true, nil
	}
	counts, err := counter.CountGRCFindingEvidenceByFindingID(r.Context(), ports.ListFindingEvidenceRequest{
		RuntimeIDs:   runtimeIDs,
		FindingID:    filter.FindingID,
		FindingIDs:   filter.FindingIDs,
		RunID:        filter.RunID,
		RuleID:       filter.RuleID,
		GraphRootURN: filter.GraphRootURN,
		Limit:        0,
	})
	if err != nil {
		return nil, true, err
	}
	return counts, true, nil
}

func (a *App) grcDashboardAggregate(r *http.Request, runtimes []*cerebrov1.SourceRuntime, findingFilter grcFindingFilter, evidenceFilter grcEvidenceFilter) (*ports.GRCDashboardAggregate, error) {
	provider, ok := a.deps.StateStore.(ports.GRCDashboardAggregateStore)
	if !ok {
		return nil, nil
	}
	if evidenceFilter.FindingIDs != nil && strings.TrimSpace(evidenceFilter.FindingID) == "" && len(grcNonEmptyFindingIDs(evidenceFilter.FindingIDs)) == 0 {
		aggregate := ports.GRCDashboardAggregate{}
		return &aggregate, nil
	}
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
	if len(runtimeIDsByTenant) == 0 {
		aggregate := ports.GRCDashboardAggregate{}
		return &aggregate, nil
	}
	var aggregate ports.GRCDashboardAggregate
	aggregate.EvidenceCountsByFindingID = map[string]int{}
	controlKeys := map[string]struct{}{}
	for tenantID, runtimeIDs := range runtimeIDsByTenant {
		item, err := provider.SummarizeGRCDashboard(r.Context(), ports.GRCDashboardAggregateRequest{
			FindingRequest: ports.ListFindingsRequest{
				TenantID:            tenantID,
				RuntimeIDs:          runtimeIDs,
				FindingID:           findingFilter.FindingID,
				RuleID:              findingFilter.RuleID,
				Severity:            findingFilter.Severity,
				Status:              findingFilter.Status,
				ResourceURN:         findingFilter.ResourceURN,
				EventID:             findingFilter.EventID,
				PolicyID:            findingFilter.PolicyID,
				Framework:           findingFilter.Framework,
				FirstObservedFrom:   findingFilter.FirstObservedFrom,
				FirstObservedBefore: findingFilter.FirstObservedBefore,
				StatusUpdatedFrom:   findingFilter.StatusUpdatedFrom,
				StatusUpdatedBefore: findingFilter.StatusUpdatedBefore,
				MinAgeDays:          findingFilter.MinAgeDays,
				MaxAgeDays:          findingFilter.MaxAgeDays,
				SLAStatus:           findingFilter.SLAStatus,
			},
			EvidenceRequest: ports.ListFindingEvidenceRequest{
				RuntimeIDs:   runtimeIDs,
				FindingID:    evidenceFilter.FindingID,
				FindingIDs:   evidenceFilter.FindingIDs,
				RunID:        evidenceFilter.RunID,
				RuleID:       evidenceFilter.RuleID,
				GraphRootURN: evidenceFilter.GraphRootURN,
				Limit:        0,
			},
		})
		if err != nil {
			return nil, err
		}
		aggregate.FindingSummary.OpenFindings += item.FindingSummary.OpenFindings
		aggregate.FindingSummary.CriticalFindings += item.FindingSummary.CriticalFindings
		aggregate.FindingSummary.HighFindings += item.FindingSummary.HighFindings
		aggregate.FindingSummary.OverdueFindings += item.FindingSummary.OverdueFindings
		aggregate.FindingSummary.Unassigned += item.FindingSummary.Unassigned
		aggregate.EvidenceCount += item.EvidenceCount
		for findingID, count := range item.EvidenceCountsByFindingID {
			if trimmed := strings.TrimSpace(findingID); trimmed != "" {
				aggregate.EvidenceCountsByFindingID[trimmed] += count
			}
		}
		for _, key := range item.FindingSummary.FailingControlKeys {
			if trimmed := strings.TrimSpace(key); trimmed != "" {
				controlKeys[trimmed] = struct{}{}
			}
		}
	}
	for key := range controlKeys {
		aggregate.FindingSummary.FailingControlKeys = append(aggregate.FindingSummary.FailingControlKeys, key)
	}
	sort.Strings(aggregate.FindingSummary.FailingControlKeys)
	aggregate.FindingSummary.ControlsFailing = len(aggregate.FindingSummary.FailingControlKeys)
	return &aggregate, nil
}

func grcRuntimeSourceIDs(runtimes []*cerebrov1.SourceRuntime) map[string]string {
	values := make(map[string]string, len(runtimes))
	for _, runtime := range runtimes {
		if runtime != nil {
			values[runtime.GetId()] = runtime.GetSourceId()
		}
	}
	return values
}

func grcEvidenceCounts(evidence []*cerebrov1.FindingEvidence) map[string]int {
	counts := map[string]int{}
	for _, item := range evidence {
		if item != nil && strings.TrimSpace(item.GetFindingId()) != "" {
			counts[item.GetFindingId()]++
		}
	}
	return counts
}

func grcFindingIDs(findings []*ports.FindingRecord) []string {
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		ids = append(ids, finding.ID)
	}
	return grcNonEmptyFindingIDs(ids)
}

func grcNonEmptyFindingIDs(ids []string) []string {
	values := make([]string, 0, len(ids))
	seen := map[string]struct{}{}
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		values = append(values, id)
	}
	return values
}

func grcFindingTitleMap(findings []*ports.FindingRecord) map[string]string {
	titles := map[string]string{}
	for _, finding := range findings {
		if finding != nil {
			titles[finding.ID] = finding.Title
		}
	}
	return titles
}

func grcFindingItems(findings []*ports.FindingRecord, sourceIDs map[string]string, evidenceCounts map[string]int) []grcFindingItem {
	items := make([]grcFindingItem, 0, len(findings))
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		items = append(items, grcFindingItem{
			ID:           finding.ID,
			Title:        fallbackString(finding.Title, finding.RuleID, finding.ID),
			Severity:     strings.ToUpper(strings.TrimSpace(finding.Severity)),
			Status:       normalizedFindingStatus(finding.Status),
			Summary:      finding.Summary,
			TenantID:     finding.TenantID,
			RuntimeID:    finding.RuntimeID,
			SourceID:     sourceIDs[finding.RuntimeID],
			Entity:       primaryEntity(finding),
			ResourceURNs: append([]string(nil), finding.ResourceURNs...),
			RuleID:       finding.RuleID,
			PolicyID:     finding.PolicyID,
			PolicyName:   finding.PolicyName,
			Controls:     grcControlRefs(finding.ControlRefs),
			GRCFindingRisk: GRCFindingRisk{
				RiskScore:       finding.RiskScore,
				LikelihoodScore: finding.LikelihoodScore,
				ImpactScore:     finding.ImpactScore,
				ConfidenceScore: finding.ConfidenceScore,
				LikelihoodLevel: finding.LikelihoodLevel,
				ImpactLevel:     finding.ImpactLevel,
				RiskReasons:     append([]string(nil), finding.RiskReasons...),
				RiskModel:       finding.RiskModelVersion,
			},
			GRCFindingWorkflowMetadata: GRCFindingWorkflowMetadata{
				StatusReason:    finding.StatusReason,
				Assignee:        finding.Assignee,
				DueAt:           timePtr(finding.DueAt),
				StatusUpdatedAt: timePtr(finding.StatusUpdatedAt),
				Notes:           append([]ports.FindingNote(nil), finding.Notes...),
				Tickets:         append([]ports.FindingTicket(nil), finding.Tickets...),
				ExternalRefs:    append([]ports.FindingExternalRef(nil), finding.ExternalRefs...),
			},
			EvidenceCount:   evidenceCounts[finding.ID],
			Owner:           fallbackString(finding.Assignee, "Unassigned"),
			SLAStatus:       grcSLAStatus(finding),
			FirstObservedAt: timePtr(finding.FirstObservedAt),
			LastObservedAt:  timePtr(finding.LastObservedAt),
		})
	}
	return items
}

func grcControlRefs(refs []ports.FindingControlRef) []grcControlRef {
	items := make([]grcControlRef, 0, len(refs))
	for _, ref := range refs {
		framework := strings.TrimSpace(ref.FrameworkName)
		controlID := strings.TrimSpace(ref.ControlID)
		if framework == "" || controlID == "" {
			continue
		}
		items = append(items, grcControlRef{FrameworkName: framework, ControlID: controlID})
	}
	return items
}

func grcEvidenceItems(evidence []*cerebrov1.FindingEvidence, findingTitles map[string]string) []grcEvidenceItem {
	items := make([]grcEvidenceItem, 0, len(evidence))
	for _, item := range evidence {
		if item == nil {
			continue
		}
		items = append(items, grcEvidenceItem{
			ID:            item.GetId(),
			RuntimeID:     item.GetRuntimeId(),
			RuleID:        item.GetRuleId(),
			FindingID:     item.GetFindingId(),
			FindingTitle:  findingTitles[item.GetFindingId()],
			RunID:         item.GetRunId(),
			ClaimIDs:      append([]string(nil), item.GetClaimIds()...),
			EventIDs:      append([]string(nil), item.GetEventIds()...),
			GraphRootURNs: append([]string(nil), item.GetGraphRootUrns()...),
			CreatedAt:     item.GetCreatedAt().AsTime(),
		})
	}
	return items
}

func grcControlItems(findings []grcFindingItem, evidence []grcEvidenceItem) []grcControlItem {
	controlMap := map[string]*grcControlItem{}
	evidenceByFinding := map[string]int{}
	for _, item := range evidence {
		evidenceByFinding[item.FindingID]++
	}
	for _, finding := range findings {
		refs := finding.Controls
		if len(refs) == 0 {
			refs = []grcControlRef{{FrameworkName: "Unmapped", ControlID: "Needs mapping"}}
		}
		for _, ref := range refs {
			key := ref.FrameworkName + "\x00" + ref.ControlID
			control := controlMap[key]
			if control == nil {
				control = &grcControlItem{
					FrameworkName: ref.FrameworkName,
					ControlID:     ref.ControlID,
					Status:        "passing",
				}
				controlMap[key] = control
			}
			control.Findings = append(control.Findings, finding)
			if finding.Status == "OPEN" || strings.EqualFold(finding.Status, "open") {
				control.OpenFindings++
				control.Status = "failing"
				if finding.Severity == "CRITICAL" {
					control.CriticalFindings++
				}
				if finding.Severity == "HIGH" {
					control.HighFindings++
				}
			}
			if finding.EvidenceCount != 0 {
				control.EvidenceItems += finding.EvidenceCount
			} else {
				control.EvidenceItems += evidenceByFinding[finding.ID]
			}
		}
	}
	controls := make([]grcControlItem, 0, len(controlMap))
	for _, control := range controlMap {
		controls = append(controls, *control)
	}
	sort.Slice(controls, func(i, j int) bool {
		left := controls[i]
		right := controls[j]
		if left.OpenFindings != right.OpenFindings {
			return left.OpenFindings > right.OpenFindings
		}
		return left.FrameworkName+left.ControlID < right.FrameworkName+right.ControlID
	})
	return controls
}

func grcConnectorItems(runtimes []*cerebrov1.SourceRuntime) []grcConnector {
	items := make([]grcConnector, 0, len(runtimes))
	for _, runtime := range runtimes {
		if runtime == nil {
			continue
		}
		lastSyncedAt := timestampPtr(runtime.GetLastSyncedAt())
		checkpointWatermark := grcRuntimeCheckpointWatermark(runtime)
		items = append(items, grcConnector{
			RuntimeID:           runtime.GetId(),
			SourceID:            runtime.GetSourceId(),
			TenantID:            runtime.GetTenantId(),
			Status:              connectorStatus(lastSyncedAt),
			Freshness:           connectorFreshness(lastSyncedAt),
			SyncLagSeconds:      timestampLagSeconds(lastSyncedAt),
			CheckpointWatermark: checkpointWatermark,
			WatermarkLagSeconds: timestampLagSeconds(checkpointWatermark),
			WatermarkFreshness:  connectorFreshness(checkpointWatermark),
			LastSyncedAt:        lastSyncedAt,
		})
	}
	return items
}

func grcBuildSummary(findings []grcFindingItem, controls []grcControlItem, evidence []grcEvidenceItem, runtimes []*cerebrov1.SourceRuntime, findingSummary *ports.FindingSummary, evidenceCount *int) grcSummary {
	var summary grcSummary
	if evidenceCount != nil {
		summary.EvidenceItems = *evidenceCount
	} else {
		summary.EvidenceItems = len(evidence)
	}
	summary.Connectors = len(runtimes)
	if findingSummary != nil {
		summary.OpenFindings = findingSummary.OpenFindings
		summary.CriticalFindings = findingSummary.CriticalFindings
		summary.HighFindings = findingSummary.HighFindings
		summary.OverdueFindings = findingSummary.OverdueFindings
		summary.Unassigned = findingSummary.Unassigned
		summary.ControlsFailing = findingSummary.ControlsFailing
	} else {
		for _, finding := range findings {
			if finding.Status == "OPEN" {
				summary.OpenFindings++
				if finding.Severity == "CRITICAL" {
					summary.CriticalFindings++
				}
				if finding.Severity == "HIGH" {
					summary.HighFindings++
				}
				if finding.SLAStatus == "overdue" {
					summary.OverdueFindings++
				}
				if finding.Owner == "Unassigned" {
					summary.Unassigned++
				}
			}
		}
		for _, control := range controls {
			if control.Status == "failing" {
				summary.ControlsFailing++
			}
		}
	}
	for _, runtime := range runtimes {
		if connectorStatus(timestampPtr(runtime.GetLastSyncedAt())) == "stale" {
			summary.StaleConnectors++
		}
	}
	return summary
}

func grcLimitFindings(items []grcFindingItem, limit int) []grcFindingItem {
	if len(items) > limit {
		return items[:limit]
	}
	return items
}

func grcLimitControls(items []grcControlItem, limit int) []grcControlItem {
	if len(items) > limit {
		return items[:limit]
	}
	return items
}

func grcLimitEvidence(items []grcEvidenceItem, limit int) []grcEvidenceItem {
	if len(items) > limit {
		return items[:limit]
	}
	return items
}

func primaryEntity(finding *ports.FindingRecord) string {
	if finding == nil {
		return ""
	}
	for _, urn := range finding.ResourceURNs {
		if strings.TrimSpace(urn) != "" {
			return strings.TrimSpace(urn)
		}
	}
	return fallbackString(finding.PolicyName, finding.PolicyID, finding.RuleID)
}

func normalizedFindingStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "open", "finding_status_open":
		return "OPEN"
	case "resolved", "finding_status_resolved":
		return "RESOLVED"
	case "suppressed", "finding_status_suppressed":
		return "SUPPRESSED"
	default:
		return "UNKNOWN"
	}
}

func grcSLAStatus(finding *ports.FindingRecord) string {
	if finding == nil {
		return "unknown"
	}
	if normalizedFindingStatus(finding.Status) != "OPEN" {
		return "closed"
	}
	if finding.DueAt.IsZero() {
		return "no_due_date"
	}
	if time.Now().UTC().After(finding.DueAt) {
		return "overdue"
	}
	if time.Until(finding.DueAt) <= 72*time.Hour {
		return "due_soon"
	}
	return "on_track"
}

func grcRecommendedAction(finding grcFindingItem) string {
	if finding.Owner == "Unassigned" {
		return "Assign an owner, confirm evidence, and set a remediation due date."
	}
	if finding.EvidenceCount == 0 {
		return "Request supporting evidence before audit review."
	}
	if len(finding.Controls) == 0 {
		return "Map this finding to the affected control objective."
	}
	return "Review evidence, confirm impact, and update remediation status."
}

func connectorStatus(lastSyncedAt *time.Time) string {
	if lastSyncedAt == nil {
		return "unknown"
	}
	if time.Since(*lastSyncedAt) > 24*time.Hour {
		return "stale"
	}
	return "healthy"
}

func connectorFreshness(lastSyncedAt *time.Time) string {
	if lastSyncedAt == nil {
		return "never_synced"
	}
	age := time.Since(*lastSyncedAt)
	switch {
	case age <= time.Hour:
		return "fresh"
	case age <= 24*time.Hour:
		return "recent"
	default:
		return "stale"
	}
}

func grcRuntimeCheckpointWatermark(runtime *cerebrov1.SourceRuntime) *time.Time {
	if runtime == nil {
		return nil
	}
	return timestampPtr(runtime.GetCheckpoint().GetWatermark())
}

func timestampLagSeconds(value *time.Time) *int64 {
	if value == nil {
		return nil
	}
	lag := time.Since(*value)
	if lag < 0 {
		lag = 0
	}
	seconds := int64(lag.Seconds())
	return &seconds
}

func severityRank(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	case "INFO":
		return 4
	default:
		return 5
	}
}

func fallbackString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func timePtr(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	utc := value.UTC()
	return &utc
}

func timestampPtr(value *timestamppb.Timestamp) *time.Time {
	if value == nil {
		return nil
	}
	return timePtr(value.AsTime())
}

func writeGRCError(w http.ResponseWriter, err error) {
	statusCode := grcHTTPStatusCode(err)
	http.Error(w, http.StatusText(statusCode), statusCode)
}

func grcHTTPStatusCode(err error) int {
	statusCode := http.StatusInternalServerError
	switch {
	case errors.Is(err, errTenantForbidden):
		statusCode = http.StatusForbidden
	case errors.Is(err, errScopeForbidden):
		statusCode = http.StatusForbidden
	case errors.Is(err, ports.ErrSourceRuntimeNotFound),
		errors.Is(err, ports.ErrFindingNotFound),
		errors.Is(err, ports.ErrFindingEvidenceNotFound),
		errors.Is(err, ports.ErrGraphEntityNotFound),
		errors.Is(err, ports.ErrGRCInventoryAssetReportNotFound):
		statusCode = http.StatusNotFound
	case errors.Is(err, sourceruntime.ErrRuntimeUnavailable),
		errors.Is(err, findings.ErrRuntimeUnavailable),
		errors.Is(err, graphagent.ErrLLMAuthenticationFailed),
		errors.Is(err, graphagent.ErrRuntimeUnavailable),
		errors.Is(err, graphquery.ErrRuntimeUnavailable):
		statusCode = http.StatusServiceUnavailable
	case errors.Is(err, sourceruntime.ErrInvalidRequest),
		errors.Is(err, findings.ErrInvalidRequest),
		errors.Is(err, graphagent.ErrInvalidRequest),
		errors.Is(err, graphquery.ErrInvalidRequest),
		errors.Is(err, errInvalidHTTPRequest):
		statusCode = http.StatusBadRequest
	}
	return statusCode
}
