package complianceimpact

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/complianceintegration"
	"github.com/writer/cerebro/internal/ports"
)

const (
	defaultMonitorPageSize = uint32(500)
	defaultMaxMonitors     = uint32(10000)
)

var (
	ErrImpactSchedulerUnavailable  = errors.New("compliance impact scheduler unavailable")
	ErrImpactMonitorLimit          = errors.New("compliance impact monitor limit exceeded")
	ErrImpactProjectionUnavailable = errors.New("compliance impact graph projection unavailable")
)

type impactAnalyzer interface {
	Analyze(context.Context, complianceintegration.ChangeSignal) (Result, error)
}

// ChangeMonitorSink is the existing monitor write boundary. RecordChangeSignal
// is idempotent by source event and monitor; it does not create another event
// authority for the source-domain change.
type ChangeMonitorSink interface {
	ListMonitors(context.Context, ports.ComplianceMonitorFilter) ([]*ports.ComplianceMonitor, error)
	RecordChangeSignal(context.Context, ports.ComplianceChangeSignal) (bool, error)
}

// Scheduler converts immutable domain changes into bounded, debounced
// assessment signals. It never runs an assessment or writes graph state.
type Scheduler struct {
	analyzer    impactAnalyzer
	monitors    ChangeMonitorSink
	maxMonitors uint32
}

func NewScheduler(analyzer impactAnalyzer, monitors ChangeMonitorSink) (*Scheduler, error) {
	if analyzer == nil || monitors == nil {
		return nil, ErrImpactSchedulerUnavailable
	}
	return &Scheduler{analyzer: analyzer, monitors: monitors, maxMonitors: defaultMaxMonitors}, nil
}

type ScheduleResult struct {
	Impact             Result              `json:"impact"`
	Directive          AssessmentDirective `json:"directive"`
	SelectedMonitorIDs []string            `json:"selected_monitor_ids"`
	RecordedSignals    uint32              `json:"recorded_signals"`
}

// Schedule analyzes one already-durable source event and records one bounded
// signal for each selected change monitor. Retries are safe because the monitor
// store keys each signal by source event and monitor ID.
func (s *Scheduler) Schedule(ctx context.Context, eventID string, signal complianceintegration.ChangeSignal) (ScheduleResult, error) {
	if s == nil || s.analyzer == nil || s.monitors == nil {
		return ScheduleResult{}, ErrImpactSchedulerUnavailable
	}
	eventID = strings.TrimSpace(eventID)
	if eventID == "" || len(eventID) > 512 || strings.ContainsRune(eventID, '\x00') {
		return ScheduleResult{}, fmt.Errorf("%w: source event is required and bounded", ErrInvalidAssessmentDirective)
	}
	impact, err := s.analyzer.Analyze(ctx, signal)
	if err != nil {
		return ScheduleResult{}, err
	}
	directive, err := BuildAssessmentDirective(impact, signal.ChangedAt())
	if err != nil {
		return ScheduleResult{}, err
	}
	monitors, err := s.loadChangeMonitors(ctx, directive.TenantID)
	if err != nil {
		return ScheduleResult{}, err
	}
	selected := selectChangeMonitors(monitors, directive)
	result := ScheduleResult{Impact: impact, Directive: directive, SelectedMonitorIDs: make([]string, 0, len(selected))}
	for _, monitor := range selected {
		result.SelectedMonitorIDs = append(result.SelectedMonitorIDs, monitor.ID)
	}

	var recordErrors []error
	for _, monitor := range selected {
		recorded, recordErr := s.monitors.RecordChangeSignal(ctx, ports.ComplianceChangeSignal{
			EventID:     eventID,
			TenantID:    directive.TenantID,
			MonitorID:   monitor.ID,
			SignalKind:  "compliance_impact:" + string(signal.Kind()) + ":" + string(directive.Mode),
			ScopeDigest: directive.Digest,
			ObservedAt:  signal.ChangedAt(),
		})
		if recordErr != nil {
			recordErrors = append(recordErrors, fmt.Errorf("record change signal for monitor %q: %w", monitor.ID, recordErr))
			continue
		}
		if recorded {
			result.RecordedSignals++
		}
	}
	return result, errors.Join(recordErrors...)
}

func (s *Scheduler) loadChangeMonitors(ctx context.Context, tenantID string) ([]*ports.ComplianceMonitor, error) {
	limit := s.maxMonitors
	if limit == 0 || limit > defaultMaxMonitors {
		limit = defaultMaxMonitors
	}
	monitors := make([]*ports.ComplianceMonitor, 0)
	afterID := ""
	for {
		page, err := s.monitors.ListMonitors(ctx, ports.ComplianceMonitorFilter{TenantID: tenantID, AfterID: afterID, Limit: defaultMonitorPageSize})
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			return monitors, nil
		}
		if len(page) > int(defaultMonitorPageSize) {
			return nil, fmt.Errorf("%w: monitor page exceeds requested limit", ErrImpactSchedulerUnavailable)
		}
		for _, monitor := range page {
			if monitor == nil || strings.TrimSpace(monitor.TenantID) != tenantID || strings.TrimSpace(monitor.ID) == "" || monitor.ID <= afterID {
				return nil, fmt.Errorf("%w: monitor page is not tenant-scoped and strictly ordered", ErrImpactSchedulerUnavailable)
			}
			// #nosec G115 -- limit is capped at 10,000 above and is safe as int.
			if len(monitors) >= int(limit) {
				return nil, fmt.Errorf("%w: more than %d monitor definitions", ErrImpactMonitorLimit, limit)
			}
			monitors = append(monitors, monitor)
			afterID = monitor.ID
		}
		if len(page) < int(defaultMonitorPageSize) {
			return monitors, nil
		}
	}
}

func selectChangeMonitors(monitors []*ports.ComplianceMonitor, directive AssessmentDirective) []*ports.ComplianceMonitor {
	planRevisionIDs := make(map[string]struct{}, len(directive.PlanRevisions))
	for _, revision := range directive.PlanRevisions {
		planRevisionIDs[strings.TrimSpace(revision.RevisionID)] = struct{}{}
	}
	selected := make([]*ports.ComplianceMonitor, 0)
	for _, monitor := range monitors {
		if monitor == nil || !monitor.Enabled || monitor.TriggerKind != ports.ComplianceTriggerChange {
			continue
		}
		if directive.Mode == AssessmentModeTargeted {
			if _, ok := planRevisionIDs[strings.TrimSpace(monitor.PlanRevisionID)]; !ok {
				continue
			}
		}
		selected = append(selected, monitor)
	}
	return selected
}
