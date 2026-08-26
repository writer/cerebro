package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

// PrepareGRCReadModels warms the read-model tables used by dashboard requests.
func (s *Store) PrepareGRCReadModels(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureSourceRuntimeTable(ctx); err != nil {
		return err
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return err
	}
	if err := s.ensureFindingEvidenceTables(ctx); err != nil {
		return err
	}
	return nil
}

// SummarizeGRCDashboard loads dashboard summary and evidence counts in one aggregate query.
func (s *Store) SummarizeGRCDashboard(ctx context.Context, request ports.GRCDashboardAggregateRequest) (ports.GRCDashboardAggregate, error) {
	if s == nil || s.db == nil {
		return ports.GRCDashboardAggregate{}, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return ports.GRCDashboardAggregate{}, err
	}
	if err := s.ensureFindingEvidenceTables(ctx); err != nil {
		return ports.GRCDashboardAggregate{}, err
	}
	if request.RuntimeScope != nil {
		if err := s.ensureSourceRuntimeTable(ctx); err != nil {
			return ports.GRCDashboardAggregate{}, err
		}
	}
	query, args, err := grcDashboardAggregateQuery(request)
	if err != nil {
		return ports.GRCDashboardAggregate{}, err
	}
	var aggregate ports.GRCDashboardAggregate
	var controlRefsJSON string
	var evidenceCountsJSON string
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(
		&aggregate.FindingSummary.OpenFindings,
		&aggregate.FindingSummary.CriticalFindings,
		&aggregate.FindingSummary.HighFindings,
		&aggregate.FindingSummary.OverdueFindings,
		&aggregate.FindingSummary.Unassigned,
		&controlRefsJSON,
		&aggregate.EvidenceCount,
		&evidenceCountsJSON,
	); err != nil {
		return ports.GRCDashboardAggregate{}, fmt.Errorf("summarize grc dashboard: %w", err)
	}
	controlKeys, err := decodeGRCDashboardControlKeys(controlRefsJSON)
	if err != nil {
		return ports.GRCDashboardAggregate{}, fmt.Errorf("decode grc dashboard control keys: %w", err)
	}
	aggregate.FindingSummary.FailingControlKeys = controlKeys
	aggregate.FindingSummary.ControlsFailing = len(controlKeys)
	evidenceCounts, err := decodeGRCDashboardEvidenceCounts(evidenceCountsJSON)
	if err != nil {
		return ports.GRCDashboardAggregate{}, fmt.Errorf("decode grc dashboard evidence counts: %w", err)
	}
	aggregate.EvidenceCountsByFindingID = evidenceCounts
	return aggregate, nil
}

func decodeGRCDashboardControlKeys(controlRefsJSON string) ([]string, error) {
	var refs []ports.FindingControlRef
	if err := json.Unmarshal([]byte(controlRefsJSON), &refs); err != nil {
		return nil, err
	}
	controlKeys := map[string]struct{}{}
	for _, ref := range refs {
		frameworkName := strings.TrimSpace(ref.FrameworkName)
		if frameworkName == "" {
			frameworkName = "Unmapped"
		}
		controlID := strings.TrimSpace(ref.ControlID)
		if controlID == "" {
			controlID = "Needs mapping"
		}
		controlKeys[frameworkName+"\x00"+controlID] = struct{}{}
	}
	keys := make([]string, 0, len(controlKeys))
	for key := range controlKeys {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys, nil
}

func decodeGRCDashboardEvidenceCounts(evidenceCountsJSON string) (map[string]int, error) {
	counts := map[string]int{}
	if strings.TrimSpace(evidenceCountsJSON) == "" {
		return counts, nil
	}
	if err := json.Unmarshal([]byte(evidenceCountsJSON), &counts); err != nil {
		return nil, err
	}
	for findingID := range counts {
		if strings.TrimSpace(findingID) == "" {
			delete(counts, findingID)
		}
	}
	return counts, nil
}

func grcDashboardAggregateQuery(request ports.GRCDashboardAggregateRequest) (string, []any, error) {
	runtimeScopeCTE, findingClauses, args, err := grcDashboardScopeClauses(request)
	if err != nil {
		return "", nil, err
	}
	whereFindings := strings.Join(findingClauses, " AND ")
	previewClauses := []string{"FALSE"}
	previewFindingIDs := normalizedNonEmptyStrings(request.PreviewFindingIDs)
	if len(previewFindingIDs) > 0 {
		previewClauses = nil
		addStringInFilter(&previewClauses, &args, "finding.id", previewFindingIDs)
	}
	wherePreview := strings.Join(previewClauses, " AND ")
	effectiveSeverity := findingEffectiveSeveritySQL()
	query := `
WITH ` + runtimeScopeCTE + `finding_scope AS (
  SELECT id, runtime_id, status, ` + effectiveSeverity + ` AS effective_severity, due_at, assignee
  FROM findings
  WHERE ` + whereFindings + `
),
summary AS (
  SELECT
    COUNT(*) FILTER (WHERE LOWER(status) = 'open') AS open_findings,
    COUNT(*) FILTER (WHERE LOWER(status) = 'open' AND effective_severity = 'CRITICAL') AS critical_findings,
    COUNT(*) FILTER (WHERE LOWER(status) = 'open' AND effective_severity = 'HIGH') AS high_findings,
    COUNT(*) FILTER (WHERE LOWER(status) = 'open' AND due_at IS NOT NULL AND due_at < NOW()) AS overdue_findings,
    COUNT(*) FILTER (WHERE LOWER(status) = 'open' AND TRIM(assignee) = '') AS unassigned
  FROM finding_scope
),
control_refs AS (
  SELECT DISTINCT
    ref.framework_name,
    ref.control_id
  FROM finding_scope AS finding
  JOIN finding_control_refs AS ref ON ref.finding_id = finding.id
  WHERE LOWER(finding.status) = 'open'
),
evidence_summary AS (
  SELECT COALESCE(SUM(counts.evidence_count), 0)::bigint AS evidence_count
  FROM finding_scope AS finding
  JOIN finding_evidence_counts AS counts
    ON counts.runtime_id = finding.runtime_id AND counts.finding_id = finding.id
),
preview_evidence_counts AS (
  SELECT COALESCE(jsonb_object_agg(finding.id, counts.evidence_count), '{}'::jsonb)::text AS evidence_counts_json
  FROM finding_scope AS finding
  JOIN finding_evidence_counts AS counts
    ON counts.runtime_id = finding.runtime_id AND counts.finding_id = finding.id
  WHERE ` + wherePreview + `
)
SELECT
  summary.open_findings,
  summary.critical_findings,
  summary.high_findings,
  summary.overdue_findings,
  summary.unassigned,
  COALESCE((SELECT jsonb_agg(jsonb_build_object('framework_name', framework_name, 'control_id', control_id) ORDER BY framework_name, control_id)::text FROM control_refs), '[]'),
  evidence_summary.evidence_count,
  preview_evidence_counts.evidence_counts_json
FROM summary
CROSS JOIN evidence_summary
CROSS JOIN preview_evidence_counts`
	return query, args, nil
}

func grcDashboardScopeClauses(request ports.GRCDashboardAggregateRequest) (string, []string, []any, error) {
	if request.RuntimeScope == nil {
		clauses, args, err := findingFilterClauses(request.FindingRequest)
		return "", clauses, args, err
	}
	tenantID := strings.TrimSpace(request.FindingRequest.TenantID)
	scopeTenantID := strings.TrimSpace(request.RuntimeScope.TenantID)
	if tenantID == "" || scopeTenantID == "" || tenantID != scopeTenantID {
		return "", nil, nil, errors.New("dashboard runtime scope must match finding tenant")
	}
	applicationWorkspaceID, err := ports.ValidateApplicationWorkspaceScope(scopeTenantID, request.RuntimeScope.ApplicationWorkspaceID)
	if err != nil {
		return "", nil, nil, fmt.Errorf("dashboard runtime scope: %w", err)
	}
	if strings.TrimSpace(request.FindingRequest.RuntimeID) != "" || len(normalizedNonEmptyStrings(request.FindingRequest.RuntimeIDs)) > 0 {
		return "", nil, nil, errors.New("dashboard finding runtime ids must be carried by runtime scope")
	}
	args := []any{tenantID}
	runtimeClauses := []string{"tenant_id = $1"}
	runtimeIDs := append([]string(nil), request.RuntimeScope.RuntimeIDs...)
	runtimeIDs = normalizedNonEmptyStrings(append(runtimeIDs, request.RuntimeScope.RuntimeID))
	addStringInFilter(&runtimeClauses, &args, "id", runtimeIDs)
	if sourceID := strings.TrimSpace(request.RuntimeScope.SourceID); sourceID != "" {
		args = append(args, sourceID)
		runtimeClauses = append(runtimeClauses, fmt.Sprintf("source_id = $%d", len(args)))
	}
	if applicationWorkspaceID != "" {
		args = append(args, applicationWorkspaceID)
		runtimeClauses = append(runtimeClauses, fmt.Sprintf("application_workspace_id = $%d", len(args)))
	}
	findingClauses := []string{"tenant_id = $1", "runtime_id = ANY(ARRAY(SELECT id FROM runtime_scope))"}
	if err := appendFindingFilterClauses(&findingClauses, &args, request.FindingRequest); err != nil {
		return "", nil, nil, err
	}
	runtimeScopeCTE := `runtime_scope AS (
  SELECT id
  FROM source_runtimes
  WHERE ` + strings.Join(runtimeClauses, " AND ") + `
),
`
	return runtimeScopeCTE, findingClauses, args, nil
}
