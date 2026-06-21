package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
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
	findingClauses, findingArgs, err := findingFilterClauses(request.FindingRequest)
	if err != nil {
		return "", nil, err
	}
	evidenceClauses, evidenceArgs, err := findingEvidenceFilterClauses(request.EvidenceRequest)
	if err != nil {
		return "", nil, err
	}
	whereFindings := strings.Join(findingClauses, " AND ")
	whereEvidence := rebasePostgresPlaceholders(strings.Join(evidenceClauses, " AND "), len(findingArgs))
	args := append([]any{}, findingArgs...)
	args = append(args, evidenceArgs...)
	effectiveSeverity := findingEffectiveSeveritySQL()
	query := `
WITH finding_scope AS (
  SELECT id, status, ` + effectiveSeverity + ` AS effective_severity, due_at, assignee, control_refs_json
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
    COALESCE(NULLIF(TRIM(ref->>'framework_name'), ''), 'Unmapped') AS framework_name,
    COALESCE(NULLIF(TRIM(ref->>'control_id'), ''), 'Needs mapping') AS control_id
  FROM finding_scope
  LEFT JOIN LATERAL jsonb_array_elements(
    CASE
      WHEN jsonb_array_length(control_refs_json) = 0
        THEN '[{"framework_name":"Unmapped","control_id":"Needs mapping"}]'::jsonb
      ELSE control_refs_json
    END
  ) AS ref ON TRUE
  WHERE LOWER(status) = 'open'
),
evidence_summary AS (
  SELECT
    COALESCE(SUM(evidence_count), 0)::bigint AS evidence_count,
    COALESCE(jsonb_object_agg(finding_id, evidence_count), '{}'::jsonb)::text AS evidence_counts_json
  FROM (
    SELECT finding_id, COUNT(*) AS evidence_count
    FROM finding_evidence
    WHERE ` + whereEvidence + `
      AND finding_id IN (SELECT id FROM finding_scope)
    GROUP BY finding_id
  ) counts
)
SELECT
  summary.open_findings,
  summary.critical_findings,
  summary.high_findings,
  summary.overdue_findings,
  summary.unassigned,
  COALESCE((SELECT jsonb_agg(jsonb_build_object('framework_name', framework_name, 'control_id', control_id) ORDER BY framework_name, control_id)::text FROM control_refs), '[]'),
  evidence_summary.evidence_count,
  evidence_summary.evidence_counts_json
FROM summary
CROSS JOIN evidence_summary`
	return query, args, nil
}

func rebasePostgresPlaceholders(query string, offset int) string {
	if offset == 0 || query == "" {
		return query
	}
	var out strings.Builder
	for i := 0; i < len(query); i++ {
		if query[i] != '$' {
			out.WriteByte(query[i])
			continue
		}
		j := i + 1
		for j < len(query) && query[j] >= '0' && query[j] <= '9' {
			j++
		}
		if j == i+1 {
			out.WriteByte(query[i])
			continue
		}
		index, err := strconv.Atoi(query[i+1 : j])
		if err != nil {
			out.WriteString(query[i:j])
			i = j - 1
			continue
		}
		out.WriteByte('$')
		out.WriteString(strconv.Itoa(index + offset))
		i = j - 1
	}
	return out.String()
}
