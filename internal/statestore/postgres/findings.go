package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	findingrisk "github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
)

var ensureFindingStatements = []string{
	`CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL UNIQUE,
  tenant_id TEXT NOT NULL,
  runtime_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL,
  summary TEXT NOT NULL,
  risk_score INTEGER NOT NULL DEFAULT 0,
  likelihood_score INTEGER NOT NULL DEFAULT 0,
  impact_score INTEGER NOT NULL DEFAULT 0,
  confidence_score INTEGER NOT NULL DEFAULT 0,
  likelihood_level TEXT NOT NULL DEFAULT '',
  impact_level TEXT NOT NULL DEFAULT '',
  risk_reasons_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  risk_model_version TEXT NOT NULL DEFAULT '',
  resource_urns_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  event_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  observed_policy_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  control_refs_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  notes_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  tickets_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  external_refs_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  policy_id TEXT NOT NULL DEFAULT '',
  policy_name TEXT NOT NULL DEFAULT '',
  check_id TEXT NOT NULL DEFAULT '',
  check_name TEXT NOT NULL DEFAULT '',
  assignee TEXT NOT NULL DEFAULT '',
  due_at TIMESTAMPTZ,
  status_reason TEXT NOT NULL DEFAULT '',
  status_updated_at TIMESTAMPTZ,
  first_observed_at TIMESTAMPTZ NOT NULL,
  last_observed_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS observed_policy_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS control_refs_json JSONB NOT NULL DEFAULT '[]'::jsonb`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS notes_json JSONB NOT NULL DEFAULT '[]'::jsonb`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS tickets_json JSONB NOT NULL DEFAULT '[]'::jsonb`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS external_refs_json JSONB NOT NULL DEFAULT '[]'::jsonb`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS policy_id TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS policy_name TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS check_id TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS check_name TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS assignee TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS due_at TIMESTAMPTZ`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS status_reason TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS status_updated_at TIMESTAMPTZ`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_score INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS likelihood_score INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS impact_score INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS confidence_score INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS likelihood_level TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS impact_level TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_reasons_json JSONB NOT NULL DEFAULT '[]'::jsonb`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_model_version TEXT NOT NULL DEFAULT ''`,
	`CREATE INDEX IF NOT EXISTS findings_runtime_rule_idx ON findings (runtime_id, rule_id)`,
	`CREATE INDEX IF NOT EXISTS findings_tenant_rule_idx ON findings (tenant_id, rule_id)`,
	`CREATE INDEX IF NOT EXISTS findings_runtime_policy_idx ON findings (runtime_id, policy_id)`,
	`CREATE INDEX IF NOT EXISTS findings_runtime_check_idx ON findings (runtime_id, check_id)`,
	`CREATE INDEX IF NOT EXISTS findings_runtime_due_at_idx ON findings (runtime_id, due_at)`,
	`CREATE INDEX IF NOT EXISTS findings_runtime_status_idx ON findings (runtime_id, status)`,
	`CREATE INDEX IF NOT EXISTS findings_runtime_severity_idx ON findings (runtime_id, severity)`,
	`CREATE INDEX IF NOT EXISTS findings_tenant_runtime_status_observed_idx ON findings (tenant_id, runtime_id, status, last_observed_at DESC, id)`,
	`CREATE INDEX IF NOT EXISTS findings_tenant_runtime_observed_idx ON findings (tenant_id, runtime_id, last_observed_at DESC, id)`,
	`CREATE INDEX IF NOT EXISTS findings_priority_idx ON findings (tenant_id, runtime_id, status, risk_score DESC, last_observed_at DESC, id)`,
	`CREATE INDEX IF NOT EXISTS findings_resource_urns_gin_idx ON findings USING GIN (resource_urns_json)`,
	`CREATE INDEX IF NOT EXISTS findings_event_ids_gin_idx ON findings USING GIN (event_ids_json)`,
	`CREATE INDEX IF NOT EXISTS findings_observed_policy_ids_gin_idx ON findings USING GIN (observed_policy_ids_json)`,
	`CREATE INDEX IF NOT EXISTS findings_control_refs_gin_idx ON findings USING GIN (control_refs_json)`,
	`CREATE INDEX IF NOT EXISTS findings_notes_gin_idx ON findings USING GIN (notes_json)`,
	`CREATE INDEX IF NOT EXISTS findings_tickets_gin_idx ON findings USING GIN (tickets_json)`,
	`CREATE INDEX IF NOT EXISTS findings_external_refs_gin_idx ON findings USING GIN (external_refs_json)`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS tombstoned BOOLEAN NOT NULL DEFAULT FALSE`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS tombstoned_at TIMESTAMPTZ`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS tombstoned_by TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS tombstoned_reason TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS tombstoned_run_id TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS prior_status TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS tombstone_generation INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_fingerprint_key`,
	`DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_indexes
        WHERE schemaname = current_schema()
          AND tablename = 'findings'
          AND indexname = 'findings_active_fingerprint_uidx'
          AND indexdef NOT ILIKE '%(tenant_id, fingerprint)%'
    ) THEN
        DROP INDEX findings_active_fingerprint_uidx;
    END IF;
END $$`,
	`CREATE UNIQUE INDEX IF NOT EXISTS findings_active_fingerprint_uidx
        ON findings (tenant_id, fingerprint) WHERE tombstoned = FALSE`,
	`CREATE INDEX IF NOT EXISTS findings_tombstoned_run_idx
        ON findings (tombstoned_run_id) WHERE tombstoned = TRUE`,
	`CREATE INDEX IF NOT EXISTS findings_tombstoned_rule_observed_idx
        ON findings (tenant_id, rule_id, tombstoned, last_observed_at)`,
	`CREATE TABLE IF NOT EXISTS finding_tombstone_events (
        id BIGSERIAL PRIMARY KEY,
        finding_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        anchor_uri TEXT NOT NULL,
        prior_status TEXT NOT NULL,
        reason TEXT NOT NULL,
        actor TEXT NOT NULL,
        run_id TEXT NOT NULL,
        tombstoned_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`,
	`CREATE INDEX IF NOT EXISTS finding_tombstone_events_run_idx
        ON finding_tombstone_events (run_id, tombstoned_at)`,
	`CREATE INDEX IF NOT EXISTS finding_tombstone_events_finding_idx
        ON finding_tombstone_events (finding_id, tombstoned_at)`,
	`CREATE TABLE IF NOT EXISTS closeout_run (
        run_id TEXT PRIMARY KEY,
        actor TEXT NOT NULL,
        change_ticket TEXT NOT NULL DEFAULT '',
        selector_json JSONB NOT NULL,
        status TEXT NOT NULL,
        started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        finished_at TIMESTAMPTZ,
        dry_run BOOLEAN NOT NULL,
        proposed_count INTEGER NOT NULL DEFAULT 0,
        applied_count INTEGER NOT NULL DEFAULT 0,
        error_message TEXT NOT NULL DEFAULT '',
        s3_summary_key TEXT NOT NULL DEFAULT ''
    )`,
	`ALTER TABLE closeout_run ADD COLUMN IF NOT EXISTS heartbeat_at TIMESTAMPTZ`,
	`UPDATE closeout_run SET heartbeat_at = started_at WHERE heartbeat_at IS NULL`,
	`ALTER TABLE closeout_run ALTER COLUMN heartbeat_at SET DEFAULT now()`,
	`ALTER TABLE closeout_run ALTER COLUMN heartbeat_at SET NOT NULL`,
	`CREATE UNIQUE INDEX IF NOT EXISTS closeout_run_singleton_running_idx
        ON closeout_run ((1)) WHERE status = 'running'`,
}

const findingSelectColumns = `id, fingerprint, tenant_id, runtime_id, rule_id, title, severity, status, summary,
  risk_score, likelihood_score, impact_score, confidence_score, likelihood_level, impact_level, risk_reasons_json::text, risk_model_version,
  resource_urns_json::text, event_ids_json::text, observed_policy_ids_json::text, control_refs_json::text,
  notes_json::text, tickets_json::text, external_refs_json::text, policy_id, policy_name, check_id, check_name, attributes_json::text, assignee, due_at, status_reason,
  status_updated_at, first_observed_at, last_observed_at,
  tombstoned, tombstoned_at, tombstoned_by, tombstoned_reason, tombstoned_run_id, prior_status, tombstone_generation`

type findingStatusReason string

const findingStatusReasonBackfillCollision findingStatusReason = "backfill_collision"

const (
	tenantScopedFingerprintBackfillActor = "tenant_scoped_fingerprint_backfill"
	tenantScopedFingerprintBackfillRunID = "tenant_scoped_fingerprint_backfill"
	maxFindingListLimit                  = uint32(500)
)

var errTenantScopedFingerprintBackfillRetry = errors.New("retry tenant-scoped fingerprint backfill")

// upsertFindingStatement persists one finding row, preserving runtime_id on conflict.
//
// runtime_id is intentionally pinned on first insert. Event-rule fingerprints already include
// runtime_id, so the same id can never collide across runtimes for them and this clause is a
// no-op. Graph-rule fingerprints are deliberately tenant-scoped (they omit runtime_id) so the
// same offender can be emitted by multiple triggering runtimes (e.g. okta inventory and
// github audit for the deprovisioned-Okta-active-in-GitHub rule); preserving the original
// runtime keeps the row addressable through the real runtime-scoped read paths
// (Service.ListFindings, ListEvidence, reports, GRC) instead of flipping it between sources
// every iteration.
const upsertFindingStatement = `
INSERT INTO findings (
  id, fingerprint, tenant_id, runtime_id, rule_id, title, severity, status, summary,
  risk_score, likelihood_score, impact_score, confidence_score, likelihood_level, impact_level, risk_reasons_json, risk_model_version,
  resource_urns_json, event_ids_json, observed_policy_ids_json, control_refs_json, notes_json, tickets_json, external_refs_json, attributes_json,
  policy_id, policy_name, check_id, check_name, assignee, due_at, status_reason,
  status_updated_at, first_observed_at, last_observed_at, tombstone_generation
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16::jsonb, $17, $18::jsonb, $19::jsonb, $20::jsonb, $21::jsonb, $22::jsonb, $23::jsonb, $24::jsonb, $25::jsonb, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36)
ON CONFLICT (id)
DO UPDATE SET
  fingerprint = EXCLUDED.fingerprint,
  tenant_id = EXCLUDED.tenant_id,
  runtime_id = findings.runtime_id,
  rule_id = EXCLUDED.rule_id,
  title = EXCLUDED.title,
  severity = EXCLUDED.severity,
  status = CASE
    WHEN findings.tombstoned THEN findings.status
    WHEN findings.status = 'suppressed' THEN findings.status
    WHEN findings.status = 'resolved' AND EXCLUDED.status = 'open' AND NOT findings.tombstoned AND (BTRIM(findings.status_reason) LIKE 'ttl_expired:%' OR $37::boolean) THEN EXCLUDED.status
    WHEN findings.status = 'resolved' AND EXCLUDED.status = 'open' THEN findings.status
    ELSE EXCLUDED.status
  END,
  summary = EXCLUDED.summary,
  risk_score = EXCLUDED.risk_score,
  likelihood_score = EXCLUDED.likelihood_score,
  impact_score = EXCLUDED.impact_score,
  confidence_score = EXCLUDED.confidence_score,
  likelihood_level = EXCLUDED.likelihood_level,
  impact_level = EXCLUDED.impact_level,
  risk_reasons_json = EXCLUDED.risk_reasons_json,
  risk_model_version = EXCLUDED.risk_model_version,
  resource_urns_json = EXCLUDED.resource_urns_json,
  event_ids_json = EXCLUDED.event_ids_json,
  observed_policy_ids_json = EXCLUDED.observed_policy_ids_json,
  control_refs_json = EXCLUDED.control_refs_json,
  notes_json = CASE
    WHEN jsonb_array_length(EXCLUDED.notes_json) = 0 THEN findings.notes_json
    ELSE EXCLUDED.notes_json
  END,
  tickets_json = CASE
    WHEN jsonb_array_length(EXCLUDED.tickets_json) = 0 THEN findings.tickets_json
    ELSE EXCLUDED.tickets_json
  END,
  external_refs_json = CASE
    WHEN jsonb_array_length(EXCLUDED.external_refs_json) = 0 THEN findings.external_refs_json
    ELSE EXCLUDED.external_refs_json
  END,
  attributes_json = EXCLUDED.attributes_json,
  policy_id = EXCLUDED.policy_id,
  policy_name = EXCLUDED.policy_name,
  check_id = EXCLUDED.check_id,
  check_name = EXCLUDED.check_name,
  assignee = CASE
    WHEN findings.assignee <> '' AND EXCLUDED.assignee = '' THEN findings.assignee
    ELSE EXCLUDED.assignee
  END,
  due_at = COALESCE(EXCLUDED.due_at, findings.due_at),
  status_reason = CASE
    WHEN findings.tombstoned THEN findings.status_reason
    WHEN findings.status = 'suppressed' THEN findings.status_reason
    WHEN findings.status = 'resolved' AND EXCLUDED.status = 'open' AND NOT (BTRIM(findings.status_reason) LIKE 'ttl_expired:%' OR $37::boolean) THEN findings.status_reason
    ELSE EXCLUDED.status_reason
  END,
  status_updated_at = CASE
    WHEN findings.tombstoned THEN findings.status_updated_at
    WHEN findings.status = 'suppressed' THEN findings.status_updated_at
    WHEN findings.status = 'resolved' AND EXCLUDED.status = 'open' AND NOT (BTRIM(findings.status_reason) LIKE 'ttl_expired:%' OR $37::boolean) THEN findings.status_updated_at
    ELSE EXCLUDED.status_updated_at
  END,
  first_observed_at = LEAST(findings.first_observed_at, EXCLUDED.first_observed_at),
  last_observed_at = GREATEST(findings.last_observed_at, EXCLUDED.last_observed_at),
  updated_at = NOW()
WHERE findings.tombstoned = FALSE
RETURNING ` + findingSelectColumns

const linkFindingExternalRefStatement = `
UPDATE findings
SET external_refs_json = CASE
      WHEN COALESCE(external_refs_json, '[]'::jsonb) @> $3::jsonb THEN (
        SELECT COALESCE(jsonb_agg(
          CASE
            WHEN ref @> ($3::jsonb -> 0) THEN ($2::jsonb -> 0)
            ELSE ref
          END
        ), '[]'::jsonb)
        FROM jsonb_array_elements(COALESCE(external_refs_json, '[]'::jsonb)) AS existing(ref)
      )
      ELSE COALESCE(external_refs_json, '[]'::jsonb) || $2::jsonb
    END,
    updated_at = NOW()
WHERE id = $1
RETURNING ` + findingSelectColumns

// UpsertFinding persists one normalized finding in the current-state store.
func (s *Store) UpsertFinding(ctx context.Context, finding *ports.FindingRecord) (*ports.FindingRecord, error) {
	if finding == nil {
		return nil, errors.New("finding is required")
	}
	id := strings.TrimSpace(finding.ID)
	if id == "" {
		return nil, errors.New("finding id is required")
	}
	fingerprint := strings.TrimSpace(finding.Fingerprint)
	if fingerprint == "" {
		return nil, errors.New("finding fingerprint is required")
	}
	tenantID := strings.TrimSpace(finding.TenantID)
	if tenantID == "" {
		return nil, errors.New("finding tenant id is required")
	}
	runtimeID := strings.TrimSpace(finding.RuntimeID)
	if runtimeID == "" {
		return nil, errors.New("finding runtime id is required")
	}
	ruleID := strings.TrimSpace(finding.RuleID)
	if ruleID == "" {
		return nil, errors.New("finding rule id is required")
	}
	title := strings.TrimSpace(finding.Title)
	if title == "" {
		return nil, errors.New("finding title is required")
	}
	severity := strings.TrimSpace(finding.Severity)
	if severity == "" {
		return nil, errors.New("finding severity is required")
	}
	status := strings.TrimSpace(finding.Status)
	if status == "" {
		return nil, errors.New("finding status is required")
	}
	summary := strings.TrimSpace(finding.Summary)
	if summary == "" {
		return nil, errors.New("finding summary is required")
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return nil, err
	}
	resourceURNsJSON, err := findingStringsJSON(finding.ResourceURNs)
	if err != nil {
		return nil, fmt.Errorf("marshal finding resource urns: %w", err)
	}
	eventIDsJSON, err := findingStringsJSON(finding.EventIDs)
	if err != nil {
		return nil, fmt.Errorf("marshal finding event ids: %w", err)
	}
	observedPolicyIDsJSON, err := findingStringsJSON(finding.ObservedPolicyIDs)
	if err != nil {
		return nil, fmt.Errorf("marshal finding observed policy ids: %w", err)
	}
	controlRefsJSON, err := findingControlRefsJSON(finding.ControlRefs)
	if err != nil {
		return nil, fmt.Errorf("marshal finding control refs: %w", err)
	}
	notesJSON, err := findingNotesJSON(finding.Notes)
	if err != nil {
		return nil, fmt.Errorf("marshal finding notes: %w", err)
	}
	ticketsJSON, err := findingTicketsJSON(finding.Tickets)
	if err != nil {
		return nil, fmt.Errorf("marshal finding tickets: %w", err)
	}
	externalRefsJSON, err := findingExternalRefsJSON(finding.ExternalRefs)
	if err != nil {
		return nil, fmt.Errorf("marshal finding external refs: %w", err)
	}
	attributesJSON, err := findingAttributesJSON(finding.Attributes)
	if err != nil {
		return nil, fmt.Errorf("marshal finding attributes: %w", err)
	}
	riskReasonsJSON, err := findingStringsJSON(finding.RiskReasons)
	if err != nil {
		return nil, fmt.Errorf("marshal finding risk reasons: %w", err)
	}
	policyID := strings.TrimSpace(finding.PolicyID)
	policyName := strings.TrimSpace(finding.PolicyName)
	checkID := strings.TrimSpace(finding.CheckID)
	checkName := strings.TrimSpace(finding.CheckName)
	assignee := strings.TrimSpace(finding.Assignee)
	var dueAt any
	if !finding.DueAt.IsZero() {
		dueAt = finding.DueAt.UTC()
	}
	statusReason := strings.TrimSpace(finding.StatusReason)
	var statusUpdatedAt any
	if !finding.StatusUpdatedAt.IsZero() {
		statusUpdatedAt = finding.StatusUpdatedAt.UTC()
	}
	firstObservedAt, lastObservedAt := normalizeFindingObservationWindow(finding.FirstObservedAt, finding.LastObservedAt, time.Now().UTC())
	reopenResolvedOnOpenEmit := findingRuleAllowsTTLReopen(ruleID)

	const maxAttempts = 4
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		targetID, generation, err := s.resolveUpsertTarget(ctx, tenantID, fingerprint, id)
		if err != nil {
			return nil, fmt.Errorf("upsert finding %q: %w", id, err)
		}
		var stored findingRow
		err = scanFindingRow(s.db.QueryRowContext(ctx, upsertFindingStatement,
			targetID,
			fingerprint,
			tenantID,
			runtimeID,
			ruleID,
			title,
			severity,
			status,
			summary,
			finding.RiskScore,
			finding.LikelihoodScore,
			finding.ImpactScore,
			finding.ConfidenceScore,
			strings.TrimSpace(finding.LikelihoodLevel),
			strings.TrimSpace(finding.ImpactLevel),
			riskReasonsJSON,
			strings.TrimSpace(finding.RiskModelVersion),
			resourceURNsJSON,
			eventIDsJSON,
			observedPolicyIDsJSON,
			controlRefsJSON,
			notesJSON,
			ticketsJSON,
			externalRefsJSON,
			attributesJSON,
			policyID,
			policyName,
			checkID,
			checkName,
			assignee,
			dueAt,
			statusReason,
			statusUpdatedAt,
			firstObservedAt,
			lastObservedAt,
			generation,
			reopenResolvedOnOpenEmit,
		), &stored)
		if err == nil {
			return stored.record()
		}
		lastErr = err
		if errors.Is(err, sql.ErrNoRows) && attempt < maxAttempts-1 {
			continue
		}
		if isPartialUniqueIndexConflict(err) && attempt < maxAttempts-1 {
			continue
		}
		return nil, fmt.Errorf("upsert finding %q: %w", id, err)
	}
	return nil, fmt.Errorf("upsert finding %q: %w", id, lastErr)
}

// resolveUpsertTarget resolves the row identity for an emit on the given tenant/fingerprint:
// if a non-tombstoned row already exists for that tenant it reuses that row's id (the ON CONFLICT (id)
// path then updates it). Otherwise it mints a fresh id derived from baseID with a
// "#g<N+1>" generation suffix where N is the max tombstone_generation observed for the
// tenant/fingerprint, and returns N+1 as the new row's tombstone_generation.
func (s *Store) resolveUpsertTarget(ctx context.Context, tenantID, fingerprint, baseID string) (string, int, error) {
	var activeID sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM findings WHERE tenant_id = $1 AND fingerprint = $2 AND tombstoned = FALSE LIMIT 1`,
		tenantID,
		fingerprint,
	).Scan(&activeID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", 0, fmt.Errorf("select active finding by tenant fingerprint: %w", err)
	}
	if activeID.Valid && activeID.String != "" {
		// Existing active row will be reopened via ON CONFLICT (id); its stored
		// tombstone_generation is preserved because that column is not in the SET list.
		return activeID.String, 0, nil
	}
	var maxGen sql.NullInt64
	if err := s.db.QueryRowContext(ctx,
		`SELECT MAX(tombstone_generation) FROM findings WHERE tenant_id = $1 AND fingerprint = $2`,
		tenantID,
		fingerprint,
	).Scan(&maxGen); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", 0, fmt.Errorf("select tombstone generation: %w", err)
	}
	if !maxGen.Valid {
		return baseID, 0, nil
	}
	next := int(maxGen.Int64) + 1
	return fmt.Sprintf("%s#g%d", findingBaseID(baseID), next), next, nil
}

var findingGenerationSuffix = regexp.MustCompile(`#g\d+$`)

func findingBaseID(id string) string {
	return findingGenerationSuffix.ReplaceAllString(id, "")
}

func isPartialUniqueIndexConflict(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	if pgErr.Code != "23505" {
		return false
	}
	return strings.Contains(pgErr.ConstraintName, "findings_active_fingerprint_uidx") ||
		strings.Contains(pgErr.Message, "findings_active_fingerprint_uidx")
}

var findingTTLEvidenceRuleIDs struct {
	once sync.Once
	ids  map[string]struct{}
}

func findingRuleAllowsTTLReopen(ruleID string) bool {
	id := strings.TrimSpace(ruleID)
	if id == "" {
		return false
	}
	findingTTLEvidenceRuleIDs.once.Do(func() {
		ids := map[string]struct{}{}
		for _, metadata := range findingrisk.BuiltinRuleMetadata() {
			if strings.TrimSpace(string(metadata.Lifecycle.Kind)) == string(findingrisk.LifecycleTTLEvidence) {
				if metadataID := strings.TrimSpace(metadata.ID); metadataID != "" {
					ids[metadataID] = struct{}{}
				}
			}
		}
		findingTTLEvidenceRuleIDs.ids = ids
	})
	_, ok := findingTTLEvidenceRuleIDs.ids[id]
	return ok
}

func normalizeFindingObservationWindow(firstObservedAt time.Time, lastObservedAt time.Time, now time.Time) (time.Time, time.Time) {
	firstObservedAt = firstObservedAt.UTC()
	lastObservedAt = lastObservedAt.UTC()
	if firstObservedAt.IsZero() {
		firstObservedAt = lastObservedAt
	}
	if lastObservedAt.IsZero() {
		lastObservedAt = firstObservedAt
	}
	if firstObservedAt.IsZero() {
		now = now.UTC()
		firstObservedAt = now
		lastObservedAt = now
	}
	return firstObservedAt, lastObservedAt
}

// ListFindings loads persisted findings filtered by tenant plus at least one of runtime_id
// or rule_id. Graph rules need a tenant+rule scope (the projected graph has no per-runtime
// partition for shared entities like okta.user), while replay-driven callers stay on the
// indexed (runtime_id, ...) path. Requiring at least one of the two prevents a caller from
// accidentally issuing a tenant-wide table scan.
func (s *Store) ListFindings(ctx context.Context, request ports.ListFindingsRequest) (_ []*ports.FindingRecord, err error) {
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		return nil, errors.New("finding tenant id is required")
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	runtimeIDs := normalizedNonEmptyStrings(append(request.RuntimeIDs, runtimeID))
	ruleID := strings.TrimSpace(request.RuleID)
	if len(runtimeIDs) == 0 && ruleID == "" {
		return nil, errors.New("finding runtime id or rule id is required")
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return nil, err
	}
	query, args, err := findingListQuery(request)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query findings for tenant %q runtime %q rule %q: %w", tenantID, runtimeID, ruleID, err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close findings rows: %w", closeErr)
		}
	}()

	findings := []*ports.FindingRecord{}
	for rows.Next() {
		var row findingRow
		if err := scanFindingRow(rows, &row); err != nil {
			return nil, fmt.Errorf("scan finding row: %w", err)
		}
		record, err := row.record()
		if err != nil {
			return nil, err
		}
		findings = append(findings, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate findings rows: %w", err)
	}
	return findings, nil
}

// ListGRCFindings loads the denormalized finding fields needed by GRC read models.
func (s *Store) ListGRCFindings(ctx context.Context, request ports.ListFindingsRequest) (_ []*ports.FindingRecord, err error) {
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		return nil, errors.New("finding tenant id is required")
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	runtimeIDs := normalizedNonEmptyStrings(append(request.RuntimeIDs, runtimeID))
	ruleID := strings.TrimSpace(request.RuleID)
	if len(runtimeIDs) == 0 && ruleID == "" {
		return nil, errors.New("finding runtime id or rule id is required")
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return nil, err
	}
	query, args, err := findingGRCListQuery(request)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query grc findings for tenant %q runtime %q rule %q: %w", tenantID, runtimeID, ruleID, err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close grc findings rows: %w", closeErr)
		}
	}()

	findings := []*ports.FindingRecord{}
	for rows.Next() {
		record, err := scanGRCFindingRow(rows)
		if err != nil {
			return nil, err
		}
		findings = append(findings, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate grc findings rows: %w", err)
	}
	return findings, nil
}

// SummarizeFindings loads aggregate finding counts for one filtered query without
// applying row pagination.
func (s *Store) SummarizeFindings(ctx context.Context, request ports.ListFindingsRequest) (ports.FindingSummary, error) {
	if s == nil || s.db == nil {
		return ports.FindingSummary{}, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return ports.FindingSummary{}, err
	}
	clauses, args, err := findingFilterClauses(request)
	if err != nil {
		return ports.FindingSummary{}, err
	}
	where := strings.Join(clauses, " AND ")
	effectiveSeverity := findingEffectiveSeveritySQL()
	query := `
SELECT
  COUNT(*),
  COUNT(*) FILTER (WHERE LOWER(status) = 'open'),
  COUNT(*) FILTER (WHERE LOWER(status) = 'open' AND ` + effectiveSeverity + ` = 'CRITICAL'),
  COUNT(*) FILTER (WHERE LOWER(status) = 'open' AND ` + effectiveSeverity + ` = 'HIGH'),
  COUNT(*) FILTER (WHERE LOWER(status) = 'open' AND due_at IS NOT NULL AND due_at < NOW()),
  COUNT(*) FILTER (WHERE LOWER(status) = 'open' AND TRIM(assignee) = ''),
  COALESCE(MAX(risk_score), 0),
  COALESCE(SUM(risk_score), 0)
FROM findings
WHERE ` + where
	var summary ports.FindingSummary
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(
		&summary.TotalFindings,
		&summary.OpenFindings,
		&summary.CriticalFindings,
		&summary.HighFindings,
		&summary.OverdueFindings,
		&summary.Unassigned,
		&summary.MaxRiskScore,
		&summary.RiskScoreTotal,
	); err != nil {
		return ports.FindingSummary{}, fmt.Errorf("summarize findings: %w", err)
	}
	severityCounts, err := s.findingSummaryCountMap(ctx, `
SELECT COALESCE(NULLIF(LOWER(TRIM(`+effectiveSeverity+`)), ''), 'unknown') AS key, COUNT(*) AS count
FROM findings
WHERE `+where+`
GROUP BY key`, args)
	if err != nil {
		return ports.FindingSummary{}, fmt.Errorf("summarize finding severities: %w", err)
	}
	summary.BySeverity = severityCounts
	statusCounts, err := s.findingSummaryCountMap(ctx, `
SELECT COALESCE(NULLIF(LOWER(TRIM(status)), ''), 'unknown') AS key, COUNT(*) AS count
FROM findings
WHERE `+where+`
GROUP BY key`, args)
	if err != nil {
		return ports.FindingSummary{}, fmt.Errorf("summarize finding statuses: %w", err)
	}
	summary.ByStatus = statusCounts
	reasonCounts, err := s.findingSummaryCountMap(ctx, `
SELECT TRIM(reason.value) AS key, COUNT(*) AS count
FROM findings
CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(risk_reasons_json, '[]'::jsonb)) AS reason(value)
WHERE `+where+` AND TRIM(reason.value) <> ''
GROUP BY key`, args)
	if err != nil {
		return ports.FindingSummary{}, fmt.Errorf("summarize finding risk reasons: %w", err)
	}
	summary.RiskReasonCounts = reasonCounts
	// #nosec G202 -- where is assembled from fixed predicates with parameterized values.
	controlQuery := `
SELECT framework_name, control_id
FROM (
  SELECT DISTINCT
    COALESCE(NULLIF(TRIM(ref->>'framework_name'), ''), 'Unmapped') AS framework_name,
    COALESCE(NULLIF(TRIM(ref->>'control_id'), ''), 'Needs mapping') AS control_id
  FROM findings
  LEFT JOIN LATERAL jsonb_array_elements(
    CASE
      WHEN jsonb_array_length(control_refs_json) = 0
        THEN '[{"framework_name":"Unmapped","control_id":"Needs mapping"}]'::jsonb
      ELSE control_refs_json
    END
  ) AS ref ON TRUE
  WHERE ` + where + ` AND LOWER(status) = 'open'
) controls`
	rows, err := s.db.QueryContext(ctx, controlQuery, args...)
	if err != nil {
		return ports.FindingSummary{}, fmt.Errorf("summarize finding controls: %w", err)
	}
	defer func() { _ = rows.Close() }()
	controlKeys := map[string]struct{}{}
	for rows.Next() {
		var frameworkName string
		var controlID string
		if err := rows.Scan(&frameworkName, &controlID); err != nil {
			return ports.FindingSummary{}, fmt.Errorf("scan summarized finding control: %w", err)
		}
		key := frameworkName + "\x00" + controlID
		controlKeys[key] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return ports.FindingSummary{}, fmt.Errorf("iterate summarized finding controls: %w", err)
	}
	for key := range controlKeys {
		summary.FailingControlKeys = append(summary.FailingControlKeys, key)
	}
	sort.Strings(summary.FailingControlKeys)
	summary.ControlsFailing = len(summary.FailingControlKeys)
	return summary, nil
}

func (s *Store) findingSummaryCountMap(ctx context.Context, query string, args []any) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	counts := map[string]int{}
	for rows.Next() {
		var key string
		var count int
		if err := rows.Scan(&key, &count); err != nil {
			return nil, err
		}
		key = strings.TrimSpace(key)
		if key == "" {
			key = "unknown"
		}
		counts[key] += count
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return counts, nil
}

// GetFinding loads one persisted finding by durable identifier.
func (s *Store) GetFinding(ctx context.Context, id string) (*ports.FindingRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return nil, err
	}
	findingID := strings.TrimSpace(id)
	if findingID == "" {
		return nil, errors.New("finding id is required")
	}
	var row findingRow
	if err := scanFindingRow(s.db.QueryRowContext(ctx, `
SELECT `+findingSelectColumns+`
FROM findings
WHERE id = $1`,
		findingID,
	), &row); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ports.ErrFindingNotFound
		}
		return nil, fmt.Errorf("query finding %q: %w", findingID, err)
	}
	return row.record()
}

// UpdateFindingStatus mutates one persisted finding lifecycle status.
func (s *Store) UpdateFindingStatus(ctx context.Context, request ports.FindingStatusUpdate) (*ports.FindingRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return nil, err
	}
	findingID := strings.TrimSpace(request.FindingID)
	if findingID == "" {
		return nil, errors.New("finding id is required")
	}
	status := strings.TrimSpace(request.Status)
	if status == "" {
		return nil, errors.New("finding status is required")
	}
	statusReason := strings.TrimSpace(request.Reason)
	updatedAt := request.UpdatedAt.UTC()
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}
	eventIDsJSON, err := findingStringsJSON(request.EventIDs)
	if err != nil {
		return nil, fmt.Errorf("marshal finding status event ids: %w", err)
	}
	expectedStatus := strings.TrimSpace(request.ExpectedStatus)
	lastObservedBefore := request.LastObservedBefore.UTC()
	if request.Tombstone != nil {
		t := request.Tombstone
		tombstonedAt := t.TombstonedAt.UTC()
		if tombstonedAt.IsZero() {
			tombstonedAt = updatedAt
		}
		args := []any{
			findingID,
			status,
			statusReason,
			updatedAt,
			tombstonedAt,
			strings.TrimSpace(t.By),
			strings.TrimSpace(t.Reason),
			strings.TrimSpace(t.RunID),
			strings.TrimSpace(t.PriorStatus),
			eventIDsJSON,
		}
		whereClause, args, preconditioned := findingStatusWhereClause(args, expectedStatus, lastObservedBefore)
		var row findingRow
		if err := scanFindingRow(s.db.QueryRowContext(ctx, `
UPDATE findings
SET status = $2,
    status_reason = $3,
    status_updated_at = $4,
    tombstoned = TRUE,
    tombstoned_at = $5,
    tombstoned_by = $6,
    tombstoned_reason = $7,
    tombstoned_run_id = $8,
    prior_status = $9,
    event_ids_json = CASE
      WHEN jsonb_array_length($10::jsonb) = 0 THEN event_ids_json
      ELSE (
        SELECT COALESCE(jsonb_agg(event_id ORDER BY event_id), '[]'::jsonb)
        FROM (
          SELECT DISTINCT btrim(value) AS event_id
          FROM jsonb_array_elements_text(COALESCE(findings.event_ids_json, '[]'::jsonb) || $10::jsonb) AS merged(value)
          WHERE btrim(value) <> ''
        ) AS unique_event_ids
      )
    END,
    updated_at = NOW()
`+whereClause+`
RETURNING `+findingSelectColumns, args...), &row); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, findingStatusNoRowsError(preconditioned)
			}
			return nil, fmt.Errorf("update finding %q tombstone status: %w", findingID, err)
		}
		return row.record()
	}
	args := []any{
		findingID,
		status,
		statusReason,
		updatedAt,
		eventIDsJSON,
	}
	whereClause, args, preconditioned := findingStatusWhereClause(args, expectedStatus, lastObservedBefore)
	var row findingRow
	if err := scanFindingRow(s.db.QueryRowContext(ctx, `
UPDATE findings
SET status = $2,
    status_reason = $3,
    status_updated_at = $4,
    event_ids_json = CASE
      WHEN jsonb_array_length($5::jsonb) = 0 THEN event_ids_json
      ELSE (
        SELECT COALESCE(jsonb_agg(event_id ORDER BY event_id), '[]'::jsonb)
        FROM (
          SELECT DISTINCT btrim(value) AS event_id
          FROM jsonb_array_elements_text(COALESCE(findings.event_ids_json, '[]'::jsonb) || $5::jsonb) AS merged(value)
          WHERE btrim(value) <> ''
        ) AS unique_event_ids
      )
    END,
    updated_at = NOW()
`+whereClause+`
RETURNING `+findingSelectColumns, args...), &row); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, findingStatusNoRowsError(preconditioned)
		}
		return nil, fmt.Errorf("update finding %q status: %w", findingID, err)
	}
	return row.record()
}

func findingStatusWhereClause(args []any, expectedStatus string, lastObservedBefore time.Time) (string, []any, bool) {
	where := "WHERE id = $1"
	preconditioned := false
	if expectedStatus = strings.TrimSpace(expectedStatus); expectedStatus != "" {
		args = append(args, expectedStatus)
		where += fmt.Sprintf("\n  AND status = $%d", len(args))
		preconditioned = true
	}
	if !lastObservedBefore.IsZero() {
		args = append(args, lastObservedBefore.UTC())
		where += fmt.Sprintf("\n  AND last_observed_at < $%d", len(args))
		preconditioned = true
	}
	return where, args, preconditioned
}

func findingStatusNoRowsError(preconditioned bool) error {
	if preconditioned {
		return ports.ErrFindingStatusPreconditionFailed
	}
	return ports.ErrFindingNotFound
}

// UpdateFindingAssignee updates or clears one persisted finding assignee.
func (s *Store) UpdateFindingAssignee(ctx context.Context, request ports.FindingAssigneeUpdate) (*ports.FindingRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return nil, err
	}
	findingID := strings.TrimSpace(request.FindingID)
	if findingID == "" {
		return nil, errors.New("finding id is required")
	}
	var row findingRow
	if err := scanFindingRow(s.db.QueryRowContext(ctx, `
UPDATE findings
SET assignee = $2, updated_at = NOW()
WHERE id = $1
RETURNING `+findingSelectColumns,
		findingID,
		strings.TrimSpace(request.Assignee),
	), &row); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ports.ErrFindingNotFound
		}
		return nil, fmt.Errorf("update finding %q assignee: %w", findingID, err)
	}
	return row.record()
}

// UpdateFindingDueDate updates one persisted finding due date.
func (s *Store) UpdateFindingDueDate(ctx context.Context, request ports.FindingDueDateUpdate) (*ports.FindingRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return nil, err
	}
	findingID := strings.TrimSpace(request.FindingID)
	if findingID == "" {
		return nil, errors.New("finding id is required")
	}
	dueAt := request.DueAt.UTC()
	if dueAt.IsZero() {
		return nil, errors.New("finding due date is required")
	}
	var row findingRow
	if err := scanFindingRow(s.db.QueryRowContext(ctx, `
UPDATE findings
SET due_at = $2, updated_at = NOW()
WHERE id = $1
RETURNING `+findingSelectColumns,
		findingID,
		dueAt,
	), &row); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ports.ErrFindingNotFound
		}
		return nil, fmt.Errorf("update finding %q due date: %w", findingID, err)
	}
	return row.record()
}

// UpdateFindingRisk updates only persisted risk fields for one finding.
func (s *Store) UpdateFindingRisk(ctx context.Context, request ports.FindingRiskUpdate) (*ports.FindingRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return nil, err
	}
	findingID := strings.TrimSpace(request.FindingID)
	if findingID == "" {
		return nil, errors.New("finding id is required")
	}
	record, err := s.updateFindingRiskColumns(ctx, findingID, request.FindingRisk, request.Attributes)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ports.ErrFindingNotFound
		}
		return nil, fmt.Errorf("update finding %q risk: %w", findingID, err)
	}
	return record, nil
}

// MarkFindingRiskProjected marks one finding's current risk model as projected without
// rewriting risk columns if a live request already updated them.
func (s *Store) MarkFindingRiskProjected(ctx context.Context, request ports.FindingRiskUpdate) (*ports.FindingRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return nil, err
	}
	findingID := strings.TrimSpace(request.FindingID)
	if findingID == "" {
		return nil, errors.New("finding id is required")
	}
	attributesJSON, err := findingAttributesJSON(request.Attributes)
	if err != nil {
		return nil, fmt.Errorf("marshal finding risk projection attributes: %w", err)
	}
	var row findingRow
	if err := scanFindingRow(s.db.QueryRowContext(ctx, `
UPDATE findings
SET attributes_json = attributes_json || $2::jsonb,
    updated_at = NOW()
WHERE id = $1
  AND risk_score = $3
  AND likelihood_score = $4
  AND impact_score = $5
  AND confidence_score = $6
  AND likelihood_level = $7
  AND impact_level = $8
  AND risk_model_version = $9
RETURNING `+findingSelectColumns,
		findingID,
		attributesJSON,
		request.RiskScore,
		request.LikelihoodScore,
		request.ImpactScore,
		request.ConfidenceScore,
		strings.TrimSpace(request.LikelihoodLevel),
		strings.TrimSpace(request.ImpactLevel),
		strings.TrimSpace(request.RiskModelVersion),
	), &row); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ports.ErrFindingNotFound
		}
		return nil, fmt.Errorf("mark finding %q risk projected: %w", findingID, err)
	}
	return row.record()
}

// AddFindingNote appends one persisted finding note.
func (s *Store) AddFindingNote(ctx context.Context, request ports.FindingNoteCreate) (*ports.FindingRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return nil, err
	}
	findingID := strings.TrimSpace(request.FindingID)
	if findingID == "" {
		return nil, errors.New("finding id is required")
	}
	notesJSON, err := findingNotesJSON([]ports.FindingNote{request.Note})
	if err != nil {
		return nil, fmt.Errorf("marshal finding note: %w", err)
	}
	if notesJSON == `[]` {
		return nil, errors.New("finding note is required")
	}
	var row findingRow
	if err := scanFindingRow(s.db.QueryRowContext(ctx, `
UPDATE findings
SET notes_json = COALESCE(notes_json, '[]'::jsonb) || $2::jsonb, updated_at = NOW()
WHERE id = $1
RETURNING `+findingSelectColumns,
		findingID,
		notesJSON,
	), &row); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ports.ErrFindingNotFound
		}
		return nil, fmt.Errorf("add note to finding %q: %w", findingID, err)
	}
	return row.record()
}

// LinkFindingTicket appends one persisted finding ticket reference.
func (s *Store) LinkFindingTicket(ctx context.Context, request ports.FindingTicketLink) (*ports.FindingRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return nil, err
	}
	findingID := strings.TrimSpace(request.FindingID)
	if findingID == "" {
		return nil, errors.New("finding id is required")
	}
	ticketsJSON, err := findingTicketsJSON([]ports.FindingTicket{request.Ticket})
	if err != nil {
		return nil, fmt.Errorf("marshal finding ticket: %w", err)
	}
	if ticketsJSON == `[]` {
		return nil, errors.New("finding ticket url is required")
	}
	dedupeJSON, err := findingTicketURLMatchJSON(request.Ticket.URL)
	if err != nil {
		return nil, fmt.Errorf("marshal finding ticket dedupe: %w", err)
	}
	var row findingRow
	if err := scanFindingRow(s.db.QueryRowContext(ctx, `
UPDATE findings
SET tickets_json = CASE
      WHEN COALESCE(tickets_json, '[]'::jsonb) @> $3::jsonb THEN COALESCE(tickets_json, '[]'::jsonb)
      ELSE COALESCE(tickets_json, '[]'::jsonb) || $2::jsonb
    END,
    updated_at = NOW()
WHERE id = $1
RETURNING `+findingSelectColumns,
		findingID,
		ticketsJSON,
		dedupeJSON,
	), &row); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ports.ErrFindingNotFound
		}
		return nil, fmt.Errorf("link ticket to finding %q: %w", findingID, err)
	}
	return row.record()
}

// LinkFindingExternalRef appends or refreshes one external lifecycle reference.
func (s *Store) LinkFindingExternalRef(ctx context.Context, request ports.FindingExternalRefLink) (*ports.FindingRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return nil, err
	}
	findingID := strings.TrimSpace(request.FindingID)
	if findingID == "" {
		return nil, errors.New("finding id is required")
	}
	externalRefsJSON, err := findingExternalRefsJSON([]ports.FindingExternalRef{request.ExternalRef})
	if err != nil {
		return nil, fmt.Errorf("marshal finding external ref: %w", err)
	}
	if externalRefsJSON == `[]` {
		return nil, errors.New("finding external ref system, kind, and external id are required")
	}
	dedupeJSON, err := findingExternalRefMatchJSON(request.ExternalRef)
	if err != nil {
		return nil, fmt.Errorf("marshal finding external ref dedupe: %w", err)
	}
	var row findingRow
	if err := scanFindingRow(s.db.QueryRowContext(ctx, linkFindingExternalRefStatement,
		findingID,
		externalRefsJSON,
		dedupeJSON,
	), &row); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ports.ErrFindingNotFound
		}
		return nil, fmt.Errorf("link external ref to finding %q: %w", findingID, err)
	}
	return row.record()
}

func findingListQuery(request ports.ListFindingsRequest) (string, []any, error) {
	clauses, args, err := findingFilterClauses(request)
	if err != nil {
		return "", nil, err
	}
	query := `
SELECT ` + findingSelectColumns + `
FROM findings
WHERE ` + strings.Join(clauses, " AND ") + `
ORDER BY ` + findingOrderClause(request)
	if limit := findingListLimit(request.Limit); limit > 0 {
		args = append(args, int64(limit))
		query += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	return query, args, nil
}

func findingGRCListQuery(request ports.ListFindingsRequest) (string, []any, error) {
	clauses, args, err := findingFilterClauses(request)
	if err != nil {
		return "", nil, err
	}
	query := `
SELECT id, tenant_id, runtime_id, rule_id, title, ` + findingEffectiveSeveritySQL() + ` AS severity, status, summary,
  risk_score, likelihood_score, impact_score, confidence_score, likelihood_level, impact_level, risk_reasons_json::text, risk_model_version,
  resource_urns_json::text, control_refs_json::text, policy_id, policy_name, assignee, due_at, first_observed_at, last_observed_at
FROM findings
WHERE ` + strings.Join(clauses, " AND ") + `
ORDER BY ` + findingOrderClause(request)
	if limit := findingListLimit(request.Limit); limit > 0 {
		args = append(args, int64(limit))
		query += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	return query, args, nil
}

func findingFilterClauses(request ports.ListFindingsRequest) ([]string, []any, error) {
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		return nil, nil, errors.New("finding tenant id is required")
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	runtimeIDs := normalizedNonEmptyStrings(append(request.RuntimeIDs, runtimeID))
	ruleID := strings.TrimSpace(request.RuleID)
	if len(runtimeIDs) == 0 && ruleID == "" {
		return nil, nil, errors.New("finding runtime id or rule id is required")
	}
	clauses := []string{"tenant_id = $1"}
	args := []any{tenantID}
	addStringInFilter(&clauses, &args, "runtime_id", runtimeIDs)
	addFindingFilter(&clauses, &args, "id", request.FindingID)
	addFindingFilter(&clauses, &args, "rule_id", request.RuleID)
	addFindingSeverityFilter(&clauses, &args, request.Severity)
	addFindingFilter(&clauses, &args, "status", request.Status)
	addFindingFilter(&clauses, &args, "policy_id", request.PolicyID)
	if !request.LastObservedBefore.IsZero() {
		args = append(args, request.LastObservedBefore.UTC())
		clauses = append(clauses, fmt.Sprintf("last_observed_at < $%d", len(args)))
	}
	if err := addFindingArrayContainsFilter(&clauses, &args, "resource_urns_json", request.ResourceURN); err != nil {
		return nil, nil, err
	}
	if err := addFindingArrayContainsFilter(&clauses, &args, "event_ids_json", request.EventID); err != nil {
		return nil, nil, err
	}
	return clauses, args, nil
}

func findingListLimit(limit uint32) uint32 {
	if limit > maxFindingListLimit {
		return maxFindingListLimit
	}
	return limit
}

// SupportsTombstones reports whether the tombstone schema has been applied to the
// findings table. Callers (notably the closeout subcommand) use this as a guard so
// they can refuse to run against a database that predates the M1 schema migration
// without requiring the full ensureFindingTables side-effect chain.
func (s *Store) SupportsTombstones(ctx context.Context) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("postgres is not configured")
	}
	var exists bool
	if err := s.db.QueryRowContext(ctx, `
        SELECT EXISTS (
            SELECT 1 FROM information_schema.columns
             WHERE table_name = 'findings' AND column_name = 'tombstoned'
        )`).Scan(&exists); err != nil {
		return false, fmt.Errorf("check tombstone support: %w", err)
	}
	return exists, nil
}

func (s *Store) ensureFindingTables(ctx context.Context) error {
	s.schemaMu.Lock()
	defer s.schemaMu.Unlock()
	if s.findingTablesReady {
		return nil
	}
	for _, statement := range ensureFindingStatements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("ensure findings tables: %w", err)
		}
	}
	if err := s.backfillTenantScopedFindingFingerprints(ctx); err != nil {
		return err
	}
	s.findingTablesReady = true
	return nil
}

func (s *Store) backfillTenantScopedFindingFingerprints(ctx context.Context) error {
	ruleIDs := tenantScopedFingerprintBackfillRuleIDs()
	if len(ruleIDs) == 0 {
		return nil
	}
	placeholders := make([]string, 0, len(ruleIDs))
	args := make([]any, 0, len(ruleIDs))
	for _, ruleID := range ruleIDs {
		args = append(args, ruleID)
		placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)))
	}
	query := fmt.Sprintf(`
SELECT id, tenant_id, rule_id, fingerprint, attributes_json, resource_urns_json, status, created_at, updated_at
FROM findings
WHERE tombstoned = FALSE
  AND rule_id IN (%s)
ORDER BY tenant_id, rule_id, id
FOR UPDATE`, strings.Join(placeholders, ", "))
	const maxAttempts = 4
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := s.backfillTenantScopedFindingFingerprintsOnce(ctx, query, args); err != nil {
			lastErr = err
			if errors.Is(err, errTenantScopedFingerprintBackfillRetry) || isPartialUniqueIndexConflict(err) {
				continue
			}
			return err
		}
		return nil
	}
	if lastErr != nil {
		return lastErr
	}
	return nil
}

func (s *Store) backfillTenantScopedFindingFingerprintsOnce(ctx context.Context, query string, args []any) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tenant-scoped fingerprint backfill: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	groups, err := loadTenantScopedFingerprintBackfillGroups(ctx, tx, query, args)
	if err != nil {
		return err
	}

	keys := make([]tenantScopedFingerprintBackfillGroupKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].tenantID != keys[j].tenantID {
			return keys[i].tenantID < keys[j].tenantID
		}
		return keys[i].fingerprint < keys[j].fingerprint
	})
	for _, key := range keys {
		rows := groups[key]
		if len(rows) == 0 {
			continue
		}
		if len(rows) == 1 {
			if err := updateTenantScopedBackfillWinnerFingerprint(ctx, tx, rows[0], key.fingerprint); err != nil {
				return err
			}
			continue
		}
		sort.SliceStable(rows, func(i, j int) bool {
			return tenantScopedBackfillRowWins(rows[i], rows[j])
		})
		winner := rows[0]
		now := time.Now().UTC()
		for _, loser := range rows[1:] {
			if err := tombstoneTenantScopedBackfillCollisionLoser(ctx, tx, loser, now); err != nil {
				return err
			}
		}
		if err := updateTenantScopedBackfillWinnerFingerprint(ctx, tx, winner, key.fingerprint); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tenant-scoped fingerprint backfill: %w", err)
	}
	committed = true
	return nil
}

type tenantScopedFingerprintBackfillGroupKey struct {
	tenantID    string
	fingerprint string
}

type tenantScopedFingerprintBackfillRow struct {
	id                 string
	tenantID           string
	ruleID             string
	currentFingerprint string
	newFingerprint     string
	status             string
	attributes         map[string]string
	resourceURNs       []string
	createdAt          time.Time
	updatedAt          time.Time
}

type tenantScopedBackfillQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func loadTenantScopedFingerprintBackfillGroups(ctx context.Context, querier tenantScopedBackfillQuerier, query string, args []any) (map[tenantScopedFingerprintBackfillGroupKey][]tenantScopedFingerprintBackfillRow, error) {
	rows, err := querier.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list tenant-scoped fingerprint backfill rows: %w", err)
	}
	defer func() { _ = rows.Close() }()
	groups := map[tenantScopedFingerprintBackfillGroupKey][]tenantScopedFingerprintBackfillRow{}
	for rows.Next() {
		var row tenantScopedFingerprintBackfillRow
		var rawAttributes []byte
		var rawResourceURNs []byte
		if err := rows.Scan(
			&row.id,
			&row.tenantID,
			&row.ruleID,
			&row.currentFingerprint,
			&rawAttributes,
			&rawResourceURNs,
			&row.status,
			&row.createdAt,
			&row.updatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan tenant-scoped fingerprint backfill row: %w", err)
		}
		attributes, err := decodeTenantScopedBackfillAttributes(rawAttributes)
		if err != nil {
			return nil, fmt.Errorf("decode tenant-scoped fingerprint backfill attributes for %q: %w", strings.TrimSpace(row.id), err)
		}
		resourceURNs, err := decodeTenantScopedBackfillResourceURNs(rawResourceURNs)
		if err != nil {
			return nil, fmt.Errorf("decode tenant-scoped fingerprint backfill resource urns for %q: %w", strings.TrimSpace(row.id), err)
		}
		row.id = strings.TrimSpace(row.id)
		row.tenantID = strings.TrimSpace(row.tenantID)
		row.ruleID = strings.TrimSpace(row.ruleID)
		row.currentFingerprint = strings.TrimSpace(row.currentFingerprint)
		row.status = strings.TrimSpace(row.status)
		row.attributes = attributes
		row.resourceURNs = resourceURNs
		row.createdAt = row.createdAt.UTC()
		row.updatedAt = row.updatedAt.UTC()
		row.newFingerprint = tenantScopedFingerprintBackfill(row.ruleID, row.tenantID, row.attributes)
		if row.id == "" || row.tenantID == "" || row.newFingerprint == "" {
			continue
		}
		key := tenantScopedFingerprintBackfillGroupKey{tenantID: row.tenantID, fingerprint: row.newFingerprint}
		groups[key] = append(groups[key], row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenant-scoped fingerprint backfill rows: %w", err)
	}
	return groups, nil
}

func decodeTenantScopedBackfillAttributes(raw []byte) (map[string]string, error) {
	attributes := map[string]string{}
	if len(raw) == 0 {
		return attributes, nil
	}
	if err := json.Unmarshal(raw, &attributes); err != nil {
		return nil, err
	}
	return attributes, nil
}

func decodeTenantScopedBackfillResourceURNs(raw []byte) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	resourceURNs := []string{}
	if err := json.Unmarshal(raw, &resourceURNs); err != nil {
		return nil, err
	}
	return normalizedNonEmptyStrings(resourceURNs), nil
}

func tenantScopedBackfillRowWins(a tenantScopedFingerprintBackfillRow, b tenantScopedFingerprintBackfillRow) bool {
	if !a.updatedAt.Equal(b.updatedAt) {
		return a.updatedAt.After(b.updatedAt)
	}
	if !a.createdAt.Equal(b.createdAt) {
		return a.createdAt.After(b.createdAt)
	}
	return strings.TrimSpace(a.id) < strings.TrimSpace(b.id)
}

func updateTenantScopedBackfillWinnerFingerprint(ctx context.Context, tx *sql.Tx, row tenantScopedFingerprintBackfillRow, fingerprint string) error {
	id := strings.TrimSpace(row.id)
	fingerprint = strings.TrimSpace(fingerprint)
	if id == "" || fingerprint == "" || strings.TrimSpace(row.currentFingerprint) == fingerprint {
		return nil
	}
	result, err := tx.ExecContext(ctx,
		`UPDATE findings SET fingerprint = $2, updated_at = NOW() WHERE id = $1 AND tombstoned = FALSE`,
		id,
		fingerprint,
	)
	if err != nil {
		return fmt.Errorf("backfill tenant-scoped fingerprint for finding %q: %w", id, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("backfill tenant-scoped fingerprint for finding %q rowsAffected: %w", id, err)
	}
	if affected == 0 {
		return fmt.Errorf("backfill tenant-scoped fingerprint for finding %q: %w", id, errTenantScopedFingerprintBackfillRetry)
	}
	return nil
}

func tombstoneTenantScopedBackfillCollisionLoser(ctx context.Context, tx *sql.Tx, row tenantScopedFingerprintBackfillRow, tombstonedAt time.Time) error {
	id := strings.TrimSpace(row.id)
	if id == "" {
		return nil
	}
	reason := string(findingStatusReasonBackfillCollision)
	tombstonedAt = tombstonedAt.UTC()
	if tombstonedAt.IsZero() {
		tombstonedAt = time.Now().UTC()
	}
	priorStatus := strings.TrimSpace(row.status)
	if priorStatus == "" {
		priorStatus = "open"
	}
	updated, err := tombstoneFindingStatusInTx(ctx, tx, ports.FindingStatusUpdate{
		FindingID: id,
		Status:    "resolved",
		Reason:    reason,
		UpdatedAt: tombstonedAt,
		Tombstone: &ports.FindingTombstoneApply{
			By:           tenantScopedFingerprintBackfillActor,
			Reason:       reason,
			RunID:        tenantScopedFingerprintBackfillRunID,
			PriorStatus:  priorStatus,
			TombstonedAt: tombstonedAt,
		},
	})
	if err != nil {
		return fmt.Errorf("tombstone tenant-scoped fingerprint backfill collision finding %q: %w", id, err)
	}
	anchorURI := tenantScopedBackfillAnchorURI(row.resourceURNs, row.attributes)
	if anchorURI == "" && updated != nil {
		anchorURI = tenantScopedBackfillAnchorURI(updated.ResourceURNs, updated.Attributes)
	}
	if err := insertFindingTombstoneEvent(ctx, tx, ports.FindingTombstoneEvent{
		FindingID:    id,
		TenantID:     strings.TrimSpace(row.tenantID),
		RuleID:       strings.TrimSpace(row.ruleID),
		AnchorURI:    anchorURI,
		PriorStatus:  priorStatus,
		Reason:       reason,
		Actor:        tenantScopedFingerprintBackfillActor,
		RunID:        tenantScopedFingerprintBackfillRunID,
		TombstonedAt: tombstonedAt,
	}); err != nil {
		return fmt.Errorf("audit tenant-scoped fingerprint backfill collision finding %q: %w", id, err)
	}
	return nil
}

func tenantScopedBackfillAnchorURI(resourceURNs []string, attributes map[string]string) string {
	for _, urn := range resourceURNs {
		if trimmed := strings.TrimSpace(urn); trimmed != "" {
			return trimmed
		}
	}
	if attributes == nil {
		return ""
	}
	return firstNonEmptyPostgres(
		attributes["primary_resource_urn"],
		attributes["resource_urn"],
		attributes["resource_id"],
		attributes["user_urn"],
		attributes["group_urn"],
	)
}

func tenantScopedFingerprintBackfillRuleIDs() []string {
	rules := make([]string, 0, len(tenantScopedFingerprintBackfillRules))
	for ruleID := range tenantScopedFingerprintBackfillRules {
		rules = append(rules, ruleID)
	}
	sort.Strings(rules)
	return rules
}

var tenantScopedFingerprintBackfillRules = map[string]func(string, map[string]string) []string{
	"github-repository-collaborator-added":       tenantScopedBackfillFields("repo", "user"),
	"github-organization-owner-added":            tenantScopedBackfillFields("org", "user"),
	"github-app-integration-installed":           tenantScopedBackfillFields("org", "github_app_id"),
	"github-personal-access-token-created":       tenantScopedBackfillFields("user_id", "token_id"),
	"github-repository-ruleset-modified":         tenantScopedBackfillFields("repo", "ruleset_id"),
	"github-webhook-modified":                    tenantScopedBackfillFields("repo", "hook_id"),
	"github-secret-scanning-alert-created":       tenantScopedBackfillFields("repo", "number"),
	"github-dependabot-open-alert":               tenantScopedBackfillFields("repository", "alert_number"),
	"github-code-security-controls-disabled":     tenantScopedBackfillGitHubScopedPosture,
	"github-org-auth-control-modified":           tenantScopedBackfillFields("org"),
	"github-org-ip-allow-list-modified":          tenantScopedBackfillFields("org"),
	"github-private-repository-forking-enabled":  tenantScopedBackfillPrivateRepositoryForking,
	"github-self-hosted-runner-change":           tenantScopedBackfillSelfHostedRunner,
	"sentinelone-protection-control-tampering":   tenantScopedBackfillSentinelOneProtectionControl,
	"identity-privileged-account-without-mfa":    tenantScopedBackfillIdentityUser,
	"identity-mfa-factor-reset-or-disabled":      tenantScopedBackfillIdentityUser,
	"identity-stale-privileged-account":          tenantScopedBackfillIdentityUser,
	"identity-admin-privilege-granted":           tenantScopedBackfillIdentityAdminPrivilege,
	"identity-auth-control-lifecycle-tampering":  tenantScopedBackfillIdentityAuthControl,
	"identity-api-token-or-oauth-app-created":    tenantScopedBackfillIdentityAPITokenOrOAuth,
	"identity-external-or-personal-group-member": tenantScopedBackfillIdentityExternalGroupMember,
}

func tenantScopedFingerprintBackfill(ruleID string, tenantID string, attributes map[string]string) string {
	builder := tenantScopedFingerprintBackfillRules[strings.TrimSpace(ruleID)]
	if builder == nil {
		return ""
	}
	inputs := builder(strings.TrimSpace(tenantID), attributes)
	if len(inputs) == 0 {
		return ""
	}
	parts := append([]string{strings.TrimSpace(ruleID), strings.TrimSpace(tenantID)}, inputs...)
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			return ""
		}
	}
	return tenantScopedFindingFingerprint(parts...)
}

func tenantScopedBackfillFields(fields ...string) func(string, map[string]string) []string {
	return func(_ string, attributes map[string]string) []string {
		inputs := make([]string, 0, len(fields))
		for _, field := range fields {
			inputs = append(inputs, tenantScopedBackfillAttribute(attributes, field))
		}
		return inputs
	}
}

func tenantScopedBackfillAttribute(attributes map[string]string, field string) string {
	field = strings.TrimSpace(field)
	if field == "" {
		return ""
	}
	if value := strings.TrimSpace(attributes[field]); value != "" {
		return value
	}
	switch field {
	case "repo":
		return strings.TrimSpace(attributes["repository"])
	case "repository":
		return strings.TrimSpace(attributes["repo"])
	case "org":
		return firstNonEmptyPostgres(attributes["organization"], attributes["resource_id"])
	case "hook_id":
		return firstNonEmptyPostgres(attributes["hook_id"], attributes["id"])
	case "ruleset_id":
		return firstNonEmptyPostgres(attributes["ruleset_id"], attributes["resource_id"])
	}
	return ""
}

func tenantScopedBackfillGitHubScopedPosture(_ string, attributes map[string]string) []string {
	if repo := firstNonEmptyPostgres(attributes["repo"], attributes["repository"]); strings.TrimSpace(repo) != "" {
		return []string{repo}
	}
	if org := firstNonEmptyPostgres(attributes["org"], attributes["organization"], attributes["resource_id"]); strings.TrimSpace(org) != "" && !strings.Contains(org, "/") {
		return []string{org}
	}
	return nil
}

func tenantScopedBackfillPrivateRepositoryForking(_ string, attributes map[string]string) []string {
	if repo := firstNonEmptyPostgres(attributes["repo"], attributes["repository"]); strings.TrimSpace(repo) != "" {
		return []string{repo}
	}
	resourceID := strings.TrimSpace(attributes["resource_id"])
	if strings.Contains(resourceID, "/") {
		return []string{resourceID}
	}
	if org := firstNonEmptyPostgres(attributes["org"], resourceID); strings.TrimSpace(org) != "" && !strings.Contains(org, "/") {
		return []string{org}
	}
	return nil
}

func tenantScopedBackfillSelfHostedRunner(_ string, attributes map[string]string) []string {
	scopeID := strings.TrimSpace(firstNonEmptyPostgres(attributes["runner_scope"], attributes["scope"]))
	if scopeID == "" {
		if repo := firstNonEmptyPostgres(attributes["repo"], attributes["repository"]); strings.TrimSpace(repo) != "" {
			scopeID = "repo:" + strings.TrimSpace(repo)
		} else if org := strings.TrimSpace(attributes["org"]); org != "" {
			scopeID = "org:" + org
		} else if enterprise := firstNonEmptyPostgres(attributes["enterprise"], attributes["enterprise_slug"], attributes["enterprise_id"]); strings.TrimSpace(enterprise) != "" {
			scopeID = "enterprise:" + strings.TrimSpace(enterprise)
		} else if resourceID := strings.TrimSpace(attributes["resource_id"]); resourceID != "" {
			if strings.Contains(resourceID, "/") {
				scopeID = "repo:" + resourceID
			} else {
				scopeID = "org:" + resourceID
			}
		}
	}
	return []string{scopeID, strings.TrimSpace(attributes["runner_id"])}
}

func tenantScopedBackfillSentinelOneProtectionControl(_ string, attributes map[string]string) []string {
	return []string{
		strings.TrimSpace(attributes["agent_id"]),
		tenantScopedBackfillSentinelOneProtectionControlType(attributes),
	}
}

func tenantScopedBackfillSentinelOneProtectionControlType(attributes map[string]string) string {
	if controlType := firstNonEmptyPostgres(attributes["control_type"], attributes["protection_control"], attributes["control_name"], attributes["control"]); strings.TrimSpace(controlType) != "" {
		return strings.ToLower(strings.TrimSpace(controlType))
	}
	if _, exists := attributes["firewall_enabled"]; exists {
		return "firewall"
	}
	return ""
}

func tenantScopedBackfillIdentityUser(tenantID string, attributes map[string]string) []string {
	return []string{tenantScopedBackfillIdentityUserURN(tenantID, attributes)}
}

func tenantScopedBackfillIdentityAdminPrivilege(tenantID string, attributes map[string]string) []string {
	return []string{
		tenantScopedBackfillIdentityUserURN(tenantID, attributes),
		firstNonEmptyPostgres(attributes["role"], attributes["role_name"], attributes["role_id"], attributes["resource_id"]),
	}
}

func tenantScopedBackfillIdentityAuthControl(_ string, attributes map[string]string) []string {
	return []string{firstNonEmptyPostgres(attributes["policy_id"], attributes["idp_id"], attributes["primary_resource_urn"], attributes["resource_id"])}
}

func tenantScopedBackfillIdentityAPITokenOrOAuth(tenantID string, attributes map[string]string) []string {
	if credentialID := firstNonEmptyPostgres(attributes["credential_id"], attributes["access_key_id"], attributes["key_id"], attributes["secret_id"], attributes["token_id"]); credentialID != "" {
		return []string{firstNonEmptyPostgres(tenantScopedBackfillIdentityUserURN(tenantID, attributes), attributes["user"]), credentialID}
	}
	if oauthAppID := firstNonEmptyPostgres(attributes["oauth_app_id"], attributes["client_id"], attributes["app_id"]); oauthAppID != "" {
		return []string{firstNonEmptyPostgres(attributes["org"], attributes["domain"], attributes["organization"]), oauthAppID}
	}
	return nil
}

func tenantScopedBackfillIdentityExternalGroupMember(_ string, attributes map[string]string) []string {
	return []string{
		firstNonEmptyPostgres(attributes["group_urn"], attributes["primary_resource_urn"], attributes["group_id"], attributes["group_name"]),
		firstNonEmptyPostgres(attributes["member_email"], attributes["member_user_id"], attributes["member_id"]),
	}
}

func tenantScopedBackfillIdentityUserURN(tenantID string, attributes map[string]string) string {
	if urn := firstNonEmptyPostgres(
		attributes["user_urn"],
		tenantScopedProjectionUserURN(attributes["primary_resource_urn"]),
		tenantScopedProjectionUserURN(attributes["primary_actor_urn"]),
	); urn != "" {
		return urn
	}
	sourceID := firstNonEmptyPostgres(attributes["source_id"], attributes["source_family"])
	userID := firstNonEmptyPostgres(
		attributes["user_id"],
		attributes["subject_id"],
		attributes["member_user_id"],
		attributes["member_id"],
		attributes["actor_id"],
		attributes["resource_id"],
		attributes["user"],
		attributes["email"],
		attributes["primary_email"],
		attributes["subject_email"],
		attributes["login"],
	)
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(sourceID) == "" || strings.TrimSpace(userID) == "" {
		return ""
	}
	return tenantScopedBackfillIdentityProjectionURN(tenantID, strings.TrimSpace(sourceID)+"_user", userID)
}

// tenantScopedBackfillIdentityProjectionURN intentionally mirrors
// internal/findings.identityProjectionURN so backfilled legacy fingerprints use
// the same synthetic identity URN that runtime rule evaluation later produces.
func tenantScopedBackfillIdentityProjectionURN(tenantID string, kind string, parts ...string) string {
	tenant := strings.TrimSpace(tenantID)
	entityKind := strings.TrimSpace(kind)
	if tenant == "" || entityKind == "" {
		return ""
	}
	values := []string{"urn", "cerebro", tenant, entityKind}
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		values = append(values, value)
	}
	return strings.Join(values, ":")
}

func tenantScopedProjectionUserURN(urn string) string {
	urn = strings.TrimSpace(urn)
	if urn == "" {
		return ""
	}
	normalized := strings.ToLower(urn)
	if strings.Contains(normalized, "_user:") ||
		strings.Contains(normalized, ".user:") ||
		strings.Contains(normalized, "_principal:") ||
		strings.Contains(normalized, "_service_account:") ||
		strings.Contains(normalized, "_service_principal:") {
		return urn
	}
	return ""
}

func tenantScopedFindingFingerprint(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte(strings.TrimSpace(part)))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func firstNonEmptyPostgres(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// BackfillFindingRisk updates existing findings with the current risk model.
func (s *Store) BackfillFindingRisk(ctx context.Context, includeUnprojected bool) ([]*ports.FindingRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return nil, err
	}
	return s.backfillFindingRisk(ctx, includeUnprojected)
}

func (s *Store) backfillFindingRisk(ctx context.Context, includeUnprojected bool) (updated []*ports.FindingRecord, err error) {
	query := `SELECT ` + findingSelectColumns + ` FROM findings WHERE risk_model_version <> $1 OR risk_score = 0`
	if includeUnprojected {
		// #nosec G202 -- attribute key is a compile-time constant, not request input.
		query += ` OR COALESCE(attributes_json->>'` + findingrisk.FindingRiskGraphProjectedModelVersionAttribute + `', '') <> $1`
	}
	rows, err := s.db.QueryContext(ctx, query, findingrisk.FindingRiskModelVersion)
	if err != nil {
		return nil, fmt.Errorf("list findings for risk backfill: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close finding risk backfill rows: %w", closeErr)
		}
	}()
	type riskBackfill struct {
		id             string
		risk           ports.FindingRisk
		sourceSeverity string
		staleRisk      bool
		record         *ports.FindingRecord
	}
	now := time.Now().UTC()
	updates := []riskBackfill{}
	for rows.Next() {
		var row findingRow
		if err := scanFindingRow(rows, &row); err != nil {
			return nil, fmt.Errorf("scan finding risk backfill row: %w", err)
		}
		record, err := row.record()
		if err != nil {
			return nil, fmt.Errorf("decode finding risk backfill row: %w", err)
		}
		sourceSeverity := strings.TrimSpace(record.Attributes[findingrisk.FindingSourceSeverityAttribute])
		if sourceSeverity == "" {
			sourceSeverity = strings.TrimSpace(row.Severity)
		}
		if sourceSeverity != "" {
			record.Attributes[findingrisk.FindingSourceSeverityAttribute] = sourceSeverity
		}
		updates = append(updates, riskBackfill{
			id:             strings.TrimSpace(record.ID),
			risk:           findingBackfillRisk(record, now),
			sourceSeverity: sourceSeverity,
			staleRisk:      strings.TrimSpace(record.RiskModelVersion) != findingrisk.FindingRiskModelVersion || record.RiskScore == 0,
			record:         record,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate finding risk backfill rows: %w", err)
	}
	for _, update := range updates {
		if update.id == "" {
			continue
		}
		if !update.staleRisk {
			updated = append(updated, update.record)
			continue
		}
		stored, updateErr := s.updateFindingRiskColumnsIfStale(ctx, update.id, update.risk, findingRiskAttributesForUpdate(update.risk, update.sourceSeverity))
		if updateErr != nil {
			if errors.Is(updateErr, sql.ErrNoRows) {
				continue
			}
			return nil, fmt.Errorf("backfill finding %q risk: %w", update.id, updateErr)
		}
		updated = append(updated, stored)
	}
	return updated, nil
}

func (s *Store) updateFindingRiskColumns(ctx context.Context, findingID string, risk ports.FindingRisk, attributes map[string]string) (*ports.FindingRecord, error) {
	return s.updateFindingRiskColumnsWhere(ctx, findingID, risk, attributes, "")
}

func (s *Store) updateFindingRiskColumnsIfStale(ctx context.Context, findingID string, risk ports.FindingRisk, attributes map[string]string) (*ports.FindingRecord, error) {
	return s.updateFindingRiskColumnsWhere(ctx, findingID, risk, attributes, " AND (risk_model_version <> $9 OR risk_score = 0)")
}

func (s *Store) updateFindingRiskColumnsWhere(ctx context.Context, findingID string, risk ports.FindingRisk, attributes map[string]string, whereSuffix string) (*ports.FindingRecord, error) {
	reasonsJSON, err := findingStringsJSON(risk.RiskReasons)
	if err != nil {
		return nil, fmt.Errorf("marshal finding risk reasons: %w", err)
	}
	attributesJSON, err := findingAttributesJSON(attributes)
	if err != nil {
		return nil, fmt.Errorf("marshal finding risk attributes: %w", err)
	}
	var row findingRow
	if err := scanFindingRow(s.db.QueryRowContext(ctx, `
UPDATE findings
SET risk_score = $2,
    likelihood_score = $3,
    impact_score = $4,
    confidence_score = $5,
    likelihood_level = $6,
    impact_level = $7,
    risk_reasons_json = $8::jsonb,
    risk_model_version = $9,
    attributes_json = attributes_json || $10::jsonb,
    updated_at = NOW()
WHERE id = $1`+whereSuffix+`
RETURNING `+findingSelectColumns,
		strings.TrimSpace(findingID),
		risk.RiskScore,
		risk.LikelihoodScore,
		risk.ImpactScore,
		risk.ConfidenceScore,
		strings.TrimSpace(risk.LikelihoodLevel),
		strings.TrimSpace(risk.ImpactLevel),
		reasonsJSON,
		strings.TrimSpace(risk.RiskModelVersion),
		attributesJSON,
	), &row); err != nil {
		return nil, err
	}
	return row.record()
}

func findingBackfillRisk(record *ports.FindingRecord, now time.Time) ports.FindingRisk {
	risk := findingrisk.AnalyzeFindingRiskContext(record, now)
	return ports.FindingRisk{
		RiskScore:        risk.Score,
		LikelihoodScore:  risk.LikelihoodScore,
		ImpactScore:      risk.ImpactScore,
		ConfidenceScore:  risk.ConfidenceScore,
		LikelihoodLevel:  risk.LikelihoodLevel,
		ImpactLevel:      risk.ImpactLevel,
		RiskReasons:      risk.Reasons,
		RiskFactors:      risk.Factors,
		RiskModelVersion: risk.RiskModelVersion,
	}
}

func findingRiskAttributesForUpdate(risk ports.FindingRisk, sourceSeverity string) map[string]string {
	attributes := map[string]string{}
	attributes["risk_score"] = strconv.Itoa(risk.RiskScore)
	attributes[findingrisk.FindingEffectiveSeverityAttribute] = findingrisk.EffectiveSeverityFromRiskScore(risk.RiskScore)
	attributes[findingrisk.FindingSourceSeverityAttribute] = strings.ToUpper(strings.TrimSpace(sourceSeverity))
	attributes["likelihood_score"] = strconv.Itoa(risk.LikelihoodScore)
	attributes["impact_score"] = strconv.Itoa(risk.ImpactScore)
	attributes["confidence_score"] = strconv.Itoa(risk.ConfidenceScore)
	attributes["likelihood_level"] = strings.TrimSpace(risk.LikelihoodLevel)
	attributes["impact_level"] = strings.TrimSpace(risk.ImpactLevel)
	attributes["risk_model_version"] = strings.TrimSpace(risk.RiskModelVersion)
	attributes["risk_reasons"] = strings.Join(risk.RiskReasons, ",")
	if factorsJSON := findingrisk.RiskFactorsJSON(risk.RiskFactors); factorsJSON != "" {
		attributes[findingrisk.FindingRiskFactorsAttribute] = factorsJSON
	}
	return attributes
}

func findingOrderClause(request ports.ListFindingsRequest) string {
	switch {
	case request.Order == ports.FindingOrderRiskScore:
		return `risk_score DESC, ` + findingSeverityRankSQL(findingEffectiveSeveritySQL()) + `, last_observed_at DESC, id`
	case request.Order == ports.FindingOrderPriority || request.PriorityOrder:
		return findingSeverityRankSQL(findingEffectiveSeveritySQL()) + `, last_observed_at DESC, id`
	default:
		return "last_observed_at DESC, id"
	}
}

func findingEffectiveSeveritySQL() string {
	return `UPPER(COALESCE(NULLIF(attributes_json->>'` + findingrisk.FindingEffectiveSeverityAttribute + `', ''), severity))`
}

func findingSeverityRankSQL(expression string) string {
	return `CASE ` + expression + `
  WHEN 'CRITICAL' THEN 0
  WHEN 'HIGH' THEN 1
  WHEN 'MEDIUM' THEN 2
  WHEN 'LOW' THEN 3
  WHEN 'INFO' THEN 4
  ELSE 5
END`
}

func findingStringsJSON(values []string) (string, error) {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			normalized = append(normalized, trimmed)
		}
	}
	if len(normalized) == 0 {
		return `[]`, nil
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func findingAttributesJSON(attributes map[string]string) (string, error) {
	if len(attributes) == 0 {
		return `{}`, nil
	}
	payload, err := json.Marshal(attributes)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func findingControlRefsJSON(values []ports.FindingControlRef) (string, error) {
	normalized := make([]ports.FindingControlRef, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		frameworkName := strings.TrimSpace(value.FrameworkName)
		controlID := strings.TrimSpace(value.ControlID)
		if frameworkName == "" || controlID == "" {
			continue
		}
		key := frameworkName + "|" + controlID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, ports.FindingControlRef{
			FrameworkName: frameworkName,
			ControlID:     controlID,
		})
	}
	if len(normalized) == 0 {
		return `[]`, nil
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func findingNotesJSON(values []ports.FindingNote) (string, error) {
	normalized := make([]ports.FindingNote, 0, len(values))
	for _, value := range values {
		id := strings.TrimSpace(value.ID)
		body := strings.TrimSpace(value.Body)
		if body == "" {
			continue
		}
		createdAt := value.CreatedAt.UTC()
		if createdAt.IsZero() {
			continue
		}
		normalized = append(normalized, ports.FindingNote{
			ID:        id,
			Body:      body,
			CreatedAt: createdAt,
		})
	}
	if len(normalized) == 0 {
		return `[]`, nil
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func findingTicketsJSON(values []ports.FindingTicket) (string, error) {
	normalized := make([]ports.FindingTicket, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		url := strings.TrimSpace(value.URL)
		if url == "" {
			continue
		}
		if _, ok := seen[url]; ok {
			continue
		}
		seen[url] = struct{}{}
		linkedAt := value.LinkedAt.UTC()
		if linkedAt.IsZero() {
			continue
		}
		normalized = append(normalized, ports.FindingTicket{
			URL:        url,
			Name:       strings.TrimSpace(value.Name),
			ExternalID: strings.TrimSpace(value.ExternalID),
			LinkedAt:   linkedAt,
		})
	}
	if len(normalized) == 0 {
		return `[]`, nil
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func findingTicketURLMatchJSON(value string) (string, error) {
	url := strings.TrimSpace(value)
	if url == "" {
		return `[]`, nil
	}
	payload, err := json.Marshal([]map[string]string{{"url": url}})
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func findingExternalRefsJSON(values []ports.FindingExternalRef) (string, error) {
	normalized := make([]ports.FindingExternalRef, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		system := strings.TrimSpace(value.System)
		kind := strings.TrimSpace(value.Kind)
		externalID := strings.TrimSpace(value.ExternalID)
		if system == "" || kind == "" || externalID == "" {
			continue
		}
		key := system + "|" + kind + "|" + externalID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		observedAt := value.ObservedAt.UTC()
		if observedAt.IsZero() {
			continue
		}
		normalized = append(normalized, ports.FindingExternalRef{
			System:               system,
			Kind:                 kind,
			ExternalID:           externalID,
			URL:                  strings.TrimSpace(value.URL),
			ExternalStatus:       strings.TrimSpace(value.ExternalStatus),
			ExternalStatusReason: strings.TrimSpace(value.ExternalStatusReason),
			LifecycleOwner:       strings.TrimSpace(value.LifecycleOwner),
			ObservedAt:           observedAt,
		})
	}
	if len(normalized) == 0 {
		return `[]`, nil
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func findingExternalRefMatchJSON(value ports.FindingExternalRef) (string, error) {
	system := strings.TrimSpace(value.System)
	kind := strings.TrimSpace(value.Kind)
	externalID := strings.TrimSpace(value.ExternalID)
	if system == "" || kind == "" || externalID == "" {
		return `[]`, nil
	}
	payload, err := json.Marshal([]map[string]string{{
		"system":      system,
		"kind":        kind,
		"external_id": externalID,
	}})
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func addFindingFilter(clauses *[]string, args *[]any, column string, value string) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return
	}
	*args = append(*args, trimmed)
	*clauses = append(*clauses, fmt.Sprintf("%s = $%d", column, len(*args)))
}

func addFindingSeverityFilter(clauses *[]string, args *[]any, value string) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return
	}
	*args = append(*args, strings.ToUpper(trimmed))
	*clauses = append(*clauses, fmt.Sprintf("%s = $%d", findingEffectiveSeveritySQL(), len(*args)))
}

func addFindingArrayContainsFilter(clauses *[]string, args *[]any, column string, value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	payload, err := findingStringsJSON([]string{trimmed})
	if err != nil {
		return fmt.Errorf("marshal %s filter: %w", column, err)
	}
	*args = append(*args, payload)
	*clauses = append(*clauses, fmt.Sprintf("%s @> $%d::jsonb", column, len(*args)))
	return nil
}

type findingWorkflowRow struct {
	NotesJSON        string
	TicketsJSON      string
	ExternalRefsJSON string
	Assignee         string
	DueAt            sql.NullTime
	StatusReason     string
	StatusUpdatedAt  sql.NullTime
}

type findingRowScanner interface {
	Scan(dest ...any) error
}

type findingRiskRow struct {
	RiskScore        int
	LikelihoodScore  int
	ImpactScore      int
	ConfidenceScore  int
	LikelihoodLevel  string
	ImpactLevel      string
	RiskReasonsJSON  string
	RiskModelVersion string
}

type findingTombstoneRow struct {
	Tombstoned          bool
	TombstonedAt        sql.NullTime
	TombstonedBy        string
	TombstonedReason    string
	TombstonedRunID     string
	PriorStatus         string
	TombstoneGeneration int
}

type findingRow struct {
	ID          string
	Fingerprint string
	TenantID    string
	RuntimeID   string
	RuleID      string
	Title       string
	Severity    string
	Status      string
	Summary     string
	findingRiskRow
	ResourceURNsJSON      string
	EventIDsJSON          string
	ObservedPolicyIDsJSON string
	ControlRefsJSON       string
	PolicyID              string
	PolicyName            string
	CheckID               string
	CheckName             string
	AttributesJSON        string
	findingWorkflowRow
	FirstObservedAt time.Time
	LastObservedAt  time.Time
	findingTombstoneRow
}

type grcFindingRow struct {
	ID        string
	TenantID  string
	RuntimeID string
	RuleID    string
	Title     string
	Severity  string
	Status    string
	Summary   string
	findingRiskRow
	ResourceURNsJSON string
	ControlRefsJSON  string
	PolicyID         string
	PolicyName       string
	Assignee         string
	DueAt            sql.NullTime
	FirstObservedAt  time.Time
	LastObservedAt   time.Time
}

func scanFindingRow(scanner findingRowScanner, row *findingRow) error {
	return scanner.Scan(
		&row.ID,
		&row.Fingerprint,
		&row.TenantID,
		&row.RuntimeID,
		&row.RuleID,
		&row.Title,
		&row.Severity,
		&row.Status,
		&row.Summary,
		&row.RiskScore,
		&row.LikelihoodScore,
		&row.ImpactScore,
		&row.ConfidenceScore,
		&row.LikelihoodLevel,
		&row.ImpactLevel,
		&row.RiskReasonsJSON,
		&row.RiskModelVersion,
		&row.ResourceURNsJSON,
		&row.EventIDsJSON,
		&row.ObservedPolicyIDsJSON,
		&row.ControlRefsJSON,
		&row.NotesJSON,
		&row.TicketsJSON,
		&row.ExternalRefsJSON,
		&row.PolicyID,
		&row.PolicyName,
		&row.CheckID,
		&row.CheckName,
		&row.AttributesJSON,
		&row.Assignee,
		&row.DueAt,
		&row.StatusReason,
		&row.StatusUpdatedAt,
		&row.FirstObservedAt,
		&row.LastObservedAt,
		&row.Tombstoned,
		&row.TombstonedAt,
		&row.TombstonedBy,
		&row.TombstonedReason,
		&row.TombstonedRunID,
		&row.PriorStatus,
		&row.TombstoneGeneration,
	)
}

func scanGRCFindingRow(scanner findingRowScanner) (*ports.FindingRecord, error) {
	var row grcFindingRow
	if err := scanner.Scan(
		&row.ID,
		&row.TenantID,
		&row.RuntimeID,
		&row.RuleID,
		&row.Title,
		&row.Severity,
		&row.Status,
		&row.Summary,
		&row.RiskScore,
		&row.LikelihoodScore,
		&row.ImpactScore,
		&row.ConfidenceScore,
		&row.LikelihoodLevel,
		&row.ImpactLevel,
		&row.RiskReasonsJSON,
		&row.RiskModelVersion,
		&row.ResourceURNsJSON,
		&row.ControlRefsJSON,
		&row.PolicyID,
		&row.PolicyName,
		&row.Assignee,
		&row.DueAt,
		&row.FirstObservedAt,
		&row.LastObservedAt,
	); err != nil {
		return nil, fmt.Errorf("scan grc finding row: %w", err)
	}
	resourceURNs, err := findingStringSliceFromJSON(row.ResourceURNsJSON)
	if err != nil {
		return nil, fmt.Errorf("decode grc finding resource urns: %w", err)
	}
	controlRefs := []ports.FindingControlRef{}
	if strings.TrimSpace(row.ControlRefsJSON) != "" {
		if err := json.Unmarshal([]byte(row.ControlRefsJSON), &controlRefs); err != nil {
			return nil, fmt.Errorf("decode grc finding control refs: %w", err)
		}
	}
	riskReasons, err := findingStringSliceFromJSON(row.RiskReasonsJSON)
	if err != nil {
		return nil, fmt.Errorf("decode grc finding risk reasons: %w", err)
	}
	return &ports.FindingRecord{
		ID:        row.ID,
		TenantID:  row.TenantID,
		RuntimeID: row.RuntimeID,
		RuleID:    row.RuleID,
		Title:     row.Title,
		Severity:  row.Severity,
		Status:    row.Status,
		Summary:   row.Summary,
		FindingRisk: ports.FindingRisk{
			RiskScore:        row.RiskScore,
			LikelihoodScore:  row.LikelihoodScore,
			ImpactScore:      row.ImpactScore,
			ConfidenceScore:  row.ConfidenceScore,
			LikelihoodLevel:  row.LikelihoodLevel,
			ImpactLevel:      row.ImpactLevel,
			RiskReasons:      riskReasons,
			RiskModelVersion: row.RiskModelVersion,
		},
		ResourceURNs: resourceURNs,
		PolicyID:     row.PolicyID,
		PolicyName:   row.PolicyName,
		ControlRefs:  controlRefs,
		FindingWorkflow: ports.FindingWorkflow{
			Assignee: row.Assignee,
			DueAt:    findingTimestamp(row.DueAt),
		},
		FirstObservedAt: row.FirstObservedAt.UTC(),
		LastObservedAt:  row.LastObservedAt.UTC(),
	}, nil
}

func (r findingRow) record() (*ports.FindingRecord, error) {
	resourceURNs := []string{}
	if err := json.Unmarshal([]byte(r.ResourceURNsJSON), &resourceURNs); err != nil {
		return nil, fmt.Errorf("decode finding resource urns: %w", err)
	}
	eventIDs := []string{}
	if err := json.Unmarshal([]byte(r.EventIDsJSON), &eventIDs); err != nil {
		return nil, fmt.Errorf("decode finding event ids: %w", err)
	}
	observedPolicyIDs := []string{}
	if err := json.Unmarshal([]byte(r.ObservedPolicyIDsJSON), &observedPolicyIDs); err != nil {
		return nil, fmt.Errorf("decode finding observed policy ids: %w", err)
	}
	controlRefs := []ports.FindingControlRef{}
	if err := json.Unmarshal([]byte(r.ControlRefsJSON), &controlRefs); err != nil {
		return nil, fmt.Errorf("decode finding control refs: %w", err)
	}
	riskReasons := []string{}
	if strings.TrimSpace(r.RiskReasonsJSON) != "" {
		if err := json.Unmarshal([]byte(r.RiskReasonsJSON), &riskReasons); err != nil {
			return nil, fmt.Errorf("decode finding risk reasons: %w", err)
		}
	}
	notes := []ports.FindingNote{}
	if err := json.Unmarshal([]byte(r.NotesJSON), &notes); err != nil {
		return nil, fmt.Errorf("decode finding notes: %w", err)
	}
	tickets := []ports.FindingTicket{}
	if err := json.Unmarshal([]byte(r.TicketsJSON), &tickets); err != nil {
		return nil, fmt.Errorf("decode finding tickets: %w", err)
	}
	externalRefs := []ports.FindingExternalRef{}
	if strings.TrimSpace(r.ExternalRefsJSON) != "" {
		if err := json.Unmarshal([]byte(r.ExternalRefsJSON), &externalRefs); err != nil {
			return nil, fmt.Errorf("decode finding external refs: %w", err)
		}
	}
	attributes := map[string]string{}
	if err := json.Unmarshal([]byte(r.AttributesJSON), &attributes); err != nil {
		return nil, fmt.Errorf("decode finding attributes: %w", err)
	}
	riskFactors := findingrisk.ParseRiskFactors(attributes[findingrisk.FindingRiskFactorsAttribute])
	severity := strings.TrimSpace(r.Severity)
	if effectiveSeverity := strings.TrimSpace(attributes[findingrisk.FindingEffectiveSeverityAttribute]); effectiveSeverity != "" {
		severity = effectiveSeverity
	}
	return &ports.FindingRecord{
		ID:          r.ID,
		Fingerprint: r.Fingerprint,
		TenantID:    r.TenantID,
		RuntimeID:   r.RuntimeID,
		RuleID:      r.RuleID,
		Title:       r.Title,
		Severity:    severity,
		Status:      r.Status,
		Summary:     r.Summary,
		FindingRisk: ports.FindingRisk{
			RiskScore:        r.RiskScore,
			LikelihoodScore:  r.LikelihoodScore,
			ImpactScore:      r.ImpactScore,
			ConfidenceScore:  r.ConfidenceScore,
			LikelihoodLevel:  r.LikelihoodLevel,
			ImpactLevel:      r.ImpactLevel,
			RiskReasons:      riskReasons,
			RiskFactors:      riskFactors,
			RiskModelVersion: r.RiskModelVersion,
		},
		ResourceURNs:      resourceURNs,
		EventIDs:          eventIDs,
		ObservedPolicyIDs: observedPolicyIDs,
		PolicyID:          r.PolicyID,
		PolicyName:        r.PolicyName,
		CheckID:           r.CheckID,
		CheckName:         r.CheckName,
		ControlRefs:       controlRefs,
		FindingWorkflow: ports.FindingWorkflow{
			Notes:           notes,
			Tickets:         tickets,
			ExternalRefs:    externalRefs,
			Assignee:        r.Assignee,
			DueAt:           findingTimestamp(r.DueAt),
			StatusReason:    r.StatusReason,
			StatusUpdatedAt: findingTimestamp(r.StatusUpdatedAt),
		},
		FindingTombstone: ports.FindingTombstone{
			Tombstoned:          r.Tombstoned,
			TombstonedAt:        findingTimestamp(r.TombstonedAt),
			TombstonedBy:        r.TombstonedBy,
			TombstonedReason:    r.TombstonedReason,
			TombstonedRunID:     r.TombstonedRunID,
			PriorStatus:         r.PriorStatus,
			TombstoneGeneration: r.TombstoneGeneration,
		},
		Attributes:      attributes,
		FirstObservedAt: r.FirstObservedAt.UTC(),
		LastObservedAt:  r.LastObservedAt.UTC(),
	}, nil
}

func findingTimestamp(value sql.NullTime) time.Time {
	if !value.Valid || value.Time.IsZero() {
		return time.Time{}
	}
	return value.Time.UTC()
}
