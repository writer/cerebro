package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/grcaudit"
	"github.com/writer/cerebro/internal/workflowevents"
)

const maxAuditProjectionPayloadBytes = 512 * 1024

var _ grcaudit.StateStore = (*Store)(nil)

type auditProjectionEvent struct {
	eventID          string
	tenantID         string
	aggregateType    string
	aggregateID      string
	aggregateVersion uint64
	operation        string
	contentDigest    string
	payloadJSON      string
	recordedAt       time.Time
	eventDigest      string
	kind             string
}

func (s *Store) ApplyAuditProjectionEvent(ctx context.Context, envelope *cerebrov1.EventEnvelope) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("postgres is not configured")
	}
	event, err := decodeAuditProjectionEvent(envelope)
	if err != nil {
		return false, err
	}
	if err := s.ensureAuditStateTables(ctx); err != nil {
		return false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin audit projection: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, auditProjectionAdvisoryLockSQL(), event.tenantID+"\x00"+event.eventID); err != nil {
		return false, fmt.Errorf("lock audit projection event: %w", err)
	}
	existingDigest, exists, err := loadAuditEventReceipt(ctx, tx, event.tenantID, event.eventID)
	if err != nil {
		return false, err
	}
	apply, err := auditReceiptDecision(existingDigest, exists, event.eventDigest)
	if err != nil || !apply {
		return false, err
	}
	if err := applyAuditProjectionPayload(ctx, tx, event); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO grc_audit_event_application_receipts (
  tenant_id, event_id, event_digest, aggregate_type, aggregate_id, aggregate_version, operation
)
VALUES ($1, $2, $3, $4, $5, $6, $7)`, event.tenantID, event.eventID, event.eventDigest,
		event.aggregateType, event.aggregateID, event.aggregateVersion, event.operation); err != nil {
		if auditPostgresUniqueViolation(err) {
			return false, grcaudit.ErrProjectionConflict
		}
		return false, fmt.Errorf("insert audit event receipt: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit audit projection: %w", err)
	}
	return true, nil
}

func (s *Store) GetAuditEngagement(ctx context.Context, principal grcaudit.Principal, engagementID string, permission grcaudit.EngagementPermission) (*grcaudit.Engagement, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureAuditStateTables(ctx); err != nil {
		return nil, err
	}
	var payload string
	err := s.db.QueryRowContext(ctx, `
SELECT state_json::text FROM grc_audit_engagements
WHERE tenant_id = $1 AND engagement_id = $2`, strings.TrimSpace(principal.TenantID), strings.TrimSpace(engagementID)).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, grcaudit.ErrEngagementNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get audit engagement: %w", err)
	}
	var engagement grcaudit.Engagement
	if err := json.Unmarshal([]byte(payload), &engagement); err != nil {
		return nil, fmt.Errorf("decode audit engagement: %w", err)
	}
	if err := grcaudit.AuthorizeEngagementAccess(principal, engagement, permission); err != nil {
		return nil, grcaudit.ErrEngagementNotFound
	}
	return &engagement, nil
}

func (s *Store) GetAuditEvidenceRequest(ctx context.Context, principal grcaudit.Principal, engagementID string, requestID string, permission grcaudit.EngagementPermission) (*grcaudit.EvidenceRequest, error) {
	engagement, err := s.GetAuditEngagement(ctx, principal, engagementID, permission)
	if err != nil {
		return nil, grcaudit.ErrEvidenceRequestNotFound
	}
	var payload string
	err = s.db.QueryRowContext(ctx, `
SELECT state_json::text FROM grc_audit_evidence_requests
WHERE tenant_id = $1 AND engagement_id = $2 AND request_id = $3`, principal.TenantID, engagement.ID, strings.TrimSpace(requestID)).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, grcaudit.ErrEvidenceRequestNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get audit evidence request: %w", err)
	}
	var request grcaudit.EvidenceRequest
	if err := json.Unmarshal([]byte(payload), &request); err != nil {
		return nil, fmt.Errorf("decode audit evidence request: %w", err)
	}
	if err := grcaudit.AuthorizeEvidenceRequestAccess(principal, *engagement, request, permission); err != nil {
		return nil, grcaudit.ErrEvidenceRequestNotFound
	}
	return &request, nil
}

func (s *Store) GetAuditPackageManifest(ctx context.Context, principal grcaudit.Principal, engagementID string, packageID string, revision uint64, permission grcaudit.EngagementPermission) (*grcaudit.PackageManifest, error) {
	engagement, err := s.GetAuditEngagement(ctx, principal, engagementID, permission)
	if err != nil {
		return nil, grcaudit.ErrPackageNotFound
	}
	var payload string
	err = s.db.QueryRowContext(ctx, `
SELECT manifest_json::text FROM grc_audit_package_manifests
WHERE tenant_id = $1 AND engagement_id = $2 AND package_id = $3 AND revision = $4`,
		principal.TenantID, engagement.ID, strings.TrimSpace(packageID), revision).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, grcaudit.ErrPackageNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get audit package manifest: %w", err)
	}
	manifest, err := decodeAuditPackageManifest(payload)
	if err != nil {
		return nil, err
	}
	if err := grcaudit.AuthorizePackageAccess(principal, *engagement, manifest, permission); err != nil {
		return nil, grcaudit.ErrPackageNotFound
	}
	return &manifest, nil
}

func applyAuditProjectionPayload(ctx context.Context, tx *sql.Tx, event auditProjectionEvent) error {
	switch event.aggregateType {
	case grcaudit.AuditAggregateEngagement:
		return applyAuditEngagement(ctx, tx, event)
	case grcaudit.AuditAggregateRequest:
		return applyAuditRequest(ctx, tx, event)
	case grcaudit.AuditAggregateSubmission:
		return applyAuditSubmission(ctx, tx, event)
	case grcaudit.AuditAggregateSample:
		return applyAuditSample(ctx, tx, event)
	case grcaudit.AuditAggregatePackage:
		return applyAuditPackage(ctx, tx, event)
	case grcaudit.AuditAggregateCapability:
		return applyAuditCapability(ctx, tx, event)
	case grcaudit.AuditAggregateGrant:
		return applyAuditGrant(ctx, tx, event)
	default:
		return grcaudit.ErrInvalidRequest
	}
}

func applyAuditEngagement(ctx context.Context, tx *sql.Tx, event auditProjectionEvent) error {
	var payload grcaudit.EngagementRecordedPayload
	if err := decodeAuditPayload(event, &payload); err != nil {
		return err
	}
	if payload.Engagement.TenantID != event.tenantID || payload.Engagement.ID != event.aggregateID || payload.Engagement.Version != event.aggregateVersion ||
		payload.Revision.TenantID != event.tenantID || payload.Revision.EngagementID != event.aggregateID ||
		payload.Engagement.CurrentRevision != payload.Revision.Revision || payload.Engagement.CurrentRevisionID != payload.Revision.ID ||
		payload.Engagement.Status != payload.Revision.Status || event.contentDigest != payload.Revision.RevisionHash {
		return grcaudit.ErrInvalidRequest
	}
	currentVersion, currentRevision, currentRevisionID, exists, err := loadAuditEngagementVersion(ctx, tx, event.tenantID, event.aggregateID)
	if err != nil {
		return err
	}
	if err := validateAuditAdvance(exists, currentVersion, event.aggregateVersion); err != nil {
		return err
	}
	if !exists {
		if payload.Revision.Revision != 1 || payload.Revision.PredecessorID != "" {
			return grcaudit.ErrVersionConflict
		}
	} else if payload.Revision.ID != currentRevisionID &&
		(payload.Revision.Revision != currentRevision+1 || payload.Revision.PredecessorID != currentRevisionID) {
		return grcaudit.ErrVersionConflict
	}
	stateJSON, err := marshalBoundedAuditJSON(payload.Engagement)
	if err != nil {
		return err
	}
	if !exists {
		_, err = tx.ExecContext(ctx, `
INSERT INTO grc_audit_engagements (
  tenant_id, engagement_id, aggregate_version, current_revision, current_revision_id, status, state_json, updated_at
)
	VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)`, event.tenantID, event.aggregateID,
			payload.Engagement.Version, payload.Engagement.CurrentRevision, payload.Engagement.CurrentRevisionID,
			payload.Engagement.Status, stateJSON, event.recordedAt)
	} else {
		_, err = tx.ExecContext(ctx, `
UPDATE grc_audit_engagements
SET aggregate_version = $3, current_revision = $4, current_revision_id = $5,
  status = $6, state_json = $7::jsonb, updated_at = $8
WHERE tenant_id = $1 AND engagement_id = $2`, event.tenantID, event.aggregateID,
			payload.Engagement.Version, payload.Engagement.CurrentRevision, payload.Engagement.CurrentRevisionID,
			payload.Engagement.Status, stateJSON, event.recordedAt)
	}
	if err != nil {
		return fmt.Errorf("write audit engagement: %w", err)
	}
	if !exists || payload.Revision.ID != currentRevisionID {
		if err := insertAuditEngagementRevision(ctx, tx, payload.Revision); err != nil {
			return err
		}
	}
	for _, participant := range payload.Engagement.Participants {
		if participant.TenantID != event.tenantID || participant.EngagementID != event.aggregateID {
			return grcaudit.ErrInvalidRequest
		}
		participantJSON, marshalErr := marshalBoundedAuditJSON(participant)
		if marshalErr != nil {
			return marshalErr
		}
		if _, execErr := tx.ExecContext(ctx, `
INSERT INTO grc_audit_participants (
  tenant_id, engagement_id, participant_id, principal_id, role, status, version, participant_json, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9)
ON CONFLICT (tenant_id, engagement_id, participant_id) DO UPDATE
SET principal_id = EXCLUDED.principal_id, role = EXCLUDED.role, status = EXCLUDED.status,
  version = EXCLUDED.version, participant_json = EXCLUDED.participant_json, updated_at = EXCLUDED.updated_at`,
			participant.TenantID, participant.EngagementID, participant.ID, participant.PrincipalID,
			participant.Role, participant.Status, participant.Version, participantJSON, participant.UpdatedAt); execErr != nil {
			return fmt.Errorf("write audit participant: %w", execErr)
		}
	}
	return nil
}

func applyAuditRequest(ctx context.Context, tx *sql.Tx, event auditProjectionEvent) error {
	var payload grcaudit.EvidenceRequestRecordedPayload
	if err := decodeAuditPayload(event, &payload); err != nil {
		return err
	}
	request := payload.Request
	if request.TenantID != event.tenantID || request.ID != event.aggregateID || request.Version != event.aggregateVersion ||
		payload.Revision.TenantID != event.tenantID || payload.Revision.RequestID != event.aggregateID || payload.Revision.EngagementID != request.EngagementID ||
		request.CurrentRevision != payload.Revision.Revision || request.CurrentRevisionID != payload.Revision.ID || request.Status != payload.Revision.Status ||
		event.contentDigest != payload.Revision.RevisionHash {
		return grcaudit.ErrInvalidRequest
	}
	currentVersion, currentRevision, currentRevisionID, exists, err := loadAuditRequestVersion(ctx, tx, event.tenantID, request.EngagementID, request.ID)
	if err != nil {
		return err
	}
	if err := validateAuditAdvance(exists, currentVersion, event.aggregateVersion); err != nil {
		return err
	}
	if !exists && (payload.Revision.Revision != 1 || payload.Revision.PredecessorID != "") {
		return grcaudit.ErrVersionConflict
	}
	if exists && (payload.Revision.Revision != currentRevision+1 || payload.Revision.PredecessorID != currentRevisionID) {
		return grcaudit.ErrVersionConflict
	}
	stateJSON, err := marshalBoundedAuditJSON(request)
	if err != nil {
		return err
	}
	if !exists {
		_, err = tx.ExecContext(ctx, `
INSERT INTO grc_audit_evidence_requests (
  tenant_id, engagement_id, request_id, aggregate_version, current_revision,
  current_revision_id, status, state_json, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9)`, request.TenantID, request.EngagementID,
			request.ID, request.Version, request.CurrentRevision, request.CurrentRevisionID, request.Status, stateJSON, event.recordedAt)
	} else {
		_, err = tx.ExecContext(ctx, `
UPDATE grc_audit_evidence_requests
SET aggregate_version = $4, current_revision = $5, current_revision_id = $6,
  status = $7, state_json = $8::jsonb, updated_at = $9
WHERE tenant_id = $1 AND engagement_id = $2 AND request_id = $3`, request.TenantID, request.EngagementID,
			request.ID, request.Version, request.CurrentRevision, request.CurrentRevisionID, request.Status, stateJSON, event.recordedAt)
	}
	if err != nil {
		return fmt.Errorf("write audit evidence request: %w", err)
	}
	return insertAuditRequestRevision(ctx, tx, payload.Revision)
}

func applyAuditSubmission(ctx context.Context, tx *sql.Tx, event auditProjectionEvent) error {
	var payload grcaudit.EvidenceSubmissionRecordedPayload
	if err := decodeAuditPayload(event, &payload); err != nil {
		return err
	}
	request := payload.Request
	submission := payload.Submission
	if request.TenantID != event.tenantID || request.ID != event.aggregateID || request.Version != event.aggregateVersion ||
		submission.TenantID != event.tenantID || submission.RequestID != request.ID || submission.EngagementID != request.EngagementID ||
		event.contentDigest != submission.SubmissionHash {
		return grcaudit.ErrInvalidRequest
	}
	currentVersion, _, _, exists, err := loadAuditRequestVersion(ctx, tx, event.tenantID, request.EngagementID, request.ID)
	if err != nil {
		return err
	}
	if err := validateAuditSubmissionAdvance(exists, currentVersion, event.aggregateVersion, submission.RequestVersion); err != nil {
		return err
	}
	stateJSON, err := marshalBoundedAuditJSON(request)
	if err != nil {
		return err
	}
	submissionJSON, err := marshalBoundedAuditJSON(submission)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO grc_audit_evidence_submissions (
  tenant_id, engagement_id, request_id, submission_id, request_version,
  submission_hash, submission_json, submitted_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)`, submission.TenantID,
		submission.EngagementID, submission.RequestID, submission.ID, submission.RequestVersion,
		submission.SubmissionHash, submissionJSON, submission.SubmittedAt); err != nil {
		if auditPostgresUniqueViolation(err) {
			return grcaudit.ErrProjectionConflict
		}
		return fmt.Errorf("insert audit evidence submission: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
UPDATE grc_audit_evidence_requests
SET aggregate_version = $4, status = $5, state_json = $6::jsonb, updated_at = $7
WHERE tenant_id = $1 AND engagement_id = $2 AND request_id = $3`, request.TenantID,
		request.EngagementID, request.ID, request.Version, request.Status, stateJSON, event.recordedAt)
	if err != nil {
		return fmt.Errorf("update submitted audit request: %w", err)
	}
	return nil
}

func applyAuditSample(ctx context.Context, tx *sql.Tx, event auditProjectionEvent) error {
	var sample grcaudit.SampleRevision
	if err := decodeAuditPayload(event, &sample); err != nil {
		return err
	}
	if sample.TenantID != event.tenantID || sample.ID != event.aggregateID || sample.Revision != event.aggregateVersion || event.contentDigest != sample.RevisionHash {
		return grcaudit.ErrInvalidRequest
	}
	var currentRevision uint64
	var currentID string
	err := tx.QueryRowContext(ctx, `
SELECT revision, sample_revision_id FROM grc_audit_sample_revisions
WHERE tenant_id = $1 AND engagement_id = $2 AND request_id = $3 AND population_id = $4
ORDER BY revision DESC LIMIT 1 FOR UPDATE`, sample.TenantID, sample.EngagementID,
		sample.EvidenceRequestID, sample.PopulationID).Scan(&currentRevision, &currentID)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("load audit sample revision: %w", err)
	}
	if err := validateAuditAdvance(exists, currentRevision, sample.Revision); err != nil {
		return err
	}
	if exists && sample.PredecessorID != currentID || !exists && sample.PredecessorID != "" {
		return grcaudit.ErrVersionConflict
	}
	payloadJSON, err := marshalBoundedAuditJSON(sample)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO grc_audit_sample_revisions (
  tenant_id, engagement_id, request_id, population_id, sample_revision_id,
  revision, predecessor_id, revision_hash, sample_json, created_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10)`, sample.TenantID,
		sample.EngagementID, sample.EvidenceRequestID, sample.PopulationID, sample.ID,
		sample.Revision, sample.PredecessorID, sample.RevisionHash, payloadJSON, sample.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert audit sample revision: %w", err)
	}
	return nil
}

func applyAuditPackage(ctx context.Context, tx *sql.Tx, event auditProjectionEvent) error {
	var manifest grcaudit.PackageManifest
	if err := decodeAuditPayload(event, &manifest); err != nil {
		return err
	}
	if manifest.TenantID != event.tenantID || manifest.PackageID != event.aggregateID || manifest.Revision != event.aggregateVersion || event.contentDigest != manifest.SemanticDigest {
		return grcaudit.ErrInvalidRequest
	}
	if err := grcaudit.VerifyPackageManifest(manifest); err != nil {
		return err
	}
	var currentRevision uint64
	var currentDigest string
	err := tx.QueryRowContext(ctx, `
SELECT current_revision, current_digest FROM grc_audit_packages
WHERE tenant_id = $1 AND engagement_id = $2 AND package_id = $3 FOR UPDATE`, manifest.TenantID,
		manifest.EngagementID, manifest.PackageID).Scan(&currentRevision, &currentDigest)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("load audit package: %w", err)
	}
	if err := validateAuditAdvance(exists, currentRevision, manifest.Revision); err != nil {
		return err
	}
	if exists && manifest.PredecessorDigest != currentDigest || !exists && manifest.PredecessorDigest != "" {
		return grcaudit.ErrVersionConflict
	}
	manifestJSON, err := marshalBoundedAuditJSON(manifest)
	if err != nil {
		return err
	}
	if !exists {
		_, err = tx.ExecContext(ctx, `
INSERT INTO grc_audit_packages (tenant_id, engagement_id, package_id, current_revision, current_digest, updated_at)
VALUES ($1, $2, $3, $4, $5, $6)`, manifest.TenantID, manifest.EngagementID,
			manifest.PackageID, manifest.Revision, manifest.SemanticDigest, event.recordedAt)
	} else {
		_, err = tx.ExecContext(ctx, `
UPDATE grc_audit_packages SET current_revision = $4, current_digest = $5, updated_at = $6
WHERE tenant_id = $1 AND engagement_id = $2 AND package_id = $3`, manifest.TenantID,
			manifest.EngagementID, manifest.PackageID, manifest.Revision, manifest.SemanticDigest, event.recordedAt)
	}
	if err != nil {
		return fmt.Errorf("write audit package pointer: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO grc_audit_package_manifests (
  tenant_id, engagement_id, package_id, revision, semantic_digest,
  predecessor_digest, manifest_json, created_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)`, manifest.TenantID, manifest.EngagementID,
		manifest.PackageID, manifest.Revision, manifest.SemanticDigest, manifest.PredecessorDigest,
		manifestJSON, event.recordedAt); err != nil {
		return fmt.Errorf("insert audit package manifest: %w", err)
	}
	for _, entry := range manifest.Entries {
		entryJSON, marshalErr := marshalBoundedAuditJSON(entry)
		if marshalErr != nil {
			return marshalErr
		}
		if _, execErr := tx.ExecContext(ctx, `
INSERT INTO grc_audit_package_manifest_entries (
  tenant_id, engagement_id, package_id, package_revision, entry_path,
  logical_type, stable_id, revision_id, redaction_action, entry_json
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)`, manifest.TenantID,
			manifest.EngagementID, manifest.PackageID, manifest.Revision, entry.Path,
			entry.LogicalType, entry.StableID, entry.RevisionID, entry.Redaction.Action, entryJSON); execErr != nil {
			return fmt.Errorf("insert audit package entry: %w", execErr)
		}
	}
	return nil
}

func applyAuditCapability(ctx context.Context, tx *sql.Tx, event auditProjectionEvent) error {
	var state grcaudit.CapabilityState
	if err := decodeAuditPayload(event, &state); err != nil {
		return err
	}
	if state.TenantID != event.tenantID || state.ID != event.aggregateID || state.Version != event.aggregateVersion || state.Kind == "" ||
		event.contentDigest != grcaudit.DigestBytes([]byte(event.payloadJSON)) {
		return grcaudit.ErrInvalidRequest
	}
	current, exists, err := loadAuditSimpleVersion(ctx, tx, `
SELECT version FROM grc_audit_capability_state WHERE tenant_id = $1 AND capability_id = $2 FOR UPDATE`, state.TenantID, state.ID)
	if err != nil {
		return err
	}
	if err := validateAuditAdvance(exists, current, state.Version); err != nil {
		return err
	}
	stateJSON, err := marshalBoundedAuditJSON(state)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO grc_audit_capability_state (tenant_id, capability_id, kind, enabled, version, state_json, updated_by, updated_at)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)
ON CONFLICT (tenant_id, capability_id) DO UPDATE
SET kind = EXCLUDED.kind, enabled = EXCLUDED.enabled, version = EXCLUDED.version,
  state_json = EXCLUDED.state_json, updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at`,
		state.TenantID, state.ID, state.Kind, state.Enabled, state.Version, stateJSON, state.UpdatedBy, state.UpdatedAt)
	if err != nil {
		return fmt.Errorf("write audit capability state: %w", err)
	}
	return nil
}

func applyAuditGrant(ctx context.Context, tx *sql.Tx, event auditProjectionEvent) error {
	var grant grcaudit.AccessGrant
	if err := decodeAuditPayload(event, &grant); err != nil {
		return err
	}
	if grant.TenantID != event.tenantID || grant.ID != event.aggregateID || grant.Version != event.aggregateVersion ||
		grant.EngagementID == "" || grant.PrincipalID == "" || grant.Permission == "" ||
		event.contentDigest != grcaudit.DigestBytes([]byte(event.payloadJSON)) {
		return grcaudit.ErrInvalidRequest
	}
	current, exists, err := loadAuditSimpleVersion(ctx, tx, `
SELECT version FROM grc_audit_access_grants WHERE tenant_id = $1 AND engagement_id = $2 AND grant_id = $3 FOR UPDATE`,
		grant.TenantID, grant.EngagementID, grant.ID)
	if err != nil {
		return err
	}
	if err := validateAuditAdvance(exists, current, grant.Version); err != nil {
		return err
	}
	grantJSON, err := marshalBoundedAuditJSON(grant)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO grc_audit_access_grants (
  tenant_id, engagement_id, grant_id, principal_id, permission, status, version, grant_json, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9)
ON CONFLICT (tenant_id, engagement_id, grant_id) DO UPDATE
SET principal_id = EXCLUDED.principal_id, permission = EXCLUDED.permission,
  status = EXCLUDED.status, version = EXCLUDED.version,
  grant_json = EXCLUDED.grant_json, updated_at = EXCLUDED.updated_at`, grant.TenantID,
		grant.EngagementID, grant.ID, grant.PrincipalID, grant.Permission, grant.Status,
		grant.Version, grantJSON, grant.UpdatedAt)
	if err != nil {
		return fmt.Errorf("write audit access grant: %w", err)
	}
	return nil
}

func insertAuditEngagementRevision(ctx context.Context, tx *sql.Tx, revision grcaudit.EngagementRevision) error {
	payload, err := marshalBoundedAuditJSON(revision)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO grc_audit_engagement_revisions (
  tenant_id, engagement_id, revision_id, revision, predecessor_id,
  revision_hash, revision_json, created_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)`, revision.TenantID,
		revision.EngagementID, revision.ID, revision.Revision, revision.PredecessorID,
		revision.RevisionHash, payload, revision.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert audit engagement revision: %w", err)
	}
	return nil
}

func insertAuditRequestRevision(ctx context.Context, tx *sql.Tx, revision grcaudit.EvidenceRequestRevision) error {
	payload, err := marshalBoundedAuditJSON(revision)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO grc_audit_evidence_request_revisions (
  tenant_id, engagement_id, request_id, revision_id, revision,
  predecessor_id, revision_hash, revision_json, created_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9)`, revision.TenantID,
		revision.EngagementID, revision.RequestID, revision.ID, revision.Revision,
		revision.PredecessorID, revision.RevisionHash, payload, revision.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert audit evidence request revision: %w", err)
	}
	return nil
}

func loadAuditEngagementVersion(ctx context.Context, tx *sql.Tx, tenantID string, engagementID string) (uint64, uint64, string, bool, error) {
	var version, revision uint64
	var revisionID string
	err := tx.QueryRowContext(ctx, `
SELECT aggregate_version, current_revision, current_revision_id
FROM grc_audit_engagements WHERE tenant_id = $1 AND engagement_id = $2 FOR UPDATE`, tenantID, engagementID).Scan(&version, &revision, &revisionID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, "", false, nil
	}
	if err != nil {
		return 0, 0, "", false, fmt.Errorf("load audit engagement version: %w", err)
	}
	return version, revision, revisionID, true, nil
}

func loadAuditRequestVersion(ctx context.Context, tx *sql.Tx, tenantID string, engagementID string, requestID string) (uint64, uint64, string, bool, error) {
	var version, revision uint64
	var revisionID string
	err := tx.QueryRowContext(ctx, `
SELECT aggregate_version, current_revision, current_revision_id
FROM grc_audit_evidence_requests
WHERE tenant_id = $1 AND engagement_id = $2 AND request_id = $3 FOR UPDATE`, tenantID, engagementID, requestID).Scan(&version, &revision, &revisionID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, "", false, nil
	}
	if err != nil {
		return 0, 0, "", false, fmt.Errorf("load audit request version: %w", err)
	}
	return version, revision, revisionID, true, nil
}

func loadAuditSimpleVersion(ctx context.Context, tx *sql.Tx, query string, args ...any) (uint64, bool, error) {
	var version uint64
	err := tx.QueryRowContext(ctx, query, args...).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("load audit aggregate version: %w", err)
	}
	return version, true, nil
}

func loadAuditEventReceipt(ctx context.Context, tx *sql.Tx, tenantID string, eventID string) (string, bool, error) {
	var digest string
	err := tx.QueryRowContext(ctx, `
SELECT event_digest FROM grc_audit_event_application_receipts
WHERE tenant_id = $1 AND event_id = $2 FOR UPDATE`, tenantID, eventID).Scan(&digest)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("load audit event receipt: %w", err)
	}
	return digest, true, nil
}

func auditProjectionAdvisoryLockSQL() string {
	return `SELECT pg_advisory_xact_lock(hashtext('grc_audit_projection_event'), hashtext($1))`
}

func auditReceiptDecision(existingDigest string, exists bool, incomingDigest string) (bool, error) {
	if !exists {
		return true, nil
	}
	if existingDigest == incomingDigest {
		return false, nil
	}
	return false, grcaudit.ErrProjectionConflict
}

func validateAuditAdvance(exists bool, current uint64, incoming uint64) error {
	if !exists && incoming == 1 || exists && incoming == current+1 {
		return nil
	}
	if !exists || incoming > current+1 {
		return grcaudit.ErrProjectionGap
	}
	return grcaudit.ErrVersionConflict
}

func validateAuditSubmissionAdvance(exists bool, current uint64, incoming uint64, requestVersion uint64) error {
	if !exists {
		return grcaudit.ErrProjectionGap
	}
	if requestVersion != current {
		return grcaudit.ErrVersionConflict
	}
	return validateAuditAdvance(true, current, incoming)
}

func decodeAuditProjectionEvent(envelope *cerebrov1.EventEnvelope) (auditProjectionEvent, error) {
	payload, err := workflowevents.DecodeComplianceAggregate(envelope)
	if err != nil {
		return auditProjectionEvent{}, err
	}
	if payload.AggregateVersion < 1 {
		return auditProjectionEvent{}, grcaudit.ErrInvalidRequest
	}
	recordedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(payload.RecordedAt))
	if err != nil {
		return auditProjectionEvent{}, fmt.Errorf("parse audit event recorded_at: %w", err)
	}
	event := auditProjectionEvent{
		eventID: strings.TrimSpace(envelope.GetId()), tenantID: strings.TrimSpace(payload.TenantID),
		aggregateType: strings.TrimSpace(payload.AggregateType), aggregateID: strings.TrimSpace(payload.AggregateID),
		aggregateVersion: uint64(payload.AggregateVersion), // #nosec G115 -- a positive int64 always fits in uint64.
		operation:        strings.TrimSpace(payload.Operation), contentDigest: strings.TrimSpace(payload.ContentDigest),
		payloadJSON: payload.PayloadJSON, recordedAt: auditProjectionTime(recordedAt), kind: strings.TrimSpace(payload.Kind),
	}
	event.eventDigest = grcaudit.DigestBytes(envelope.GetPayload())
	if event.eventID == "" || event.tenantID == "" || event.tenantID != strings.TrimSpace(envelope.GetTenantId()) ||
		event.aggregateType == "" || event.aggregateID == "" || event.operation == "" || event.recordedAt.IsZero() ||
		strings.TrimSpace(event.payloadJSON) == "" || len(event.payloadJSON) > maxAuditProjectionPayloadBytes ||
		!json.Valid([]byte(event.payloadJSON)) || !validAuditProjectionDigest(event.contentDigest) ||
		!auditEventKindMatchesAggregate(event.kind, event.aggregateType) {
		return auditProjectionEvent{}, grcaudit.ErrInvalidRequest
	}
	return event, nil
}

func auditEventKindMatchesAggregate(kind string, aggregateType string) bool {
	switch aggregateType {
	case grcaudit.AuditAggregateEngagement, grcaudit.AuditAggregateCapability, grcaudit.AuditAggregateGrant:
		return kind == workflowevents.EventKindComplianceAuditEngagementRecorded
	case grcaudit.AuditAggregateRequest:
		return kind == workflowevents.EventKindComplianceAuditRequestUpdated
	case grcaudit.AuditAggregateSubmission:
		return kind == workflowevents.EventKindComplianceAuditSubmissionRecorded
	case grcaudit.AuditAggregateSample:
		return kind == workflowevents.EventKindComplianceSampleRecorded
	case grcaudit.AuditAggregatePackage:
		return kind == workflowevents.EventKindComplianceAuditPackageRecorded
	default:
		return false
	}
}

func validAuditProjectionDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, character := range strings.TrimPrefix(value, "sha256:") {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func decodeAuditPayload(event auditProjectionEvent, target any) error {
	if err := json.Unmarshal([]byte(event.payloadJSON), target); err != nil {
		return fmt.Errorf("decode audit projection payload: %w", err)
	}
	return nil
}

func decodeAuditPackageManifest(payload string) (grcaudit.PackageManifest, error) {
	var manifest grcaudit.PackageManifest
	if err := json.Unmarshal([]byte(payload), &manifest); err != nil {
		return grcaudit.PackageManifest{}, fmt.Errorf("decode audit package manifest: %w", err)
	}
	if err := grcaudit.VerifyPackageManifest(manifest); err != nil {
		return grcaudit.PackageManifest{}, fmt.Errorf("verify audit package manifest: %w", err)
	}
	return manifest, nil
}

func marshalBoundedAuditJSON(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode audit state: %w", err)
	}
	if len(payload) > maxAuditProjectionPayloadBytes {
		return "", grcaudit.ErrInvalidRequest
	}
	return string(payload), nil
}

func auditProjectionTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Millisecond)
}

func auditPostgresUniqueViolation(err error) bool {
	var pgError *pgconn.PgError
	return errors.As(err, &pgError) && pgError.Code == "23505"
}
